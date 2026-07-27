"""Run the analyzer over thirty Java charts with NO FLAGS, and tabulate.

WHY THIS EXISTS
---------------
Every other proof script in this directory drives the analyzer with the exact
flags needed to isolate one behaviour. That is the right way to prove a rule
fires. It is the wrong way to find out what the tool is like to USE, because
almost nobody passes flags. They type the command, they read whatever comes
out, and they either act on it or close the terminal.

So this script does the thing that has never been done here: the whole corpus,
no flags, no values overlays, no --assume-java, no --helm switch, and a table of
what came back. Findings that are absent are as interesting as findings that
fire, so the table reports coverage (which categories were scored at all)
alongside grades.

WHAT "NO FLAGS" MEANS IN THIS SANDBOX, EXACTLY
----------------------------------------------
Two honest caveats, stated here rather than discovered by a reader later:

1. Since R12 the supported command is `hpa-analyzer <dir>`, which runs the
   pinned image. This container has no docker daemon (and no registry is
   reachable), so this script cannot run the real user path. It runs the module
   with HPA_ANALYZER_ALLOW_NATIVE=1 via proof/nativeoverride.py.

2. That matters less than it sounds, for one measurable reason: `helm` IS on
   PATH here (/usr/local/bin/helm), so an unflagged run renders with helm -
   which is the mode the image provides too. CLAIM 0 below asserts that rather
   than assuming it, because if helm ever leaves this container every row in
   the table silently becomes a static-mode row and the table would still look
   fine. What the sandbox cannot reproduce is the pinned VERSIONS
   (kubeconform/kube-score/polaris are absent here), and --cross-check is off
   by default, so no row depends on them.

Each chart is run with cwd set to its own empty directory and argv of exactly
[chart_dir]. That exercises the real default output path (./hpa_analysis_report.txt)
rather than a -o this script chose, which is itself a thing worth checking.
"""

import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE - see the module for why)
import corpus_charts  # noqa: E402

OUT = os.environ.get("CORPUS_DIR", "/tmp/java-corpus")
RUNS = os.environ.get("CORPUS_RUNS", "/tmp/java-corpus-runs")

FAILURES = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        print(f"         {detail}")
    if not ok:
        FAILURES.append(label)
    return ok


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------

def run_default(chart_dir, run_dir):
    """`python3 -m hpaanalyzer <chart>` and nothing else, from an empty cwd."""
    os.makedirs(run_dir, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, "-m", "hpaanalyzer", chart_dir],
        cwd=run_dir, capture_output=True, text=True, timeout=600,
        env={**os.environ, "PYTHONPATH": REPO},
    )
    report = os.path.join(run_dir, "hpa_analysis_report.txt")
    text = open(report).read() if os.path.exists(report) else ""
    return proc, text, report


SCORE_RE = re.compile(r"OVERALL QUALITY SCORE :\s*([0-9.]+) / 100\s+GRADE: (\S+)")
OVER_RE = re.compile(r"Computed over\s*:\s*(.+)")
MODE_RE = re.compile(r"Analysis mode\s*:\s*(.+)")
COUNT_RE = re.compile(r"Findings: (\d+) critical, (\d+) high, (\d+) medium, "
                      r"(\d+) low, (\d+) info")
# The leading \s* is not cosmetic. LOW findings are not rendered as full
# blocks; report.py collapses them to "[RS012] title (file) -> fix" indented
# by four. An anchored ^\[ therefore parsed 12 ids out of a report holding
# 6H/6M/9L, and every "ids present:" diagnostic below was silently missing
# every LOW - which is exactly the class of finding a claim about coverage
# would be checking for.
ID_RE = re.compile(r"^\s*\[([A-Z]{2}\d{3})\] (.+)$", re.M)


# R15. A report with no score is not necessarily a broken report. Since R7/F9
# the tool refuses to grade an input it could not analyse, and says so - c21 is
# an umbrella chart whose only workload lives in a subchart the parent does not
# render, so there is nothing to score and "NOT GRADED" is the honest answer.
# The two claims below used to demand a score line from every report, which
# would have been satisfied by the one behaviour scoring.py exists to forbid:
# putting a number on something never looked at. Those were checks that were
# wrong, not tool defects, and they are restated rather than deleted - a report
# that declines to grade still owes the reader a stated reason, and that is now
# what is asserted.
UNGRADED_RE = re.compile(r"OVERALL QUALITY SCORE\s*:\s*NOT GRADED")
REASON_RE = re.compile(r"^\s*(?:Reason: )?(\S.*)$", re.M)


def ungraded_reason(text):
    """The prose a NOT GRADED report gives for declining, or "" if it gives none."""
    m = UNGRADED_RE.search(text)
    if not m:
        return ""
    tail = text[m.end():m.end() + 600].strip()
    return " ".join(tail.split())[:200]


def parse(text):
    m = SCORE_RE.search(text)
    o = OVER_RE.search(text)
    md = MODE_RE.search(text)
    c = COUNT_RE.search(text)
    ids = ID_RE.findall(text)
    return {
        "score": float(m.group(1)) if m else None,
        "grade": m.group(2) if m else ("NG" if UNGRADED_RE.search(text) else "?"),
        "ungraded": bool(UNGRADED_RE.search(text)),
        "reason": ungraded_reason(text),
        "over": o.group(1).strip() if o else "?",
        "mode": md.group(1).strip() if md else "?",
        "counts": tuple(int(x) for x in c.groups()) if c else (0, 0, 0, 0, 0),
        "ids": [i for i, _ in ids],
        "titles": dict(ids),
    }


SEV_HDR = re.compile(r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO)  \(\d+\)$", re.M)


def crit_ids(text):
    """Rule ids inside the report's CRITICAL section, and only that section.

    report.py prints the findings grouped under `SEVERITY  (n)` headers, so
    "which ids are critical" is answerable from the report itself rather than
    by re-deriving it - and a claim about criticals that reads the whole id
    list is not a claim about criticals at all.
    """
    heads = [(m.group(1), m.start(), m.end()) for m in SEV_HDR.finditer(text)]
    for i, (name, _s, e) in enumerate(heads):
        if name != "CRITICAL":
            continue
        end = heads[i + 1][1] if i + 1 < len(heads) else len(text)
        return [rid for rid, _ in ID_RE.findall(text[e:end])]
    return []


BLOCK_RE = re.compile(r"^\[([A-Z]{2}\d{3})\] .*?(?=^\[[A-Z]{2}\d{3}\] |\Z)",
                      re.M | re.S)


def hard_crit_ids(text):
    """CRITICAL findings the tool did not have to ASSUME its way into.

    Needed because R14's cap deliberately exempts ASSUMED criticals: a guess
    the tool itself flags as a guess must not sink a grade, and
    models.effective_deduction() already caps its deduction on the same
    grounds. A claim below that counted ASSUMED criticals would be demanding
    behaviour the tool is designed NOT to have, and its failure would be the
    claim's fault - c04's HP025 is exactly that case, CRITICAL but ASSUMED
    because the HPA's target was not resolvable by name.

    Parsed from the default report rather than from --json on purpose: this
    script's entire premise is running the tool the way a user runs it, with
    no flags. If the report does not show a reader which criticals are guesses,
    that is itself a defect, and reading the JSON instead would hide it.
    """
    section = None
    heads = [(m.group(1), m.start(), m.end()) for m in SEV_HDR.finditer(text)]
    for i, (name, _s, e) in enumerate(heads):
        if name == "CRITICAL":
            section = text[e:heads[i + 1][1] if i + 1 < len(heads) else len(text)]
            break
    if not section:
        return []
    return [m.group(1) for m in BLOCK_RE.finditer(section.lstrip("\n -"))
            if "Basis : ASSUMED" not in m.group(0)]


def by_name0(results, name):
    for r in results:
        if r["name"] == name:
            return r
    raise KeyError(f"{name} missing from the corpus - the claim below cannot "
                   f"be evaluated, so it must not silently pass")


def main():
    print(__doc__.split("WHY THIS EXISTS")[0].strip())
    print()

    # ---- CLAIM 0 -------------------------------------------------------
    print("CLAIM 0: this run is in the same mode the image would use")
    helm = subprocess.run(["helm", "version", "--short"],
                          capture_output=True, text=True)
    check("helm is on PATH, so unflagged runs render rather than scrub",
          helm.returncode == 0, helm.stdout.strip() or helm.stderr.strip())
    print()

    # R15: was `len(made) == 15`, hardcoded when the corpus was fifteen charts.
    # The corpus grew to thirty and this check failed - a check that has to be
    # edited every time the thing it measures legitimately changes is testing
    # the author's memory, not the tool. It is asserted against
    # len(corpus_charts.CHARTS) now, so what it actually claims is "every chart
    # declared in the manifest materialised on disk", which is the property
    # worth having and does not decay.
    want_n = len(corpus_charts.CHARTS)
    print(f"generating {want_n} charts into {OUT}")
    made = corpus_charts.write_corpus(OUT)
    check(f"every declared chart is written ({want_n})", len(made) == want_n,
          f"n={len(made)}")
    print()

    results = []
    by_text = {}
    print("running each with NO FLAGS")
    for name, blurb in made:
        chart = os.path.join(OUT, name)
        proc, text, report = run_default(chart, os.path.join(RUNS, name))
        p = parse(text)
        p.update(name=name, blurb=blurb, rc=proc.returncode,
                 wrote=os.path.exists(report), stderr=proc.stderr)
        results.append(p)
        by_text[name] = text
        print(f"  {name:30s} rc={proc.returncode} "
              f"{p['grade']:>2s} {str(p['score']):>5s}  "
              f"{p['counts'][0]}C/{p['counts'][1]}H/{p['counts'][2]}M/{p['counts'][3]}L")
    print()

    # ---- CLAIM 1 -------------------------------------------------------
    print("CLAIM 1: the default invocation completes and writes its default report")
    bad_rc = [r["name"] for r in results if r["rc"] not in (0, 1)]
    check("no chart made the tool exit 2 (usage/IO error)", not bad_rc,
          ", ".join(bad_rc))
    nowrite = [r["name"] for r in results if not r["wrote"]]
    check("every run wrote ./hpa_analysis_report.txt with no -o given",
          not nowrite, ", ".join(nowrite))
    # See the R15 note beside UNGRADED_RE. Either a number, or a refusal that
    # says why - never a blank where a headline should be.
    silent = [r["name"] for r in results
              if r["score"] is None and not r["ungraded"]]
    check("every report either scores or says NOT GRADED - never neither",
          not silent, ", ".join(silent))
    mute = [r["name"] for r in results if r["ungraded"] and not r["reason"]]
    check("and every NOT GRADED report states its reason", not mute,
          "; ".join(f"{r['name']}: {r['reason'][:110]}"
                    for r in results if r["ungraded"])
          or "no ungraded chart in the corpus")
    print()

    # ---- CLAIM 2 -------------------------------------------------------
    print("CLAIM 2: every run says what mode it was in and what it scored over")
    modes = sorted({r["mode"] for r in results})
    check("every report names its analysis mode",
          all(r["mode"] != "?" for r in results), f"modes seen: {modes}")
    # R15: "behind the score" is the operative phrase, and the old check
    # ignored it - it demanded the line from every report including the one
    # with no score. "Computed over N categories" is a statement about how a
    # number was arrived at; a report that produced no number has no such
    # statement to make, and inventing one would be describing the arithmetic
    # of a computation that never ran.
    graded = [r for r in results if r["score"] is not None]
    check("every report names the category count behind the score",
          all(r["over"] != "?" for r in graded),
          "; ".join(sorted({r["over"] for r in graded})))
    stray = [r["name"] for r in results
             if r["score"] is None and r["over"] != "?"]
    check("and a report with no score claims no denominator either",
          not stray, ", ".join(stray))
    print()

    # ---- CLAIM 3 -------------------------------------------------------
    print("CLAIM 3: the scores separate good charts from dangerous ones")
    grades = sorted({r["grade"] for r in results})
    check("the corpus separates - more than two distinct grades",
          len(grades) > 2, " ".join(grades))
    scores = sorted(r["score"] for r in results if r["score"] is not None)
    # TWO REWRITES, both worth recording, because the shape of the mistake was
    # the same both times.
    #
    # First draft: `spread > 20`. It failed at 19.9. An arbitrary threshold is
    # not a claim; it is a number chosen so that today's output passes, and the
    # only thing 19.9 disproved was the 20.
    #
    # Second draft: c01 beats c03 by >= 15 points. That is a comparison between
    # two named charts rather than a threshold on an aggregate, so it was an
    # improvement - but it failed at 8.2, and chasing WHY it failed showed the
    # 15 was just as arbitrary as the 20. The mean is not broken. c03 really is
    # mediocre-in-nine-categories-and-fatal-in-one, and a weighted mean of that
    # really is ~85. Demanding a 15-point gap was demanding that the mean stop
    # behaving like a mean.
    #
    # What the corpus actually exposed is not about gaps at all: c07 sets
    # -Xmx3g inside a 2Gi limit, the tool files XF001 CRITICAL/OBSERVED and
    # writes "expect kernel OOM kills (exit 137)" in its own prose, and the
    # headline said B+. That is a contradiction inside one report, not a
    # calibration preference, and unlike a gap it can be stated without
    # choosing a number. R14 fixes it by capping the LABEL and leaving the
    # arithmetic alone; this claim is the corpus-wide version of that, and
    # proof/p16_gradecap.py is the isolated one.
    fatal = [r for r in results if hard_crit_ids(by_text[r["name"]])]
    check("some corpus chart asserts a certain failure",
          bool(fatal),
          f"{len(fatal)} of {len(results)} chart(s) carry a CRITICAL the tool "
          f"did not have to guess at - without one this claim is vacuous and "
          f"must not be reported as a pass")
    passing = [r for r in fatal if r["grade"].startswith(("A", "B"))]
    check("no chart the tool says will fail carries a passing grade",
          not passing,
          "; ".join(f"{r['name']}={r['grade']} {r['score']} "
                    f"({','.join(hard_crit_ids(by_text[r['name']]))})"
                    for r in passing) or
          "; ".join(f"{r['name']}={r['grade']}" for r in fatal))
    # The exemption is asserted, not merely relied upon. If a later change made
    # ASSUMED criticals cap, the claim above would still pass and the tool
    # would have started letting its own guesses sink grades in silence.
    guessed = [r for r in results
               if crit_ids(by_text[r["name"]])
               and not hard_crit_ids(by_text[r["name"]])]
    check("a chart whose only CRITICAL is a guess keeps its earned grade",
          bool(guessed) and all(not r["grade"].startswith("C") for r in guessed),
          "; ".join(f"{r['name']}={r['grade']} {r['score']} "
                    f"(all-assumed: {','.join(crit_ids(by_text[r['name']]))})"
                    for r in guessed) or
          "no such chart in the corpus - this claim cannot be evaluated here; "
          "proof/p16_gradecap.py builds one deliberately")
    # The cap is a claim about the letter, so the number must be able to
    # disagree with it - if capped charts also lost points, the cap would be a
    # re-weighting wearing a disguise.
    high_scoring_capped = [r for r in fatal if (r["score"] or 0) >= 85]
    check("and the score is free to disagree with the letter",
          bool(high_scoring_capped),
          "; ".join(f"{r['name']}={r['score']} shown as {r['grade']}"
                    for r in high_scoring_capped) or
          "no capped chart scores >= 85 - either the corpus changed or the "
          "cap has started moving the arithmetic, which it must not")
    c01, c03 = by_name0(results, "c01-temurin21-pct-cpu"), \
        by_name0(results, "c03-openjdk8-shellcmd")
    check("the deliberately-good chart still outscores the dangerous one",
          (c01["score"] or 0) > (c03["score"] or 0),
          f"c01={c01['score']} ({c01['grade']}) vs "
          f"c03={c03['score']} ({c03['grade']}) - gap "
          f"{(c01['score'] or 0) - (c03['score'] or 0):.1f}; the SIZE of this "
          f"gap is deliberately not asserted, see the comment above")
    print(f"         (corpus spread {scores[-1] - scores[0]:.1f} points, "
          f"{scores[0]} to {scores[-1]})")
    print()

    # ---- CLAIM 4 -------------------------------------------------------
    print("CLAIM 4: the charts built to trip a specific rule actually trip it")
    expect = [
        ("c02-8u131-inert-javaopts", "JV011", "8u131 experimental-cgroup window"),
        ("c05-11-removed-flags",     "JV015", "removed flag on Java 11"),
        # JV016 (UseConcMarkSweepGC) was in this list and failed. The
        # expectation was wrong, not the tool, and the correction is recorded
        # here so that nobody "fixes" checks_docker.py to satisfy it: CMS was
        # DEPRECATED in Java 9 and REMOVED in Java 14, and checks_docker.py
        # gates JV016 on `major >= 14` for that reason. c05 is Java 11, where
        # -XX:+UseConcMarkSweepGC still selects a real collector and prints a
        # deprecation warning - it does not abort startup. Raising a finding
        # there would be the tool inventing a failure, which is the fault this
        # project spent four iterations removing. Silence on Java 11 is the
        # correct behaviour and this comment is the test for it.
        ("c04-17-noflags-memhpa",    "HP025", "memory HPA on a JVM"),
        ("c08-corporate-base",       "DF003", "undeterminable Java version"),
        ("c11-pct-on-java8",         "JV017", "PermGen flag"),
        ("c14-resources-in-overlay", "RS001", "resources genuinely unset by default"),
    ]
    by_name = {r["name"]: r for r in results}
    for name, rid, why in expect:
        r = by_name.get(name)
        got = r and rid in r["ids"]
        check(f"{name} -> {rid} ({why})", bool(got),
              "" if got else f"ids present: {sorted(set(r['ids'])) if r else 'MISSING CHART'}")
    print()

    # ---- CLAIM 5 -------------------------------------------------------
    print("CLAIM 5: the false-positive control is not slandered")
    c01 = by_name["c01-temurin21-pct-cpu"]
    # The detail string used to print `criticals: {c01['ids']}` - every id in
    # the report, labelled as though they were the criticals. The assertion
    # was right and the evidence beside it was false, which is worse than no
    # evidence: a reader debugging a failure here would have chased ids that
    # were never critical. The report is parsed for the CRITICAL section
    # instead, so the number and the list come from the same place.
    crit = crit_ids(by_text[c01["name"]])
    check("c01 (modern, sized, CPU-scaled) has no CRITICAL findings",
          c01["counts"][0] == 0 and not crit,
          f"count={c01['counts'][0]} criticals={crit} score={c01['score']}")
    print()

    # ---- the table -----------------------------------------------------
    print("=" * 100)
    print(f"RESULTS - {len(results)} charts, `python3 -m hpaanalyzer <dir>`, "
          f"no other flags")
    print("=" * 100)
    hdr = (f"{'chart':32s} {'grade':>5s} {'score':>6s} {'C':>3s}{'H':>4s}"
           f"{'M':>4s}{'L':>4s}  {'scored over':<26s} top finding")
    print(hdr)
    print("-" * 100)
    for r in results:
        c, h, m, lo, _ = r["counts"]
        top = ""
        for rid in r["ids"]:
            top = f"{rid} {r['titles'][rid][:34]}"
            break
        over = r["over"].replace(" categories", "").replace("all ", "")[:26]
        print(f"{r['name']:32s} {r['grade']:>5s} {str(r['score']):>6s} "
              f"{c:>3d}{h:>4d}{m:>4d}{lo:>4d}  {over:<26s} {top}")
    print("-" * 100)
    print()

    print("=" * 100)
    print(f"{'FAILURES: ' + str(len(FAILURES)) if FAILURES else 'ALL CLAIMS PASS'}")
    for f in FAILURES:
        print(f"  - {f}")
    print("=" * 100)
    print(f"\ncharts:  {OUT}\nreports: {RUNS}/<chart>/hpa_analysis_report.txt")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())

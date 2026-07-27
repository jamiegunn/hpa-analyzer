"""Thirty-two charts x the whole flag surface, asserting INVARIANTS not snapshots.

WHY THIS EXISTS
---------------
p14 ran fifteen charts with no flags, because that is how the tool is actually
used. It found three defects. This script asks the opposite question: the CLI
advertises twenty-odd flags, each of which claims to change something. Which of
them actually do, and do the ones that are supposed to change NOTHING keep
their word?

WHY INVARIANTS AND NOT GOLDEN OUTPUT
------------------------------------
The obvious way to test the whole corpus against N flag configurations is to record
the output of each and diff on every run. That produces a fixture of several
megabytes that nobody reads, that goes red on every cosmetic wording change,
and that - crucially - proves nothing about whether the output is CORRECT. A
golden file is a record of what the tool did, not of what it should do.

So every claim below is a relation between two runs, or between a run and a
rule stated in the tool's own documentation:

  * a verbosity flag must not move the score          (relation between runs)
  * --json must agree with the text it accompanies    (relation between views)
  * --fail-on X must exit 1 iff a finding >= X exists (rule vs observation)
  * --assume-java must not manufacture a JVM          (rule vs observation)

Those survive rewording. They fail when the tool is wrong.

WHAT "ALL N CHARTS" MEANS
-------------------------
R16 note: this section said "ALL 32 CHARTS" and the labels below said 32, while
the code had always counted `len(charts)` - so when the corpus grew to
thirty-five the assertions stayed correct and every line printing them started
lying. A green line whose text is wrong is the exact defect this suite exists to
find, so the count is now interpolated everywhere rather than typed.

Every chart written by proof/corpus_charts.py, plus fixtures/good-chart
and fixtures/bad-chart - the two ends of the range the rest of the proof suite
is calibrated against. The other seven fixtures are already driven directly by
p1-p13 with the exact flags each one exists to exercise; re-running them here
under every flag would add runtime without adding a claim.

SANDBOX CAVEAT (same as p14)
----------------------------
Since R12 the supported command is `hpa-analyzer <dir>`, which runs the pinned
image. This container has no docker daemon, so the module is run directly with
HPA_ANALYZER_ALLOW_NATIVE=1 via proof/nativeoverride.py. `helm` IS on PATH here
(/usr/local/bin/helm), so unflagged runs render - CLAIM 0 asserts that rather
than assuming it. kubeconform/kube-score/polaris are absent, so --cross-check
is exercised only for the one property it can honestly be held to here (that it
does not change the score), and R11 already logged its non-determinism.
"""

import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402
import corpus_charts  # noqa: E402

CORPUS = os.environ.get("FLAGMATRIX_CORPUS", "/tmp/flagmatrix-corpus")
RUNS = os.environ.get("FLAGMATRIX_RUNS", "/tmp/flagmatrix-runs")
WORKERS = int(os.environ.get("FLAGMATRIX_WORKERS", "4"))

FAILURES = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        for line in str(detail).splitlines():
            print(f"         {line}")
    if not ok:
        FAILURES.append(label)
    return ok


def section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


# ---------------------------------------------------------------------------
# the run cache
# ---------------------------------------------------------------------------
#
# The corpus x ~25 flag configurations is ~900 subprocesses. Every claim below
# would otherwise re-run the same command several times, so runs are memoised
# on (chart, argv) and executed in a pool. A claim asks for a run by its flags;
# whether that run has already happened is not the claim's business.

_CACHE = {}
_ORDER = []


def _slug(args):
    if not args:
        return "default"
    s = "_".join(args).replace("/", "-").replace("=", "").replace(",", "-")
    s = re.sub(r"[^A-Za-z0-9._-]", "", s)
    return s[:80] or "default"


def want(chart, *args):
    """Declare that a run is needed. Returns its key; does not execute yet."""
    key = (chart, tuple(args))
    if key not in _CACHE:
        _CACHE[key] = None
        _ORDER.append(key)
    return key


def _execute(key):
    chart, args = key
    rundir = os.path.join(RUNS, os.path.basename(chart), _slug(list(args)))
    shutil.rmtree(rundir, ignore_errors=True)
    os.makedirs(rundir, exist_ok=True)
    argv = [sys.executable, "-m", "hpaanalyzer", chart] + list(args)
    proc = subprocess.run(argv, cwd=rundir, capture_output=True, text=True,
                          timeout=600,
                          env={**os.environ, "PYTHONPATH": REPO})
    return key, {
        "rc": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "dir": rundir,
        "argv": list(args),
        "chart": chart,
    }


def execute_all():
    todo = [k for k in _ORDER if _CACHE[k] is None]
    if not todo:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for key, res in pool.map(_execute, todo):
            _CACHE[key] = res
    print(f"  ({len(todo)} analyzer runs executed, {len(_CACHE)} cached)")


def got(chart, *args):
    r = _CACHE.get((chart, tuple(args)))
    if r is None:
        raise AssertionError(f"run not executed: {chart} {args}")
    return r


def rd(run, rel):
    p = os.path.join(run["dir"], rel)
    return open(p).read() if os.path.exists(p) else None


def rjson(run, rel="out.json"):
    t = rd(run, rel)
    return json.loads(t) if t else None


# ---------------------------------------------------------------------------
# report parsing
# ---------------------------------------------------------------------------

SCORE_RE = re.compile(r"OVERALL QUALITY SCORE :\s*([0-9.]+) / 100\s+GRADE: (\S+)")
NOTGRADED_RE = re.compile(r"OVERALL QUALITY SCORE : NOT GRADED")
MODE_RE = re.compile(r"Analysis mode\s*:\s*(\S+)")
ID_RE = re.compile(r"^\s*\[([A-Z]{2}\d{3})\]", re.M)
GEN_RE = re.compile(r"^Generated\s+:.*$", re.M)


def parse_text(t):
    if t is None:
        return None
    m = SCORE_RE.search(t)
    md = MODE_RE.search(t)
    return {
        "score": float(m.group(1)) if m else None,
        "grade": m.group(2) if m else (None if NOTGRADED_RE.search(t) else "?"),
        "graded": bool(m),
        "mode": md.group(1) if md else "?",
        "ids": sorted(set(ID_RE.findall(t))),
    }


def normalise(t):
    """Report text with the only legitimately-varying line removed."""
    return GEN_RE.sub("Generated        : <ts>", t or "")


# ---------------------------------------------------------------------------
# the corpus
# ---------------------------------------------------------------------------

TEXT = ["-o", "report.txt"]
BOTH = TEXT + ["--json", "out.json"]

# Presentation flags: documented as changing how much of the analysis is
# printed. None of them is documented as changing the analysis.
PRESENTATION = [
    ("summary", ["--summary"]),
    ("full", ["--full"]),
    ("all", ["--all"]),
    ("teach", ["--teach"]),
    ("stdout", ["--stdout"]),
]

# Three of the six measurable components, and then all six. The difference
# between these two is CLAIM 11's whole subject.
PARTIAL_MEASURED = ["--measured", "metaspace=180Mi,threads=60,direct=64Mi"]
ALL_MEASURED = ["--measured", "metaspace=180Mi,codecache=64Mi,threads=60,"
                              "direct=64Mi,gc=48Mi,xss=1Mi"]

SEVERITIES = ["low", "medium", "high", "critical"]
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def build_corpus():
    shutil.rmtree(CORPUS, ignore_errors=True)
    os.makedirs(CORPUS, exist_ok=True)
    made = corpus_charts.write_corpus(CORPUS)
    charts = [os.path.join(CORPUS, d) for d, _ in made]
    charts += [os.path.join(REPO, "fixtures", "good-chart"),
               os.path.join(REPO, "fixtures", "bad-chart")]
    return charts


def name(c):
    return os.path.basename(c)


def _uncat(j):
    """Category names out of score_coverage.unassessed, whose entries are
    objects (category + the reason it could not be scored), not strings."""
    out = []
    for u in j["score_coverage"]["unassessed"]:
        out.append(u if isinstance(u, str) else str(u.get("category", u)))
    return ",".join(out)


def find(charts, prefix):
    for c in charts:
        if name(c).startswith(prefix):
            return c
    raise AssertionError(f"no chart named {prefix}*")


# ---------------------------------------------------------------------------
def main():
    shutil.rmtree(RUNS, ignore_errors=True)
    charts = build_corpus()
    print(f"corpus: {len(charts)} charts under {CORPUS} (+2 fixtures)")

    c16 = find(charts, "c16")
    c17 = find(charts, "c17")
    c18 = find(charts, "c18")
    c19 = find(charts, "c19")
    c20 = find(charts, "c20")
    c22 = find(charts, "c22")
    c24 = find(charts, "c24")
    c30 = find(charts, "c30")

    # ---- declare every run up front, then execute once -------------------
    for c in charts:
        want(c)                                        # bare default
        want(c, *BOTH)                                 # baseline w/ json
        for _, extra in PRESENTATION:
            want(c, *(BOTH + extra))
        want(c, *(TEXT + ["--quiet"]))
        want(c, *(BOTH + ["--html", "report.html"]))
        want(c, *(BOTH + ["--helm", "on"]))
        want(c, *(BOTH + ["--helm", "off"]))
        want(c, *(BOTH + ["--helm", "auto"]))
        want(c, *(BOTH + ["--require-coverage"]))
        want(c, *(BOTH + ["--min-score", "90"]))
        want(c, *(BOTH + ["--min-score", "0"]))
        for s in SEVERITIES:
            want(c, *(BOTH + ["--fail-on", s]))
        want(c, *(BOTH + ["--fail-on", "none"]))
        want(c, "--check")
        want(c, *(BOTH + ["--assume-java", "17"]))
        want(c, *(BOTH + ["--kube-version", "1.31.0"]))
    # targeted runs
    want(c18, *(BOTH + PARTIAL_MEASURED))
    want(c18, *(BOTH + ALL_MEASURED))
    want(c17, *(BOTH + ["--kube-version", "1.20.0"]))
    want(c16, *(BOTH + ["--kube-version", "1.20.0"]))
    want(c24, *(BOTH + ["--assume-java", "8"]))
    want(charts[0], *(BOTH + ["--fail-on", "critical", "--min-score", "99",
                              "--require-coverage"]))
    want(c30, "--check")
    # determinism: a second run of an identical command in a different dir
    want(charts[0], *(TEXT + ["--all"]))

    print("executing...")
    execute_all()

    base = {c: got(c, *BOTH) for c in charts}
    bt = {c: parse_text(rd(base[c], "report.txt")) for c in charts}
    bj = {c: rjson(base[c]) for c in charts}

    # -------------------------------------------------------------------
    section("CLAIM 0 - the ground the rest of the matrix stands on")
    # -------------------------------------------------------------------
    helm_path = shutil.which("helm")
    check("helm is on PATH, so unflagged runs render rather than guess",
          bool(helm_path), f"helm = {helm_path}")

    missing = [name(c) for c in charts if rd(base[c], "report.txt") is None]
    check(f"all {len(charts)} charts produce a report file", not missing, missing)

    nojson = [name(c) for c in charts if bj[c] is None]
    check(f"all {len(charts)} charts produce --json output", not nojson, nojson)

    bad_rc = [(name(c), base[c]["rc"]) for c in charts if base[c]["rc"] != 0]
    check("with no CI gate, every chart exits 0 regardless of grade",
          not bad_rc, bad_rc)

    ungraded = sorted(name(c) for c in charts if not bj[c]["graded"])
    print(f"         graded: {len(charts)-len(ungraded)}/{len(charts)}; "
          f"NOT GRADED: {ungraded or 'none'}")
    for c in charts:
        if not bj[c]["graded"]:
            check(f"{name(c)}: NOT GRADED carries a stated reason",
                  bool(NOTGRADED_RE.search(rd(base[c], "report.txt") or "")),
                  "")

    # -------------------------------------------------------------------
    section("CLAIM 1 - presentation flags do not move the analysis")
    # -------------------------------------------------------------------
    # A score that changes when you ask for more verbose output means the
    # verbosity flag is reaching the analysis. That is the single most
    # dangerous class of CLI bug in a tool people gate deploys on.
    for label, extra in PRESENTATION:
        moved_score, moved_grade, moved_ids = [], [], []
        for c in charts:
            r = parse_text(rd(got(c, *(BOTH + extra)), "report.txt"))
            b = bt[c]
            if r is None:
                moved_score.append(f"{name(c)}: no report under --{label}")
                continue
            if r["score"] != b["score"]:
                moved_score.append(f"{name(c)}: {b['score']} -> {r['score']}")
            if r["grade"] != b["grade"]:
                moved_grade.append(f"{name(c)}: {b['grade']} -> {r['grade']}")
            if label in ("summary",):
                # --summary prints fewer findings on purpose; the SET is
                # allowed to shrink, but never to gain an id that the full
                # report did not have.
                extraids = set(r["ids"]) - set(b["ids"])
                if extraids:
                    moved_ids.append(f"{name(c)}: +{sorted(extraids)}")
            elif set(r["ids"]) != set(b["ids"]):
                d = set(r["ids"]) ^ set(b["ids"])
                moved_ids.append(f"{name(c)}: {sorted(d)}")
        check(f"--{label} does not move the score on any chart",
              not moved_score, moved_score[:5])
        check(f"--{label} does not move the grade on any chart",
              not moved_grade, moved_grade[:5])
        check(f"--{label} does not invent finding ids",
              not moved_ids, moved_ids[:5])

    # --json is itself a flag, and must be inert on the text report.
    inert = []
    for c in charts:
        a = normalise(rd(got(c), "hpa_analysis_report.txt"))
        b = normalise(rd(base[c], "report.txt"))
        pa, pb = parse_text(a), parse_text(b)
        if (pa or {}).get("score") != (pb or {}).get("score") or \
           (pa or {}).get("ids") != (pb or {}).get("ids"):
            inert.append(name(c))
    check("adding --json/-o does not change the report's score or findings",
          not inert, inert[:5])

    # -------------------------------------------------------------------
    section("CLAIM 2 - --json agrees with the text it was produced beside")
    # -------------------------------------------------------------------
    dis_score, dis_grade, dis_ids, dis_cap = [], [], [], []
    for c in charts:
        t, j = bt[c], bj[c]
        if j["graded"]:
            if t["score"] != j["score"]:
                dis_score.append(f"{name(c)}: text {t['score']} json {j['score']}")
            if t["grade"] != j["grade"]:
                dis_grade.append(f"{name(c)}: text {t['grade']} json {j['grade']}")
        jids = sorted({f["rule"] for f in j["findings"]})
        # the text report renders every finding; ids in the text that the json
        # lacks (or vice versa) mean one view is hiding something.
        only_json = set(jids) - set(t["ids"])
        only_text = set(t["ids"]) - set(jids)
        if only_json or only_text:
            dis_ids.append(f"{name(c)}: json-only {sorted(only_json)} "
                           f"text-only {sorted(only_text)}")
        cap = j.get("grade_cap_reason")
        if cap and not re.search(r"capped at", rd(base[c], "report.txt") or "", re.I):
            dis_cap.append(f"{name(c)}: json capped, text does not say so")
    check("score matches between --json and the text report", not dis_score, dis_score[:5])
    check("grade matches between --json and the text report", not dis_grade, dis_grade[:5])
    check("finding ids match between --json and the text report", not dis_ids, dis_ids[:5])
    check("a capped grade is visible in BOTH views", not dis_cap, dis_cap[:5])

    # counts block must agree with the findings list it summarises
    dis_counts = []
    for c in charts:
        j = bj[c]
        tally = {}
        for f in j["findings"]:
            tally[f["severity"].lower()] = tally.get(f["severity"].lower(), 0) + 1
        for sev, n in j["counts"].items():
            if tally.get(sev, 0) != n:
                dis_counts.append(f"{name(c)}: {sev} counts {n} != {tally.get(sev,0)}")
    check("--json counts agree with its own findings list",
          not dis_counts, dis_counts[:5])

    # -------------------------------------------------------------------
    section("CLAIM 3 - --quiet's one line agrees with the full report")
    # -------------------------------------------------------------------
    # The mode is not always one word: when helm ran and refused, the mode
    # IS the refusal, sentence and all, and that is the right call - a one-line
    # summary that hid it would be the lie. So the pattern takes everything
    # between the brackets, and the coverage clause is optional because it only
    # appears when coverage is partial.
    QUIET_RE = re.compile(r"hpa-analyzer \[([^\]]+)\]: score ([0-9.]+)/100 "
                          r"\(grade (\S+?)(?: CAPPED)?\)"
                          r"(?: over \d+/\d+ categories)?, (\d+) finding")
    QUIET_NG = re.compile(r"hpa-analyzer \[([^\]]+)\]: NOT GRADED")
    bad = []
    for c in charts:
        r = got(c, *(TEXT + ["--quiet"]))
        line = (r["stdout"] or "").strip()
        j = bj[c]
        m = QUIET_RE.search(line)
        if not j["graded"]:
            if not QUIET_NG.search(line):
                bad.append(f"{name(c)}: graded=False but quiet said {line!r}")
            continue
        if not m:
            bad.append(f"{name(c)}: unparseable quiet line {line!r}")
            continue
        if float(m.group(2)) != j["score"] or m.group(3) != j["grade"]:
            bad.append(f"{name(c)}: quiet {m.group(2)}/{m.group(3)} vs "
                       f"json {j['score']}/{j['grade']}")
        if int(m.group(4)) != len(j["findings"]):
            bad.append(f"{name(c)}: quiet {m.group(4)} findings vs "
                       f"json {len(j['findings'])}")
        if m.group(1) != j["mode"]:
            bad.append(f"{name(c)}: quiet mode {m.group(1)} vs json {j['mode']}")
    check("--quiet's single line matches score, grade, mode and count",
          not bad, bad[:5])

    quiet_noise = [name(c) for c in charts
                   if len((got(c, *(TEXT + ["--quiet"]))["stdout"] or "")
                          .strip().splitlines()) != 1]
    check("--quiet prints exactly one line on stdout",
          not quiet_noise, quiet_noise[:5])

    # -------------------------------------------------------------------
    section("CLAIM 4 - --html carries the same analysis as the text")
    # -------------------------------------------------------------------
    bad_html, bad_score = [], []
    for c in charts:
        r = got(c, *(BOTH + ["--html", "report.html"]))
        h = rd(r, "report.html")
        if not h:
            bad_html.append(name(c))
            continue
        j = rjson(r)
        if j["graded"]:
            # the score appears in the HTML as a number; require the exact
            # string, so a rounding change in one renderer and not the other
            # is caught rather than tolerated.
            if f"{j['score']:.1f}" not in h:
                bad_score.append(f"{name(c)}: {j['score']} absent from HTML")
        hids = set(re.findall(r"\b([A-Z]{2}\d{3})\b", h))
        jids = {f["rule"] for f in j["findings"]}
        if jids - hids:
            bad_score.append(f"{name(c)}: HTML missing ids {sorted(jids-hids)[:4]}")
    check("--html writes a file for every chart", not bad_html, bad_html[:5])
    check("--html carries the same score and every finding id",
          not bad_score, bad_score[:5])

    # -------------------------------------------------------------------
    section("CLAIM 5 - --fail-on exits 1 iff a finding at or above X exists")
    # -------------------------------------------------------------------
    # This is the flag CI actually gates on. It is checked against the json's
    # own counts, on every chart, at every severity - not on a fixture picked
    # because it happens to have one critical.
    wrong = []
    for c in charts:
        j = bj[c]
        for s in SEVERITIES:
            at_or_above = sum(n for sev, n in j["counts"].items()
                              if SEV_RANK.get(sev, -1) >= SEV_RANK[s])
            rc = got(c, *(BOTH + ["--fail-on", s]))["rc"]
            expect = 1 if at_or_above else 0
            if rc != expect:
                wrong.append(f"{name(c)} --fail-on {s}: rc={rc} expect={expect} "
                             f"({at_or_above} at/above)")
    check("--fail-on agrees with the report's own severity counts on all "
          f"{len(charts)} charts x 4 severities", not wrong, wrong[:8])

    none_rc = [(name(c), got(c, *(BOTH + ["--fail-on", "none"]))["rc"])
               for c in charts
               if got(c, *(BOTH + ["--fail-on", "none"]))["rc"] != 0]
    check("--fail-on none never fails", not none_rc, none_rc[:5])

    # -------------------------------------------------------------------
    section("CLAIM 6 - --min-score exits 1 iff score < N")
    # -------------------------------------------------------------------
    wrong = []
    for c in charts:
        j = bj[c]
        for n, thresh in (("90", 90.0), ("0", 0.0)):
            rc = got(c, *(BOTH + ["--min-score", n]))["rc"]
            if not j["graded"]:
                # An ungradeable chart cannot satisfy a minimum score. Passing
                # it would be the tool telling CI "good enough" about a chart
                # it declined to grade.
                if rc != 1:
                    wrong.append(f"{name(c)} --min-score {n}: NOT GRADED but rc={rc}")
                continue
            expect = 1 if j["score"] < thresh else 0
            if rc != expect:
                wrong.append(f"{name(c)} --min-score {n}: rc={rc} "
                             f"expect={expect} (score {j['score']})")
    check(f"--min-score agrees with the reported score on all {len(charts)} charts",
          not wrong, wrong[:8])

    # -------------------------------------------------------------------
    section("CLAIM 7 - --require-coverage exits 1 iff a category was unassessed")
    # -------------------------------------------------------------------
    wrong = []
    for c in charts:
        j = bj[c]
        un = j["score_coverage"]["unassessed"]
        rc = got(c, *(BOTH + ["--require-coverage"]))["rc"]
        expect = 1 if (un or not j["graded"]) else 0
        if rc != expect:
            wrong.append(f"{name(c)}: rc={rc} expect={expect} unassessed={un}")
    check("--require-coverage agrees with score_coverage.unassessed",
          not wrong, wrong[:8])

    covered = [name(c) for c in charts if not bj[c]["score_coverage"]["unassessed"]]
    print(f"         {len(covered)}/{len(charts)} charts scored all 10 categories")

    # -------------------------------------------------------------------
    section("CLAIM 8 - the three gates combine without cancelling")
    # -------------------------------------------------------------------
    c0 = charts[0]
    r = got(c0, *(BOTH + ["--fail-on", "critical", "--min-score", "99",
                          "--require-coverage"]))
    j = bj[c0]
    any_fail = (j["counts"].get("critical", 0) > 0 or j["score"] < 99
                or bool(j["score_coverage"]["unassessed"]))
    check("combined gates exit 1 if any single gate would",
          r["rc"] == (1 if any_fail else 0),
          f"{name(c0)}: rc={r['rc']} score={j['score']} "
          f"crit={j['counts'].get('critical',0)} "
          f"unassessed={j['score_coverage']['unassessed']}")

    # -------------------------------------------------------------------
    section("CLAIM 9 - --helm on/off/auto declare their mode, and differ")
    # -------------------------------------------------------------------
    # c20's template calls `required` on a value that is not set, so helm
    # CANNOT render it. It is named here rather than silently skipped: a loop
    # that quietly drops the one chart where the render fails is a loop that
    # tests only the easy case, and this comparison is between charts helm can
    # render. c20 gets its own claims below.
    renderable = [c for c in charts if c is not c20]
    modes_wrong, auto_ne_on, no_out = [], [], []
    for c in renderable:
        on = rjson(got(c, *(BOTH + ["--helm", "on"])))
        off = rjson(got(c, *(BOTH + ["--helm", "off"])))
        auto = rjson(got(c, *(BOTH + ["--helm", "auto"])))
        if on is None or off is None or auto is None:
            no_out.append(name(c))
            continue
        if off["mode"] != "static":
            modes_wrong.append(f"{name(c)}: --helm off reported mode {off['mode']}")
        if auto["mode"] != on["mode"]:
            auto_ne_on.append(f"{name(c)}: auto={auto['mode']} on={on['mode']}")
    check("every renderable chart produces output under all three --helm modes",
          not no_out, no_out[:5])
    check("--helm off always reports static mode", not modes_wrong, modes_wrong[:5])
    check("--helm auto matches --helm on where helm is installed",
          not auto_ne_on, auto_ne_on[:5])

    # The difference between rendering and guessing must be VISIBLE somewhere.
    # c19 hides a whole container behind a default-false conditional: static
    # analysis treats the branch as taken, helm does not. If those two agree,
    # one of the two modes is not doing its job.
    on19 = rjson(got(c19, *(BOTH + ["--helm", "on"])))
    off19 = rjson(got(c19, *(BOTH + ["--helm", "off"])))
    check("c19 (container behind a default-false if): helm and static disagree",
          {f["rule"] for f in on19["findings"]} !=
          {f["rule"] for f in off19["findings"]}
          or on19["score"] != off19["score"],
          f"helm score {on19['score']} ids {len(on19['findings'])}; "
          f"static score {off19['score']} ids {len(off19['findings'])}")

    # c20's template calls `required` on an unset value: helm MUST fail to
    # render it. This is the case where the three modes are supposed to behave
    # DIFFERENTLY from each other, and each difference is a promise:
    #
    #   --helm on   "render or tell me you could not" -> refuse, exit non-zero
    #   --helm auto "render if you can"               -> fall back, say so
    #   --helm off  "do not try"                      -> static, no complaint
    #
    # An earlier version of this claim asserted that `--helm on` must still
    # produce a report saying the render failed. That was the check being
    # wrong, not the tool: a report built from a static guess, produced under a
    # flag that means "rendered truth only", is exactly the silent downgrade
    # the flag exists to prevent. Refusing is the correct answer. The claim
    # below was rewritten to demand what `--helm on` actually promises.
    on20 = got(c20, *(BOTH + ["--helm", "on"]))
    check("c20 + --helm on: the tool refuses rather than guessing (exit 2)",
          on20["rc"] == 2, f"rc={on20['rc']}")
    check("c20 + --helm on: writes no report at all",
          rd(on20, "report.txt") is None and rd(on20, "out.json") is None,
          "a report written under a refused render would be the guess it "
          "refused to make")
    err20 = (on20["stderr"] or "")
    check("c20 + --helm on: the error names the flag, the file and the reason",
          all(s in err20 for s in ("--helm on", "deployment.yaml",
                                   "image.tag must be set")),
          err20.strip()[:200])

    auto20 = got(c20, *(BOTH + ["--helm", "auto"]))
    ja20 = rjson(auto20)
    check("c20 + --helm auto: falls back to static AND records why in the mode",
          ja20 is not None and ja20["mode"].startswith("static")
          and "refused" in ja20["mode"],
          f"mode={ja20['mode'][:120] if ja20 else None}")
    check("c20 + --helm auto: the recorded reason is helm's own message, not "
          "a paraphrase",
          ja20 is not None and "image.tag must be set" in ja20["mode"],
          "a paraphrased render error cannot be pasted into a search box")

    off20 = rjson(got(c20, *(BOTH + ["--helm", "off"])))
    check("c20 + --helm off: plain static mode, no render error attached",
          off20 is not None and off20["mode"] == "static",
          f"mode={off20['mode'] if off20 else None}")

    # -------------------------------------------------------------------
    section("CLAIM 10 - --assume-java does not manufacture a JVM")
    # -------------------------------------------------------------------
    # c24 is nginx. Nothing in it is Java. --assume-java is documented as
    # supplying a version when the tag HIDES one; on a chart with no JVM at
    # all there is nothing to supply it TO, and inventing a heap budget for
    # nginx is the exact R8 defect in reverse.
    j24 = rjson(got(c24, *(BOTH + ["--assume-java", "17"])))
    b24 = bj[c24]
    jvm_ids = {f["rule"] for f in j24["findings"] if f["rule"].startswith(("JV", "XF"))}
    check("c24 (nginx): --assume-java 17 raises no JVM or cross-file finding",
          not jvm_ids, sorted(jvm_ids))
    check("c24 (nginx): --assume-java 17 does not move the score",
          j24["score"] == b24["score"],
          f"{b24['score']} -> {j24['score']}")

    # Where the version is already known from the Dockerfile, restating it
    # must be a no-op. Charts whose detected version is already 17.
    noop_bad = []
    for c in charts:
        b = bj[c]
        a = rjson(got(c, *(BOTH + ["--assume-java", "17"])))
        if not (a and b):
            continue
        detected17 = "Java 17" in (rd(base[c], "report.txt") or "")
        if detected17 and (a["score"] != b["score"]
                           or {f["rule"] for f in a["findings"]} !=
                              {f["rule"] for f in b["findings"]}):
            noop_bad.append(f"{name(c)}: {b['score']} -> {a['score']}")
    check("--assume-java 17 is a no-op where Java 17 was already detected",
          not noop_bad, noop_bad[:5])

    # -------------------------------------------------------------------
    section("CLAIM 11 - --measured narrows the estimate, never widens it")
    # -------------------------------------------------------------------
    # An earlier version of this claim measured THREE of the six components
    # and asserted that UNDETERMINED must disappear. It did not, and the check
    # was the thing that was wrong: three measured components leave three
    # estimated ones, each still carrying its documented range, and a range
    # wide enough to straddle the limit is still a straddle. Measuring some of
    # the unknowns is not the same as measuring the unknown. The claim now
    # distinguishes the two cases, because the difference is the whole point of
    # the flag.
    m18 = got(c18, *(BOTH + PARTIAL_MEASURED))
    a18 = got(c18, *(BOTH + ALL_MEASURED))
    jm = rjson(m18)
    jb = bj[c18]
    tm = rd(m18, "report.txt") or ""
    ta = rd(a18, "report.txt") or ""
    tb = rd(base[c18], "report.txt") or ""
    check("c18: --measured is accepted without error", m18["rc"] in (0, 1),
          (m18["stderr"] or "").strip()[:200])
    check("c18: the run without --measured reports an UNDETERMINED fit",
          "UNDETERMINED" in tb,
          "c18 exists to straddle the band; if this fails the band constants "
          "moved and the chart must be re-sized, not the claim relaxed")
    check("c18: measuring 3 of 6 components does NOT settle the verdict "
          "(the remaining three still carry ranges)",
          "UNDETERMINED" in tm,
          f"UNDETERMINED occurrences: none={tb.count('UNDETERMINED')} "
          f"partial={tm.count('UNDETERMINED')}")
    check("c18: measuring all 6 components settles it - no UNDETERMINED left",
          "UNDETERMINED" not in ta,
          f"UNDETERMINED occurrences with all six measured: "
          f"{ta.count('UNDETERMINED')}")
    check("c18: a fully measured budget states that it has no range",
          "no range" in ta or "has no range" in ta,
          "the report should say the total is a point, not a band")
    non_java_moved = []
    cats_b = {f["rule"]: f["category"] for f in jb["findings"]}
    cats_m = {f["rule"]: f["category"] for f in jm["findings"]}
    for rid in set(cats_b) ^ set(cats_m):
        cat = cats_b.get(rid) or cats_m.get(rid)
        if not rid.startswith(("JV", "XF")):
            non_java_moved.append(f"{rid} ({cat})")
    check("c18: --measured moves only JVM/cross-file findings",
          not non_java_moved, non_java_moved[:8])

    # -------------------------------------------------------------------
    section("CLAIM 12 - --check inspects inputs and refuses to grade")
    # -------------------------------------------------------------------
    bad = []
    for c in charts:
        r = got(c, "--check")
        if r["rc"] != 0:
            bad.append(f"{name(c)}: rc={r['rc']}")
        for stray in ("hpa_analysis_report.txt", "report.txt", "out.json"):
            if os.path.exists(os.path.join(r["dir"], stray)):
                bad.append(f"{name(c)}: --check wrote {stray}")
        if "OVERALL QUALITY SCORE" in (r["stdout"] or ""):
            bad.append(f"{name(c)}: --check printed a score")
    check(f"--check exits 0 on all {len(charts)} chart directories and writes no report",
          not bad, bad[:8])

    notdir = os.path.join(RUNS, "_notachart_target")
    os.makedirs(notdir, exist_ok=True)
    want(notdir, "--check")
    execute_all()
    check("--check exits 2 on a directory that is not a chart",
          got(notdir, "--check")["rc"] == 2,
          f"rc={got(notdir, '--check')['rc']}")

    # c30 misfiles every input: Dockerfile under build/, a manifest outside
    # templates/, values named config.yaml. --check exists precisely to tell
    # someone that before they trust a report built on half of it.
    c30out = got(c30, "--check")["stdout"] or ""
    mentions = sum(1 for kw in ("build/", "k8s/", "config.yaml")
                   if kw in c30out)
    check("c30 (misfiled inputs): --check names at least one misplaced input",
          mentions >= 1,
          f"{mentions}/3 of build/, k8s/, config.yaml named in the check output")

    # -------------------------------------------------------------------
    section("CLAIM 13 - -o is honoured and --html defaults beside it")
    # -------------------------------------------------------------------
    bad = []
    for c in charts:
        r = base[c]
        if not os.path.exists(os.path.join(r["dir"], "report.txt")):
            bad.append(f"{name(c)}: -o report.txt not written")
        if os.path.exists(os.path.join(r["dir"], "hpa_analysis_report.txt")):
            bad.append(f"{name(c)}: wrote the default path as well as -o")
    check("-o writes exactly where it was told and nowhere else",
          not bad, bad[:5])

    d = got(charts[0])["dir"]
    check("with no -o the report lands at ./hpa_analysis_report.txt",
          os.path.exists(os.path.join(d, "hpa_analysis_report.txt")),
          d)

    # -------------------------------------------------------------------
    section("CLAIM 14 - identical inputs give identical output")
    # -------------------------------------------------------------------
    # Run the same command twice in two different directories. Anything that
    # differs beyond the timestamp is non-determinism, and a report that is
    # not reproducible cannot be diffed between two commits - which is most of
    # what a CI report is for.
    a = normalise(rd(got(charts[0], *(TEXT + ["--all"])), "report.txt"))
    rerun_dir = os.path.join(RUNS, "_determinism")
    shutil.rmtree(rerun_dir, ignore_errors=True)
    os.makedirs(rerun_dir, exist_ok=True)
    subprocess.run([sys.executable, "-m", "hpaanalyzer", charts[0]]
                   + TEXT + ["--all"],
                   cwd=rerun_dir, capture_output=True, text=True, timeout=600,
                   env={**os.environ, "PYTHONPATH": REPO})
    b = normalise(open(os.path.join(rerun_dir, "report.txt")).read())
    check("the same chart and flags twice produce a byte-identical report "
          "(timestamp excluded)",
          a == b,
          "" if a == b else f"first {len(a)} bytes, second {len(b)} bytes")

    # -------------------------------------------------------------------
    section("CLAIM 15 - --kube-version moves deprecated-API severity")
    # -------------------------------------------------------------------
    # c16 and c17 are the same chart. c17 declares kubeVersion covering the
    # window where networking.k8s.io/v1beta1 Ingress and policy/v1beta1 PDB
    # still exist; c16 declares nothing. A flag whose whole purpose is to
    # supply that context must produce a different answer on c16 at 1.31 than
    # at 1.20 - otherwise it is decoration.
    j16_31 = rjson(got(c16, *(BOTH + ["--kube-version", "1.31.0"])))
    j16_20 = rjson(got(c16, *(BOTH + ["--kube-version", "1.20.0"])))
    sev31 = {f["rule"]: f["severity"] for f in j16_31["findings"]}
    sev20 = {f["rule"]: f["severity"] for f in j16_20["findings"]}
    moved = {r: (sev20.get(r), sev31.get(r)) for r in set(sev31) | set(sev20)
             if sev20.get(r) != sev31.get(r)}
    check("c16: --kube-version 1.20 vs 1.31 changes at least one finding "
          "or its severity",
          bool(moved) or j16_20["score"] != j16_31["score"],
          f"changed: {dict(list(moved.items())[:6])}; "
          f"scores {j16_20['score']} -> {j16_31['score']}")

    # c17 DECLARES a range that ends before 1.21. Asking for 1.31 contradicts
    # the chart's own statement about itself. Whatever the tool decides to do
    # with that, it must not do it silently.
    r17 = got(c17, *(BOTH + ["--kube-version", "1.31.0"]))
    t17 = rd(r17, "report.txt") or ""
    j17 = rjson(r17)
    # An earlier version of this check searched for `kubeVersion|1\.31|conflict`
    # and passed - but it passed on the string "1.31" appearing anywhere,
    # including in the mode line that merely echoes the flag back. A check that
    # passes because the tool repeated my own argument to me is not a check.
    # What has to be visible is the INCOMPATIBILITY: the chart's declared range
    # and the requested version named together as being in conflict.
    conflict_visible = bool(re.search(
        r">=1\.19\.0-0 <1\.21\.0-0[^\n]*incompatible[^\n]*1\.31\.0", t17)
        or re.search(r"incompatible with Kubernetes v?1\.31\.0", t17))
    check("c17: a --kube-version outside the chart's declared kubeVersion "
          "range is reported as an incompatibility, not merely echoed",
          conflict_visible,
          "the chart declares >=1.19.0-0 <1.21.0-0 and was analyzed at 1.31.0; "
          "the report must say those two cannot both be true")

    # The report now contains, in one document, helm's refusal of this chart
    # against 1.31 AND a finding that says nothing breaks. Both cannot be
    # right. TP010 is ranked from the chart's self-declared kubeVersion; the
    # operator named the cluster on the command line. When those two sources
    # disagree the operator's statement is the one about reality.
    tp010 = [f for f in j17["findings"] if f["rule"] == "TP010"]
    breaks = [f for f in tp010
              if "nothing breaks today" in (f.get("fix", "") + f.get("detail", "")
                                            + f.get("why", "")).lower()]
    check("c17: at --kube-version 1.31.0, a v1beta1 Ingress and PDB are NOT "
          "described as breaking nothing",
          not breaks,
          "networking.k8s.io/v1beta1 Ingress was removed in 1.22 and "
          "policy/v1beta1 PDB in 1.25. At 1.31 these are not future work, "
          f"they are the reason the chart cannot install. severities: "
          f"{[f['severity'] for f in tp010]}")

    # And the remediation advice is generated without reading the argv it is
    # advising about.
    # Collapse whitespace before matching: the report hard-wraps at 100
    # columns, so `[^\n]*` between two halves of one sentence is a check that
    # passes whenever the wrap lands in the middle of the thing being looked
    # for. This one did pass, for exactly that reason, until the wrap moved.
    flat17 = re.sub(r"\s+", " ", t17)
    advice_loop = bool(re.search(
        r"Re-run with an explicit --kube-version.{0,60}1\.31\.0", flat17))
    check("c17: the tool does not advise supplying a flag that was supplied",
          not advice_loop,
          "the report tells the operator to re-run with `--kube-version "
          "1.31.0` in a run that was invoked with --kube-version 1.31.0")

    j17_base = bj[c17]
    check("c17 vs c16 on defaults: declaring kubeVersion changes the answer",
          j17_base["score"] != bj[c16]["score"]
          or {f["rule"] for f in j17_base["findings"]}
          != {f["rule"] for f in bj[c16]["findings"]},
          f"c16 {bj[c16]['score']} {bj[c16]['grade']} vs "
          f"c17 {j17_base['score']} {j17_base['grade']}")

    # -------------------------------------------------------------------
    section("CLAIM 16 - analysis reaches every workload kind that is scored")
    # -------------------------------------------------------------------
    # c22 is a CronJob whose container asks for -Xmx6g under a 4Gi limit. That
    # is the same arithmetic that caps c07 at C. The kind is irrelevant to the
    # arithmetic: a JVM told to take 6g of heap inside a 4Gi cgroup is killed
    # whether the pod was made by a Deployment or by a schedule.
    #
    # ChartContext.workloads admits Deployment, StatefulSet, DaemonSet,
    # ReplicaSet, Job, CronJob and Rollout. The scorer takes its category list
    # from what it decided to run, not from what it decided to look at, so a
    # kind that the JVM/cross-file pass skips is still scored - out of a clean
    # slate, because no rule in that category ever executed. That is this
    # tool's own named forbidden fabrication: "Score an unassessed category
    # 100: invents a clean bill of health for something never looked at."
    #
    # The claim is not "CronJobs must be analysed". It is the weaker and
    # non-negotiable one: a category may not be SCORED unless something in it
    # actually ran. Either analyse the workload or drop the category - the tool
    # may choose, but it may not do neither and report 100.
    j22 = bj[c22]
    cross_scored = "CROSS" in [
        a if isinstance(a, str) else a.get("category") for a in
        j22["score_coverage"]["assessed"]]
    cross_findings = [f for f in j22["findings"] if f["rule"].startswith("XF")]
    check("c22: a -Xmx6g heap under a 4Gi limit is reported, or CROSS is not "
          "scored - not both silent and scored 100",
          bool(cross_findings) or not cross_scored,
          f"CROSS assessed={cross_scored}, XF findings={len(cross_findings)}, "
          f"score {j22['score']} {j22['grade']}, coverage note: "
          f"{j22['score_coverage']['note']!r}. XF001-XF005 are the only rules "
          f"in CROSS and all five are emitted from _memory_budget(), which "
          f"_pairs() never reached because the kind is CronJob.")

    # An earlier version of this second check demanded a JV* finding whose text
    # mentioned "heap", and it was the check that was wrong. c22 DOES apply a
    # heap flag - -Xmx6g is set, explicitly, which is exactly what JV021 exists
    # to complain about the absence of - so the JAVA category has nothing to
    # say about it. The defect was never "JAVA has no findings"; it was that
    # the JVM pass never ran at all. Demand the evidence that it ran: the
    # report models this container's JVM, by name.
    t22_probe = rd(base[c22], "report.txt") or ""
    java_scored = "JAVA" in [
        a if isinstance(a, str) else a.get("category") for a in
        j22["score_coverage"]["assessed"]]
    modelled = bool(re.search(
        r"JVM memory budget - CronJob '[^']+' / container '[^']+'", t22_probe))
    check("c22: the JVM pass reaches the CronJob's container, or JAVA is not "
          "scored",
          modelled or not java_scored,
          f"JAVA assessed={java_scored}; a 'JVM memory budget' table naming "
          f"the CronJob container is the evidence that _pairs() admitted it. "
          f"JV rules present: "
          f"{sorted({f['rule'] for f in j22['findings'] if f['rule'].startswith('JV')})}")

    # The same statement, generalised: no chart may report full coverage of a
    # category in which not one rule ran. This is R14b's backstop looked at
    # from the other side - R14b stops a category with findings from being
    # dropped; nothing stops a category with no rule executions from being
    # kept.
    empty_but_scored = []
    for c in charts:
        j = bj[c]
        if not j["graded"]:
            continue
        got_cats = {f["category"] for f in j["findings"]}
        # CROSS is the only category whose rules are ALL emitted from one
        # function, so it is the only one where "no findings" is reliably
        # distinguishable from "looked and found nothing" by inspection.
        # Restricting the sweep to it keeps the claim honest.
        if "CROSS" in [a if isinstance(a, str) else a.get("category")
                       for a in j["score_coverage"]["assessed"]]:
            if not any(f["rule"].startswith("XF") for f in j["findings"]):
                jvm_here = any(f["rule"].startswith("JV") for f in j["findings"])
                if jvm_here and "Cross-File Consistency" not in got_cats:
                    empty_but_scored.append(name(c))
    print(f"  (charts scoring CROSS with JVM findings but no XF findings: "
          f"{empty_but_scored or 'none'})")

    # -------------------------------------------------------------------
    section("CLAIM 17 - an HPA target that cannot be scaled is reported")
    # -------------------------------------------------------------------
    # c22's HPA points at a batch/v1 CronJob. CronJob does not implement the
    # scale subresource, so this HPA cannot work: the controller will report
    # FailedGetScale and the autoscaler is inert forever. HP041 already proves
    # the tool resolves scaleTargetRef names correctly (c27's case mismatch is
    # caught), so this is not a parsing gap - the kind is simply never checked
    # against the set of kinds that can be scaled.
    #
    # Worse than silence: the report goes on to print a full HPA scaling
    # arithmetic table for a target that will never scale, which is a
    # confident answer to a question that does not apply.
    t22 = rd(base[c22], "report.txt") or ""
    target_flagged = [f for f in j22["findings"]
                      if "scale" in (f["title"] + f["detail"]).lower()
                      and "cronjob" in (f["title"] + f["detail"]).lower()]
    check("c22: an HPA whose scaleTargetRef.kind has no scale subresource is "
          "reported",
          bool(target_flagged),
          "scaleTargetRef is apiVersion: batch/v1, kind: CronJob. "
          "HPA rules present: "
          f"{sorted({f['rule'] for f in j22['findings'] if f['rule'].startswith('HP')})}")
    check("c22: the tool does not print HPA scaling arithmetic for a target "
          "it cannot scale",
          bool(target_flagged) or "HPA scaling arithmetic" not in t22,
          "a scaling table for an inert HPA is a confident answer to a "
          "question that does not apply")

    # -------------------------------------------------------------------
    section(f"SUMMARY TABLE - {len(charts)} charts on defaults")
    # -------------------------------------------------------------------
    print(f"{'chart':36s} {'grade':>6s} {'score':>6s} {'uncap':>6s} "
          f"{'C/H/M/L/I':>15s}  mode   unassessed")
    for c in charts:
        j = bj[c]
        cnt = j["counts"]
        counts = "/".join(str(cnt.get(k, 0)) for k in
                          ("critical", "high", "medium", "low", "info"))
        sc = f"{j['score']:.1f}" if j["graded"] else "-"
        print(f"{name(c):36s} {str(j['grade'] or 'NG'):>6s} {sc:>6s} "
              f"{str(j.get('grade_uncapped') or '-'):>6s} {counts:>15s}  "
              f"{j['mode'][:6]:6s} {_uncat(j) or '-'}")

    print()
    print("=" * 78)
    if FAILURES:
        print(f"{len(FAILURES)} CLAIM(S) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("all claims hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())

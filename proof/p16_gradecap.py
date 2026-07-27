"""R14. A chart the tool says will be OOM-killed cannot carry a passing grade.

HOW THIS WAS FOUND
------------------
Not by reading the code. `proof/p14_corpus.py` ran fifteen Java charts with no
flags - the way an actual user runs it - and one claim went red:

    the deliberately-good chart beats the dangerous one by >= 15 points
    c01=92.9 (A-) vs c03=84.7 (B) - gap 8.2

Chasing that produced a sharper and more provable statement than the gap ever
was. c07 sets `-Xmx3g` inside a `limits.memory: 2Gi`. The tool finds it, files
XF001 at CRITICAL with basis OBSERVED - not a guess, the two numbers are both
written down in the chart - prints the arithmetic, and says in its own prose
that the container will be OOM-killed under first real load. Then the front
page of that same report said:

    OVERALL QUALITY SCORE :  87.8 / 100   GRADE: B+

Both numbers are arithmetically correct. Together they are a lie, and it is
the headline that carries it, which is the worst possible place: a headline is
the part that gets skimmed, screenshotted and pasted into a ticket.

WHY THE MEAN CANNOT FIX ITSELF
------------------------------
The score is a weighted mean over ten categories, and it is doing exactly what
a mean does. c07's own category table:

    RESOURCES 100.0 A+ | HPA 97.0 A+ | JAVA 88.0 B+ | CROSS 76.0 C | ...

Nine categories with little wrong dilute the one category that says the process
cannot start. Re-weighting until the number "looks right" was rejected: every
version of that invents a measurement, and scoring.py's own docstring forbids
exactly this class of move. So the ARITHMETIC is left alone and the LABEL is
capped, with the cap and its cause printed next to the grade. A disclosed rule
is not a thumb on the scale; a silent one would be.

WHAT THIS SCRIPT ASSERTS
------------------------
1. The cap fires where the tool has asserted a certain failure.
2. It does not fire on charts that have no such finding.
3. It does not fire on ASSUMED criticals - those are the tool's own guesses,
   and models.effective_deduction() already refuses to let a guess sink a
   grade. A cap that fired where the deduction does not would make one finding
   weigh two different amounts in two places.
4. The numeric score never moves. The cap is a statement about the label.
5. The cap is never silent, on any of the four surfaces that print a grade:
   the stdout summary, the text report, the HTML report and the JSON.
6. A chart already at or below the cap is not "capped" - reporting a cap that
   changed nothing would be noise, and would make the disclosure worthless
   where it matters.
7. The good fixture is untouched.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE)
import corpus_charts as cc  # noqa: E402

sys.path.insert(0, REPO)
from hpaanalyzer.scoring import CRITICAL_GRADE_CAP, _GRADE_ORDER  # noqa: E402

FAILURES = []
TMP = tempfile.mkdtemp(prefix="p16-")


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        print(f"         {detail}")
    if not ok:
        FAILURES.append(label)
    return ok


def analyze(path, tag):
    """Run the tool the way a user does: no flags beyond the output paths.

    The HTML is requested too, because claim 5 is about every surface that
    prints a grade and the HTML is the one a reader is most likely to send to
    somebody else.
    """
    txt = os.path.join(TMP, f"{tag}.txt")
    js = os.path.join(TMP, f"{tag}.json")
    html = os.path.join(TMP, f"{tag}.html")
    p = subprocess.run(
        [sys.executable, "-m", "hpaanalyzer", path, "-o", txt, "--json", js,
         "--html", html],
        cwd=REPO, capture_output=True, text=True, timeout=600,
        env={**os.environ, "PYTHONPATH": REPO})
    if not os.path.exists(js):
        raise RuntimeError(f"{tag}: analyzer produced no JSON\n{p.stderr[-2000:]}")
    return (json.load(open(js)), open(txt).read(), open(html).read(), p.stdout)


def hard_criticals(data):
    """CRITICAL findings the tool did NOT have to assume its way into."""
    return sorted({f["rule"] for f in data["findings"]
                   if f["severity"] == "CRITICAL"
                   and not f["basis"].upper().startswith("ASSUMED")})


def soft_criticals(data):
    return sorted({f["rule"] for f in data["findings"]
                   if f["severity"] == "CRITICAL"
                   and f["basis"].upper().startswith("ASSUMED")})


def above_cap(g):
    return _GRADE_ORDER.index(g) > _GRADE_ORDER.index(CRITICAL_GRADE_CAP)


def flat(s):
    """Collapse runs of whitespace, so a wrapped paragraph can be searched.

    The text report wraps at 100 columns and indents continuation lines; the
    HTML does not wrap at all. A first draft of this script searched for the
    reason string verbatim and failed on every capped chart - it was asserting
    that the report does NOT wrap, which is not the claim and is not even
    desirable. What claim 5 is about is whether the sentence reaches the
    reader, and a wrapped sentence reaches the reader.
    """
    return re.sub(r"\s+", " ", s)


def assumed_only_chart():
    """A chart whose only CRITICAL is one the tool had to ASSUME.

    XF006 (R13) is the cleanest such finding in the tool: MaxRAMPercentage with
    no limits.memory. Its severity is CRITICAL and its basis is ASSUMED,
    because the consequence depends on the node's RAM and the chart does not
    choose the node. Built here rather than borrowed from the corpus because
    every corpus chart that raises XF006 also raises an observed critical, so
    the corpus cannot isolate this case - and a claim that cannot be isolated
    is a claim that cannot fail.
    """
    n = "svc"
    files = {
        "Chart.yaml": cc.CHART_YAML.format(name=n, desc="p16 fixture", app="1.0.0"),
        "values.yaml": "replicaCount: 2\n",
        "templates/deployment.yaml": cc.workload(
            n, "registry.example.com/svc:1.0.0", replicas=2,
            resources=cc.res("500m", "1Gi", None, None)),
        "templates/service.yaml": cc.SERVICE.format(name=n),
        "Dockerfile": cc.dockerfile(
            "eclipse-temurin:17.0.11_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }
    root = os.path.join(TMP, "assumed_only")
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write(content)
    return root


def main():
    print("R14 - the grade cannot contradict the findings under it\n")

    corpus = os.path.join(TMP, "corpus")
    cc.write_corpus(corpus)
    charts = sorted(os.listdir(corpus))

    runs = {}
    for name in charts:
        runs[name[:3]] = analyze(os.path.join(corpus, name), name[:3])

    # ----------------------------------------------------------------- 1 & 2
    print("CLAIM 1/2  the cap fires exactly where a non-ASSUMED CRITICAL is,\n"
          "           and the uncapped band was above the cap\n")
    for tag in sorted(runs):
        data, _txt, _html, _out = runs[tag]
        hard = hard_criticals(data)
        capped = data["grade_cap_reason"] is not None
        raw = data["grade_uncapped"]
        expect = bool(hard) and above_cap(raw)
        check(f"{tag}: cap={'yes' if capped else 'no '} "
              f"(uncapped {raw}, hard criticals {hard or 'none'})",
              capped == expect,
              "" if capped == expect else
              f"expected cap={expect}; the rule is 'any non-ASSUMED CRITICAL "
              f"and an uncapped grade above {CRITICAL_GRADE_CAP}'")

    # --------------------------------------------------------------------- 3
    print("\nCLAIM 3   an ASSUMED-only CRITICAL does not cap\n"
          "          (the tool's own uncertainty must not sink a grade)\n")
    data, txt, _html, _out = analyze(assumed_only_chart(), "assumed_only")
    hard, soft = hard_criticals(data), soft_criticals(data)
    check("fixture raises a CRITICAL at all", bool(soft),
          f"assumed criticals: {soft or 'none'} - without one this claim is "
          f"vacuous and must not be reported as a pass")
    check("and it is ASSUMED, not observed or derived", not hard,
          f"hard criticals: {hard or 'none'}")
    check("so the grade is NOT capped", data["grade_cap_reason"] is None,
          f"grade {data['grade']}, uncapped {data['grade_uncapped']}")
    check("and the grade equals the raw band",
          data["grade"] == data["grade_uncapped"],
          f"{data['grade']} vs {data['grade_uncapped']}")

    # --------------------------------------------------------------------- 4
    print("\nCLAIM 4   the cap moves the label and never the number\n")
    for tag in sorted(runs):
        data, txt, _html, _out = runs[tag]
        if data["grade_cap_reason"] is None:
            continue
        # The score printed in the text report is produced by a different code
        # path from the JSON's, so comparing them is not a tautology.
        m = re.search(r"OVERALL QUALITY SCORE :\s*([0-9.]+) / 100", txt)
        check(f"{tag}: score {data['score']} identical in report and JSON",
              m is not None and abs(float(m.group(1)) - data["score"]) < 0.05,
              f"report says {m.group(1) if m else 'NOT FOUND'}")
        check(f"{tag}: the cap reason quotes that same number",
              f"{data['score']:.1f}" in data["grade_cap_reason"],
              data["grade_cap_reason"][:120])

    # --------------------------------------------------------------------- 5
    print("\nCLAIM 5   the cap is disclosed on every surface that prints a grade\n")
    for tag in sorted(runs):
        data, txt, html, out = runs[tag]
        why = data["grade_cap_reason"]
        if why is None:
            continue
        ids = re.search(r"\(([A-Z]{2}\d{3}(?:, [A-Z]{2}\d{3})*)\)", why)
        check(f"{tag}: reason names the rule ids that caused it",
              ids is not None
              and sorted(ids.group(1).split(", ")) == hard_criticals(data),
              f"reason says {ids.group(1) if ids else 'NOTHING'}; "
              f"hard criticals are {hard_criticals(data)}")
        check(f"{tag}: reason names the band it capped FROM",
              f"from {data['grade_uncapped']}" in why,
              f"uncapped {data['grade_uncapped']} not in reason")
        check(f"{tag}: text report prints the reason", flat(why) in flat(txt),
              "" if flat(why) in flat(txt) else
              f"looked for: {flat(why)[:90]}...")
        check(f"{tag}: HTML report prints the reason", flat(why) in flat(html),
              "" if flat(why) in flat(html) else
              "not present - HTML escaping may have altered it")
        check(f"{tag}: text report's headline grade is the capped one",
              re.search(r"OVERALL QUALITY SCORE :.*GRADE: "
                        + re.escape(CRITICAL_GRADE_CAP) + r"\s*$",
                        txt, re.M) is not None,
              re.search(r"OVERALL QUALITY SCORE :.*", txt).group(0))
        check(f"{tag}: stdout summary prints the capped grade and the reason",
              f"GRADE {CRITICAL_GRADE_CAP} " in out and flat(why) in flat(out),
              out.split("GRADE")[1][:60] if "GRADE" in out else out[-200:])
        # The one-line mode is where a silent cap would do the most damage.
        q = subprocess.run(
            [sys.executable, "-m", "hpaanalyzer",
             os.path.join(corpus, [c for c in charts if c.startswith(tag)][0]),
             "--quiet", "-o", os.path.join(TMP, "q.txt")],
            cwd=REPO, capture_output=True, text=True, timeout=600,
            env={**os.environ, "PYTHONPATH": REPO})
        check(f"{tag}: --quiet marks the grade as capped",
              f"grade {CRITICAL_GRADE_CAP} CAPPED" in q.stdout,
              q.stdout.strip())

    # --------------------------------------------------------------------- 6
    print("\nCLAIM 6   a chart already at or below the cap is not reported as capped\n")
    at_or_below = [t for t, (d, *_r) in runs.items()
                   if hard_criticals(d) and not above_cap(d["grade_uncapped"])]
    check("the corpus contains such a chart",
          bool(at_or_below),
          f"charts with hard criticals already at/below {CRITICAL_GRADE_CAP}: "
          f"{at_or_below or 'NONE - claim 6 cannot be evaluated'}")
    for tag in at_or_below:
        data = runs[tag][0]
        check(f"{tag}: uncapped {data['grade_uncapped']}, no cap reported",
              data["grade_cap_reason"] is None and
              data["grade"] == data["grade_uncapped"],
              f"grade {data['grade']}, reason {data['grade_cap_reason']}")

    # --------------------------------------------------------------------- 7
    print("\nCLAIM 7   the good fixture is untouched\n")
    good, gtxt, _gh, _go = analyze(os.path.join(REPO, "fixtures", "good-chart"),
                                   "good")
    check("fixtures/good-chart still 100.0 A+",
          good["score"] == 100.0 and good["grade"] == "A+",
          f"{good['score']} {good['grade']}")
    check("no cap, no cap reason", good["grade_cap_reason"] is None)
    check("and no 'capped at' text anywhere in its report",
          "capped at" not in gtxt)

    # --------------------------------------------------------------------- 8
    print("\nCLAIM 8   the headline defect that opened R14 is fixed\n"
          "          c07: -Xmx3g inside a 2Gi limit, graded B+ 87.8\n")
    c07, c07txt, _c7h, _c7o = runs["c07"]
    check("c07 still raises XF001 at CRITICAL, basis observed",
          "XF001" in hard_criticals(c07),
          f"hard criticals: {hard_criticals(c07)}")
    check("c07's report still says the container will be OOM-killed",
          "OOM" in c07txt.upper())
    check("c07's uncapped band is still B+ (the score did not move)",
          c07["grade_uncapped"] == "B+" and abs(c07["score"] - 87.8) < 0.05,
          f"{c07['grade_uncapped']} {c07['score']}")
    check(f"but the grade it PRINTS is {CRITICAL_GRADE_CAP}",
          c07["grade"] == CRITICAL_GRADE_CAP, f"grade {c07['grade']}")
    check("no chart in the corpus shows a grade above the cap while "
          "asserting a certain failure",
          all(not (hard_criticals(d) and above_cap(d["grade"]))
              for d, *_r in runs.values()),
          ", ".join(f"{t}={d['grade']}" for t, (d, *_r) in sorted(runs.items())
                    if hard_criticals(d) and above_cap(d["grade"])) or "none")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILURE(S):")
        for f in FAILURES:
            print(f"  - {f}")
    else:
        print("ALL CLAIMS PASS")
    shutil.rmtree(TMP, ignore_errors=True)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())

"""R13. What the tool says when there is no memory limit to compare against.

HOW THIS WAS FOUND
------------------
Not by reading the code. `proof/p14_corpus.py` ran fifteen Java charts with no
flags - the way an actual user runs it - and one row of the table did not make
sense:

    c12-no-mem-limit      B+   88.2   1C 3H 4M 10L

c12 is a chart whose image sets `-XX:MaxRAMPercentage=75` and whose pod spec
sets no `limits.memory` at all. A container-aware JVM with no cgroup memory
limit reads the NODE's memory as its budget, so that chart asks for 75% of the
node's RAM in every replica. On a 16 GiB node that is a 12 GiB heap target per
pod; on a 64 GiB node, 48 GiB. It is the single most dangerous chart in the
corpus. The tool scored it B+ and said this:

    | Java / JVM Container Fitness           |  94.0 | A  | 14 |  1M  |
    | Cross-File Consistency (Chart <-> JVM) | 100.0 | A+ | 14 |  -   |
    | Max heap (H)   | UNBOUNDED | no limit and no explicit sizing - unbounded |

Four separate defects, in increasing order of seriousness:

1. "no explicit sizing" is FALSE. The chart sizes the heap explicitly. What the
   tool means is "I could not turn that sizing into a number", and it reports it
   as a property of the user's chart instead of as a property of its own
   arithmetic. A reader who acts on it sets -Xmx and does not set the limit,
   which is the wrong half.

2. The ESTIMATED PEAK RSS row read "T = H + non-heap components (all measured,
   no estimates)" while every component row above it was labelled "(est.)". The
   wording is chosen by `banded`, whose comment asserts it "is false only when
   the user has measured EVERY non-heap component" - true when it was written,
   false once `total` could be None.

3. Cross-File Consistency scored 100.0 / A+ - fourteen of a hundred weight
   points of clean bill of health. It is not a passing grade, it is an empty
   category: XF001, XF002, XF003, XF004 and XF005 are EVERY rule in that
   category and all five are gated on `if lim ...`. With no memory limit the
   category cannot deduct a single point, by construction. This is the third
   time this project has shipped this exact fault - PB004/Dockerfile in R8, the
   helper-supplied resources in R11 - and scoring.py's own docstring names it:
   "Score an unassessed category 100: invents a clean bill of health for
   something never looked at."

4. No finding, anywhere, at any severity, says the words "you asked for a
   percentage of a limit you did not set". The tool holds every fact needed -
   it prints "MaxRAMPercentage is computed FROM it" in its own prose - and
   draws no conclusion.

c03 shows defect 3 without defect 1: `-Xmx512m`, no limit, heap therefore known
and bounded, and Cross-File Consistency still 100.0 / A+ over zero findings.

WHAT THIS SCRIPT ASSERTS
------------------------
The corrected behaviour, with negative controls for each, so that a later
"simplification" that reintroduces any of the four fails here rather than in
somebody's cluster.
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
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE - see the module for why)
import corpus_charts as cc  # noqa: E402

FAILURES = []
TMP = tempfile.mkdtemp(prefix="p15-")


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        print(f"         {detail}")
    if not ok:
        FAILURES.append(label)
    return ok


# --------------------------------------------------------------------------
# fixtures: one knob at a time
# --------------------------------------------------------------------------

def chart(kind):
    """A minimal Java chart. `kind` moves exactly one thing.

    Every variant is the SAME chart apart from the named knob, so a difference
    between two runs can only be attributed to that knob. The alternative -
    reusing the corpus charts, which differ in a dozen ways each - would make
    every comparison below unfalsifiable.
    """
    n = "svc"
    limit = {"pct+limit": "1Gi", "xmx+limit": "1Gi", "nothing+limit": "1Gi"}.get(kind)
    env = {
        "pct+limit": {"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
        "pct+nolimit": {"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
        "xmx+limit": {"JAVA_TOOL_OPTIONS": "-Xmx512m"},
        "xmx+nolimit": {"JAVA_TOOL_OPTIONS": "-Xmx512m"},
        "nothing+limit": {},
        "nothing+nolimit": {},
    }[kind]
    files = {
        "Chart.yaml": cc.CHART_YAML.format(name=n, desc="p15 fixture", app="1.0.0"),
        "values.yaml": "replicaCount: 2\n",
        "templates/deployment.yaml": cc.workload(
            n, "registry.example.com/svc:1.0.0", replicas=2,
            resources=cc.res("500m", "1Gi", None, limit)),
        "templates/service.yaml": cc.SERVICE.format(name=n),
        "Dockerfile": cc.dockerfile(
            "eclipse-temurin:17.0.11_9-jre", env=env,
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }
    root = os.path.join(TMP, kind.replace("+", "_"))
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write(content)
    return root


def analyze(path):
    txt = os.path.join(TMP, "r.txt")
    js = os.path.join(TMP, "r.json")
    subprocess.run([sys.executable, "-m", "hpaanalyzer", path, "-o", txt,
                    "--json", js],
                   cwd=REPO, capture_output=True, text=True, timeout=600,
                   env={**os.environ, "PYTHONPATH": REPO})
    return json.load(open(js)), open(txt).read()


def ids(data):
    return {f["rule"] for f in data["findings"]}


def sev_of(data, rid):
    for f in data["findings"]:
        if f["rule"] == rid:
            return f["severity"]
    return None


def unassessed(data):
    """The category NAMES that were dropped from the denominator.

    score_coverage.unassessed is a list of {category, reason} objects, not a
    list of names - a first draft of this script wrote `"CROSS" in
    d["score_coverage"]["unassessed"]`, which is False for every input ever
    and would have "passed" claim 5 by never being able to fail it.
    """
    return {u["category"] for u in data["score_coverage"]["unassessed"]}


def reason_for(data, name):
    for u in data["score_coverage"]["unassessed"]:
        if u["category"] == name:
            return u["reason"]
    return ""


def cat_row(text, name):
    m = re.search(r"^\| " + re.escape(name) + r"\s*\|\s*([0-9.]+|N/A)\s*\|\s*(\S+)",
                  text, re.M)
    return (m.group(1), m.group(2)) if m else (None, None)


def main():
    print(__doc__.split("WHAT THIS SCRIPT ASSERTS")[0].strip()[:0] or "", end="")
    print("R13 - no memory limit to compare against\n")

    runs = {k: analyze(chart(k)) for k in
            ("pct+nolimit", "pct+limit", "xmx+nolimit", "xmx+limit",
             "nothing+nolimit", "nothing+limit")}

    # ---- CLAIM 1 -------------------------------------------------------
    print("CLAIM 1: a percentage of a limit that does not exist is a finding")
    d, t = runs["pct+nolimit"]
    check("XF006 is raised", "XF006" in ids(d),
          f"ids: {sorted(ids(d))}")
    check("and it is CRITICAL - the heap target is a share of the NODE",
          sev_of(d, "XF006") == "CRITICAL", f"severity={sev_of(d, 'XF006')}")
    xf6 = next((f for f in d["findings"] if f["rule"] == "XF006"), {})
    check("it is labelled ASSUMED, because node RAM is an assumption",
          xf6.get("basis", "").upper().startswith("ASSUMED"), xf6.get("basis"))
    check("and its `assumes` names that assumption, so it can be checked",
          "node" in (xf6.get("assumes") or ""), xf6.get("assumes"))
    check("its fix names the LIMIT, not the heap flag",
          "limits.memory" in (xf6.get("fix") or ""), xf6.get("fix"))
    print()

    # ---- CLAIM 2 -------------------------------------------------------
    print("CLAIM 2: negative controls - XF006 fires ONLY on that combination")
    for k in ("pct+limit", "xmx+nolimit", "xmx+limit",
              "nothing+nolimit", "nothing+limit"):
        dd, _ = runs[k]
        check(f"no XF006 for {k}", "XF006" not in ids(dd),
              "" if "XF006" not in ids(dd) else "fired where it must not")
    print()

    # ---- CLAIM 3 -------------------------------------------------------
    print("CLAIM 3: the budget table stops calling explicit sizing 'no sizing'")
    check("pct+nolimit no longer reports 'no explicit sizing'",
          "no explicit sizing" not in t,
          [ln.strip() for ln in t.splitlines() if "Max heap (H)" in ln][:1])
    check("and it names MaxRAMPercentage as the source of the number",
          bool(re.search(r"Max heap \(H\).*\n?.*MaxRAMPercentage", t))
          or "MaxRAMPercentage" in "".join(
              ln for ln in t.splitlines() if "Max heap" in ln),
          [ln.strip()[:100] for ln in t.splitlines() if "Max heap (H)" in ln][:1])
    dn, tn = runs["nothing+nolimit"]
    check("but a chart with genuinely no sizing still says so",
          "no explicit sizing" in tn,
          [ln.strip()[:90] for ln in tn.splitlines() if "Max heap (H)" in ln][:1])
    print()

    # ---- CLAIM 4 -------------------------------------------------------
    print("CLAIM 4: 'all measured, no estimates' appears only when that is true")
    offenders = []
    for k, (dd, tt) in runs.items():
        if "all measured, no estimates" in tt and "(est.)" in tt:
            offenders.append(k)
    check("no report claims a fully-measured total over estimated components",
          not offenders, ", ".join(offenders))
    print()

    # ---- CLAIM 5 -------------------------------------------------------
    print("CLAIM 5: CROSS leaves the mean when there is nothing to cross-check")
    dn, tn = runs["nothing+nolimit"]
    score, grade = cat_row(tn, "Cross-File Consistency (Chart <-> JVM)")
    check("CROSS is not scored 100/A+ over zero possible findings",
          "CROSS" in unassessed(dn),
          f"assessed={dn['score_coverage']['assessed']} row={score}/{grade}")
    check("the denominator shrinks by CROSS's 14 weight points",
          dn["score_coverage"]["weight_assessed"] == 86,
          f"weight_assessed={dn['score_coverage']['weight_assessed']}")
    check("and the reason names the missing limit, not just 'N/A'",
          "limits.memory" in reason_for(dn, "CROSS"),
          reason_for(dn, "CROSS")[:120])
    check("and that reason reaches the report the user actually reads",
          bool(re.search(r"limits\.memory", tn)), "")
    dx, tx = runs["xmx+nolimit"]
    check("same for a bounded heap with no limit (c03's shape)",
          "CROSS" in unassessed(dx),
          f"assessed={dx['score_coverage']['assessed']}")
    print()

    # ---- CLAIM 6 -------------------------------------------------------
    print("CLAIM 6: but the percentage case KEEPS CROSS in the mean")
    dp, _tp = runs["pct+nolimit"]
    check("XF006 is a real deduction, so CROSS must stay assessed",
          "CROSS" in dp["score_coverage"]["assessed"],
          f"unassessed={sorted(unassessed(dp))}")
    check("dropping it would have deleted the deduction (the R8 fault)",
          dp["score_coverage"]["weight_assessed"] == 100,
          f"weight_assessed={dp['score_coverage']['weight_assessed']}")
    print()

    # ---- CLAIM 7 -------------------------------------------------------
    print("CLAIM 7: charts that DO set a limit are untouched")
    for k in ("pct+limit", "xmx+limit", "nothing+limit"):
        dd, _ = runs[k]
        check(f"{k}: CROSS still assessed over all 10 categories",
              dd["score_coverage"]["weight_assessed"] == 100,
              f"unassessed={dd['score_coverage']['unassessed']}")
    dg, _ = analyze(os.path.join(REPO, "fixtures", "good-chart"))
    check("fixtures/good-chart still scores 100.0 A+ over all 10",
          dg["score"] == 100.0 and dg["score_coverage"]["weight_assessed"] == 100,
          f"score={dg['score']} weight={dg['score_coverage']['weight_assessed']}")
    print()

    # ---- CLAIM 8 -------------------------------------------------------
    print("CLAIM 8: the dangerous chart now outranks the safe one, in that order")
    dp, _ = runs["pct+nolimit"]
    dl, _ = runs["pct+limit"]
    check("pct+nolimit scores strictly worse than the same chart with a limit",
          dp["score"] < dl["score"],
          f"nolimit={dp['score']} limit={dl['score']}")
    print()

    print("=" * 90)
    print(f"{'FAILURES: ' + str(len(FAILURES)) if FAILURES else 'ALL CLAIMS PASS'}")
    for f in FAILURES:
        print(f"  - {f}")
    print("=" * 90)
    shutil.rmtree(TMP, ignore_errors=True)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())

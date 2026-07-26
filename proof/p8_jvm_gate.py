#!/usr/bin/env python3
"""PROOF R8, Bar 1: the JVM analysis was gated on a FILENAME, not on a JVM.

The reason this program exists is one sum:

    peak RSS  =  heap + metaspace + code cache + threads*Xss + direct + GC

and the one question it answers that `kubectl` cannot: does that sum fit
inside `limits.memory`?  When it does not, the kernel kills the cgroup, the
pod restarts with exit 137, and nothing in the JVM's own logs says why.

Two lines decide whether that sum is ever computed:

    hpaanalyzer/checks_docker.py:32   if not ctx.dockerfiles: ... return
    hpaanalyzer/proofs.py:35          if ctx.dockerfiles:

Neither asks whether a JVM is present.  Both ask whether a file called
`Dockerfile` happens to sit in the directory the user pointed at.  Those are
different questions, and the gap between them fails in BOTH directions:

  FACE A (silence).  `fixtures/umbrella-chart/charts/worker` sets
         JAVA_TOOL_OPTIONS=-Xmx4g on a container whose limit is 2Gi.  The JVM
         reads JAVA_TOOL_OPTIONS unaided - however the image was built - so a
         4 GiB heap in a 2 GiB cgroup is a guaranteed OOM kill that needs no
         estimate to see.  There is no Dockerfile beside the chart, so the
         tool never does the subtraction.  Grade: A-.

  FACE B (invention).  `fixtures/nojvm-chart` is nginx: nginx image, nginx
         Dockerfile, not one Java string anywhere.  Because a file named
         Dockerfile exists, the tool prints JV021 at HIGH - "No JVM heap
         sizing is actually applied", fix: set -XX:MaxRAMPercentage - plus
         JV026 and DF003, and scores the chart in a category titled
         "Java / JVM Container Fitness".

The code comment above the second gate states the intent plainly: "inventing
a JVM memory budget for a chart that may run nginx would be fiction."  That
intent is right.  The test chosen for it does the opposite of enforcing it -
it admits the nginx chart and turns away the chart holding -Xmx4g.

CLAIM 1  the gate is not the arithmetic.  The same pod spec is analysed three
         times; the only difference is a Dockerfile that contributes ZERO JVM
         flags to the sum.  Its presence alone flips a CRITICAL guaranteed-
         OOMKill finding between absent and present - and an nginx base image
         works just as well as a Temurin one.
CLAIM 2  FACE A, on the real fixture and the committed pre-fix tree: the
         OOMKill is not reported, and the arithmetic that shows it is not
         printed either.
CLAIM 3  FACE B, on the real fixture and the committed pre-fix tree: findings
         about a runtime that is not there, at HIGH, with a fix instruction
         an nginx operator cannot carry out.
CLAIM 4  AFTER: FACE A is closed.  XF001 fires at CRITICAL on OBSERVED basis
         with no Dockerfile in sight, and the report shows the subtraction.
CLAIM 5  AFTER: FACE B is closed.  No JVM findings, no JVM category in the
         score - and the report SAYS the JVM checks did not apply rather than
         going quiet, because silence is indistinguishable from a pass.
CLAIM 6  AFTER: the path that always worked is untouched.  fixtures/bad-chart
         (openjdk:8u151, 57 rules, score 45.5) and fixtures/sidecar-chart
         (Temurin 17) both ship real Java Dockerfiles, and every JVM-family
         rule they produce must be identical BEFORE and AFTER.  Widening
         coverage by changing what the tool says about charts it already
         handled is not a fix, it is a trade - and this one is not offered as
         a trade.

BEFORE is the committed pre-fix tree, extracted with `git archive` at the SHA
pinned in proof/baseline.py (NOT HEAD), run as a real subprocess over real
directories.  Run: python3 proof/p8_jvm_gate.py
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline import BASELINE, resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)

WORKER = os.path.join(REPO, "fixtures", "umbrella-chart", "charts", "worker")
NOJVM = os.path.join(REPO, "fixtures", "nojvm-chart")
# Controls for CLAIM 6, as (chart, strict, min_jvm_rules) triples. `strict`
# means the entire rule set and score must match the baseline exactly.
# bad-chart qualifies; sidecar-chart does not, because iterations R1-R7
# legitimately changed one of its non-JVM rules (RS015), and asserting
# whole-report identity there would be asserting that the last seven
# iterations did nothing. Its JVM-family rules are still compared exactly,
# which is the part R8 could break.
#
# min_jvm_rules is per chart and is not decoration: it is the assertion that
# the control can fail at all. sidecar-chart is a healthy Temurin 17 chart and
# honestly produces one JVM rule, so demanding three of it would be demanding
# that a good chart look bad.
JAVA_CHARTS = [(os.path.join(REPO, "fixtures", "bad-chart"), True, 3),
               (os.path.join(REPO, "fixtures", "sidecar-chart"), False, 1)]

# Two Dockerfiles that contribute NOTHING to the memory sum: no -Xmx, no
# MaxRAMPercentage, no JAVA_OPTS, no ENV of any kind. They exist in this proof
# only to be present, because being present is the entire input the pre-fix
# gate consumed.
DF_JAVA = ('FROM eclipse-temurin:21-jre\n'
           'COPY app.jar /app.jar\n'
           'ENTRYPOINT ["java","-jar","/app.jar"]\n')
DF_NGINX = ('FROM nginx:1.27\n'
            'COPY site /usr/share/nginx/html\n')

_BEFORE_TREE = None


def before_tree():
    global _BEFORE_TREE
    if _BEFORE_TREE is None:
        tmp = tempfile.mkdtemp(prefix="hpa-before-r8-")
        tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _BEFORE_TREE = tmp
    return _BEFORE_TREE


def cli(tree, target):
    """Run the CLI the way a user does: a real process, real report on disk."""
    d = tempfile.mkdtemp(prefix="hpa-r8-out-")
    out = os.path.join(d, "r.txt")
    jsn = os.path.join(d, "r.json")
    p = subprocess.run(
        [sys.executable, "-m", "hpaanalyzer", target, "-o", out, "--full",
         "--quiet", "--json", jsn],
        capture_output=True, text=True, cwd=tree,
        env=dict(os.environ, PYTHONPATH=tree))
    if not os.path.isfile(jsn):
        raise SystemExit(f"CLI produced no JSON ({tree}):\n{p.stderr[-2000:]}")
    with open(jsn, encoding="utf-8") as f:
        payload = json.load(f)
    with open(out, encoding="utf-8") as f:
        text = f.read()
    return {"rc": p.returncode, "json": payload, "text": text}


def findings(res, rid=None):
    fs = res["json"].get("findings", [])
    return [f for f in fs if rid is None or f.get("rule") == rid]


def rules(res):
    return sorted({f.get("rule") for f in res["json"].get("findings", [])})


def score(res):
    s = res["json"].get("score")
    if isinstance(s, dict):
        for k in ("score", "overall", "value"):
            if k in s:
                return float(s[k])
    if s is not None:
        return float(s)
    m = re.search(r"score\s+([0-9.]+)\s*/\s*100", res["text"])
    if not m:
        raise SystemExit("proof harness: could not read a score from the run")
    return float(m.group(1))


def flat(res):
    """Report text with wrapping and table borders removed, nothing else.

    The coverage and proof tables hard-wrap at a fixed column width, so a
    phrase this proof searches for is routinely split across two lines with a
    `|` between the halves. Searching the raw text would make this a test of
    the wrapper. (Same lesson as R6 and R7; recorded again because it is the
    single most repeated mistake in this suite.)
    """
    return " ".join(res["text"].replace("|", " ").split())


def worker_copy(prefix, dockerfile=None):
    """The worker chart, optionally with a JVM-flag-free Dockerfile beside it."""
    d = tempfile.mkdtemp(prefix=prefix)
    dst = os.path.join(d, "worker")
    shutil.copytree(WORKER, dst)
    if dockerfile is not None:
        with open(os.path.join(dst, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write(dockerfile)
    return dst


FAIL = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    if not ok:
        FAIL.append(label)


def hr(title=""):
    print()
    print("=" * 76)
    if title:
        print(title)
        print("=" * 76)


HEAP_RULES = {"XF001", "XF002", "XF004", "XF005"}
JVM_RULES_PREFIXES = ("JV", "XF")


def java_row_score(run):
    """The number the scorecard prints for the Java category, or None if the
    row says 'not assessed'.

    Searching the text for the category NAME is not a test: after the fix the
    name still appears, on a row that reads 'not assessed', and it has to -
    C2.6 requires the ungraded area to say it was ungraded rather than vanish.
    What must not survive is a NUMBER in that row, in either direction: 76.0
    is a deduction for invented findings, and 100.0 A+ would be the clean bill
    of health for something never looked at that scoring.py's own docstring
    forbids. So parse the cell.
    """
    for ln in run["text"].splitlines():
        s = ln.strip()
        if "Java / JVM Container Fitness" in s and s.startswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            try:
                return float(cells[1])
            except (IndexError, ValueError):
                return None
    return None


def unassessed(run):
    """Category names the run reports as not scored (empty on the baseline,
    which had no score_coverage block at all)."""
    sc = run["json"].get("score_coverage") or {}
    return {u.get("category") for u in sc.get("unassessed", [])}


def main():
    print(__doc__)
    print(f"baseline = {BASELINE} ({BASELINE_SHA[:12]})")

    # The whole proof rests on the fixture actually containing the case it
    # claims to. Assert it out of the file rather than trusting the prose.
    dep = os.path.join(WORKER, "templates", "deploy.yaml")
    if not os.path.isfile(dep):
        raise SystemExit(f"proof harness: {dep} does not exist")
    src = open(dep, encoding="utf-8").read()
    if "-Xmx4g" not in src or "memory: 2Gi" not in src:
        raise SystemExit("proof harness: the worker fixture no longer holds "
                         "the 4g-heap-under-2Gi case this proof is about")
    if os.path.exists(os.path.join(WORKER, "Dockerfile")):
        raise SystemExit("proof harness: the worker fixture has grown a "
                         "Dockerfile; FACE A is no longer isolated")
    ng = open(os.path.join(NOJVM, "Dockerfile"), encoding="utf-8").read()
    if re.search(r"java|jdk|jre|jvm", ng, re.I) and "Java" not in ng:
        raise SystemExit("proof harness: the nojvm fixture is not JVM-free")

    # ---------------------------------------------------------------- 1 ----
    hr("CLAIM 1: the gate is a filename. Same pod spec, three runs; the only\n"
       "         variable is a Dockerfile that adds nothing to the sum.")
    bt = before_tree()
    none_ = cli(bt, worker_copy("hpa-r8-none-"))
    java_ = cli(bt, worker_copy("hpa-r8-java-", DF_JAVA))
    ngx_ = cli(bt, worker_copy("hpa-r8-ngx-", DF_NGINX))

    n_xf = [f["rule"] for f in findings(none_) if f["rule"] in HEAP_RULES]
    j_xf = [f["rule"] for f in findings(java_) if f["rule"] in HEAP_RULES]
    x_xf = [f["rule"] for f in findings(ngx_) if f["rule"] in HEAP_RULES]

    check("no Dockerfile -> the 4g-under-2Gi OOMKill is NOT reported",
          n_xf == [], f"heap findings={n_xf or 'none'}  score={score(none_)}")
    check("+ a Temurin Dockerfile with zero JVM flags -> XF001 CRITICAL",
          "XF001" in j_xf, f"heap findings={j_xf}  score={score(java_)}")
    check("+ an NGINX Dockerfile with zero JVM flags -> XF001 CRITICAL too",
          "XF001" in x_xf, f"heap findings={x_xf}  score={score(ngx_)}")
    check("so the deciding input is the file's existence, not its content",
          n_xf == [] and "XF001" in j_xf and "XF001" in x_xf,
          f"delta = {score(none_) - score(java_):+.1f} points for adding a "
          f"file the arithmetic never reads")

    # ---------------------------------------------------------------- 2 ----
    hr("CLAIM 2 (FACE A): on the real fixture, the pre-fix tool is silent about\n"
       "         a heap twice the size of the cgroup it must live in.")
    b_worker = cli(bt, WORKER)
    check("BEFORE reports no heap-vs-limit finding at all",
          [f for f in findings(b_worker) if f["rule"] in HEAP_RULES] == [],
          f"score={score(b_worker)} grade={b_worker['json'].get('grade')} "
          f"findings={len(findings(b_worker))}")
    check("BEFORE does not print the memory budget table either",
          "JVM memory budget" not in b_worker["text"],
          "so there is nothing for a reader to check the tool's work against")
    check("the case is real and needs no estimate: 4 GiB heap, 2 GiB limit",
          "-Xmx4g" in src and "memory: 2Gi" in src,
          "heap alone is 2x the limit before any non-heap component is counted")

    # ---------------------------------------------------------------- 3 ----
    hr("CLAIM 3 (FACE B): the same gate invents a JVM for a chart that has none.")
    b_nojvm = cli(bt, NOJVM)
    b_rules = set(rules(b_nojvm))
    jv = sorted(r for r in b_rules if r.startswith("JV"))
    check("BEFORE prints JV021 'No JVM heap sizing is actually applied' at HIGH",
          any(f["rule"] == "JV021" and f["severity"] == "HIGH"
              for f in findings(b_nojvm)),
          "on a chart whose every image is nginx:1.27.0-alpine")
    check("BEFORE prints further JVM findings on the same chart",
          len(jv) >= 2, f"JV rules = {jv}")
    check("BEFORE scores it in a category named for a runtime it does not run",
          java_row_score(b_nojvm) is not None,
          f"the scorecard prints Java = {java_row_score(b_nojvm)} for a chart "
          f"that runs nginx; overall score={score(b_nojvm)}")
    check("BEFORE tells an nginx operator to re-run with --assume-java",
          "assume-java" in flat(b_nojvm),
          "an instruction that has no meaning for this workload")

    # ---------------------------------------------------------------- 4 ----
    hr("CLAIM 4 (AFTER): FACE A closed - the subtraction happens because the "
       "pod\n         spec says -Xmx4g, which is what evidence of a JVM "
       "actually looks like.")
    a_worker = cli(REPO, WORKER)
    xf1 = findings(a_worker, "XF001")
    check("AFTER reports XF001 at CRITICAL with no Dockerfile present",
          bool(xf1) and xf1[0]["severity"] == "CRITICAL",
          f"score={score(a_worker)} (was {score(b_worker)})")
    check("AFTER labels it OBSERVED, not an estimate",
          bool(xf1) and str(xf1[0].get("basis", "")).upper().endswith("OBSERVED"),
          f"basis={xf1[0].get('basis') if xf1 else 'n/a'} - -Xmx and the limit "
          f"are both read straight out of the user's files")
    fa = flat(a_worker)
    check("AFTER shows the arithmetic, so the reader can check it",
          "JVM memory budget" in fa and "ESTIMATED PEAK RSS" in fa)
    check("AFTER names the mechanism that made the flags reachable",
          "JAVA_TOOL_OPTIONS" in fa,
          "the JVM reads it unaided; how the image was built is irrelevant")
    check("AFTER still says which IMAGE-level checks it could not run",
          "DF000" in {f["rule"] for f in findings(a_worker)},
          "widening coverage must not quietly drop the coverage statement")

    # ---------------------------------------------------------------- 5 ----
    hr("CLAIM 5 (AFTER): FACE B closed - and closed out loud.")
    a_nojvm = cli(REPO, NOJVM)
    a_rules = set(rules(a_nojvm))
    left = sorted(r for r in a_rules if r.startswith(JVM_RULES_PREFIXES))
    check("AFTER prints no JVM finding on the nginx chart",
          left == [], f"remaining JVM-family rules = {left or 'none'}")
    check("AFTER drops DF003 'Java version undeterminable' as well",
          "DF003" not in a_rules,
          "there is no Java version to be undeterminable about")
    check("AFTER puts no number in the Java or Cross row - not even 100",
          java_row_score(a_nojvm) is None
          and {"JAVA", "CROSS"} <= unassessed(a_nojvm),
          f"Java cell = {java_row_score(a_nojvm) or 'not assessed'}, "
          f"unassessed = {sorted(unassessed(a_nojvm))}, "
          f"score={score(a_nojvm)} over "
          f"{len((a_nojvm['json'].get('score_coverage') or {}).get('assessed', []))}"
          f" categories (was {score(b_nojvm)} over 10)")
    an = flat(a_nojvm)
    check("AFTER says the JVM checks did not apply, rather than going quiet",
          "no jvm evidence" in an.lower(),
          "silence and a clean bill of health look identical on paper")
    check("...and calls the absence scope rather than health",
          "scope, not a pass" in an.lower(),
          "the C2.6 rule: an ungraded area must say it was ungraded")
    check("...and names every input it examined to reach that answer",
          all(v in an for v in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS",
                                "_JAVA_OPTIONS")),
          "a reader who disagrees needs to know which input the tool read, "
          "so they can point at the one it missed")

    # ---------------------------------------------------------------- 6 ----
    hr("CLAIM 6 (AFTER): the charts that always worked are unchanged.")
    for chart, strict, min_jvm in JAVA_CHARTS:
        nm = os.path.basename(chart)
        b_java, a_java = cli(bt, chart), cli(REPO, chart)
        br, ar = rules(b_java), rules(a_java)
        bj = [r for r in br if r.startswith(JVM_RULES_PREFIXES)]
        aj = [r for r in ar if r.startswith(JVM_RULES_PREFIXES)]
        # A control that cannot fail proves nothing: assert it exercises the
        # code path this iteration touched before trusting its verdict. This
        # is why fixtures/good-chart is not used - it scores 100.0 with zero
        # findings, so "unchanged" there would also hold for a build that had
        # deleted every rule in the program.
        check(f"{nm}: the control actually exercises the JVM path",
              len(bj) >= min_jvm and "JVM memory budget" in b_java["text"],
              f"{len(br)} rules, {len(bj)} of them JVM-family, and the memory "
              f"budget table is present")
        check(f"{nm}: identical JVM-family rules BEFORE and AFTER", bj == aj,
              f"+{sorted(set(aj) - set(bj))} -{sorted(set(bj) - set(aj))}"
              if bj != aj else f"{len(aj)} JVM rules unchanged: {aj}")
        if strict:
            check(f"{nm}: identical FULL rule set and score BEFORE and AFTER",
                  br == ar and abs(score(b_java) - score(a_java)) < 1e-9,
                  f"{len(ar)} rules, {score(a_java)}"
                  if br == ar else
                  f"+{sorted(set(ar) - set(br))} -{sorted(set(br) - set(ar))}"
                  f" | {score(b_java)} -> {score(a_java)}")

    # ---------------------------------------------------------------------
    hr("RESULT")
    if FAIL:
        print(f"{len(FAIL)} check(s) FAILED:")
        for f in FAIL:
            print(f"  - {f}")
        return 1
    print("all checks pass: the JVM analysis now runs when there is a JVM and\n"
          "stays quiet when there is not, and neither answer is silent about\n"
          "what it did or did not look at.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""PROOF R7, Bar 2: the false finding did not just cost points, it gave orders.

Bar 1 (proof/p7_subcharts.py) shows the mechanism is right: HP041 no longer
fires on a scaleTargetRef a subchart satisfies, the subchart's objects are
recorded and named instead of discarded, and a ref matching nothing still
fires at HIGH. That is "correct".

This asks the user's harder question - "not just correct, but does it do what
it is supposed to do". A static analyser is not a scoreboard. Every finding it
prints ends with a `Fix:` line, and the whole value proposition is that a
person reads that line and edits their chart. So the question Bar 2 has to
answer is not "was the finding wrong" but "what happened to the person who
believed it".

The pre-fix tool printed this, at HIGH, labelled OBSERVED - the basis it
reserves for facts read directly out of your files:

    [HP041] HPA target does not match any workload in the chart      HIGH
        Fix : Make the ref use the same fullname helper as the Deployment.

There is exactly one Deployment the pre-fix tool can see in this chart, and it
is not the one the HPA targets. So the instruction, followed, retargets a
correct HPA onto the wrong workload. That is the claim measured below, by
performing the edit and re-running the pre-fix tool on the result.

CLAIM 1  the pre-fix advice is not merely noise: applied literally it breaks
         a working chart, and the pre-fix tool then pronounces the broken
         chart clean - the false positive is self-confirming
CLAIM 2  it charged real points for the non-defect, and the AFTER tree does
         not - measured on the same bytes
CLAIM 3  the AFTER report answers the question the finding used to raise, in
         the coverage table, in terms a reader can act on: which subchart,
         which object, which file
CLAIM 4  the instruction the AFTER report gives instead ("run the analyzer
         against the subchart directly") is executed here and shown to work -
         advice a proof does not run is advice nobody has checked
CLAIM 5  the subchart's container asks for a 4g heap under a 2Gi limit. At
         R7 neither run found it, and this claim said so and named the cause:
         a different defect, in which the JVM checks were gated on a
         Dockerfile. R8 removed that gate, and this claim has been rewritten
         to measure the CURRENT state in both directions - it now fails if
         the direct run stops reporting the OOMKill, and it would have failed
         at R7. As first written it asserted only an absence, which is a
         claim with no failure signal: it went on passing after R8 fixed the
         thing it was complaining about. See the comment at the claim.

BEFORE is the committed pre-fix tree, extracted with `git archive` at the SHA
pinned in proof/baseline.py (NOT HEAD), run as a real subprocess over real
directories. Run: python3 proof/p7b_bar2.py
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline import BASELINE, resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)
FIXTURE = os.path.join(REPO, "fixtures", "umbrella-chart")
SUBCHART = os.path.join(FIXTURE, "charts", "worker")

_BEFORE_TREE = None


def before_tree():
    global _BEFORE_TREE
    if _BEFORE_TREE is None:
        tmp = tempfile.mkdtemp(prefix="hpa-before-r7b-")
        tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _BEFORE_TREE = tmp
    return _BEFORE_TREE


def cli(tree, target):
    """Run the CLI the way a user does: a real process, real report on disk."""
    d = tempfile.mkdtemp(prefix="hpa-r7b-out-")
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


def copy_fixture(prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    dst = os.path.join(d, "umbrella-chart")
    shutil.copytree(FIXTURE, dst)
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


def main():
    print(__doc__)
    print(f"baseline = {BASELINE} ({BASELINE_SHA[:12]})")
    if not shutil.which("helm"):
        raise SystemExit("helm is required to prove this; it is not on PATH")
    if not os.path.isfile(os.path.join(SUBCHART, "Chart.yaml")):
        raise SystemExit(f"proof harness: {SUBCHART}/Chart.yaml does not exist")

    before = cli(before_tree(), FIXTURE)
    after = cli(REPO, FIXTURE)

    # ---------------------------------------------------------------- 1 ----
    hr("CLAIM 1: the advice, followed, breaks a working chart - and the tool "
       "that\n          gave it then calls the broken chart clean.")
    b = findings(before, "HP041")
    if not b:
        raise SystemExit("proof harness: the pre-fix tree did not fire HP041; "
                         "there is nothing to measure")
    print(f"  pre-fix finding : [{b[0]['rule']}] {b[0]['severity']} "
          f"({b[0].get('basis')})")
    print(f"  pre-fix Fix line: {b[0]['fix']}")

    # The chart's only visible Deployment is umbrella-api. "Use the same
    # fullname helper as the Deployment" has exactly one referent for a reader
    # who trusts the tool about which Deployments exist, so that is the edit.
    broken = copy_fixture("hpa-r7b-followed-")
    hpa = os.path.join(broken, "templates", "hpa.yaml")
    with open(hpa, encoding="utf-8") as f:
        txt = f.read()
    edited = txt.replace("name: umbrella-worker\n  minReplicas",
                         "name: umbrella-api\n  minReplicas")
    if edited == txt:
        raise SystemExit("proof harness: the fixture's HPA ref did not match; "
                         "the 'followed advice' edit was a no-op")
    with open(hpa, "w", encoding="utf-8") as f:
        f.write(edited)
    print("  edit applied    : scaleTargetRef.name umbrella-worker -> "
          "umbrella-api")

    followed = cli(before_tree(), broken)
    check("the pre-fix tool is SATISFIED by the broken chart",
          not findings(followed, "HP041"),
          f"HP041 count {len(findings(followed, 'HP041'))}")
    # And the damage: the worker now has no HPA at all, and the API has one it
    # was never sized for. The tool cannot see either fact, which is the point.
    helm = shutil.which("helm")
    rendered = subprocess.run([helm, "template", "r", broken],
                              capture_output=True, text=True, check=True).stdout
    # Read the damage out of the rendered objects, not out of string surgery
    # on the blob. The first draft of this check split the text on
    # "HorizontalPodAutoscaler" and inspected the tail, which silently assumed
    # helm emits the HPA last; it does not, and the check failed against a
    # chart that was broken exactly as claimed. A proof that reports a defect
    # in its own harness as a defect in the target is the C2.2 error one level
    # up, and it is the reason this file parses.
    objs = [d for d in yaml.safe_load_all(rendered) if isinstance(d, dict)]
    hpas = [d for d in objs if d.get("kind") == "HorizontalPodAutoscaler"]
    if len(hpas) != 1:
        raise SystemExit(f"proof harness: expected 1 HPA, rendered {len(hpas)}")
    tgt = ((hpas[0].get("spec") or {}).get("scaleTargetRef") or {}).get("name")
    deploys = {(d.get("metadata") or {}).get("name")
               for d in objs if d.get("kind") == "Deployment"}
    print(f"  after the edit  : HPA targets {tgt!r}; "
          f"Deployments rendered = {sorted(deploys)}")
    check("the chart is nevertheless broken: the HPA now targets the API",
          tgt == "umbrella-api")
    check("and the worker it was written for is now unautoscaled",
          "umbrella-worker" in deploys and tgt != "umbrella-worker")
    check("the AFTER tree never issues that instruction on this chart",
          not findings(after, "HP041"))

    # ---------------------------------------------------------------- 2 ----
    hr("CLAIM 2: it charged points for a defect that was not there.")
    sb, sa = score(before), score(after)
    print(f"  BEFORE score : {sb}")
    print(f"  AFTER  score : {sa}")
    print(f"  delta        : +{round(sa - sb, 1)} on byte-identical input")
    check("the pre-fix score was depressed by the false finding", sa > sb,
          f"{sb} -> {sa}")
    check("the AFTER score is not a whitewash - the chart still has findings",
          len(findings(after)) > 0, f"{len(findings(after))} finding(s)")

    # ---------------------------------------------------------------- 3 ----
    hr("CLAIM 3: the reader can act on what replaced it.")
    # A suppression that leaves the reader with nothing is not an improvement
    # over a wrong answer; it is a quieter wrong answer. The replacement has to
    # carry enough to check the tool's work by hand.
    # Flattened: the coverage table hard-wraps its cells at a fixed column
    # width, so a phrase this proof looks for is routinely split across two
    # lines with a `|` border between the halves. Searching the raw text would
    # make this a test of the wrapping, which is the mistake R6 caught in its
    # own suite. Only whitespace and borders are removed; no wording is.
    cov = " ".join(after["text"].replace("|", " ").split())
    for probe, why in [
            ("umbrella-worker", "the HPA target the finding used to be about"),
            ("charts/worker/templates/deploy.yaml",
             "the file the object actually came from"),
            ("NOT graded", "an unambiguous statement that it was not scored")]:
        check(f"the report names {why}", probe in cov, repr(probe))
    check("the pre-fix report named none of it",
          "charts/worker/templates/deploy.yaml" not in before["text"])

    # ---------------------------------------------------------------- 4 ----
    hr("CLAIM 4: the instruction it gives instead is executed here.")
    # "Run the analyzer against the subchart directly" is the only remedy the
    # new coverage row offers. Advice a proof does not run is advice nobody
    # has checked - the R6 lesson, applied to prose.
    check("the report actually gives that instruction",
          "Run the analyzer against the subchart directly" in cov)
    sub = cli(REPO, SUBCHART)
    n_sub = len(findings(sub))
    print(f"  analyzer on {os.path.relpath(SUBCHART, REPO)}: "
          f"score {score(sub)}, {n_sub} finding(s)")
    check("running it produces a real graded report, not an error", sub["rc"] in (0, 1, 2))
    check("and it grades the workload the parent refused to grade",
          "umbrella-worker" in sub["text"], f"{n_sub} finding(s)")

    # ---------------------------------------------------------------- 5 ----
    hr("CLAIM 5: what R7 left behind, and what became of it.")
    # charts/worker sets JAVA_TOOL_OPTIONS=-Xmx4g under a 2Gi memory limit.
    # That is a guaranteed kernel OOM kill and it is the single thing this
    # tool exists to catch.
    #
    # As WRITTEN AT R7 this claim measured that NEITHER run found it, and
    # named the reason: the JVM checks were gated on a Dockerfile being
    # present and this subchart ships none. R8 removed that gate. The claim
    # was left in place across R8 and it went on passing - because the id set
    # it searched, {JV001, JV002, JV003, JV010, CR001, CR002}, does not
    # contain XF001, which is the rule that actually fires. So it asserted
    # "the OOMKill is still missed" on a tree that reports it at CRITICAL.
    #
    # That is the same failure mode as p8b's severity-case bug and it is worth
    # more than a silent edit: a claim about what a tool CANNOT do has no
    # natural failure signal. When the tool improves, the claim keeps passing.
    # Every "what is still missed" claim in this repo is therefore now written
    # to assert the CURRENT state in both directions - it fails if the gap
    # closes AND if a closed gap re-opens - rather than only the absence.
    deploy = os.path.join(SUBCHART, "templates", "deploy.yaml")
    with open(deploy, encoding="utf-8") as f:
        dtxt = f.read()
    if "-Xmx4g" not in dtxt or "memory: 2Gi" not in dtxt:
        raise SystemExit("proof harness: the fixture no longer contains the "
                         "4g-heap-under-2Gi case this claim measures")
    # The heap-vs-limit verdict, by rule id AND by what it says, so that
    # renaming the rule cannot make this claim quietly stop measuring.
    def heap_verdict(res):
        return [f for f in findings(res)
                if f["rule"] == "XF001"
                or ("heap" in f["title"].lower()
                    and "limit" in f["title"].lower())]

    hit_parent = heap_verdict(after)
    hit_direct = heap_verdict(sub)
    print(f"  fixture declares : JAVA_TOOL_OPTIONS=-Xmx4g, limits.memory=2Gi")
    print(f"  parent run finds : "
          f"{[f['rule'] + ' ' + str(f['severity']).upper() for f in hit_parent] or 'nothing'}")
    print(f"  direct run finds : "
          f"{[f['rule'] + ' ' + str(f['severity']).upper() for f in hit_direct] or 'nothing'}")
    check("R8 closed it for the direct run: the OOMKill is now REPORTED",
          bool(hit_direct),
          f"{hit_direct[0]['rule']} {hit_direct[0]['title']}" if hit_direct else
          "no heap-vs-limit finding - R8 has regressed")
    check("...at CRITICAL, since it is a guaranteed kill and not a risk",
          bool(hit_direct) and
          str(hit_direct[0]["severity"]).upper() == "CRITICAL",
          str(hit_direct[0]["severity"]).upper() if hit_direct else "")
    check("...without needing a Dockerfile, which this subchart does not ship",
          not os.path.exists(os.path.join(SUBCHART, "Dockerfile")))
    print()
    print("  The PARENT run still does not report it, and that is R7's")
    print("  boundary rather than a residual bug: the object belongs to a")
    print("  subchart, subcharts are out of scope, and the whole point of R7")
    print("  was that an out-of-scope object must be DECLARED and not")
    print("  silently treated as absent. So the requirement on the parent is")
    print("  not that it finds the heap - it is that it says whose it is.")
    check("the parent still does not grade a subchart's workload",
          not hit_parent)
    check("but it names the subchart and its objects rather than going quiet",
          "worker" in after["text"] and "umbrella-worker" in after["text"])
    check("and DF000 no longer claims the JVM checks were skipped",
          all("JVM checks skipped" not in f.get("title", "")
              + str(f.get("detail", ""))
              for f in findings(sub, "DF000")),
          "post-R8 wording: 'JVM checks ran from the pod spec'")
    check("and the score it prints declares the categories it covered",
          "categories" in sub["text"])

    # ------------------------------------------------------------ verdict --
    hr()
    total = len(FAIL)
    print(f"  {'ALL' if not total else total} check(s) "
          f"{'passed' if not total else 'FAILED'}")
    if FAIL:
        print("\nNOT PROVEN. Failing checks:")
        for f in FAIL:
            print(f"  - {f}")
        return 1
    print("Bar 2 MET for R7. The finding this iteration removed was not a")
    print("cosmetic false positive: it carried an instruction that, followed,")
    print("breaks a correct chart, and the tool then reports the broken chart")
    print("as fixed. What replaced it is a coverage row a reader can verify")
    print("by hand and a remedy this proof executes. The heap defect inside")
    print("the subchart, which R7 could only declare, is reported at CRITICAL")
    print("since R8 - by the direct run the R7 coverage row tells you to make.")
    print("The parent still does not grade it, and says whose it is instead.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

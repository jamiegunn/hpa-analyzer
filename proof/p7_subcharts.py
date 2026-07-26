#!/usr/bin/env python3
"""PROOF R7, Bar 1: "out of scope" was being spent as evidence of a defect.

WHAT THE TOOL IS SUPPOSED TO DO, for this iteration specifically.

    C2.2  A value the tool cannot determine must be reported as
          undetermined. Never report a limit of the method as a finding
          about the target.

and, from the report's own basis vocabulary:

    OBSERVED - read directly from your files (stated as fact).

Subcharts are declared out of scope. That is a defensible scope decision on
its own: a vendored chart is someone else's code, and folding it into YOUR
grade misrepresents what you are responsible for. The tool even records the
omission in its coverage table, which is more than most linters do.

WHY IT DID NOT DO THAT.

The omission was not contained. `helm template` renders subcharts - that is
what an umbrella chart IS - and discovery.py drops those objects on the floor
before anything else looks at them:

    if src.startswith("charts/"):
        skipped_subchart += 1
        continue

Every later check therefore reasons over a world in which those objects do not
exist. HP041 asks "does any workload in this chart match the HPA's
scaleTargetRef?", finds none, and reports:

    [HP041] HPA target does not match any workload in the chart      HIGH
        Basis : OBSERVED - read directly from your files (stated as fact).
        Found : HPA 'umbrella-worker' targets Deployment/umbrella-worker,
                which matches no Deployment/StatefulSet template here
        Why   : A dangling scaleTargetRef means the HPA controls nothing
                (AbleToScale=False) while everyone assumes autoscaling works.
        Fix   : Make the ref use the same fullname helper as the Deployment.

Deployment/umbrella-worker exists. helm rendered it, in the same run, from
charts/worker. The analyzer threw it away and then reported its own blindness
as a HIGH-severity fact about the user's chart, complete with a fix
instruction for a bug that is not there and a score deduction for it.

This is the C2.2 conflation in its purest form, and worse than the R6 one: R6
mis-transcribed another program's verdict, this invents a defect. A user who
follows the fix edits a correct fullname helper until the false finding
changes shape.

The BEFORE column is the real pre-fix tool, extracted with `git archive` at
the SHA pinned in proof/baseline.py and run in a subprocess against the same
fixture bytes.

Run: python3 proof/p7_subcharts.py
"""

import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline import BASELINE, resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)

# The fixture lives in the CURRENT tree and is passed to both trees by
# absolute path. The baseline archive does not contain it - which is correct:
# the variable under test is the analyzer, not the chart, so both columns must
# read the same bytes off disk.
FIXTURE = os.path.join(REPO, "fixtures", "umbrella-chart")

# An umbrella chart with:
#   templates/api.yaml            -> Deployment umbrella-api      (parent)
#   templates/hpa.yaml            -> HPA targeting umbrella-worker
#   charts/worker/.../deploy.yaml -> Deployment umbrella-worker    (SUBCHART)
# The HPA is correct. helm renders both Deployments. Nothing about this chart
# is broken; the only question is whether the tool says so.

_CHILD = r"""
import json, os, sys
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
r = analyze(sys.argv[2], helm_mode="auto")
ctx = r.context
print("---JSON---")
print(json.dumps({
    "findings": [{"id": f.rule_id, "sev": f.severity.name, "title": f.title,
                  "detail": f.detail, "basis": getattr(f.basis, "name", "")}
                 for f in r.findings],
    "workloads": sorted({(d.kind or "") + "/" +
                         str((d.data.get("metadata") or {}).get("name"))
                         for d in ctx.docs
                         if (d.kind or "") in ("Deployment", "StatefulSet",
                                               "DaemonSet")}),
    "coverage": [list(map(str, row)) for row in ctx.coverage],
    # R7 additions; absent on the baseline tree, and that absence IS the
    # before state - getattr must not be allowed to crash the proof.
    "subchart_docs": [ (d.kind or "") + "/" +
                       str((d.data.get("metadata") or {}).get("name"))
                       for d in getattr(ctx, "subchart_docs", []) ],
    "subchart_names": list(getattr(ctx, "subchart_names", [])),
}))
"""


def _run_tree(root):
    p = subprocess.run([sys.executable, "-c", _CHILD, root, FIXTURE],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"child failed ({root}):\n{p.stderr[-2500:]}")
    return json.loads(p.stdout.split("---JSON---", 1)[1])


_BEFORE_TREE = None


def before_tree():
    global _BEFORE_TREE
    if _BEFORE_TREE is None:
        tmp = tempfile.mkdtemp(prefix="hpa-before-r7-")
        tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _BEFORE_TREE = tmp
    return _BEFORE_TREE


CHECKS = []


def check(label, cond):
    CHECKS.append((label, bool(cond)))
    print(f"  [{'OK ' if cond else 'FAIL'}] {label}")


def hr(title=""):
    print("\n" + "=" * 76)
    if title:
        print(title)
        print("=" * 76)


def _hp041(res):
    return [f for f in res["findings"] if f["id"] == "HP041"]


def main():
    print(__doc__)
    print(f"baseline = {BASELINE} ({BASELINE_SHA[:12]})")
    print(f"fixture  = {FIXTURE}")

    before = _run_tree(before_tree())
    after = _run_tree(REPO)

    # ---------------------------------------------------------------- 0 ----
    hr("CLAIM 0: helm really does render the object the tool says is missing.")
    import shutil
    helm = shutil.which("helm")
    if not helm:
        raise SystemExit("helm is required to prove this; it is not on PATH")
    r = subprocess.run([helm, "template", "r", FIXTURE],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"helm refused the fixture: {r.stderr[:400]}")
    print(f"  helm rendered {r.stdout.count('# Source:')} documents, including:")
    for ln in r.stdout.splitlines():
        if ln.startswith("# Source:"):
            print(f"    {ln}")
    check("the subchart Deployment is in helm's own output",
          "charts/worker/templates/deploy.yaml" in r.stdout)
    check("its name is exactly what the HPA targets",
          "name: umbrella-worker" in r.stdout)

    # ---------------------------------------------------------------- 1 ----
    hr("CLAIM 1: BEFORE, the tool reported that object as absent - as fact.")
    b_hp041 = _hp041(before)
    print(f"  BEFORE workloads visible to the checks: {before['workloads']}")
    for f in b_hp041:
        print(f"  BEFORE finding: [{f['id']}] {f['sev']} - {f['title']}")
        print(f"    basis : {f['basis']}")
        print(f"    detail: {f['detail'][:150]}")
    check("BEFORE: HP041 fired", len(b_hp041) == 1)
    check("BEFORE: at HIGH severity", bool(b_hp041) and b_hp041[0]["sev"] == "HIGH")
    check("BEFORE: labelled OBSERVED, i.e. stated as fact",
          bool(b_hp041) and b_hp041[0]["basis"] == "OBSERVED")
    check("BEFORE: the subchart workload was invisible to the checks",
          "Deployment/umbrella-worker" not in before["workloads"])

    # ---------------------------------------------------------------- 2 ----
    hr("CLAIM 2: AFTER, the false finding is gone and the gap is named.")
    a_hp041 = _hp041(after)
    print(f"  AFTER  workloads GRADED (unchanged, by design): "
          f"{after['workloads']}")
    print(f"  AFTER  subchart objects now visible-but-not-graded: "
          f"{after['subchart_docs']}")
    print(f"  AFTER  subcharts named: {after['subchart_names']}")
    for f in a_hp041:
        print(f"  AFTER  finding: [{f['id']}] {f['sev']} - {f['detail'][:150]}")
    check("AFTER: HP041 no longer fires on a target a subchart provides",
          not a_hp041)
    check("AFTER: the subchart's workload is recorded, not discarded",
          "Deployment/umbrella-worker" in after["subchart_docs"])
    check("AFTER: the subchart is named, not just counted",
          "worker" in after["subchart_names"])
    # The parent's grade must still be a statement about the PARENT. Silence
    # about a false finding is not the goal; not grading someone else's chart
    # is still correct, and this proves the fix did not smuggle it in.
    check("AFTER: the subchart workload is still NOT graded",
          "Deployment/umbrella-worker" not in after["workloads"])

    # ---------------------------------------------------------------- 3 ----
    hr("CLAIM 3: the reader is told, in the coverage table, what happened.")
    b_cov = " | ".join(" ".join(r) for r in before["coverage"])
    a_cov = " | ".join(" ".join(r) for r in after["coverage"])
    print("  BEFORE coverage rows mentioning subcharts:")
    for row in before["coverage"]:
        if "subchart" in " ".join(row).lower() or "charts/" in row[0]:
            print(f"    {row[0]}  ->  {row[1][:110]}")
    print("  AFTER coverage rows mentioning subcharts:")
    for row in after["coverage"]:
        if "subchart" in " ".join(row).lower() or "charts/" in row[0]:
            print(f"    {row[0]}  ->  {row[1][:110]}")
    check("BEFORE: coverage counted objects but named nothing",
          "1 object(s) SKIPPED" in b_cov and "worker" not in b_cov)
    check("AFTER: the subchart is named in coverage", "worker" in a_cov)
    check("AFTER: coverage says which KINDS went unanalyzed",
          "Deployment" in a_cov)
    check("AFTER: the HPA's unverifiable target is spelled out in coverage",
          "umbrella-worker" in a_cov)

    # ---------------------------------------------------------------- 4 ----
    hr("CLAIM 4: a genuinely dangling ref must still be caught.")
    # The fix must not be "stop firing HP041". Point the HPA at a name NO
    # chart provides and it has to come back, or the fix has traded a false
    # positive for a false negative - which is the worse trade, because
    # nobody notices.
    tmp = tempfile.mkdtemp(prefix="hpa-p7-dangle-")
    dst = os.path.join(tmp, "umbrella-chart")
    subprocess.run(["cp", "-r", FIXTURE, dst], check=True)
    hpa = os.path.join(dst, "templates", "hpa.yaml")
    with open(hpa, encoding="utf-8") as f:
        txt = f.read()
    txt = txt.replace("name: umbrella-worker\n  minReplicas",
                      "name: umbrella-typo\n  minReplicas")
    with open(hpa, "w", encoding="utf-8") as f:
        f.write(txt)
    p = subprocess.run([sys.executable, "-c", _CHILD.replace("sys.argv[2]",
                                                             repr(dst)),
                        REPO, dst], capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"dangling-ref child failed:\n{p.stderr[-2000:]}")
    dangle = json.loads(p.stdout.split("---JSON---", 1)[1])
    d_hp041 = _hp041(dangle)
    for f in d_hp041:
        print(f"  typo'd ref: [{f['id']}] {f['sev']} - {f['detail'][:130]}")
    check("AFTER: a ref matching NOTHING (not even a subchart) still fires",
          len(d_hp041) == 1)
    check("AFTER: still HIGH", bool(d_hp041) and d_hp041[0]["sev"] == "HIGH")

    # ---------------------------------------------------------------- 5 ----
    hr("CLAIM 5: what this fix does NOT do.")
    print("  * It does not analyze subcharts. The parent's grade is still a")
    print("    statement about the parent, and folding a vendored chart's")
    print("    findings into your score would be a different lie - you did")
    print("    not write it and cannot fix it in this repository.")
    print("  * It therefore does not find real problems inside subcharts.")
    print("    charts/worker's container asks for -Xmx4g under a 2Gi limit:")
    print("    a guaranteed OOMKill, and this tool still says nothing about")
    print("    it. What changed is that the silence is now itemised by name")
    print("    and kind instead of being a bare object count.")
    print("  * It fixes exactly one class of false finding - checks that")
    print("    conclude 'absent' from 'not in ctx.docs'. HP041 was the one")
    print("    that could be demonstrated. Any other check reasoning the")
    print("    same way is untouched until someone shows it doing harm.")

    # ------------------------------------------------------------ verdict --
    hr()
    failed = [lbl for lbl, ok in CHECKS if not ok]
    print(f"  {len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("\nNOT PROVEN. Failing checks:")
        for f in failed:
            print(f"  - {f}")
        return 1
    print("Bar 1 MET for R7. The tool no longer reports its own scope")
    print("boundary as a HIGH-severity defect in the user's chart. The")
    print("boundary itself is unchanged and now states what is behind it:")
    print("which subcharts, which kinds, which names, and which of the")
    print("report's own claims could not be checked because of it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

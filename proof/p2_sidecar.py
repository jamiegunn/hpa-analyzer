#!/usr/bin/env python3
"""PROOF R2: the tool had no pod-level resource footprint, and the one
node-capacity claim it did print was wrong by more than an order of magnitude.

This script does not describe the old behaviour from memory, and it does not
reconstruct it from a formula I claim the old code used. It EXTRACTS the
pre-fix source from git (`git archive <baseline>`, the commit this iteration
series started from - pinned in proof/baseline.py, NOT HEAD), runs it in a subprocess against the same fixture, and puts its
output next to the current tool's. Both columns are real program output. The
only variable is the fix.

AUTHORITY (fetched, not recalled) -- kubernetes/staging/src/k8s.io/
component-helpers/resource/helpers.go, aggregateContainerResourcesByFn:

    result := v1.ResourceList{}
    for _, container := range pod.Spec.Containers {
        addResourceList(result, containerResources)
    }

    restartableInitContainerResources := v1.ResourceList{}
    initContainerResources := v1.ResourceList{}
    // init containers define the minimum of any resource
    //
    // Let's say `InitContainerUse(i)` is the resource requirements when the
    // i-th init container is initializing, then
    // `InitContainerUse(i) = sum(Resources of restartable init containers
    //  with index < i) + Resources of i-th init container`.
    for _, container := range pod.Spec.InitContainers {
        if isRestartableInitContainer(&container) {
            addResourceList(result, containerResources)
            addResourceList(restartableInitContainerResources, containerResources)
            containerResources = restartableInitContainerResources
        } else {
            combinedResources := v1.ResourceList{}
            addResourceList(combinedResources, containerResources)
            addResourceList(combinedResources, restartableInitContainerResources)
            containerResources = combinedResources
        }
        maxResourceList(initContainerResources, containerResources)
    }
    maxResourceList(result, initContainerResources)

In words: a native sidecar (init container with restartPolicy: Always) is
ADDED to the pod's request like a regular container, because it runs for the
pod's whole life. A one-shot init container is MAX'd, because it is finished
before the regular containers start -- but it is max'd against the sidecars
that are already running alongside it.

The reference implementation below is transcribed from that Go, by hand, and
imports nothing from hpaanalyzer. When the tool and the reference agree, that
is two independent derivations agreeing; when the tool agrees with itself it
is not evidence of anything.

WHAT THIS SCRIPT PROVES
  1. The pre-fix tree contains no pod-level request/limit total. Shown from
     git, not from reading the current code.
  2. RS008's "node fit example" divided node allocatable by a SINGLE
     CONTAINER's request and called the answer "such pods": on the shipped
     sidecar fixture it claimed a node holds 64 pods where the upstream
     formula says 3, a 21.3x overstatement. It now says 3.
  3. The native sidecar contributed to no total the tool printed. It now
     appears in the footprint table, labelled with how it counts.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline import BASELINE, resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)

MiB = 1024 ** 2
GiB = 1024 ** 3
FIXTURE = os.path.join(REPO, "fixtures", "sidecar-chart")


# --------------------------------------------------------------------------
# Reference implementation, transcribed from the Go above. Independent of the
# tool, so a disagreement is evidence about the tool and not about itself.
# --------------------------------------------------------------------------

def _q(c, section):
    r = (c.get("resources") or {}).get(section) or {}
    cpu, mem = r.get("cpu"), r.get("memory")
    return {"cpu": _cpu(cpu), "memory": _mem(mem)}


def _cpu(v):
    if v is None:
        return 0
    v = str(v)
    return int(float(v[:-1])) if v.endswith("m") else int(float(v) * 1000)


def _mem(v):
    if v is None:
        return 0
    v = str(v)
    for suf, mul in (("Gi", GiB), ("Mi", MiB), ("Ki", 1024), ("G", 10**9),
                     ("M", 10**6), ("K", 10**3)):
        if v.endswith(suf):
            return int(float(v[:-len(suf)]) * mul)
    return int(float(v))


def _add(a, b):
    for k in a:
        a[k] += b[k]


def _max(a, b):
    for k in a:
        a[k] = max(a[k], b[k])


def pod_requests(ps):
    """Reference port of aggregateContainerResourcesByFn (requests)."""
    result = {"cpu": 0, "memory": 0}
    for c in ps.get("containers") or []:
        _add(result, _q(c, "requests"))

    restartable = {"cpu": 0, "memory": 0}
    init_max = {"cpu": 0, "memory": 0}
    for c in ps.get("initContainers") or []:
        cr = _q(c, "requests")
        if str(c.get("restartPolicy", "")) == "Always":
            _add(result, cr)
            _add(restartable, cr)
            candidate = dict(restartable)
        else:
            candidate = {k: cr[k] + restartable[k] for k in cr}
        _max(init_max, candidate)
    _max(result, init_max)
    return result


# --------------------------------------------------------------------------
# The BEFORE column: the committed pre-fix tree, run for real.
# --------------------------------------------------------------------------

_CHILD = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import render
r = analyze(sys.argv[2], helm_mode="off")
print("---JSON---")
print(json.dumps({
    "modules": sorted(m for m in sys.modules if m.startswith("hpaanalyzer.")),
    "rs008_math": next((f.math for f in r.findings if f.rule_id == "RS008"), None),
    "report": render(r, "sidecar-chart", level="deep"),
}))
"""


def before():
    """Extract the baseline tree into a tempdir and run it.

    The fixture is copied in because it is not part of that commit - it was
    written for this iteration. That is the point of it: a chart the pre-fix
    tool was never tested against, whose defects are all at pod scope.
    """
    tmp = tempfile.mkdtemp(prefix="hpa-before-")
    tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                         capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
    subprocess.run(["cp", "-r", FIXTURE, os.path.join(tmp, "sidecar-chart")],
                   check=True)
    out = subprocess.run(
        [sys.executable, "-c", _CHILD, tmp, os.path.join(tmp, "sidecar-chart")],
        capture_output=True, text=True, check=True).stdout
    return json.loads(out.split("---JSON---", 1)[1]), tmp


def after():
    from hpaanalyzer.engine import analyze
    from hpaanalyzer.kube import pod_spec
    from hpaanalyzer.report import render
    r = analyze(FIXTURE, helm_mode="off")
    return {
        "ps": pod_spec(r.context.workloads[0]),
        "rs008_math": next((f.math for f in r.findings
                            if f.rule_id == "RS008"), None),
        "report": render(r, "sidecar-chart", level="deep"),
    }


# --------------------------------------------------------------------------

def claim_1(b, a):
    print("=" * 74)
    print("CLAIM 1: the pre-fix tree had no pod-level resource total.")
    print("=" * 74)
    tracked = subprocess.run(["git", "ls-tree", "--name-only", BASELINE_SHA,
                              "hpaanalyzer/"], cwd=REPO, capture_output=True,
                             text=True, check=True).stdout.split()
    print("  modules in the pre-fix package:")
    print("   ", ", ".join(os.path.basename(t) for t in tracked))
    had = any("podresources" in t for t in tracked)
    print(f"  a module computing pod totals: {'yes' if had else 'NONE'}")
    print(f"  modules its analysis loaded  : "
          f"{len(b['modules'])}, none named *podresources*: "
          f"{not any('podresources' in m for m in b['modules'])}")
    ref = pod_requests(a["ps"])
    from hpaanalyzer.podresources import pod_resources
    live = pod_resources(a["ps"]).requests
    print(f"  today: hpaanalyzer.podresources.pod_resources exists and returns")
    print(f"         cpu {live['cpu']}m, mem {live['memory'] // MiB} MiB")
    print(f"  hand-transcribed reference returns")
    print(f"         cpu {ref['cpu']}m, mem {ref['memory'] // MiB} MiB")
    agree = live["cpu"] == ref["cpu"] and live["memory"] == ref["memory"]
    print(f"  --> two independent derivations agree: {agree}")
    return (not had) and agree


def claim_2(b, a):
    print()
    print("=" * 74)
    print("CLAIM 2: the node-fit arithmetic used a container where the")
    print("         scheduler uses a pod.")
    print("=" * 74)
    ps = a["ps"]
    ref = pod_requests(ps)
    for c in ps.get("containers") or []:
        q = _q(c, "requests")
        print(f"    + container      {c['name']:<14} "
              f"cpu {q['cpu']:>5}m  mem {q['memory'] // MiB:>5} MiB")
    for c in ps.get("initContainers") or []:
        q = _q(c, "requests")
        side = str(c.get("restartPolicy", "")) == "Always"
        kind = "sidecar (ADDED)" if side else "init (MAX'd)"
        print(f"    {'+' if side else ' '} {kind:<16} {c['name']:<14} "
              f"cpu {q['cpu']:>5}m  mem {q['memory'] // MiB:>5} MiB")
    print(f"    = POD REQUESTS                  "
          f"cpu {ref['cpu']:>5}m  mem {ref['memory'] // MiB:>5} MiB")
    truth = (8 * GiB) // ref["memory"]

    print(f"\n  BEFORE, RS008 verbatim:\n    {b['rs008_math']}")
    print(f"\n  AFTER, RS008 verbatim:\n    {a['rs008_math']}")

    def claimed(math):
        m = re.search(r"=\s*(\d+)\s+(?:such |of these )?pods", math or "")
        return int(m.group(1)) if m else None

    cb, ca = claimed(b["rs008_math"]), claimed(a["rs008_math"])
    print(f"\n  upstream pods per 8 GiB node : {truth}")
    print(f"  claimed before               : {cb}"
          + (f"   ({cb / truth:.1f}x)" if cb else ""))
    print(f"  claimed after                : {ca}")
    print("\n  The old finding was about container 'istio-proxy' (request")
    print("  128Mi), so it divided 8 GiB by 128 MiB. You cannot schedule an")
    print("  istio-proxy on its own - it arrives inside a pod that also")
    print("  carries a 2 GiB JVM and a 128 MiB native sidecar, so the")
    print("  sentence 'N such pods' was false for every N it could produce.")
    return cb is not None and cb != truth and ca == truth


def claim_3(b, a):
    print()
    print("=" * 74)
    print("CLAIM 3: the native sidecar contributed to no total that was")
    print("         printed.")
    print("=" * 74)
    ps = a["ps"]
    with_side = pod_requests(ps)
    stripped = dict(ps)
    stripped["initContainers"] = [
        c for c in ps.get("initContainers") or []
        if str(c.get("restartPolicy", "")) != "Always"]
    without = pod_requests(stripped)
    dcpu = with_side["cpu"] - without["cpu"]
    dmem = with_side["memory"] - without["memory"]
    print(f"  pod requests with    log-shipper: cpu {with_side['cpu']}m, "
          f"mem {with_side['memory'] // MiB} MiB")
    print(f"  pod requests without log-shipper: cpu {without['cpu']}m, "
          f"mem {without['memory'] // MiB} MiB")
    print(f"  the native sidecar is worth       cpu {dcpu}m, "
          f"mem {dmem // MiB} MiB per replica")
    print(f"  at replicaCount=3 that is         cpu {3 * dcpu}m, "
          f"mem {3 * dmem // MiB} MiB of cluster capacity")

    def cited(report):
        return bool(re.search(r"log-shipper.*(sidecar|summed)", report)
                    or re.search(r"(sidecar|summed).*log-shipper", report))

    print(f"\n  BEFORE: report says how 'log-shipper' counts toward a total: "
          f"{cited(b['report'])}")
    print(f"  AFTER : report says how 'log-shipper' counts toward a total: "
          f"{cited(a['report'])}")
    for line in a["report"].splitlines():
        if "log-shipper" in line and "summed" in line:
            print(f"          {line.strip()}")
    return dcpu > 0 and dmem > 0 and not cited(b["report"]) \
        and cited(a["report"])


def main():
    print(__doc__)
    b, tmp = before()
    a = after()
    print(f"(BEFORE column produced by `git archive {BASELINE}` -> {tmp}, "
          f"run in a subprocess.)\n")
    proven = [claim_1(b, a), claim_2(b, a), claim_3(b, a)]
    print()
    print("=" * 74)
    if all(proven):
        print("ALL THREE CLAIMS PROVEN, before and after. Contract C1.5:")
        print('  "It counts toward pod QoS, toward the pod\'s scheduling')
        print('   footprint ... Any total the tool prints must say which')
        print('   containers are in it."')
        print("R1 fixed the QoS half. R2 fixes the footprint half: the 21.3x")
        print("capacity overstatement is gone and the sidecar is named in the")
        print("total it belongs to.")
        return 0
    print("PROOF INCOMPLETE:", proven)
    return 1


if __name__ == "__main__":
    sys.exit(main())

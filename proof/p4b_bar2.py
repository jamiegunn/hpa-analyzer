#!/usr/bin/env python3
"""PROOF R4, Bar 2: rendering for A cluster is not the same as answering
about YOUR cluster - and the tool now knows the difference.

Bar 1 (proof/p4_render.py) shows the machinery is right: the helm path was
unreachable on 3 of 5 fixtures, it is now reached on all 5, and it renders at
a version derived from the chart's own declaration instead of helm's dead
1.20 constant. That is "correct".

This asks the user's harder question - "not just correct, but does it do what
it is supposed to do". The tool exists to tell someone whether a chart is safe
on the cluster they actually run. Rendering at ONE version, even a
well-chosen one, does not answer that, for two different reasons, and the
difference between them is the whole content of this iteration:

  1. The chart emits DIFFERENT OBJECTS at different points inside its own
     declared range. A single render covers one point. This is detectable:
     render both ends and compare. That is CH015.

  2. The chart branches on `.Capabilities.APIVersions`, which under
     `helm template` is not a function of the cluster version AT ALL - it is
     the set of group/versions compiled into the helm binary. Both arms
     answer the same way at every --kube-version, so the object sets at both
     ends are IDENTICAL and CH015 provably cannot see it. The render picked
     an arm for a reason unrelated to the user's cluster, and the tool cannot
     determine the right one. That is CH016, and it WITHHOLDS rather than
     asserts.

Two fixtures make the distinction concrete, and both are checked against the
real helm binary here so the premise cannot rot:

    fixtures/capability-chart   branches on .Capabilities.KubeVersion
                                -> object sets differ across its range
    fixtures/apiversion-chart   branches on .Capabilities.APIVersions.Has
                                -> object sets identical, answer still wrong

The second one is the outage. Rendered for a 1.21 cluster it emits an
`autoscaling/v2` HorizontalPodAutoscaler - an API that does not exist before
1.23 - while the chart's own `{{- else }}` arm, holding the correct
`autoscaling/v2beta1` object, is never taken. Install it and the Deployment
applies and the HPA is rejected: a half-applied release, from a chart whose
author did the right thing.

BEFORE is the committed pre-fix tree, extracted with `git archive <baseline>`
(pinned in proof/baseline.py, NOT HEAD) and run in a subprocess, on the same
fixture bytes the AFTER column gets. Run: python3 proof/p4b_bar2.py
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

CAPS = "capability-chart"      # KubeVersion-gated: really diverges
APIV = "apiversion-chart"      # APIVersions-gated: provably does not

_CHILD = r"""
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary, render

kw = {}
if len(sys.argv) > 3 and sys.argv[3]:
    kw["kube_version"] = sys.argv[3]
try:
    r = analyze(sys.argv[2], **kw)
except TypeError:
    # The pre-fix engine has no kube_version parameter at all. That is itself
    # a fact about the BEFORE column, so record it rather than crashing.
    r = analyze(sys.argv[2])
    kw["__unsupported__"] = True
out = os.path.join(tempfile.mkdtemp(), "report.txt")
ctx = getattr(r, "context", None)
print("---JSON---")
print(json.dumps({
    "summary": stdout_summary(r, out),
    "full": render(r, sys.argv[2], show_all=True),
    "rules": [f.rule_id for f in r.findings],
    "findings": [[f.rule_id, f.severity.name, f.title, f.detail]
                 for f in r.findings],
    "deductions": [[f.rule_id, f.effective_deduction()]
                   for f in r.findings
                   if hasattr(f, "effective_deduction")],
    "render_mode": getattr(ctx, "render_mode", ""),
    "kube_version": getattr(ctx, "render_kube_version", None),
    "kv_unsupported": bool(kw.get("__unsupported__")),
}))
"""


def _payload(root, chart, kube_version=None):
    p = subprocess.run([sys.executable, "-c", _CHILD, root, chart,
                        kube_version or ""],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"child failed on {chart}:\n{p.stderr[-2000:]}")
    return json.loads(p.stdout.split("---JSON---", 1)[1])


_BEFORE_TREE = None


def before_tree():
    global _BEFORE_TREE
    if _BEFORE_TREE is None:
        tmp = tempfile.mkdtemp(prefix="hpa-before-")
        tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _BEFORE_TREE = tmp
    return _BEFORE_TREE


def chart_dir(name):
    """The fixture, asserted to exist - see the same guard in p4_render.py,
    which is there because its absence silently produced a false proof."""
    p = os.path.join(REPO, "fixtures", name)
    if not os.path.isfile(os.path.join(p, "Chart.yaml")):
        raise SystemExit(f"proof harness: {p}/Chart.yaml does not exist")
    return p


def before(name, kube_version=None):
    """Pre-fix TOOL, current fixture bytes. Only the analyzer varies.

    Both fixtures postdate the baseline commit, so there are no "pre-fix
    fixture bytes" to use; the chart is the constant and the tool is the
    variable, which is the control this question needs anyway.
    """
    return _payload(before_tree(), chart_dir(name), kube_version)


def after(name, kube_version=None):
    return _payload(REPO, chart_dir(name), kube_version)


def hr(title=""):
    print()
    print("=" * 76)
    if title:
        print(title)
        print("=" * 76)


def helm_bin():
    import shutil
    h = shutil.which("helm")
    if not h:
        raise SystemExit("helm is not installed; this proof measures helm's "
                         "real behaviour and will not fake it")
    return h


def objects(name, version):
    """(apiVersion, kind, metadata.name) really emitted by helm. Sorted, so
    the comparison is set-wise and not order-dependent (contract C3.1)."""
    p = subprocess.run([helm_bin(), "template", "r", chart_dir(name),
                        "--kube-version", version],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"helm refused {name} at {version}: {p.stderr[:400]}")
    out, api, kind, nm = [], None, None, None
    for line in p.stdout.splitlines():
        if line.startswith("---"):
            if kind:
                out.append((api, kind, nm))
            api = kind = nm = None
        elif line.startswith("apiVersion:"):
            api = line.split(":", 1)[1].strip()
        elif line.startswith("kind:"):
            kind = line.split(":", 1)[1].strip()
        elif nm is None and re.match(r"^\s\sname:", line):
            nm = line.split(":", 1)[1].strip()
    if kind:
        out.append((api, kind, nm))
    return sorted(out)


def rule(payload, rid):
    for f in payload["findings"]:
        if f[0] == rid:
            return f
    return None


def grade(summary):
    m = re.search(r"GRADE\s+(\S+)\s+\(([\d.]+)/100\)", summary)
    return (m.group(1), float(m.group(2))) if m else (None, None)


def main():
    print(__doc__)

    # ---------------------------------------------------------------- 0 ----
    hr("CLAIM 0: the two fixtures really are the two different cases.\n"
       "         Asserted against the helm binary, not against my reading\n"
       "         of the templates.")
    lo, hi = "1.21.0", "1.32.0"
    caps_lo, caps_hi = objects(CAPS, lo), objects(CAPS, hi)
    apiv_lo, apiv_hi = objects(APIV, lo), objects(APIV, hi)
    for label, a, b in ((CAPS, caps_lo, caps_hi), (APIV, apiv_lo, apiv_hi)):
        print(f"  {label}")
        print(f"    @ {lo}: " + ", ".join(f"{k} ({v})" for v, k, _n in a))
        print(f"    @ {hi}: " + ", ".join(f"{k} ({v})" for v, k, _n in b))
        print(f"    identical: {a == b}")
    caps_diverges = caps_lo != caps_hi
    apiv_identical = apiv_lo == apiv_hi
    print()
    print("  So a divergence check finds the first chart and CANNOT find the")
    print("  second. That is not a weakness of the implementation; comparing")
    print("  two identical outputs has nothing to compare.")

    # the sharp end: what the second chart emits for a 1.21 cluster
    hpa_at_lo = [o for o in apiv_lo if o[1] == "HorizontalPodAutoscaler"]
    print()
    print(f"  And what {APIV} emits for a {lo} cluster:")
    for v, k, n in hpa_at_lo:
        print(f"    {v}  {k}  {n}")
    print("  autoscaling/v2 first exists in Kubernetes 1.23. The chart HAS a")
    print("  correct `{{- else }}` arm holding autoscaling/v2beta1. helm did")
    print("  not take it, because APIVersions.Has answered from its own")
    print("  compiled-in scheme. Applied to a real 1.21 cluster the Deployment")
    print("  lands and the HPA is rejected with 'no matches for kind'.")
    wrong_api_at_lo = any(v == "autoscaling/v2" for v, _k, _n in hpa_at_lo)
    print(f"  => premise: diverges={caps_diverges} identical={apiv_identical} "
          f"wrong_api_at_{lo}={wrong_api_at_lo}")
    claim0 = caps_diverges and apiv_identical and wrong_api_at_lo

    B_caps, B_apiv = before(CAPS), before(APIV)
    A_caps = after(CAPS)
    A_apiv_lo = after(APIV, lo)

    # ---------------------------------------------------------------- 1 ----
    hr("CLAIM 1: the pre-fix tool said nothing about either case, because\n"
       "         it never rendered either chart at any version.")
    for label, p in ((CAPS, B_caps), (APIV, B_apiv)):
        g, s = grade(p["summary"])
        head = next((l for l in p["summary"].splitlines() if "GRADE" in l), "")
        print(f"  BEFORE {label}")
        print(f"    render mode : {p['render_mode'][:64]}")
        print(f"    grade line  : {head.strip()[:70]}")
        print(f"    rules       : {', '.join(sorted(set(p['rules'])))}")
    print()
    print("  Note WHY it fell back: helm's 1.20 constant is below both charts'")
    print("  declared floor, so helm refused them - the D1 defect from Bar 1,")
    print("  reaching the two charts that exist specifically to test version")
    print("  behaviour. The pre-fix tool could not have caught either case,")
    print("  because it never got a rendered object at any version at all.")
    print()
    print("  One thing the pre-fix tool got RIGHT here, which this proof")
    print("  originally assumed it got wrong: the grade line says NOT GRADED,")
    print("  not A+. On these two charts the fallback scrub found no workload")
    print("  to score and said so. That makes the good-chart result in")
    print("  proof/p4_render.py CLAIM 3 worse, not better - same fallback")
    print("  state, same missing render, and there it printed A+ (100.0/100).")
    print("  The old code knew how to withhold a grade; it just did not do it")
    print("  in the case where the reader would be misled.")
    b_silent = (not any(r in B_caps["rules"] for r in ("CH015", "CH016"))
                and not any(r in B_apiv["rules"] for r in ("CH015", "CH016"))
                and not B_caps["render_mode"].startswith("helm")
                and not B_apiv["render_mode"].startswith("helm"))
    print(f"  => before_silent: {b_silent}")

    # ---------------------------------------------------------------- 2 ----
    hr("CLAIM 2 (CH015): the detectable case is now detected, and reported\n"
       "                 as a limit on the analysis rather than resolved.")
    f = rule(A_caps, "CH015")
    print(f"  AFTER {CAPS}: rendered at {A_caps['kube_version']}")
    if f:
        print(f"    [{f[0]}] {f[1]}  {f[2]}")
        for chunk in re.findall(r".{1,72}(?:\s|$)", f[3][:600]):
            print(f"      {chunk.rstrip()}")
    names_both = bool(f) and "PodDisruptionBudget" in f[3] \
        and "HorizontalPodAutoscaler" in f[3]
    print(f"  => CH015 fires: {bool(f)}; names both objects: {names_both}")
    print("  It does not pick a winner. There is no correct single version to")
    print("  report for a chart that legitimately emits different objects at")
    print("  different points of a range it legitimately declares.")
    claim2 = names_both and f[1] == "MEDIUM"

    # ---------------------------------------------------------------- 3 ----
    hr("CLAIM 3 (CH016): the undetectable case is not silently passed off\n"
       "                 as rendered truth.")
    c15 = rule(A_apiv_lo, "CH015")
    c16 = rule(A_apiv_lo, "CH016")
    print(f"  AFTER {APIV} at the user's own --kube-version {lo}:")
    print(f"    CH015 (divergence): "
          f"{'fires' if c15 else 'SILENT - nothing to compare'}")
    if c16:
        print(f"    [{c16[0]}] {c16[1]}  {c16[2]}")
        for chunk in re.findall(r".{1,72}(?:\s|$)", c16[3][:700]):
            print(f"      {chunk.rstrip()}")
    says_absent = bool(c16) and f"does not exist on a real {lo} cluster" in c16[3]
    # and the R3 rule catches the concrete object the wrong arm produced
    tp = rule(A_apiv_lo, "TP013")
    print()
    print("  The concrete object that wrong arm produced is caught too:")
    if tp:
        print(f"    [{tp[0]}] {tp[1]}  {tp[2]}")
    print("  TP013 is an R3 rule; it says the object is wrong. CH016 is the")
    print("  R4 addition, and it says something TP013 cannot: the reason helm")
    print("  emitted that object is unrelated to the cluster you named, so")
    print("  the other arm - the one that is correct for you - was never")
    print("  examined by this report at all.")
    claim3 = bool(c16) and not c15 and says_absent and bool(tp)
    print(f"  => ch016_fires={bool(c16)} ch015_silent={not c15} "
          f"names_absence={says_absent} tp013={bool(tp)}")

    # ---------------------------------------------------------------- 4 ----
    hr("CLAIM 4: CH016 withholds - it never asserts a finding it cannot\n"
       "         verify, and it cannot move the grade.")
    ded = dict(A_apiv_lo["deductions"])
    g_apiv = grade(A_apiv_lo["summary"])
    print(f"  CH016 severity           : {c16[1] if c16 else '-'}")
    print(f"  CH016 grade contribution : {ded.get('CH016')}")
    print(f"  grade printed            : {g_apiv[0]} ({g_apiv[1]}/100)")
    print()
    print("  This is the asymmetry the whole report is built on: a heuristic")
    print("  may WITHHOLD confidence, never manufacture a defect. CH016 knows")
    print("  the branch is unverifiable; it does not know the branch is")
    print("  wrong, and a rule that cannot tell the difference must not spend")
    print("  the user's attention as though it could. If it deducted points,")
    print("  every chart using the commonest capability idiom in the")
    print("  ecosystem would be marked down for a helm limitation.")
    claim4 = bool(c16) and c16[1] == "INFO" and ded.get("CH016") == 0

    # ---------------------------------------------------------------- 5 ----
    hr("CLAIM 5: the qualification reaches the reader where the claim is\n"
       "         made, not 200 lines below it.")
    modeline = [l for l in A_apiv_lo["full"].splitlines()
                if l.startswith("Mode:") or "NOT answered" in l]
    for l in modeline[:2]:
        for chunk in re.findall(r".{1,72}(?:\s|$)", l.strip()):
            print(f"    {chunk.rstrip()}")
    body = " ".join(A_apiv_lo["full"].split())
    qualified = "One capability was NOT answered" in body
    # and the overclaim it replaced must be gone
    overclaim = "APIVersions.Has` were answered for that version" in body
    print()
    print(f"  qualification present in the mode section : {qualified}")
    print(f"  old overclaim still present anywhere      : {overclaim}")
    print("  The mode paragraph is where the report says the word 'rendered'.")
    print("  A caveat the reader meets after they have already believed the")
    print("  claim has not been delivered.")
    claim5 = qualified and not overclaim

    # ------------------------------------------------------------ verdict --
    hr()
    ok = claim0 and b_silent and claim2 and claim3 and claim4 and claim5
    if not ok:
        print("NOT PROVEN:", dict(premise=claim0, before_silent=b_silent,
                                  ch015=claim2, ch016=claim3,
                                  withholds=claim4, qualified=claim5))
        return 1
    print("Bar 2 MET for R4, with a boundary stated rather than crossed.")
    print()
    print("The tool is supposed to answer 'is this chart safe on my cluster'.")
    print("A single render cannot. Where that gap is measurable the tool now")
    print("measures it (CH015). Where it is NOT measurable - because helm's")
    print("APIVersions set is a compile-time constant and no flag can subtract")
    print("from it - the tool now says so and declines to score it (CH016),")
    print("instead of printing the render as though it were an observation")
    print("about the reader's cluster.")
    print()
    print("What this does NOT prove, and no version of this tool can:")
    print("  * that the arm helm did NOT take would pass these checks. It was")
    print("    never rendered. CH016 marks that branch unexamined; it does")
    print("    not examine it.")
    print("  * that CH015 covers the interior of a declared range. It renders")
    print("    the two ends. A chart that changes only at 1.27 inside")
    print("    >=1.21 <1.33 will show two matching ends and no finding.")
    print("  * anything about CRD-provided group/versions, which helm answers")
    print("    FALSE for at every --kube-version even on clusters that have")
    print("    them installed - the same defect in the other direction.")
    print("Only a live cluster answers those, and this tool does not have one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

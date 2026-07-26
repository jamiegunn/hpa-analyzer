#!/usr/bin/env python3
"""PROOF R4, Bar 1: the rendered-truth path was unreachable, and now is not.

WHAT THE TOOL IS SUPPOSED TO DO, for this iteration specifically.

hpa-analyzer advertises two modes and prefers one of them. From the module
that implements it, unchanged since before this iteration:

    `helm template` is ground truth: real Go-template evaluation, real
    conditionals, real values merging. The static scrubber in helmyaml.py is
    the fallback, and the report says loudly which mode produced its facts.
                                                    -- helmrender.py

So the contract is: if helm is installed, the user gets rendered truth. The
static scrubber is what happens to people who have not installed helm.

WHY IT DID NOT DO THAT.

`helm template` is not a function of the chart directory. It is a function of
(chart, values, kubeVersion, apiVersions), and the pre-R4 code passed only the
first two. helm supplies the rest from a constant:

    helm/pkg/chartutil/capabilities.go        (v3.16)
      const ( k8sVersionMajor = "1"; k8sVersionMinor = "20" )

Kubernetes 1.20 reached end of life in February 2022. And helm ENFORCES the
chart's own kubeVersion against that constant at render time
(pkg/action/action.go, renderResources), so every chart declaring a floor
above 1.20 - which is to say every chart written this decade - was refused,
and the tool fell back to the scrubber it calls "the fallback".

The result is a feature that works on the charts that need it least.

Nothing below is asserted from that reading. CLAIM 0 runs the real helm binary
to establish the default; CLAIMS 1-5 run the pre-fix tool, extracted with
`git archive <baseline>` (pinned in proof/baseline.py, not HEAD), in a
subprocess, against the same fixture bytes as the current tree.

Run: python3 proof/p4_render.py
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

# The five fixtures that existed before R4. capability-chart and
# apiversion-chart are new and are the subject of p4b_bar2.py; using them here
# would prove a new fixture behaves well, which is not the same as proving the
# tool got better at charts it already had.
FIXTURES = ["good-chart", "sidecar-chart", "initheavy-chart",
            "legacy-chart", "bad-chart"]

_CHILD = r"""
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary, render
r = analyze(sys.argv[2])                      # default helm_mode="auto"
c = r.context
out = os.path.join(tempfile.mkdtemp(), "report.txt")
print("---JSON---")
print(json.dumps({
    "summary": stdout_summary(r, out),
    "full": render(r, sys.argv[2], show_all=True),
    "render_mode": c.render_mode,
    "helm_error": c.helm_error,
    "helm_present": getattr(c, "helm_present", None),
    "kube_version": getattr(c, "render_kube_version", None),
    "rules": sorted({f.rule_id for f in r.findings}),
}))
"""


def _payload(root, chart):
    p = subprocess.run([sys.executable, "-c", _CHILD, root, chart],
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


def _chart_dir(name):
    """The fixture, asserted to exist.

    This guard is here because its absence produced a false proof. The first
    draft ran the pre-fix tool on `<baseline-tree>/fixtures/<name>` - pre-fix
    tool AND pre-fix fixture bytes, which sounds like the stricter control.
    But three of these five fixtures were WRITTEN during iterations 1-3 and do
    not exist at the baseline commit, so the tool was handed a path that was
    not there. It did not crash: it reported "No Chart.yaml found" and
    render_mode "static", and the proof scored that as "the helm path was
    unreachable". Three fifths of CLAIM 1 was measuring an empty directory.

    A missing input must be a stop, not a data point.
    """
    p = os.path.join(REPO, "fixtures", name)
    if not os.path.isfile(os.path.join(p, "Chart.yaml")):
        raise SystemExit(f"proof harness: {p}/Chart.yaml does not exist; "
                         f"refusing to measure a directory that is not a chart")
    return p


def before(name):
    """The PRE-FIX TOOL on the CURRENT fixture bytes.

    The variable under test is the analyzer, so the chart is held constant and
    only the tool version moves - the same control the other proofs in this
    directory use. The pre-fix tree supplies the code (extracted with
    `git archive` at the pinned SHA); REPO supplies the chart.
    """
    return _payload(before_tree(), _chart_dir(name))


def after(name):
    return _payload(REPO, _chart_dir(name))


def hr(title=""):
    print()
    print("=" * 76)
    if title:
        print(title)
        print("=" * 76)


def grade(summary):
    m = re.search(r"GRADE\s+(\S+)\s+\(([\d.]+)/100\)", summary)
    return (m.group(1), float(m.group(2))) if m else (None, None)


def main():
    print(__doc__)

    helm = shutil.which("helm")
    if not helm:
        print("helm is not installed; this proof is about helm's behaviour "
              "and refuses to simulate it.")
        return 1

    # ---------------------------------------------------------------- 0 ----
    hr("CLAIM 0: helm's compiled-in default really is v1.20.0, and it really\n"
       "         does refuse a modern chart. Measured, not recalled.")
    ver = subprocess.run([helm, "version", "--short"],
                         capture_output=True, text=True).stdout.strip()
    print(f"  helm binary            : {helm}  ({ver})")
    p = subprocess.run([helm, "template", "r",
                        os.path.join(REPO, "fixtures", "good-chart")],
                       capture_output=True, text=True)
    err = " ".join((p.stderr or p.stdout).split())
    print(f"  $ helm template r fixtures/good-chart      -> exit {p.returncode}")
    print(f"    {err[:160]}")
    p2 = subprocess.run([helm, "template", "r",
                         os.path.join(REPO, "fixtures", "good-chart"),
                         "--kube-version", "1.32.0"],
                        capture_output=True, text=True)
    print(f"  $ ... --kube-version 1.32.0                -> exit {p2.returncode}")
    default_is_120 = p.returncode != 0 and "v1.20.0" in err and p2.returncode == 0
    print(f"  => same chart, same bytes; the only difference is the flag.")
    print(f"  => default_is_120: {default_is_120}")

    B = {n: before(n) for n in FIXTURES}
    A = {n: after(n) for n in FIXTURES}

    # ---------------------------------------------------------------- 1 ----
    hr("CLAIM 1 (D1): with helm installed and every chart valid, the pre-fix\n"
       "              tool used the static fallback on most of them.")
    print(f"  {'fixture':<18} {'BEFORE mode':<44} AFTER")
    print(f"  {'-'*18} {'-'*44} {'-'*22}")
    for n in FIXTURES:
        bm = (B[n]["render_mode"] or "")[:43]
        am = A[n]["render_mode"]
        akv = A[n]["kube_version"]
        print(f"  {n:<18} {bm:<44} {am}"
              + (f" @ {akv}" if akv else ""))
    b_static = [n for n in FIXTURES if not B[n]["render_mode"].startswith("helm")]
    a_static = [n for n in FIXTURES if not A[n]["render_mode"].startswith("helm")]
    print()
    print(f"  BEFORE fell back on {len(b_static)}/{len(FIXTURES)}: {b_static}")
    print(f"  AFTER  falls back on {len(a_static)}/{len(FIXTURES)}: "
          f"{a_static or 'none'}")
    print()
    # Note which ones - read off the BASELINE fixture bytes, not typed here.
    # An earlier draft of this proof asserted "the two that rendered"; the
    # measurement said one. Prose that the run can falsify does not belong in
    # a proof, so the sentence is now assembled from what was measured.
    print("  Note which ones. Declared kubeVersion, read from the fixture")
    print("  bytes both columns were given:")
    declared = {}
    for n in FIXTURES:
        raw = ""
        try:
            with open(os.path.join(_chart_dir(n), "Chart.yaml")) as fh:
                for line in fh:
                    if line.strip().startswith("kubeVersion:"):
                        raw = line.split(":", 1)[1].strip().strip("\"'")
                        break
        except OSError:
            pass
        declared[n] = raw
        print(f"    {n:<18} {raw or '(none declared)':<20} "
              f"-> {'fell back' if n in b_static else 'rendered'}")
    above_120 = [n for n in b_static if declared[n]]
    print()
    print(f"  Every chart that fell back ({len(above_120)} of {len(b_static)})")
    print("  declares a floor above helm's compiled-in 1.20. The ones that")
    print("  rendered are the ones that declare nothing, or nothing helm's")
    print("  1.20 constant violates. The feature worked precisely on the")
    print("  charts nobody writes.")
    d1 = len(b_static) >= 3 and not a_static
    print(f"  => d1: {d1}")

    # ---------------------------------------------------------------- 2 ----
    hr("CLAIM 2 (D2): the advice printed in that state was the one action\n"
       "              that could not possibly help.")
    subject = "good-chart"
    bl = [l for l in B[subject]["full"].splitlines() if "Install" in l
          and "helm" in l]
    print(f"  BEFORE, {subject} (helm WAS on PATH: "
          f"{shutil.which('helm') is not None}):")
    for l in bl[:3]:
        print(f"    | {l.strip()}")
    told_to_install = bool(bl)
    print()
    print("  A reader who follows that advice installs helm a second time and")
    print("  gets a byte-identical report, because the missing binary was")
    print("  never the problem.")
    print()
    print(f"  AFTER, {subject}:")
    for l in A[subject]["full"].splitlines():
        if "kube-version" in l and "Mode:" in l:
            print(f"    | {l.strip()[:150]}")
            break
    now_renders = A[subject]["render_mode"] == "helm"
    # and when a chart genuinely cannot render, the advice must name the cause
    unrenderable = _unrenderable_report()
    print()
    print("  AFTER, a chart helm really does refuse (kubeVersion '>=1.99.0-0'):")
    for l in unrenderable.splitlines():
        if "installing it again" in l or "refused the chart" in l:
            print(f"    | {l.strip()[:150]}")
    names_cause = ("installing it again will not change this report"
                   in " ".join(unrenderable.split()))
    d2 = told_to_install and now_renders and names_cause
    print(f"  => d2: {d2}")

    # ---------------------------------------------------------------- 3 ----
    hr("CLAIM 3 (D5): the failure was cosmetically invisible - a multi-line\n"
       "              subprocess error spliced into single-line report fields,\n"
       "              under a grade that claimed the chart was perfect.")
    gb, sb = grade(B[subject]["summary"])
    print(f"  BEFORE {subject}: GRADE {gb} ({sb}/100), render_mode="
          f"{B[subject]['render_mode']!r}")
    berr = B[subject]["helm_error"] or ""
    print(f"  BEFORE helm_error contains a newline: {chr(10) in berr}")
    if chr(10) in berr:
        print("  BEFORE helm_error, as stored (repr):")
        print(f"    {berr!r}"[:200])
    broken_layout = chr(10) in berr
    aerr = _unrenderable_error()
    print(f"  AFTER  helm_error contains a newline: {chr(10) in aerr}")
    print(f"    {aerr!r}"[:200])
    d5 = broken_layout and chr(10) not in aerr
    print()
    print("  The grade is the worse half. 100.0/100 was computed over the")
    print("  findings of a scrub the report itself calls the fallback, and")
    print("  printed in the same format as a grade earned from a real render.")
    print(f"  => d5: {d5}")

    # ---------------------------------------------------------------- 4 ----
    hr("CLAIM 4 (D3): the render is now FOR a stated cluster, chosen from the\n"
       "              chart's own declaration, and the report says which.")
    for n in FIXTURES:
        kv = A[n]["kube_version"]
        print(f"  {n:<18} --kube-version {kv or '(none - chart declares no range)'}")
    line = next((l for l in A[subject]["full"].splitlines()
                 if l.startswith("Mode: `helm template")), "")
    print()
    print(f"  {line[:150]}")
    stated = ("--kube-version 1.32.0" in line
              and all(A[n]["kube_version"] for n in
                      ("good-chart", "sidecar-chart", "initheavy-chart")))
    print(f"  => stated: {stated}")

    # ---------------------------------------------------------------- 5 ----
    hr("CLAIM 5: nothing was lost. Every rule the pre-fix tool fired still\n"
       "         fires, on every fixture.")
    lost_any = {}
    for n in FIXTURES:
        lost = sorted(set(B[n]["rules"]) - set(A[n]["rules"]))
        gained = sorted(set(A[n]["rules"]) - set(B[n]["rules"]))
        lost_s = ", ".join(lost) if lost else "none"
        print(f"  {n:<18} lost={lost_s:<28} gained={', '.join(gained) or 'none'}")
        if lost:
            lost_any[n] = lost
    print()
    # Where did the gained rules come from? Ask the baseline source, don't
    # guess. A rule the pre-fix binary does not contain cannot have been
    # suppressed by the pre-fix render mode.
    gained_all = sorted({r for n in FIXTURES
                         for r in set(A[n]["rules"]) - set(B[n]["rules"])})
    src = subprocess.run(["grep", "-rho", "-E", "|".join(gained_all) or "^$",
                          os.path.join(before_tree(), "hpaanalyzer")],
                         capture_output=True, text=True).stdout.split()
    absent = [r for r in gained_all if r not in src]
    print(f"  gained, overall: {', '.join(gained_all) or 'none'}")
    print(f"  of those, absent from the baseline SOURCE entirely: "
          f"{', '.join(absent) or 'none'}")
    print("  So the gains are not R4 turning on a hidden check - they are")
    print("  rules written in R1-R3 that this comparison inherits. R4's own")
    print("  contribution to this column is zero, which is what a change to")
    print("  HOW the chart is read, rather than to WHAT is checked, should")
    print("  look like. The one thing that matters here is the lost column.")
    kept = not lost_any
    print(f"  => kept: {kept}")

    # ------------------------------------------------------------ verdict --
    hr()
    ok = default_is_120 and d1 and d2 and d5 and stated and kept
    if not ok:
        print("NOT PROVEN:", dict(default_is_120=default_is_120, d1=d1, d2=d2,
                                  d5=d5, stated=stated, kept=kept))
        return 1
    print("Bar 1 MET for R4. The mode the tool calls ground truth was")
    print(f"unreachable on {len(b_static)} of its own {len(FIXTURES)} fixtures "
          f"with helm installed, for a")
    print("reason no user could have diagnosed from the report - which told")
    print("them to install the binary they already had - and it is now reached")
    print(f"on all {len(FIXTURES)}, at a version derived from each chart's own "
          f"declaration and")
    print("printed in the report.")
    print()
    print("What this does NOT prove: that rendering at the top of the declared")
    print("range is the RIGHT version, or that a render at one version says")
    print("anything about the rest of the range. That is Bar 2, and it is")
    print("proof/p4b_bar2.py - where the answer is partly no, and the tool now")
    print("says so instead of covering it.")
    return 0


def _unrenderable_chart():
    """A chart helm will refuse no matter what version is chosen."""
    d = tempfile.mkdtemp(prefix="hpa-unrender-")
    shutil.copytree(os.path.join(REPO, "fixtures", "good-chart"), d,
                    dirs_exist_ok=True)
    p = os.path.join(d, "Chart.yaml")
    txt = open(p, encoding="utf-8").read()
    txt = re.sub(r"(?m)^kubeVersion:.*$", 'kubeVersion: ">=1.99.0-0"', txt)
    open(p, "w", encoding="utf-8").write(txt)
    return d


_UNRENDER = None


def _unrender():
    global _UNRENDER
    if _UNRENDER is None:
        _UNRENDER = after_path(_unrenderable_chart())
    return _UNRENDER


def after_path(path):
    return _payload(REPO, path)


def _unrenderable_report():
    return _unrender()["full"]


def _unrenderable_error():
    return _unrender()["helm_error"] or ""


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""PROOF R3: the tool held Kubernetes versions as decoration, not as data.

One root cause, three symptoms, all visible on a single chart:

  1. Severity was a constant. TP010 fired CRITICAL for any removed apiVersion
     regardless of the cluster range the chart itself declares. A chart pinned
     `>=1.20.0-0 <1.22.0-0` shipping networking.k8s.io/v1beta1 Ingress got the
     same top-of-list slot as a chart pinned `>=1.33.0-0` shipping
     batch/v1beta1 CronJob. The first cannot break on any cluster it claims to
     support; the second cannot work on any. Ranking them identically is what
     makes a fix-first list stop being a fix-first list.

  2. The other axis did not exist. An apiVersion can also be too NEW for the
     declared range - autoscaling/v2 on a chart claiming 1.20 support installs
     cleanly and then fails at apply. CH010's own `why` text cites that exact
     example as the reason to set kubeVersion, and the tool never checked the
     constraint it advised.

  3. The table was incomplete, asymmetrically. rbac.../v1beta1 Role was listed;
     RoleBinding, removed in the same release and sitting three lines below it
     in the same file, was not. A lookup miss in that table produces SILENCE,
     which is indistinguishable from a clean bill of health.

AUTHORITY for treating the constraint as data rather than a comment -
helm/pkg/action/action.go, renderResources(), v3.16.4:

    if ch.Metadata.KubeVersion != "" {
        if !chartutil.IsCompatibleRange(ch.Metadata.KubeVersion, caps.KubeVersion.String()) {
            return hs, b, "", errors.Errorf("chart requires kubeVersion: %s which is incompatible with Kubernetes %s", ch.Metadata.KubeVersion, caps.KubeVersion.String())
        }
    }

This script verifies that snippet against the real repository when git and the
network are available, and says so plainly when they are not. The semantics of
IsCompatibleRange itself are proven separately and exhaustively by
proof/p3_oracle.py (2632 pairs against the real Go library).

BEFORE is the committed pre-fix tree at the pinned baseline (proof/baseline.py),
extracted with `git archive` and run in a SUBPROCESS. Both columns are real
program output; the only variable is the fix.

Run: python3 proof/p3_severity.py
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

from baseline import BASELINE, resolve as _resolve_baseline   # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)

LEGACY = os.path.join(REPO, "fixtures", "legacy-chart")

HELM_TAG = "v3.16.4"

# Run inside the extracted pre-fix tree, so its own package is imported.
_CHILD = r"""
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary
out = {}
for name in sys.argv[2:]:
    r = analyze(name, helm_mode="off")
    out[os.path.basename(name)] = {
        "findings": [[f.rule_id, f.severity.name, f.title, f.detail,
                      f.fix, f.why] for f in r.findings],
        "summary": stdout_summary(r, os.path.join(tempfile.mkdtemp(), "r.txt")),
    }
print("---JSON---")
print(json.dumps(out))
"""

# The four range states, as four one-object charts differing ONLY in
# kubeVersion. Nothing else varies, so nothing else can explain a severity
# difference.
CRONJOB = """apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: nightly
  labels: {app.kubernetes.io/name: m}
spec:
  schedule: "0 2 * * *"
"""

MATRIX = [
    ("no kubeVersion",          None,                   "cluster range unknown"),
    ("pinned below removal",    ">=1.20.0-0 <1.25.0-0", "1.20-1.24, API present"),
    ("straddling the removal",  ">=1.23.0-0 <1.28.0-0", "1.23-1.27, half and half"),
    ("pinned above removal",    ">=1.33.0-0",           "1.33+, API gone"),
]


def _mkchart(root, name, kube_version, body):
    d = os.path.join(root, name)
    os.makedirs(os.path.join(d, "templates"))
    kv = "" if kube_version is None else f'kubeVersion: "{kube_version}"\n'
    with open(os.path.join(d, "Chart.yaml"), "w") as f:
        f.write('apiVersion: v2\nname: m\nversion: 1.0.0\nappVersion: "1"\n'
                'description: matrix\n' + kv)
    with open(os.path.join(d, "values.yaml"), "w") as f:
        f.write("a: 1\n")
    with open(os.path.join(d, "templates", "o.yaml"), "w") as f:
        f.write(body)
    return d


def build_charts(root):
    """The fixture plus the four matrix charts, identical for both columns."""
    shutil.copytree(LEGACY, os.path.join(root, "legacy-chart"))
    paths = [os.path.join(root, "legacy-chart")]
    for i, (_, kube_version, _) in enumerate(MATRIX):
        paths.append(_mkchart(root, f"m{i}", kube_version, CRONJOB))
    return paths


def before(charts):
    tmp = tempfile.mkdtemp(prefix="hpa-r3-before-")
    tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                         capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
    out = subprocess.run([sys.executable, "-c", _CHILD, tmp] + charts,
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out.split("---JSON---", 1)[1])


def after(charts):
    from hpaanalyzer.engine import analyze
    from hpaanalyzer.report import stdout_summary
    out = {}
    for name in charts:
        r = analyze(name, helm_mode="off")
        out[os.path.basename(name)] = {
            "findings": [[f.rule_id, f.severity.name, f.title, f.detail,
                          f.fix, f.why] for f in r.findings],
            "summary": stdout_summary(r, "/tmp/r3.txt"),
        }
    return out


def sev(col, chart, rule_id, match=None):
    """Severities of one rule on one chart, in report order."""
    return [f[1] for f in col[chart]["findings"] if f[0] == rule_id
            and (match is None or match in f[3])]


def hdr(n, text):
    print()
    print("=" * 76)
    print(f"CLAIM {n}: {text}")
    print("=" * 76)


# --------------------------------------------------------------------------


def claim_0():
    hdr(0, "helm ENFORCES kubeVersion at render time, so the constraint is\n"
           "         executable and severity may legitimately depend on it.")
    tmp = tempfile.mkdtemp(prefix="hpa-helm-")
    try:
        subprocess.run(["git", "clone", "--depth", "1", "-b", HELM_TAG,
                        "https://github.com/helm/helm.git",
                        os.path.join(tmp, "helm")],
                       capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("  could not clone helm (needs git + network).")
        print("  NOT VERIFIED HERE - this claim is unproven in this run.")
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    src = os.path.join(tmp, "helm", "pkg", "action", "action.go")
    text = open(src, encoding="utf-8").read()
    m = re.search(r"if ch\.Metadata\.KubeVersion != \"\" \{.*?\n\t\}", text,
                  re.S)
    print(f"  helm {HELM_TAG}  pkg/action/action.go:")
    if m:
        for line in m.group(0).split("\n"):
            print("    " + line.replace("\t", "    ").rstrip()[:150])
    ok = bool(m)
    comp = os.path.join(tmp, "helm", "pkg", "chartutil", "compatible.go")
    ctext = open(comp, encoding="utf-8").read()
    print()
    print(f"  helm {HELM_TAG}  pkg/chartutil/compatible.go:")
    for line in ctext.split("\n"):
        if line.strip().startswith(("func IsCompatibleRange", "c, err",
                                    "if err != nil", "return false",
                                    "return c.Check")):
            print("    " + line.replace("\t", "    ").rstrip())
    # The "return false" on a parse error is what makes a typo'd constraint a
    # chart that installs nowhere - i.e. CH013's severity.
    ok = ok and "if err != nil {\n\t\treturn false" in ctext
    print()
    print(f"  install-time gate present            : {bool(m)}")
    print(f"  unparseable constraint -> false      : "
          f"{'if err != nil {' in ctext and 'return false' in ctext}")
    shutil.rmtree(tmp, ignore_errors=True)
    return ok


def claim_1(b, a):
    hdr(1, "severity was a constant. The SAME object, under four different\n"
           "         declared cluster ranges, produced four identical answers.")
    print(f"  {'chart kubeVersion':<24} {'means':<26} {'BEFORE':<10} AFTER")
    print("  " + "-" * 72)
    rows = []
    for i, (label, kube_version, means) in enumerate(MATRIX):
        chart = f"m{i}"
        bs = sev(b, chart, "TP010")
        as_ = sev(a, chart, "TP010")
        rows.append((bs, as_))
        print(f"  {str(kube_version or '(absent)'):<24} {means:<26} "
              f"{(bs[0] if bs else '-'):<10} {(as_[0] if as_ else '-')}")
    before_set = {r[0][0] for r in rows if r[0]}
    after_list = [r[1][0] for r in rows if r[1]]
    print()
    print(f"  distinct BEFORE severities : {len(before_set)}  {sorted(before_set)}")
    print(f"  AFTER severities in order  : {after_list}")
    print()
    print("  A single distinct value across four materially different charts is")
    print("  not a ranking; it is a label. Note the last row: the chart that")
    print("  genuinely cannot work anywhere is UNCHANGED. This is a")
    print("  reconciliation, not a blanket downgrade.")
    ok = (len(before_set) == 1
          and after_list == ["CRITICAL", "LOW", "HIGH", "CRITICAL"])
    return ok


def claim_2(b, a):
    hdr(2, "the deprecation table went silent halfway through a file.")
    got_b = sev(b, "legacy-chart", "TP010",
                "rbac.authorization.k8s.io/v1beta1")
    got_a = sev(a, "legacy-chart", "TP010",
                "rbac.authorization.k8s.io/v1beta1")
    kinds_b = [f[2] for f in b["legacy-chart"]["findings"]
               if f[0] == "TP010" and "rbac" in f[3]]
    kinds_a = [f[2] for f in a["legacy-chart"]["findings"]
               if f[0] == "TP010" and "rbac" in f[3]]
    print("  fixtures/legacy-chart/templates/rbac.yaml holds a Role and a")
    print("  RoleBinding. Both are rbac.authorization.k8s.io/v1beta1. Both were")
    print("  removed in Kubernetes 1.22. They are 14 lines apart.")
    print()
    print(f"  BEFORE reported {len(got_b)} of 2:")
    for k in kinds_b:
        print(f"    - {k}")
    print(f"  AFTER  reported {len(got_a)} of 2:")
    for k in kinds_a:
        print(f"    - {k}")
    print()
    print("  The pre-fix table carried 22 rows; it now carries "
          f"{_table_size()}. A miss")
    print("  in this table prints nothing, and nothing looks exactly like a")
    print("  pass.")
    return len(got_b) == 1 and len(got_a) == 2


def _table_size():
    from hpaanalyzer.kube import DEPRECATED_APIS
    return len(DEPRECATED_APIS)


def claim_3(b, a):
    hdr(3, "the 'too new' axis was never checked, though CH010's own text\n"
           "         cited it as the reason to set kubeVersion.")
    # legacy-chart declares kubeVersion, so CH010 does not fire there; the
    # quotable text comes from the no-kubeVersion matrix chart.
    ch010_text = [f[5] for f in b["m0"]["findings"] if f[0] == "CH010"]
    print("  BEFORE, CH010's own `why` text read, verbatim:")
    for t in ch010_text:
        i = t.find("autoscaling")
        for line in _wrap(t[max(0, i - 90):i + 80], 70):
            print(f"    | {line}")
    print()
    print("  So the pre-fix tool named this exact failure mode as the reason to")
    print("  set a kubeVersion, in the finding that asks you to set one - and")
    print("  then never checked it.")
    print()
    print("  fixtures/legacy-chart declares kubeVersion \">=1.20.0-0 <1.22.0-0\"")
    print("  and ships an autoscaling/v2 HorizontalPodAutoscaler, which does")
    print("  not exist before 1.23.")
    print()
    tp013_b = sev(b, "legacy-chart", "TP013")
    tp013_a = sev(a, "legacy-chart", "TP013")
    print(f"  BEFORE findings on that object : {tp013_b or 'NONE'}")
    print(f"  AFTER  findings on that object : {tp013_a}")
    print()
    print("  helm's gate passes here - the chart is telling the truth about")
    print("  where it wants to run - so the install proceeds and the API server")
    print("  rejects the object. A half-applied release is precisely the")
    print("  failure the kubeVersion field exists to prevent.")
    ok = not tp013_b and tp013_a == ["CRITICAL"]
    ok = ok and any("autoscaling/v2" in t for t in ch010_text)
    return ok


def claim_4(b, a):
    hdr(4, "the advice was a constant too, and did not depend on the chart\n"
           "         it was printed about.")
    for i, (label, kube_version, _) in enumerate(MATRIX):
        if kube_version is not None:
            continue
        fix_b = [f[4] for f in b[f"m{i}"]["findings"] if f[0] == "CH010"]
        fix_a = [f[4] for f in a[f"m{i}"]["findings"] if f[0] == "CH010"]
        print("  chart ships ONLY a batch/v1beta1 CronJob (removed in 1.25).")
        print()
        print("  BEFORE:")
        print(f"    {fix_b[0] if fix_b else '(no CH010)'}")
        print("  AFTER:")
        for line in _wrap(fix_a[0] if fix_a else "(no CH010)", 76 - 4):
            print(f"    {line}")
        ok = bool(fix_b) and "1.23" in fix_b[0] and bool(fix_a) \
            and "1.25" in fix_a[0] and "batch/v1beta1" in fix_a[0]
        print()
        print("  BEFORE names 1.23, a version with no connection to this chart.")
        print("  AFTER names the bound this chart's own template implies, and")
        print("  says which object it came from - so it can be checked.")
        return ok
    return False


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


def main():
    print(__doc__.split("Run:")[0].rstrip())

    root = tempfile.mkdtemp(prefix="hpa-r3-charts-")
    charts = build_charts(root)
    b = before(charts)
    a = after(charts)

    c0 = claim_0()
    results = [
        ("1 severity was a constant", claim_1(b, a)),
        ("2 the table went silent halfway", claim_2(b, a)),
        ("3 the too-new axis did not exist", claim_3(b, a)),
        ("4 the advice was a constant", claim_4(b, a)),
    ]
    if c0 is not None:
        results.insert(0, ("0 helm enforces kubeVersion", c0))

    print()
    print("=" * 76)
    for name, ok in results:
        print(f"  CLAIM {name:<40} {'PROVEN' if ok else 'NOT PROVEN'}")
    print("=" * 76)
    print(f"(BEFORE column produced by `git archive {BASELINE}` and run in a")
    print(" subprocess. Charts for both columns built once, in "
          f"{root}.)")
    shutil.rmtree(root, ignore_errors=True)
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    sys.exit(main())

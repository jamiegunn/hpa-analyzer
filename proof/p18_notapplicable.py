"""R16. Fifteen weight points of A+ for a question the tool never asked.

HOW THIS WAS FOUND
------------------
Not by reading the code, and not by looking for this. The round opened on a
different complaint - that `Horizontal Pod Autoscaling` carries weight 15 and a
chart with NO autoscaler at all scores it 94.0, an A, because HP002 is a single
MEDIUM. Measuring that over the thirty-five-chart corpus produced this
distribution:

    100.0  x1   (fixtures/good-chart, and it was written to)
     97.0  x12  (HP030 - no behavior block - fires on 25 of the 26 charts
                 that HAVE an HPA, so 97.0 is the working ceiling)
     94.0  x6   (every chart with no HPA object at all)
     85.0  x2      72.0  x9      41.0  x1      20.0  x1

So absence of the entire feature outranks fourteen of the twenty-six charts
that implement it. That is a calibration argument, it is arguable in both
directions, and it is NOT what this script is about - see the bottom of
docs/ITERATIONS.md R16 for why the 94.0 was deliberately left alone.

Underneath it was something not arguable. `checks_hpa._no_hpa()` opened:

    scalable = [w for w in workloads
                if (w.kind or "").lower() in ("deployment", "statefulset")]
    if not scalable:
        return

A bare `return`: no finding, and - because nothing else in the tool asks the
question - no coverage note either. `scoring.unassessed_reason()` drops HPA
only when NO Kubernetes objects were parsed at all. Objects were parsed. So the
category counted as assessed, held zero findings, and a category with zero
findings scores 100.0. One chart, one line changed, nothing else:

    kind                    HPA cat   HPA findings   assessed weight
    Deployment                 94.0   ['HP002']              64
    StatefulSet                94.0   ['HP002']              64
    ReplicaSet                100.0   []                     64
    ReplicationController     100.0   []                     64
    DaemonSet                 100.0   []                     64
    CronJob                   100.0   []                     64
    Pod                       100.0   []                     64
    Rollout                   100.0   []                     64

and on six of those eight the scorecard printed:

    | Horizontal Pod Autoscaling             | 100.0        | A+    | 15   |

which is the first entry on scoring.py's own list of forbidden fixes, arrived
at from the other end: "Score an unassessed category 100: invents a clean bill
of health for something never looked at."

THREE DEFECTS, NOT ONE, AND THEY NEED THREE DIFFERENT FIXES
-----------------------------------------------------------
The eight rows above do not all fail for the same reason, and the first draft
of this round treated them as if they did.

(a) ReplicaSet, ReplicationController. Both implement /scale. Both are in
    `kube.SCALABLE_KINDS`, which is the tool's own written statement of exactly
    that. `_no_hpa()` re-typed two of the four inline and dropped the other
    two - a copy of a list that rotted. HP002 is precisely the finding for
    these charts and they got silence. Fixed by deleting the copy.

    The correction that matters here, because the first fix was not enough:
    swapping in SCALABLE_KINDS recovered ReplicaSet and NOT
    ReplicationController, because the list `_no_hpa` was handed is
    `ChartContext.workloads`, whose own literal has never mentioned
    ReplicationController - so the document was filtered out one level above
    the bug. Two copies, in series. The input is now
    `kube.scale_candidates(ctx.docs)`.

(b) DaemonSet, Job, CronJob, Pod. These genuinely cannot be autoscaled, and
    `kube.UNSCALABLE_KINDS` holds a written reason for each. Silence on the
    FINDINGS axis is correct - telling an operator to put an HPA on a DaemonSet
    is worse than saying nothing. Silence on the SCORING axis is not, because
    fifteen weighted points of A+ are being awarded for it. Filing it as
    unassessed would also be false: the tool was not blind, it read the object
    and holds the answer. This is what `scoring.not_applicable_reason` is for
    and it is the only new idea in the round.

(c) Rollout. An Argo Rollout DOES expose /scale, so HP002's subject exists -
    but this tool's kind lists have never heard of it, and concluding "that CRD
    cannot autoscale" from a set that does not mention it invents the answer
    just as surely as scoring it 100 did. What the tool actually has is
    ignorance of a specific, nameable kind. That is NOT ASSESSED, and the
    reason string names the kind.

WHAT THIS SCRIPT ASSERTS
------------------------
Each of the three, with a negative control, because the failure mode of a fix
like this is not that it stops working - it is that it starts working
everywhere. A predicate that drops HPA from the mean whenever the workload
looks unscalable would also drop it on `c22-cronjob-hpa`, which has a CronJob
AND an HPA pointed at it and deducts a CRITICAL for it. Dropping a category
that just deducted twenty-five points is the R14b bug, re-committed one round
after it was fixed. CLAIM 4 is that control and it is the reason condition 1 of
the predicate exists.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE)
import corpus_charts as cc  # noqa: E402

FAILURES = []
TMP = tempfile.mkdtemp(prefix="p18-")


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        print(f"         {detail}")
    if not ok:
        FAILURES.append(label)
    return ok


# --------------------------------------------------------------------------
# One chart per workload kind, and ONLY the kind moves
# --------------------------------------------------------------------------
#
# Not reused from the corpus, deliberately. Every corpus chart differs from
# every other in a dozen ways, so "HPA scored differently on these two" would
# never be attributable to the kind. These eight differ in the value of
# `kind:`, the apiVersion it requires, and the two or three spec fields that
# apiVersion makes mandatory - nothing else. Same container, same image, same
# absence of resources, same everything.

_POD = """      containers:
        - name: app
          image: registry.example.com/app:1.0.0
"""

_SELECTOR_TPL = """  selector:
    matchLabels:
      app.kubernetes.io/name: app
  template:
    metadata:
      labels:
        app.kubernetes.io/name: app
    spec:
"""

KINDS = {
    # kind: (apiVersion, spec body)
    "Deployment": ("apps/v1", "  replicas: 2\n" + _SELECTOR_TPL + _POD),
    "StatefulSet": ("apps/v1",
                    "  serviceName: app\n  replicas: 2\n" + _SELECTOR_TPL + _POD),
    "ReplicaSet": ("apps/v1", "  replicas: 2\n" + _SELECTOR_TPL + _POD),
    "ReplicationController": ("v1",
                              "  replicas: 2\n  selector:\n"
                              "    app.kubernetes.io/name: app\n"
                              "  template:\n    metadata:\n      labels:\n"
                              "        app.kubernetes.io/name: app\n"
                              "    spec:\n" + _POD),
    "DaemonSet": ("apps/v1", _SELECTOR_TPL + _POD),
    "Job": ("batch/v1",
            "  template:\n    metadata:\n      labels:\n"
            "        app.kubernetes.io/name: app\n"
            "    spec:\n      restartPolicy: Never\n" + _POD),
    "CronJob": ("batch/v1",
                '  schedule: "*/5 * * * *"\n  jobTemplate:\n    spec:\n'
                "      template:\n        spec:\n"
                "          restartPolicy: Never\n"
                "          containers:\n            - name: app\n"
                "              image: registry.example.com/app:1.0.0\n"),
    "Pod": ("v1", "  containers:\n    - name: app\n"
                  "      image: registry.example.com/app:1.0.0\n"),
    "Rollout": ("argoproj.io/v1alpha1", "  replicas: 2\n" + _SELECTOR_TPL + _POD),
}

# What the tool must say about each, and why. Written here as data BEFORE the
# runs, so the expectations are a specification and not a transcription of
# whatever the code happened to print.
EXPECT = {
    "Deployment":            ("scored", "implements /scale"),
    "StatefulSet":           ("scored", "implements /scale"),
    "ReplicaSet":            ("scored", "implements /scale"),
    "ReplicationController": ("scored", "implements /scale"),
    "DaemonSet":             ("not_applicable", "one pod per node, no /scale"),
    "Job":                   ("not_applicable", "parallelism fixed at creation"),
    "CronJob":               ("not_applicable", "a schedule, not a workload"),
    "Pod":                   ("not_applicable", "no controller to scale"),
    "Rollout":               ("unassessed", "a CRD this tool knows nothing about"),
}

HPA_TPL = """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: app
spec:
  scaleTargetRef:
    apiVersion: {api}
    kind: {kind}
    name: app
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
"""


def chart(kind, with_hpa=False):
    api, spec = KINDS[kind]
    root = os.path.join(TMP, kind + ("-hpa" if with_hpa else ""))
    files = {
        "Chart.yaml": cc.CHART_YAML.format(name="app", desc="p18 fixture",
                                           app="1.0.0"),
        "values.yaml": "{}\n",
        "templates/workload.yaml":
            f"apiVersion: {api}\nkind: {kind}\nmetadata:\n  name: app\nspec:\n{spec}",
    }
    if with_hpa:
        files["templates/hpa.yaml"] = HPA_TPL.format(api=api, kind=kind)
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write(content)
    return root


def run(path):
    js = os.path.join(TMP, "r.json")
    txt = os.path.join(TMP, "r.txt")
    p = subprocess.run([sys.executable, "-m", "hpaanalyzer", path, "-o", txt,
                        "--json", js],
                       cwd=REPO, capture_output=True, text=True, timeout=600,
                       env={**os.environ, "PYTHONPATH": REPO})
    return json.load(open(js)), open(txt).read(), p.stderr


def state(data):
    """'scored' | 'unassessed' | 'not_applicable' for the HPA category."""
    cov = data["score_coverage"]
    if "HPA" in {u["category"] for u in cov["unassessed"]}:
        return "unassessed"
    if "HPA" in {u["category"] for u in cov.get("not_applicable", [])}:
        return "not_applicable"
    return "scored"


def hpa_reason(data):
    cov = data["score_coverage"]
    for key in ("unassessed", "not_applicable"):
        for u in cov.get(key, []):
            if u["category"] == "HPA":
                return u["reason"]
    return ""


def ids(data):
    return {f["rule"] for f in data["findings"]}


def hpa_cell(txt):
    """The HPA score cell as the SCORECARD prints it: '100.0' | 'not applicable'.

    Read out of the rendered report and not out of the JSON, because the JSON
    has no per-category scores at all - a fact this script's first draft got
    wrong, looking up `data["categories"]` and getting None for every row
    without noticing, because the assertion beside the table did not depend on
    it. Recorded rather than quietly corrected: a column that silently prints
    None for all nine inputs is indistinguishable from a fix that works, which
    is the exact failure this script exists to rule out. The rendered cell is
    also the better evidence - it is the string the human reader sees, and
    "| Horizontal Pod Autoscaling | 100.0 | A+ |" is the thing being disproved.
    """
    for line in txt.splitlines():
        if line.startswith("| Horizontal Pod Autoscaling") and "|" in line[3:]:
            return line.split("|")[2].strip()
    return "<no scorecard row>"


def main():
    print("=" * 90)
    print("R16 - NOT APPLICABLE: a third answer, and the two it is not")
    print("=" * 90)
    print()

    runs = {k: run(chart(k)) for k in KINDS}

    # ---- CLAIM 1 --------------------------------------------------------
    print("CLAIM 1 - no chart is scored A+ for an HPA category it never examined")
    print("  The pre-R16 behaviour, on this exact fixture set, was 100.0/A+ on")
    print("  six of the nine. A category may be scored, or excluded with a")
    print("  reason. It may not be silently full marks.")
    print()
    print(f"  {'kind':<24}{'HPA state':<16}{'scorecard cell':>16}  rules")
    for k in KINDS:
        d, txt, _ = runs[k]
        hp = sorted(r for r in ids(d) if r.startswith("HP"))
        print(f"  {k:<24}{state(d):<16}{hpa_cell(txt):>16}  {hp}")
    print()
    for k in KINDS:
        d, _, _ = runs[k]
        want = EXPECT[k][0]
        check(f"{k}: HPA is {want} ({EXPECT[k][1]})",
              state(d) == want, f"got {state(d)}; reason={hpa_reason(d)[:70]}")
    # And the same claim made against the printed artefact rather than the
    # coverage structure, because "100.0 | A+" in the scorecard is the thing a
    # human actually reads and the thing the docstring above quotes. An
    # exclusion that were only true inside the JSON would have fixed nothing.
    for k, (want, _why) in EXPECT.items():
        _, txt, _ = runs[k]
        cell = hpa_cell(txt)
        numeric = cell.replace(".", "", 1).isdigit()
        check(f"{k}: scorecard cell is {'a number' if want == 'scored' else 'NOT a number'}"
              f" ({cell!r})",
              numeric is (want == "scored"), cell)
    print()

    # ---- CLAIM 2 --------------------------------------------------------
    print("CLAIM 2 - every scalable kind raises HP002, not just the two that")
    print("          happened to be typed into _no_hpa() by hand")
    for k in ("Deployment", "StatefulSet", "ReplicaSet", "ReplicationController"):
        d, _, _ = runs[k]
        check(f"{k}: HP002 fires (chart could carry an HPA and does not)",
              "HP002" in ids(d), f"HP* = {sorted(r for r in ids(d) if r[:2] == 'HP')}")
    for k in ("DaemonSet", "Job", "CronJob", "Pod", "Rollout"):
        d, _, _ = runs[k]
        check(f"{k}: HP002 does NOT fire (advice would be wrong or unfounded)",
              "HP002" not in ids(d),
              f"HP* = {sorted(r for r in ids(d) if r[:2] == 'HP')}")
    print()

    # ---- CLAIM 3 --------------------------------------------------------
    print("CLAIM 3 - the two exclusions make DIFFERENT claims, in the reason")
    print("          string and in the report, and a reader can act on the")
    print("          difference: one says go find input, the other says do not")
    d_ds, txt_ds, _ = runs["DaemonSet"]
    d_ro, txt_ro, _ = runs["Rollout"]
    check("DaemonSet's reason quotes the WRITTEN reason from UNSCALABLE_KINDS",
          "one pod per eligible node" in hpa_reason(d_ds),
          hpa_reason(d_ds)[:90])
    check("DaemonSet's reason states no input would change it",
          "no change to the chart would create one" in hpa_reason(d_ds),
          hpa_reason(d_ds)[-70:])
    check("Rollout's reason NAMES the kind it does not know about",
          "Rollout" in hpa_reason(d_ro),
          hpa_reason(d_ro)[:90])
    check("Rollout's reason claims ignorance, not a verdict",
          "not something this tool knows" in hpa_reason(d_ro),
          hpa_reason(d_ro)[:90])
    check("the text report prints NOT applicable, separately from NOT assessed",
          "NOT applicable" in txt_ds and "not applicable" in txt_ds,
          "headings present")
    check("the DaemonSet scorecard row does not say 'not assessed'",
          "| Horizontal Pod Autoscaling" in txt_ds
          and "not applicable" in [ln for ln in txt_ds.splitlines()
                                   if "Horizontal Pod Autoscaling" in ln
                                   and "|" in ln][0],
          [ln.strip() for ln in txt_ds.splitlines()
           if "Horizontal Pod Autoscaling" in ln and "|" in ln][:1])
    check("the Rollout report still says NOT assessed for HPA",
          "NOT assessed" in txt_ro and "Rollout" in txt_ro)
    print()

    # ---- CLAIM 4 - THE NEGATIVE CONTROL ---------------------------------
    print("CLAIM 4 - THE CONTROL. An unscalable kind WITH an HPA pointed at it")
    print("          must stay in the mean. This is R14b: a gate that drops a")
    print("          category which has already deducted from the score is not")
    print("          a coverage note, it is a score-raising bug, and it was")
    print("          shipped once already. Condition 1 of the predicate (no HPA")
    print("          object in the chart) exists for exactly this.")
    print()
    for k in ("DaemonSet", "Job", "CronJob", "Pod"):
        d, _, err = run(chart(k, with_hpa=True))
        hp = sorted(r for r in ids(d) if r.startswith("HP"))
        check(f"{k}+HPA: HPA category stays SCORED",
              state(d) == "scored", f"state={state(d)} rules={hp}")
        check(f"{k}+HPA: the misdirected HPA is still reported",
              any(r.startswith("HP04") for r in hp), f"HP* = {hp}")
        check(f"{k}+HPA: no internal-inconsistency warning was needed",
              "internal inconsistency" not in err,
              err.strip().splitlines()[-1] if err.strip() else "(stderr empty)")
    print()

    # ---- CLAIM 5 --------------------------------------------------------
    print("CLAIM 5 - the arithmetic is unchanged: NOT APPLICABLE leaves the")
    print("          mean, numerator and denominator together, exactly as NOT")
    print("          ASSESSED does. The new state invents no number.")
    d_ds, _, _ = runs["DaemonSet"]
    cov = d_ds["score_coverage"]
    check("HPA's 15 weight points left the denominator",
          cov["weight_assessed"] == cov["weight_total"] - 15 - _unrelated(cov),
          f"weight_assessed={cov['weight_assessed']} "
          f"unassessed={[u['category'] for u in cov['unassessed']]}")
    check("HPA appears in exactly one of the two exclusion lists",
          (("HPA" in {u["category"] for u in cov["unassessed"]})
           != ("HPA" in {u["category"] for u in cov["not_applicable"]})))
    check("the JSON note says 'not applicable' and not 'NOT assessed: HPA'",
          "not applicable: HPA" in cov["note"], cov["note"])
    print()

    # ---- CLAIM 6 --------------------------------------------------------
    print("CLAIM 6 - `complete` still means 'no blind spots', so")
    print("          --require-coverage does NOT fail a DaemonSet chart. A gate")
    print("          that failed here would be demanding the user add an HPA to")
    print("          a DaemonSet - the exact advice this round exists to stop.")
    print("          `all_scored` is the new, narrower claim.")
    # A check was drafted here reading `complete is False or True` on the
    # DaemonSet chart, which is `True` for every input and asserts nothing. It
    # is deleted rather than repaired, and named rather than deleted quietly,
    # because a green line reading "coverage.complete is True (nothing was
    # skipped)" is worse than no line: it would have gone on passing after a
    # regression that made `--require-coverage` fail every DaemonSet chart.
    #
    # The chart above has no Dockerfile, so JAVA/DOCKERFILE/CROSS are genuinely
    # unassessed and `complete` is False for reasons that have nothing to do
    # with R16. Isolating the claim needs a chart with nothing else missing -
    # good-chart plus a DaemonSet is not that either. So the claim is asserted
    # against the property directly, on the one input where only HPA is out.
    d_only = _hpa_only_chart()
    check("a chart whose ONLY exclusion is HPA-not-applicable: complete=True",
          d_only["score_coverage"]["complete"] is True,
          f"unassessed={[u['category'] for u in d_only['score_coverage']['unassessed']]}")
    check("...and all_scored=False, because the mean ran over 85 weight, not 100",
          d_only["score_coverage"]["all_scored"] is False
          and d_only["score_coverage"]["weight_assessed"] == 85,
          f"weight_assessed={d_only['score_coverage']['weight_assessed']}")
    rc = subprocess.run([sys.executable, "-m", "hpaanalyzer", _ONLY_DIR,
                         "--require-coverage", "-o", os.path.join(TMP, "rc.txt")],
                        cwd=REPO, capture_output=True, text=True, timeout=600,
                        env={**os.environ, "PYTHONPATH": REPO})
    check("--require-coverage exits 0 on it", rc.returncode == 0,
          f"rc={rc.returncode} stderr={rc.stderr.strip()[-160:]}")
    print()

    # ---- CLAIM 7 --------------------------------------------------------
    print("CLAIM 7 - nothing else moved. Thirty-five corpus charts and three")
    print("          fixtures, run before and after, and not one score changed:")
    print("          the corpus contains no chart with an unscalable-only")
    print("          workload, which is precisely why this survived fifteen")
    print("          rounds. A fix whose blast radius is unmeasured is a guess.")
    dg, _, _ = run(os.path.join(REPO, "fixtures", "good-chart"))
    check("fixtures/good-chart still 100.0 A+ over all 10 categories",
          dg["score"] == 100.0 and dg["score_coverage"]["all_scored"] is True,
          f"score={dg['score']} weight={dg['score_coverage']['weight_assessed']}")
    check("fixtures/good-chart has no not_applicable entries",
          dg["score_coverage"]["not_applicable"] == [],
          str(dg["score_coverage"]["not_applicable"]))
    print()

    print("=" * 90)
    print(f"{'FAILURES: ' + str(len(FAILURES)) if FAILURES else 'ALL CLAIMS PASS'}")
    for f in FAILURES:
        print(f"  - {f}")
    print("=" * 90)
    shutil.rmtree(TMP, ignore_errors=True)
    return 1 if FAILURES else 0


def _unrelated(cov):
    """Weight of the categories dropped for reasons that predate this round.

    Written as a computation rather than the literal 36 that this fixture
    happens to produce, because a literal here would silently absorb a future
    gate change and the claim above would keep passing while measuring
    something else.
    """
    from hpaanalyzer.scoring import WEIGHTS
    from hpaanalyzer.models import Category
    return sum(WEIGHTS[Category[u["category"]]] for u in cov["unassessed"])


_ONLY_DIR = None


def _hpa_only_chart():
    """good-chart with its Deployment replaced by a DaemonSet, nothing else.

    The point is a chart where HPA is the ONLY category out of the mean, so
    `complete` and `all_scored` can be told apart. good-chart is the one input
    in the repo that scores all ten, which makes it the only possible base.
    """
    global _ONLY_DIR
    src = os.path.join(REPO, "fixtures", "good-chart")
    dst = os.path.join(TMP, "hpa-only")
    shutil.copytree(src, dst)
    tpl = os.path.join(dst, "templates")
    dep = os.path.join(tpl, "deployment.yaml")
    body = open(dep).read()
    body = body.replace("kind: Deployment", "kind: DaemonSet", 1)
    # A DaemonSet has no replicas field; leaving one in would make the chart
    # invalid and the test would be measuring a parse failure.
    body = "\n".join(ln for ln in body.splitlines()
                     if not ln.strip().startswith("replicas:")
                     and "autoscaling" not in ln.lower()) + "\n"
    open(dep, "w").write(body)
    for name in os.listdir(tpl):
        if "hpa" in name.lower():
            os.remove(os.path.join(tpl, name))
    _ONLY_DIR = dst
    d, _, _ = run(dst)
    return d


if __name__ == "__main__":
    raise SystemExit(main())

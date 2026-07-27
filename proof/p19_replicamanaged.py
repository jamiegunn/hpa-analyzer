#!/usr/bin/env python3
"""R17. The same defect, priced eight different ways, because eight places
re-typed the same list of Kubernetes kinds by hand.

WHAT THIS ROUND IS ABOUT
------------------------
R8, R11, R13, R14b, R15 and R16 were each, underneath their own headline, one
instance of a single fault: a rule that decides whether to look at a workload
by comparing `doc.kind` against a tuple of strings written out at the call
site. Each copy was individually plausible when written. Copies do not stay in
step, and the tool has no way to notice when one falls behind - a kind that is
missing from a tuple produces silence, and silence in this tool is scored as
100.0.

R16 closed one of them and left the others annotated but deliberately
unmeasured, which is the honest state to leave something in but not a place to
stop. R17 measured all of them. Eight sites; seven condemned; one left alone
and the reason written down at the site.

The claims below are what the fix has to be true for. Every expectation is
written as data ABOVE the run that tests it, so what is being checked is a
specification and not a transcript of whatever the code printed today.

THE MEASUREMENT THAT OPENED IT
------------------------------
One chart per kind. Identical in every byte but the `kind:` line and the
fields the API requires: `replicas: 3` in the template, and an HPA whose
scaleTargetRef names that same object. Every one of them is the same mistake -
helm and an HPA both writing spec.replicas, which is HP050, a CRITICAL:

    kind                    before R17          after R17
    Deployment              85.5  C  HP050      85.5  C  HP050
    StatefulSet             85.5  C  HP050      85.5  C  HP050
    ReplicaSet              92.5  A- (silent)   85.5  C  HP050
    Rollout                 92.1  A- (silent)   85.5  C  HP050
    ReplicationController   NOT GRADED          85.5  C  HP050

Seven points and four grade bands between two spellings of one mistake. And
the A- is worse than it looks: HP050 is CRITICAL and R14 caps the OVERALL
grade at C whenever a non-ASSUMED critical is present, so what ReplicaSet and
Rollout escaped was not a deduction, it was the cap. The tool's loudest signal,
switched off by a missing word in a tuple.

ReplicationController's row is a different failure again. It was not scored
low or scored high - it was not scored. `ChartContext.workloads` filters
FIRST, and its literal has never contained "ReplicationController", so the
document was gone before any rule saw it; F9 then fired `ungradeable_reason`
("templates present, no workloads") and the report printed NOT GRADED. That
output is not dishonest - the tool did not claim a pass - but the reader cannot
tell "this chart has no workload" from "this chart has a workload of a kind I
do not recognise", and those call for opposite responses.

WHAT IS *NOT* CLAIMED
---------------------
That every kind should now be treated alike. R16 built `not_applicable`
precisely so the tool could say "this question does not apply here" instead of
scoring silence, and the fastest way to undo R16 would be to widen these lists
until a DaemonSet gets told to raise its replica count. CLAIM 2 exists to fail
if that happens. Bare `Pod` is still excluded from `ctx.workloads` and that is
a real remaining gap, recorded in models.py rather than fixed here, because a
Pod has no controller and half the rules downstream assume one.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE)

TMP = tempfile.mkdtemp(prefix="p19-")
FAIL = []
PASSED = 0


def check(label, ok, detail=""):
    global PASSED
    if ok:
        PASSED += 1
        print("  PASS  %s" % label)
    else:
        print("  FAIL  %s%s" % (label, ("  --  " + detail) if detail else ""))
        FAIL.append(label)


# --------------------------------------------------------------- chart builder

_POD = """      containers:
        - name: app
          image: registry.example.com/app:1.0.0
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {cpu: 200m, memory: 128Mi}
"""
_JVM_POD = """      containers:
        - name: app
          image: eclipse-temurin:21-jre
          env:
            - name: JAVA_TOOL_OPTIONS
              value: "-Xmx6g"
          resources:
            requests: {cpu: 500m, memory: 4Gi}
            limits: {cpu: "1", memory: 4Gi}
"""
_SEL = """  selector:
    matchLabels:
      app.kubernetes.io/name: app
  template:
    metadata:
      labels:
        app.kubernetes.io/name: app
    spec:
"""
# a ReplicationController's selector is a flat map, not a LabelSelector
_RC_SEL = _SEL.replace("  selector:\n    matchLabels:\n", "  selector:\n")

# (apiVersion, spec-prefix-before-the-pod-template)
KINDS = {
    "Deployment":            ("apps/v1", "  replicas: 3\n" + _SEL),
    "StatefulSet":           ("apps/v1", "  serviceName: app\n  replicas: 3\n" + _SEL),
    "ReplicaSet":            ("apps/v1", "  replicas: 3\n" + _SEL),
    "ReplicationController": ("v1", "  replicas: 3\n" + _RC_SEL),
    "Rollout":               ("argoproj.io/v1alpha1", "  replicas: 3\n" + _SEL),
    "DaemonSet":             ("apps/v1", _SEL),
    "Job":                   ("batch/v1", _SEL.replace("  selector:\n    matchLabels:\n"
                                                       "      app.kubernetes.io/name: app\n", "")),
    "CronJob":               (None, None),   # built by hand below, it nests twice
}

# ---------------------------------------------------------------------------
# EXPECTATIONS, as data, before any run.
# ---------------------------------------------------------------------------
#
# REPLICA_MANAGED is the tool's answer to one question: does this object carry
# a replica count that the CHART AUTHOR chose? It is not "can an HPA target
# it" (ReplicationController implements /scale but so does nothing else on the
# NOT list) and not "is this a workload" (a Job is a workload). It is the
# question every rule in the family was actually asking, and the reason a
# Rollout is IN while a DaemonSet is OUT: a Rollout's replica count is a number
# in someone's values.yaml, a DaemonSet's is a property of the cluster.
REPLICA_MANAGED = ["Deployment", "StatefulSet", "ReplicaSet",
                   "ReplicationController", "Rollout"]
NOT_REPLICA_MANAGED = ["DaemonSet", "Job", "CronJob"]

# CLAIM 1: given the identical defect, these five must produce the identical
# verdict. Not "similar" - identical, in score, grade, cap and rule set. Any
# difference between two rows here is a kind name leaking into arithmetic.
#
# CLAIM 2: these three must produce NO replica-managed finding at all. Not a
# softened one. If HP050, AV001, AV003 or AV010 appears on a DaemonSet, R17
# has re-created the advice R16 deleted, wearing different rule IDs.
REPLICA_RULES = {"HP050", "HP051", "AV001", "AV002", "AV003", "AV010"}

# CLAIM 3: AV010's detail must name the kinds the chart actually ships. Before
# R17 it was the fixed string "Deployments/StatefulSets", printed verbatim onto
# a chart that might contain neither.
#
# CLAIM 4: `proofs._pairs()` must be kind-blind. The JVM/limit arithmetic is
# the same arithmetic whoever created the pod.
#
# CLAIM 5: checks_hpa.py's F3 count is the one site R17 did NOT change, on the
# grounds that two constructed probes failed to reach it. That is a claim about
# the program and it is checkable: trace every target in this script and the
# whole fixture set, and count executions of that line. If it is ever reached,
# this check fails and the annotation at the site has to be revisited rather
# than trusted.
F3_SITE = ("checks_hpa.py", '"deployment", "statefulset"')

# CLAIM 6: HP025's BASIS must not depend on the kind of a workload that no HPA
# references. ASSUMED is not a label - Finding.effective_deduction() caps
# ASSUMED findings at HIGH - so a basis that flips on an unrelated kind is a
# score that flips on an unrelated kind.
BASIS_EXPECT = {
    "alone":                 "assumed",   # genuinely one workload: a real guess
    "plus-Deployment":       "derived",
    "plus-StatefulSet":      "derived",
    "plus-ReplicaSet":       "derived",   # was "assumed" before R17
    "plus-Rollout":          "derived",   # was "assumed" before R17
}

HPA_TPL = """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: app
spec:
  scaleTargetRef: {{apiVersion: {api}, kind: {kind}, name: app}}
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target: {{type: Utilization, averageUtilization: 70}}
"""


def _workload_yaml(kind, pod=_POD):
    if kind == "CronJob":
        return ('apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: app\n'
                'spec:\n  schedule: "*/5 * * * *"\n  jobTemplate:\n    spec:\n'
                '      template:\n        spec:\n'
                + "\n".join("    " + ln for ln in pod.splitlines()) + "\n")
    api, prefix = KINDS[kind]
    return f"apiVersion: {api}\nkind: {kind}\nmetadata:\n  name: app\nspec:\n{prefix}{pod}"


def chart(kind, name=None, with_hpa=True, pod=_POD, extra=None):
    root = os.path.join(TMP, name or kind.lower())
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(os.path.join(root, "templates"))
    open(os.path.join(root, "Chart.yaml"), "w").write(
        "apiVersion: v2\nname: app\nversion: 0.1.0\nappVersion: \"1.0.0\"\n")
    open(os.path.join(root, "values.yaml"), "w").write("{}\n")
    open(os.path.join(root, "templates", "wl.yaml"), "w").write(
        _workload_yaml(kind, pod))
    if with_hpa:
        api = "batch/v1" if kind == "CronJob" else KINDS[kind][0]
        open(os.path.join(root, "templates", "hpa.yaml"), "w").write(
            HPA_TPL.format(api=api, kind=kind))
    for rel, body in (extra or {}).items():
        open(os.path.join(root, "templates", rel), "w").write(body)
    return root


def run(path):
    js = os.path.join(TMP, "r.json")
    p = subprocess.run([sys.executable, "-m", "hpaanalyzer", path, "--json", js],
                       cwd=REPO, capture_output=True, text=True, timeout=600,
                       env={**os.environ, "PYTHONPATH": REPO})
    if not os.path.exists(js):
        raise SystemExit("analyzer produced no JSON for %s: rc=%d %s"
                         % (path, p.returncode, p.stderr[-400:]))
    return json.load(open(js))


def rules(d):
    return sorted({f["rule"] for f in d["findings"]})


def verdict(d):
    return (d["score"], d["grade"], d["graded"], bool(d.get("grade_cap_reason")),
            tuple(rules(d)))


# ============================================================ CLAIM 1
print("=" * 78)
print("CLAIM 1 - one defect, one verdict, whatever the kind is called")
print("=" * 78)
print("""
Five charts. Each ships one workload with `replicas: 3` and one HPA naming
that same object, which is HP050: helm and the autoscaler both writing
spec.replicas, and on the next `helm upgrade` the replica count snaps back to
3 whatever the HPA had decided. Nothing else differs.
""")

v1 = {}
for k in REPLICA_MANAGED:
    d = run(chart(k))
    v1[k] = verdict(d)
    print(f"  {k:24s} {str(d['score']):>6} {str(d['grade']):>4}  "
          f"cap={'yes' if d.get('grade_cap_reason') else 'no ':3s}  {' '.join(rules(d))}")

base = v1["Deployment"]
for k in REPLICA_MANAGED[1:]:
    check("%s is priced exactly as Deployment is" % k, v1[k] == base,
          "%r != %r" % (v1[k], base))
check("HP050 fires on all five", all("HP050" in v[4] for v in v1.values()))
check("the R14 grade cap engages on all five - the CRITICAL is not just "
      "deducted, it caps", all(v[3] for v in v1.values()))
check("all five are graded at all (ReplicationController was NOT GRADED)",
      all(v[2] for v in v1.values()))

# ============================================================ CLAIM 2
print("\n" + "=" * 78)
print("CLAIM 2 - and the kinds that must NOT move, still do not")
print("=" * 78)
print("""
The failure mode of a fix like this one is over-correction: widen the lists
until every kind is 'supported' and the tool starts telling a DaemonSet to
raise its replica count. R16 deleted exactly that advice. These three charts
are built the same way as the five above, HPA included, and must come back
with none of HP050/HP051/AV001/AV002/AV003/AV010 on them.
""")
for k in NOT_REPLICA_MANAGED:
    d = run(chart(k))
    got = REPLICA_RULES & set(rules(d))
    print(f"  {k:24s} {str(d['score']):>6} {str(d['grade']):>4}  "
          f"replica-managed findings: {sorted(got) or 'none'}")
    check("%s gets no replica-managed advice" % k, not got, str(sorted(got)))

# ============================================================ CLAIM 3
print("\n" + "=" * 78)
print("CLAIM 3 - AV010 names the kinds the chart actually ships")
print("=" * 78)
print("""
The old detail string was a constant: "Chart ships Deployments/StatefulSets
but no PDB." - printed onto a StatefulSet-only chart, a Rollout-only chart and
anything else that reached it. A reader checking the claim against their own
chart finds two kinds named and neither present.
""")
for k in REPLICA_MANAGED:
    d = run(chart(k))
    det = [f["detail"] for f in d["findings"] if f["rule"] == "AV010"]
    print(f"  {k:24s} {det}")
    check("AV010 on a %s-only chart names %s and nothing else" % (k, k),
          det == ["Chart ships %s but no PDB." % k], str(det))

# a two-kind chart must name both, in a stable order
_two = chart("Deployment", name="two-kinds", extra={
    "sts.yaml": _workload_yaml("StatefulSet").replace("name: app", "name: app2")})
_d = run(_two)
_det = [f["detail"] for f in _d["findings"] if f["rule"] == "AV010"]
check("a Deployment+StatefulSet chart names both, sorted",
      _det == ["Chart ships Deployment, StatefulSet but no PDB."], str(_det))

# ============================================================ CLAIM 4
print("\n" + "=" * 78)
print("CLAIM 4 - the JVM arithmetic does not care who created the pod")
print("=" * 78)
print("""
`proofs._pairs()` gates every cross-file JVM check - all five XF rules are
emitted from `_memory_budget`, which is reached only from there. R15 widened
its kind list from three to seven and R17 deleted it outright, because what
that literal contained was the contents of `ctx.workloads` as of R15,
hand-copied; adding ReplicationController to `ctx.workloads` in this same
round made it stale the same day. Below: identical charts, a temurin JRE told
to take -Xmx6g inside a 4Gi limit.
""")
xf = {}
for k in REPLICA_MANAGED + NOT_REPLICA_MANAGED:
    d = run(chart(k, name="jvm-" + k.lower(), with_hpa=False, pod=_JVM_POD))
    xf[k] = sorted(r for r in rules(d) if r.startswith("XF"))
    print(f"  {k:24s} {xf[k]}")
check("every workload kind gets the same cross-file JVM verdict",
      len(set(map(tuple, xf.values()))) == 1, str(xf))
check("and that verdict is not 'nothing' - the charts really are broken",
      all(v for v in xf.values()), str(xf))

# ============================================================ CLAIM 5
print("\n" + "=" * 78)
print("CLAIM 5 - the one site R17 did not touch is the one nothing reaches")
print("=" * 78)
print("""
checks_hpa.py still contains an inline ("deployment", "statefulset") in the F3
pairing count. R17 left it there deliberately: two constructed probes failed
to execute the line, and editing a predicate that no measurement reaches is a
guess with a diff attached - which is how this whole family started. That is a
falsifiable claim, so it is tested rather than asserted: every chart this
script builds, plus every fixture in the repo, is run under a line tracer and
executions of that line are counted. A non-zero count means the annotation is
wrong and the site needs a decision, not a comment.
""")

# Locating the site by grepping for the text is what the first version of this
# check did, and it found TWO lines: the code at 751 and line 73, which is
# `_no_hpa`'s docstring quoting the old code it replaced. It then traced line
# 73 - a docstring, executed never, by construction - and reported zero hits
# with a PASS. The claim underneath it was true, but the evidence for it was
# worthless, and a check that cannot fail is not a check. Only the structural
# assertion beside it caught the problem, which is the argument for keeping
# assertions that look redundant.
#
# So the site is found by parsing, not by grepping. `ast` sees expressions and
# not prose, and a tuple inside a docstring is a string to it.
def _f3_lines(path):
    import ast
    tree = ast.parse(open(path).read())
    want = ("deployment", "statefulset")
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple):
            vals = [e.value for e in node.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if tuple(vals) == want:
                out.append(node.lineno)
    return sorted(set(out))


_lines = _f3_lines(os.path.join(REPO, "hpaanalyzer", "checks_hpa.py"))
check("the F3 site is the only ('deployment','statefulset') tuple left in "
      "checks_hpa.py's actual code", len(_lines) == 1, str(_lines))
if not _lines:
    raise SystemExit("no F3 site found - if it was removed, delete CLAIM 5")

_targets = [chart(k, name="trace-" + k.lower()) for k in REPLICA_MANAGED]
_targets += [os.path.join(REPO, "fixtures", d)
             for d in sorted(os.listdir(os.path.join(REPO, "fixtures")))
             if os.path.isdir(os.path.join(REPO, "fixtures", d))]
_tracer = os.path.join(TMP, "tracer.py")
open(_tracer, "w").write('''
import json, os, sys
TARGET_FILE = sys.argv[1]
TARGET_LINE = int(sys.argv[2])
COUNT_TO = sys.argv[3]
hits = [0]
def trace(frame, event, arg):
    if event == "call":
        if os.path.basename(frame.f_code.co_filename) == TARGET_FILE:
            return local
        return None
    return None
def local(frame, event, arg):
    if event == "line" and frame.f_lineno == TARGET_LINE:
        hits[0] += 1
    return local
sys.argv = ["hpaanalyzer"] + sys.argv[4:]
sys.settrace(trace)
try:
    import runpy
    try:
        runpy.run_module("hpaanalyzer", run_name="__main__")
    except SystemExit:
        pass
finally:
    sys.settrace(None)
    open(COUNT_TO, "w").write(json.dumps(hits[0]))
''')
_hits = 0
_counts = os.path.join(TMP, "hits.json")
for t in _targets:
    subprocess.run([sys.executable, _tracer, "checks_hpa.py", str(_lines[0]),
                    _counts, t, "--json", os.path.join(TMP, "t.json")],
                   cwd=REPO, capture_output=True, text=True, timeout=600,
                   env={**os.environ, "PYTHONPATH": REPO})
    _hits += json.load(open(_counts))
print("  traced %d targets; checks_hpa.py:%d executed %d time(s)"
      % (len(_targets), _lines[0], _hits))
check("the F3 kind tuple is unreached across every target here - the comment "
      "at the site is a measurement, not an excuse", _hits == 0,
      "executed %d times; the site now needs a decision" % _hits)

# ============================================================ CLAIM 6
print("\n" + "=" * 78)
print("CLAIM 6 - a finding's BASIS does not turn on an unrelated workload's kind")
print("=" * 78)
print("""
HP025 fires when a memory-utilization HPA targets a JVM. When the tool cannot
see the JVM directly it falls back to "one workload, one Java Dockerfile, so
the pairing is obvious" - and marks that ASSUMED, honestly. `len(scalable) <=
1` is what "one workload" meant, and `scalable` was the inline pair, so a
SECOND workload only counted if it happened to be a Deployment or a
StatefulSet. Add a ReplicaSet instead and the tool went back to calling the
pairing obvious on a two-workload chart.

That is not cosmetic. Finding.effective_deduction() caps ASSUMED findings at
HIGH, so ASSUMED and DERIVED score differently: the kind of a workload nobody
referenced was moving the number.
""")

_DOCKERFILE = ("FROM eclipse-temurin:21-jre\n"
               "ENV JAVA_OPTS=\"-XX:MaxRAMPercentage=75\"\n"
               "ENTRYPOINT [\"java\",\"-jar\",\"/app.jar\"]\n")
# a NEUTRAL image: if the container itself looks like a JVM, _target_is_jvm
# returns OBSERVED and never reaches the branch under test. The first attempt
# at this measurement used a temurin image and proved nothing - recorded here
# because a probe that cannot fail is the thing this suite exists to catch.
_MEM_POD = """      containers:
        - name: app
          image: registry.example.com/app:1.0.0
          resources:
            requests: {cpu: 100m, memory: 1Gi}
            limits: {cpu: 200m, memory: 1Gi}
"""
_MEM_HPA = """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: app
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: app}
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: memory
        target: {type: Utilization, averageUtilization: 70}
"""


def basis_chart(second):
    root = os.path.join(TMP, "basis-" + (second or "alone").lower())
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(os.path.join(root, "templates"))
    open(os.path.join(root, "Chart.yaml"), "w").write(
        "apiVersion: v2\nname: app\nversion: 0.1.0\nappVersion: \"1.0.0\"\n")
    open(os.path.join(root, "values.yaml"), "w").write("{}\n")
    open(os.path.join(root, "Dockerfile"), "w").write(_DOCKERFILE)
    open(os.path.join(root, "templates", "wl.yaml"), "w").write(
        _workload_yaml("Deployment", _MEM_POD))
    open(os.path.join(root, "templates", "hpa.yaml"), "w").write(_MEM_HPA)
    if second:
        open(os.path.join(root, "templates", "second.yaml"), "w").write(
            _workload_yaml(second, _MEM_POD).replace("name: app\n", "name: app2\n", 1))
    return root


for label, want in BASIS_EXPECT.items():
    second = None if label == "alone" else label.split("-", 1)[1]
    d = run(basis_chart(second))
    got = [f["basis"] for f in d["findings"] if f["rule"] == "HP025"]
    print(f"  {label:22s} HP025 basis = {got}")
    check("HP025 on the '%s' chart is %s" % (label, want),
          got == [want], "expected [%r], got %r" % (want, got))

# ---------------------------------------------------------------------------
print("\n" + "-" * 78)
print("  %d of %d checks passed" % (PASSED, PASSED + len(FAIL)))
if FAIL:
    for f in FAIL:
        print("    FAILED: %s" % f)
    print("\nR17 IS NOT PROVEN.")
else:
    print("\nALL CLAIMS PASS.")
shutil.rmtree(TMP, ignore_errors=True)
raise SystemExit(1 if FAIL else 0)

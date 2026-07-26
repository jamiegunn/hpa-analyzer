"""Bar 2 (docs/SPEC.md S4) for iteration 2: the pod scheduling footprint.

tests/test_podresources.py is Bar 1 - the arithmetic agrees with
component-helpers/resource/helpers.go. That bar is necessary and not
sufficient. Upstream-exact totals that never reach the terminal have not
helped anyone. This suite asks the other question: on a chart whose defects
exist ONLY at pod scope, does the tool say so where the user is looking, and
does it stay quiet when the same chart is correct?

Everything here runs the real engine over a real directory on disk
(contract C5.3). Nothing is mocked, with one deliberate exception in
TestTheHeuristicNeverHidesAFinding, where the point IS to compare two engines.
"""

import os
import shutil
import tempfile
import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary

FIXTURES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "fixtures"))

CHART = """apiVersion: v2
name: fit
version: 1.0.0
appVersion: "1.0.0"
kubeVersion: ">=1.33.0-0"
"""

# The app container is deliberately beyond reproach: Guaranteed, probed,
# non-root, read-only, capabilities dropped. Every finding this chart produces
# must therefore come from the pod aggregate, which is the only thing under
# test. If the pod-scope rules cannot be seen HERE they cannot be seen at all.
DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: fit
  labels:
    app.kubernetes.io/name: fit
    app.kubernetes.io/instance: fit
    app.kubernetes.io/version: "1.0.0"
    app.kubernetes.io/managed-by: Helm
spec:
  replicas: 4
  template:
    metadata:
      labels:
        app.kubernetes.io/name: fit
    spec:
      initContainers:
{init}
      containers:
        - name: app
          image: eclipse-temurin:17.0.10_7-jre-jammy
          resources:
            requests: {{cpu: "500m", memory: "1Gi"}}
            limits: {{cpu: "500m", memory: "1Gi"}}
          readinessProbe:
            httpGet: {{path: /health/ready, port: 8080}}
            timeoutSeconds: 3
          livenessProbe:
            httpGet: {{path: /health/live, port: 8080}}
            initialDelaySeconds: 60
            periodSeconds: 20
            timeoutSeconds: 3
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
"""

# 6 GiB for a migration that exits in seconds, against a 1 GiB steady state.
BIG_INIT = """        - name: db-migrate
          image: busybox:1.36
          resources:
            requests: {cpu: "2", memory: "6Gi"}
            limits: {cpu: "2", memory: "6Gi"}
"""

# The same init container, sized like the thing it is.
SMALL_INIT = """        - name: db-migrate
          image: busybox:1.36
          resources:
            requests: {cpu: "100m", memory: "128Mi"}
            limits: {cpu: "100m", memory: "128Mi"}
"""

# A native sidecar with nothing declared. To the scheduler this is a regular
# container contributing zero, for the pod's entire life.
BLIND_SIDECAR = """        - name: metrics-agent
          image: otel/opentelemetry-collector:0.98.0
          restartPolicy: Always
"""

# A native sidecar with limits but no requests: the same zero contribution to
# the scheduler, but a visibly different mistake by the author.
HALF_SIDECAR = """        - name: metrics-agent
          image: otel/opentelemetry-collector:0.98.0
          restartPolicy: Always
          resources:
            limits: {cpu: "200m", memory: "256Mi"}
"""

# Not a container: `resources` as a scalar. A chart can render this, and the
# analyzer's job is to say so, not to die on it. R2 introduced a reader that
# assumed the block was a mapping; its own conformance test caught the crash
# before it shipped, and this is the end-to-end half of that guard.
MALFORMED_INIT = """        - name: db-migrate
          image: busybox:1.36
          resources: small
"""

SIZED_SIDECAR = """        - name: metrics-agent
          image: otel/opentelemetry-collector:0.98.0
          restartPolicy: Always
          resources:
            requests: {cpu: "50m", memory: "128Mi"}
            limits: {cpu: "50m", memory: "128Mi"}
"""


class _ChartCase(unittest.TestCase):
    def setUp(self):
        self.dirs = []

    def tearDown(self):
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def chart(self, init_block):
        d = tempfile.mkdtemp(prefix="fitness-pr-")
        self.dirs.append(d)
        os.makedirs(os.path.join(d, "templates"))
        for rel, body in (("Chart.yaml", CHART),
                          ("values.yaml", "replicaCount: 4\n"),
                          (os.path.join("templates", "deployment.yaml"),
                           DEPLOY.format(init=init_block))):
            with open(os.path.join(d, rel), "w") as f:
                f.write(body)
        return d

    def run_chart(self, init_block):
        result = analyze(self.chart(init_block), helm_mode="off")
        return result, stdout_summary(result, "/tmp/r.txt")

    def finding(self, result, rule_id):
        for f in result.findings:
            if f.rule_id == rule_id:
                return f
        self.fail(f"{rule_id} was not raised at all; got "
                  f"{sorted({x.rule_id for x in result.findings})}")


class TestInitPeakReachesTheUser(_ChartCase):
    """RS016. An init container that decides the pod's reservation is the
    textbook 'pod is Pending on a cluster with plenty of room' ticket, and no
    per-container view can produce it."""

    def test_it_reaches_the_terminal_fix_first_list(self):
        result, summary = self.run_chart(BIG_INIT + SIZED_SIDECAR)
        self.assertIn("RS016", [f.rule_id for f in result.findings])
        self.assertIn("RS016", summary,
                      "RS016 was detected but never printed - Bar 2 failure")

    def test_the_finding_is_actionable_without_further_research(self):
        result, _ = self.run_chart(BIG_INIT + SIZED_SIDECAR)
        f = self.finding(result, "RS016")
        self.assertIn("db-migrate", f.detail)     # names the container
        self.assertIn("6 GiB", f.math)            # shows the peak
        self.assertIn("1 GiB", f.math)            # and the steady state
        self.assertIn("max(", f.math)             # and the rule that combines them
        self.assertIn("4 x", f.math)              # scaled by replicas
        self.assertTrue(any(w in f.fix.lower() for w in ("job", "smallest")))

    def test_it_reports_both_numbers_not_just_the_larger(self):
        # The whole point is the GAP. A finding that printed only "6 GiB" would
        # be indistinguishable from a pod that genuinely needs 6 GiB.
        result, _ = self.run_chart(BIG_INIT + SIZED_SIDECAR)
        f = self.finding(result, "RS016")
        self.assertIn("steady", f.math)
        self.assertIn("init peak", f.math)

    def test_a_proportionate_init_container_stays_quiet(self):
        result, summary = self.run_chart(SMALL_INIT + SIZED_SIDECAR)
        self.assertNotIn("RS016", [f.rule_id for f in result.findings])
        self.assertNotIn("RS016", summary)

    def test_the_1_25x_threshold_is_a_threshold_not_a_rounding_error(self):
        # An init container that exceeds the steady state by a hair is
        # arithmetically the deciding term and is not a defect. Pin it, so
        # nobody "fixes" the rule later into firing on every chart with an
        # init container.
        just_over = """        - name: db-migrate
          image: busybox:1.36
          resources:
            requests: {cpu: "550m", memory: "1100Mi"}
            limits: {cpu: "550m", memory: "1100Mi"}
"""
        result, _ = self.run_chart(just_over + SIZED_SIDECAR)
        self.assertNotIn("RS016", [f.rule_id for f in result.findings])


class TestBlindSidecarReachesTheUser(_ChartCase):
    """RS017. A native sidecar is invisible to every per-container check in
    this tool, because kube.containers() walks spec.containers only."""

    def test_it_reaches_the_terminal_fix_first_list(self):
        result, summary = self.run_chart(SMALL_INIT + BLIND_SIDECAR)
        self.assertIn("RS017", [f.rule_id for f in result.findings])
        self.assertIn("RS017", summary)

    def test_severity_matches_the_defect_not_the_declaration_site(self):
        # RS001 - the same defect in spec.containers - is CRITICAL. The
        # scheduler draws no distinction, so neither may the severity.
        result, _ = self.run_chart(SMALL_INIT + BLIND_SIDECAR)
        self.assertEqual(self.finding(result, "RS017").severity.name, "CRITICAL")

    def test_limits_without_requests_is_a_step_less_bad(self):
        # Still zero to the scheduler, but bounded damage and visible intent.
        result, _ = self.run_chart(SMALL_INIT + HALF_SIDECAR)
        f = self.finding(result, "RS017")
        self.assertEqual(f.severity.name, "HIGH")
        self.assertIn("resources block is present", f.detail)

    def test_the_fix_says_where_to_put_the_requests(self):
        # The trap this rule exists for: the container is not in
        # spec.containers, so the obvious place to edit is the wrong one.
        result, _ = self.run_chart(SMALL_INIT + BLIND_SIDECAR)
        f = self.finding(result, "RS017")
        self.assertIn("initContainers", f.fix)
        self.assertIn("metrics-agent", f.detail)

    def test_a_sized_sidecar_stays_quiet(self):
        result, summary = self.run_chart(SMALL_INIT + SIZED_SIDECAR)
        self.assertNotIn("RS017", [f.rule_id for f in result.findings])
        self.assertNotIn("RS017", summary)

    def test_a_one_shot_init_container_is_not_accused_of_being_a_sidecar(self):
        # wait-for-db has no resources and no restartPolicy. It is a real
        # RS-class problem for the init peak, but it is NOT a sidecar, and
        # saying it "runs for the pod's whole life" would be false.
        oneshot = ("        - name: wait-for-db\n"
                   "          image: busybox:1.36\n")
        result, _ = self.run_chart(oneshot)
        self.assertNotIn("RS017", [f.rule_id for f in result.findings])


class TestTheClaimAboutNodeCapacity(_ChartCase):
    """C1.5: any total the tool prints must say which containers are in it,
    and any capacity claim must be about a pod."""

    def test_the_report_names_every_container_in_the_total(self):
        from hpaanalyzer.report import render
        r = analyze(os.path.join(FIXTURES, "sidecar-chart"), helm_mode="off")
        text = render(r, "sidecar-chart", level="deep")
        for name in ("payments", "istio-proxy", "log-shipper"):
            self.assertIn(name, text)
        self.assertIn("=> POD REQUEST", text)

    def test_no_footprint_row_label_is_split_across_lines(self):
        # A label the reader has to reassemble by eye is not a label. The
        # footprint table originally carried a separate "Role" column; at
        # WIDTH=100 that left 31 characters for the first column, and
        # "Deployment/payments  => POD REQUEST" is 35, so the renderer split
        # the pod total's own label into "=> POD" and "REQUEST" on two rows.
        # The fix was to merge Role into "How it counts" - the role IS how it
        # counts - and this test is what stops a sixth column from silently
        # reintroducing it. It checks EVERY label in the table, not just the
        # one that failed, because the next column added will break a
        # different one.
        from hpaanalyzer.report import render
        for fixture in ("sidecar-chart", "initheavy-chart"):
            r = analyze(os.path.join(FIXTURES, fixture), helm_mode="off")
            text = render(r, fixture, level="deep")
            labels = ["=> POD REQUEST", "steady state", "init peak"]
            for doc in r.context.workloads:
                wname = f"{doc.kind}/{doc.data['metadata']['name']}"
                labels.append(wname)
                for c in (doc.data["spec"]["template"]["spec"].get("containers", [])
                          + doc.data["spec"]["template"]["spec"].get("initContainers", [])):
                    labels.append(f"{wname}:{c['name']}")
            for label in labels:
                # The whole label must survive on one physical line of output.
                self.assertTrue(
                    any(label in line for line in text.splitlines()),
                    f"{fixture}: '{label}' is wrapped across lines in the "
                    f"report - the reader cannot find it by scanning")

    def test_the_node_fit_sentence_uses_the_pod_total(self):
        # Regression guard for the R2 defect itself: RS008 used to divide node
        # allocatable by a single container's request. On this fixture that
        # said 64 pods per 8 GiB node where upstream says 3.
        r = analyze(os.path.join(FIXTURES, "sidecar-chart"), helm_mode="off")
        f = self.finding(r, "RS008")
        self.assertIn("2.2 GiB", f.math)          # the pod total
        self.assertIn("= 3 ", f.math + " ")       # ... and the honest answer
        self.assertNotIn("64 such pods", f.math)

    def test_a_malformed_resources_block_does_not_kill_the_run(self):
        # An analyzer that crashes on a malformed chart reports nothing about
        # the rest of the chart either, which is the worst possible response
        # to the exact input it exists to catch. It should analyse what it can
        # and stay quiet about what it cannot resolve.
        result, summary = self.run_chart(MALFORMED_INIT)
        self.assertTrue(result.findings)
        self.assertIn("GRADE", summary)
        for f in result.findings:
            if "pods" in (f.math or ""):
                self.fail(f"{f.rule_id} claimed node capacity from a chart "
                          f"whose resources block is not a mapping: {f.math}")

    def test_undetermined_totals_produce_no_capacity_claim(self):
        # C2.2. A container whose quantity will not resolve must not silently
        # contribute zero and let the tool print a confident number.
        unresolved = """        - name: db-migrate
          image: busybox:1.36
          resources:
            requests: {cpu: "{{ .Values.migrate.cpu }}", memory: "6Gi"}
            limits: {cpu: "2", memory: "6Gi"}
"""
        result, _ = self.run_chart(unresolved)
        for f in result.findings:
            if "pods" in (f.math or ""):
                self.fail(f"{f.rule_id} claimed node capacity from an "
                          f"undetermined pod total: {f.math}")


class TestTheHeuristicNeverHidesAFinding(unittest.TestCase):
    """The R2 rationale fix consults kube.is_sidecar(), a name/image heuristic.
    That is only sound because it withholds a SENTENCE, never a FINDING. This
    test is the guard on that claim: with the heuristic forced off, the set of
    findings and severities must be byte-identical."""

    def test_rationale_selection_changes_no_finding(self):
        from hpaanalyzer import checks_workload
        real = checks_workload._pick
        try:
            checks_workload._pick = lambda infra, app, other: app
            before = analyze(os.path.join(FIXTURES, "sidecar-chart"),
                             helm_mode="off")
        finally:
            checks_workload._pick = real
        after = analyze(os.path.join(FIXTURES, "sidecar-chart"),
                        helm_mode="off")
        self.assertEqual(
            sorted((f.rule_id, f.severity.name) for f in before.findings),
            sorted((f.rule_id, f.severity.name) for f in after.findings))

    def test_infra_containers_get_no_jvm_advice(self):
        # proof/p2b_rationale.py measured 8 false premises here before the fix.
        import re
        result = analyze(os.path.join(FIXTURES, "sidecar-chart"),
                         helm_mode="off")
        bad = []
        for f in result.findings:
            if "'istio-proxy'" not in (f.detail or ""):
                continue
            for field in ("title", "why", "fix"):
                text = getattr(f, field, "") or ""
                for pat in (r"-Xmx", r"\bJVM\b", r"Spring", r"/actuator/",
                            r"USER in the Dockerfile"):
                    if re.search(pat, text, re.I):
                        bad.append(f"{f.rule_id}.{field}: {pat}")
        self.assertEqual(bad, [], "JVM rationale attached to an Envoy proxy")

    def test_the_app_container_keeps_its_jvm_advice(self):
        # The other direction. Withholding the JVM sentence from the JVM would
        # be the same defect, mirrored.
        result = analyze(os.path.join(FIXTURES, "sidecar-chart"),
                         helm_mode="off")
        app_text = " ".join(
            (f.why or "") + (f.fix or "") for f in result.findings
            if "'payments'" in (f.detail or ""))
        self.assertIn("JVM", app_text)


if __name__ == "__main__":
    unittest.main()

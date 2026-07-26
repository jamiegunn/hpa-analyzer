"""Bar 2 (docs/SPEC.md S4): does the QoS analysis actually do its job?

Bar 1 - "the arithmetic matches upstream" - is covered by tests/test_qos.py.
That bar is necessary and not sufficient. A tool can compute pod QoS perfectly
and still fail its user, by reporting the answer somewhere the user never
looks. SPEC S4 Bar 2 therefore requires that a real defect of this class
appears in the TERMINAL fix-first list, and that a clean chart stays quiet.

These tests run the real engine over real chart directories on disk. They do
not mock the analyzer (contract C5.3).
"""

import os
import shutil
import tempfile
import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary

FIXTURES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "fixtures"))

CHART_YAML = """apiVersion: v2
name: fit
version: 1.0.0
appVersion: "1.0.0"
"""

# A pod whose app container is Guaranteed and whose ONLY flaw is a
# resource-less init container. Everything else is deliberately correct, so
# nothing can crowd the QoS finding out of the fix-first list. If RS015 is not
# visible here it is not visible anywhere.
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
  replicas: 3
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
          env:
            - name: JAVA_TOOL_OPTIONS
              value: "-XX:MaxRAMPercentage=70.0"
          resources:
            requests: {{cpu: "1", memory: "2Gi"}}
            limits: {{cpu: "1", memory: "2Gi"}}
          readinessProbe:
            httpGet: {{path: /health/ready, port: 8080}}
          livenessProbe:
            httpGet: {{path: /health/live, port: 8080}}
            initialDelaySeconds: 60
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
"""

DIRTY_INIT = """        - name: wait-for-db
          image: busybox:1.36
          command: ["sh", "-c", "sleep 1"]
"""

CLEAN_INIT = """        - name: wait-for-db
          image: busybox:1.36
          command: ["sh", "-c", "sleep 1"]
          resources:
            requests: {cpu: "1", memory: "2Gi"}
            limits: {cpu: "1", memory: "2Gi"}
"""


def _chart(init_block):
    d = tempfile.mkdtemp(prefix="fitness-")
    with open(os.path.join(d, "Chart.yaml"), "w") as f:
        f.write(CHART_YAML)
    with open(os.path.join(d, "values.yaml"), "w") as f:
        f.write("replicaCount: 3\n")
    os.makedirs(os.path.join(d, "templates"))
    with open(os.path.join(d, "templates", "deployment.yaml"), "w") as f:
        f.write(DEPLOY.format(init=init_block))
    return d


class TestQoSReachesTheUser(unittest.TestCase):
    """A defect the tool can see but does not surface has not been found."""

    def setUp(self):
        self.dirs = []

    def tearDown(self):
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def _run(self, init_block):
        d = _chart(init_block)
        self.dirs.append(d)
        result = analyze(d, helm_mode="off")
        return result, stdout_summary(result, "/tmp/r.txt")

    def test_pod_level_qos_defect_reaches_the_fix_first_list(self):
        # Bar 2: not "is RS015 in result.findings" - is it in what the
        # terminal PRINTS. The fix-first list shows CRITICAL/HIGH only, so a
        # finding below HIGH is invisible however correct it is.
        result, summary = self._run(DIRTY_INIT)
        ids = [f.rule_id for f in result.findings]
        self.assertIn("RS015", ids, "the engine did not even detect it")
        self.assertIn("RS015", summary,
                      "RS015 was detected but never printed to the terminal - "
                      "SPEC S4 Bar 2 failure (see docs/ITERATIONS.md R1)")

    def test_the_fix_is_actionable_without_further_research(self):
        # Bar 2 requires "a fix an engineer can apply without further
        # research": it must name the offending container and say what to do.
        result, _ = self._run(DIRTY_INIT)
        f = next(x for x in result.findings if x.rule_id == "RS015")
        self.assertIn("wait-for-db", f.detail)
        self.assertIn("init", f.detail)
        for word in ("request", "limit"):
            self.assertIn(word, f.fix.lower())
        self.assertTrue(f.math, "a resource claim with no arithmetic shown")

    def test_a_clean_pod_stays_quiet(self):
        # The other half of Bar 2. A rule that fires on correct input is not a
        # safety net, it is noise that trains users to ignore the tool.
        result, summary = self._run(CLEAN_INIT)
        ids = [f.rule_id for f in result.findings]
        self.assertNotIn("RS015", ids)
        self.assertNotIn("RS011", ids)      # not BestEffort either
        self.assertNotIn("RS015", summary)

    def test_severity_is_justified_by_the_guard_not_by_the_bar(self):
        # RS015 was raised to HIGH so it would reach the terminal. That is only
        # legitimate because the rule cannot fire on a pod that did not ask for
        # Guaranteed. Pin the guard: with no Guaranteed container anywhere, a
        # Burstable pod is just Burstable and RS015 must stay silent.
        init = ("        - name: wait-for-db\n"
                "          image: busybox:1.36\n"
                "          resources:\n"
                "            requests: {cpu: \"10m\", memory: \"32Mi\"}\n"
                "            limits: {cpu: \"20m\", memory: \"64Mi\"}\n")
        burstable_app = DEPLOY.format(init=init).replace(
            'limits: {cpu: "1", memory: "2Gi"}',
            'limits: {cpu: "2", memory: "4Gi"}')
        d = tempfile.mkdtemp(prefix="fitness-")
        self.dirs.append(d)
        os.makedirs(os.path.join(d, "templates"))
        for rel, body in (("Chart.yaml", CHART_YAML),
                          ("values.yaml", "replicaCount: 3\n"),
                          (os.path.join("templates", "deployment.yaml"),
                           burstable_app)):
            with open(os.path.join(d, rel), "w") as f:
                f.write(body)
        result = analyze(d, helm_mode="off")
        self.assertNotIn("RS015", [f.rule_id for f in result.findings])


class TestQoSProofTableIsPodLevel(unittest.TestCase):
    """C5.1: the proof table must show the pod verdict, not just containers -
    the pod row is the only value kubelet uses."""

    def test_table_has_a_pod_verdict_row_and_a_verification_command(self):
        from hpaanalyzer.report import render
        r = analyze(os.path.join(FIXTURES, "sidecar-chart"), helm_mode="off")
        text = render(r, "sidecar-chart", level="deep")
        self.assertIn("=> POD", text)
        self.assertIn("status.qosClass", text)
        # roles must be distinguishable, or a reader cannot tell why an init
        # container is dragging the pod down
        for role in ("init", "sidecar", "container"):
            self.assertIn(role, text)


if __name__ == "__main__":
    unittest.main()

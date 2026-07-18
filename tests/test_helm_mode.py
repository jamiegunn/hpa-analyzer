"""helm-mode behavior, tested with a mocked helm binary.

The sandbox running these tests may not have helm; these tests substitute
canned `helm template` output at the discovery layer, which exercises the
real parsing, doc-mapping, conditional-detection and HP050/HP051 logic.
"""

import unittest
from unittest import mock

from hpaanalyzer import discovery
from hpaanalyzer.engine import analyze
from hpaanalyzer.models import Severity

from .util import chart_with_replicas

RENDERED_WITH_REPLICAS_AND_HPA = """---
# Source: t/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: release-name-app
spec:
  replicas: 2
  selector:
    matchLabels: {app: t}
  template:
    metadata:
      labels: {app: t}
    spec:
      containers:
        - name: app
          image: "repo/app:1.0"
          resources:
            requests: {cpu: 500m, memory: 1Gi}
            limits: {memory: 1Gi}
---
# Source: t/templates/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: release-name-app
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: release-name-app}
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource: {name: cpu, target: {type: Utilization, averageUtilization: 70}}
"""

RENDERED_NO_HPA = RENDERED_WITH_REPLICAS_AND_HPA.split("---\n# Source: t/templates/hpa.yaml")[0]


def run_with_mock_render(chart_dir, output, helm_mode="auto"):
    with mock.patch.object(discovery, "find_helm", return_value="/usr/bin/helm"), \
         mock.patch.object(discovery, "render_chart",
                           return_value=(output, None)):
        return analyze(chart_dir, helm_mode=helm_mode)


class TestHelmMode(unittest.TestCase):
    def test_render_mode_recorded(self):
        root = chart_with_replicas("replicas: 2")
        r = run_with_mock_render(root, RENDERED_WITH_REPLICAS_AND_HPA)
        self.assertEqual(r.context.render_mode, "helm")

    def test_rendered_truth_hp050(self):
        root = chart_with_replicas("replicas: 2")
        r = run_with_mock_render(root, RENDERED_WITH_REPLICAS_AND_HPA)
        hits = [f for f in r.findings if f.rule_id == "HP050"]
        self.assertEqual(len(hits), 1)
        self.assertIn("rendered output", hits[0].detail)
        self.assertIs(hits[0].severity, Severity.CRITICAL)

    def test_conditional_hpa_detected_when_not_rendered(self):
        # HPA template exists but helm output has no HPA (flag off):
        # ungated replicas => HP051 (pre-armed conflict), not HP050
        root = chart_with_replicas(
            "replicas: 2",
            values="replicaCount: 2\nautoscaling:\n  enabled: false\n")
        r = run_with_mock_render(root, RENDERED_NO_HPA)
        conditional = [d for d in r.context.docs if not d.rendered]
        self.assertTrue(any(d.kind == "HorizontalPodAutoscaler"
                            for d in conditional))
        self.assertEqual([f.rule_id for f in r.findings
                          if f.rule_id in ("HP050", "HP051")], ["HP051"])

    def test_conditional_hpa_with_proper_gate_is_quiet(self):
        root = chart_with_replicas(
            "{{- if not .Values.autoscaling.enabled }}\n"
            "  replicas: 2\n  {{- end }}",
            values="replicaCount: 2\nautoscaling:\n  enabled: false\n")
        r = run_with_mock_render(root, RENDERED_WITH_REPLICAS_AND_HPA
                                 .split("---\n# Source: t/templates/hpa.yaml")[0])
        self.assertEqual([f.rule_id for f in r.findings
                          if f.rule_id in ("HP050", "HP051", "HP052")], [])

    def test_helm_failure_falls_back_to_static(self):
        root = chart_with_replicas("replicas: 2")
        with mock.patch.object(discovery, "find_helm",
                               return_value="/usr/bin/helm"), \
             mock.patch.object(discovery, "render_chart",
                               return_value=(None, "boom")):
            r = analyze(root, helm_mode="auto")
        self.assertTrue(r.context.render_mode.startswith("static"))
        self.assertIn("boom", r.context.render_mode)
        # static path must still find the conflict
        self.assertIn("HP050", {f.rule_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()

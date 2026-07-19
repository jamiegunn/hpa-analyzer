"""Cluster-verification probes: emitted only when relevant, with correct
commands and real names/selectors filled in from the chart."""

import unittest

from hpaanalyzer.clusterprobes import build_probes
from hpaanalyzer.engine import analyze

from .util import CHART_YAML, make_tree

DEP = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {{name: web}}\n"
       "spec:\n  selector: {{matchLabels: {{app: web}}}}\n"
       "  template:\n    metadata: {{labels: {{app: web}}}}\n"
       "    spec:\n      containers:\n        - name: app\n"
       "          image: eclipse-temurin:17-jre\n{res}")

RES_FULL = ("          resources:\n            requests: {cpu: 500m, memory: 1Gi}\n"
            "            limits: {memory: 1Gi}\n")
RES_NONE = ""

HPA = ("apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
       "metadata: {name: web}\nspec:\n"
       "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: web}\n"
       "  minReplicas: 2\n  maxReplicas: 8\n  metrics:\n    - type: Resource\n"
       "      resource: {name: cpu, target: {type: Utilization, "
       "averageUtilization: 70}}\n")


def _dep(res):
    return DEP.format(res=res)


def keys(root, **kw):
    r = analyze(root, helm_mode="off", **kw)
    return {p.key for p in build_probes(r)}, r


class TestRelevanceGating(unittest.TestCase):
    def test_no_hpa_no_metrics_probe(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": _dep(RES_FULL)})
        ks, _ = keys(root)
        self.assertNotIn("metrics-pipeline", ks)

    def test_hpa_triggers_metrics_probe(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": _dep(RES_FULL),
                          "templates/h.yaml": HPA})
        ks, _ = keys(root)
        self.assertIn("metrics-pipeline", ks)

    def test_full_resources_no_limitrange_probe(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": _dep(RES_FULL)})
        ks, _ = keys(root)
        self.assertNotIn("limitrange", ks)

    def test_missing_requests_triggers_limitrange_probe(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": _dep(RES_NONE)})
        ks, _ = keys(root)
        self.assertIn("limitrange", ks)

    def test_deprecated_api_triggers_version_probe(self):
        dep = _dep(RES_FULL).replace("apps/v1", "apps/v1beta1", 1)
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": dep})
        ks, r = keys(root)
        self.assertIn("TP010", {f.rule_id for f in r.findings})
        self.assertIn("api-removal", ks)

    def test_jvm_triggers_sees_limit_probe(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "Dockerfile": "FROM eclipse-temurin:17-jre\n"
                                        'ENTRYPOINT ["java","-jar","/a.jar"]\n',
                          "templates/d.yaml": _dep(RES_FULL)})
        ks, _ = keys(root)
        self.assertIn("jvm-sees-limit", ks)

    def test_no_workload_no_probes(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n"})
        ks, _ = keys(root)
        self.assertEqual(ks, set())


class TestCommandContent(unittest.TestCase):
    def test_real_selector_filled_in(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": _dep(RES_NONE)})
        _, r = keys(root)
        probe = next(p for p in build_probes(r) if p.key == "limitrange")
        joined = " ".join(probe.commands)
        self.assertIn("-l app=web", joined)
        self.assertIn("status.qosClass", joined)

    def test_multi_container_qos_probe_and_command(self):
        multi = (_dep(RES_FULL).rstrip("\n") + "\n"
                 "        - name: sidecar\n          image: nginx:1.25\n"
                 "          resources: {requests: {memory: 64Mi}, "
                 "limits: {memory: 128Mi}}\n")
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": multi})
        _, r = keys(root)
        probe = next((p for p in build_probes(r) if p.key == "pod-qos"), None)
        self.assertIsNotNone(probe)
        self.assertIn("status.qosClass", " ".join(probe.commands))

    def test_templated_names_trigger_resolve_probe(self):
        # good-chart uses {{ include "orders.fullname" . }} -> placeholder names
        import os
        good = os.path.join(os.path.dirname(__file__), "..", "fixtures",
                            "good-chart")
        r = analyze(good, helm_mode="off")
        ks = {p.key for p in build_probes(r)}
        self.assertIn("resolve-names", ks)

    def test_probes_carry_trigger_provenance(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": _dep(RES_NONE),
                          "templates/h.yaml": HPA})
        _, r = keys(root)
        for p in build_probes(r):
            self.assertTrue(p.triggered_by, f"{p.key} has no provenance")
            self.assertTrue(p.commands and all(c.strip() for c in p.commands))


if __name__ == "__main__":
    unittest.main()

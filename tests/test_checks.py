import os
import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer.models import Severity
from hpaanalyzer.scoring import overall_score

from .util import chart_with_replicas, make_tree, CHART_YAML

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def rules(result):
    return {f.rule_id for f in result.findings}


def find(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


class TestFixtureCharts(unittest.TestCase):
    def test_bad_chart_finds_the_planted_problems(self):
        r = analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")
        got = rules(r)
        for expected in ("HP050",   # replicas vs HPA, ungated
                         "HP025",   # memory metric on a JVM
                         "RS002",   # 512m millibytes
                         "TP010",   # removed apiVersions
                         "JV011",   # 8u151 experimental-only cgroup
                         "DF013",   # dead JAVA_OPTS
                         "DF021",   # secret in ENV
                         "PB003",   # identical probes
                         "PA001"):  # duplicate values key
            self.assertIn(expected, got, f"missing {expected}")
        score = overall_score(r)
        self.assertIsNotNone(score)
        self.assertLess(score, 60)

    def test_bad_chart_overlay_regressions_detected(self):
        r = analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")
        overlay = [f for f in r.findings
                   if f.detail.startswith("[with values overlay")]
        self.assertTrue(any(f.rule_id == "HP004" for f in overlay),
                        "prod-only min>max not caught")
        self.assertTrue(any(f.rule_id == "RS006" for f in overlay),
                        "prod-only cpu limit<request not caught")

    def test_good_chart_is_clean_and_scored(self):
        r = analyze(os.path.join(FIXTURES, "good-chart"), helm_mode="off")
        non_info = [f for f in r.findings if f.severity is not Severity.INFO]
        self.assertEqual(non_info, [],
                         f"good chart has findings: "
                         f"{[(f.rule_id, f.detail) for f in non_info]}")
        self.assertGreaterEqual(overall_score(r), 95)

    def test_rs002_points_at_values_file_line(self):
        r = analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")
        f = find(r, "RS002")[0]
        self.assertEqual(f.file, "values.yaml")
        self.assertIsNotNone(f.line)


class TestReplicasGating(unittest.TestCase):
    def _run(self, replicas_block):
        return analyze(chart_with_replicas(replicas_block), helm_mode="off")

    def test_ungated_replicas_is_critical(self):
        r = self._run("replicas: {{ .Values.replicaCount }}")
        hits = find(r, "HP050")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)

    def test_standard_gate_passes(self):
        r = self._run("{{- if not .Values.autoscaling.enabled }}\n"
                      "  replicas: {{ .Values.replicaCount }}\n"
                      "  {{- end }}")
        self.assertEqual(find(r, "HP050"), [])
        self.assertEqual(find(r, "HP052"), [])

    def test_alternate_gate_idiom_passes(self):
        # different flag path, still a negated autoscaling condition
        r = self._run("{{- if not .Values.hpa.enabled }}\n"
                      "  replicas: 2\n  {{- end }}")
        self.assertEqual(find(r, "HP050"), [])

    def test_eq_false_idiom_passes(self):
        r = self._run("{{- if eq .Values.autoscaling.enabled false }}\n"
                      "  replicas: 2\n  {{- end }}")
        self.assertEqual(find(r, "HP050"), [])

    def test_inverted_gate_is_critical(self):
        r = self._run("{{- if .Values.autoscaling.enabled }}\n"
                      "  replicas: 2\n  {{- end }}")
        hits = find(r, "HP050")
        self.assertEqual(len(hits), 1)
        self.assertIn("inverted", hits[0].title)

    def test_unrelated_gate_downgrades_to_verify(self):
        r = self._run("{{- if .Values.someOtherFlag }}\n"
                      "  replicas: 2\n  {{- end }}")
        self.assertEqual(find(r, "HP050"), [])
        self.assertEqual(len(find(r, "HP052")), 1)
        self.assertIs(find(r, "HP052")[0].severity, Severity.MEDIUM)


class TestInsufficientInput(unittest.TestCase):
    def test_empty_dir_not_graded(self):
        root = make_tree({"README.txt": "nothing here"})
        r = analyze(root, helm_mode="off")
        self.assertIsNone(overall_score(r))

    def test_dockerfile_only_is_graded_on_docker_categories(self):
        root = make_tree({"Dockerfile": "FROM openjdk:8u151-jre\n"
                                        'ENTRYPOINT ["java","-jar","a.jar"]\n'})
        r = analyze(root, helm_mode="off")
        score = overall_score(r)
        self.assertIsNotNone(score)
        self.assertLess(score, 80)   # java 8u151 alone must hurt


class TestSidecarExclusion(unittest.TestCase):
    def test_istio_sidecar_gets_no_jvm_tables(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "Dockerfile": "FROM openjdk:17\nENTRYPOINT [\"java\",\"-jar\",\"a.jar\"]\n",
            "templates/deployment.yaml": (
                "apiVersion: apps/v1\nkind: Deployment\n"
                "metadata: {name: t}\n"
                "spec:\n  selector: {matchLabels: {app: t}}\n"
                "  template:\n    metadata: {labels: {app: t}}\n"
                "    spec:\n      containers:\n"
                "        - name: app\n          image: repo/app:1\n"
                "          resources: {requests: {cpu: 500m, memory: 1Gi}, "
                "limits: {memory: 1Gi}}\n"
                "        - name: istio-proxy\n          image: istio/proxyv2:1.20\n"
                "          resources: {requests: {cpu: 100m, memory: 128Mi}, "
                "limits: {memory: 128Mi}}\n"),
        })
        r = analyze(root, helm_mode="off")
        titles = [p.title for p in r.proofs if "memory budget" in p.title]
        self.assertTrue(any("'app'" in t for t in titles))
        self.assertFalse(any("istio-proxy" in t for t in titles),
                         "sidecar was given a JVM memory budget")


class TestAssumeJava(unittest.TestCase):
    def test_assume_java_enables_version_checks(self):
        root = make_tree({
            "Dockerfile": "FROM registry.corp.example/base/java:v9\n"
                          'ENTRYPOINT ["java","-jar","a.jar"]\n'})
        r_unknown = analyze(root, helm_mode="off")
        self.assertIn("DF003", rules(r_unknown))
        self.assertNotIn("JV011", rules(r_unknown))
        r_assumed = analyze(root, helm_mode="off", assume_java="8u151")
        self.assertIn("JV011", rules(r_assumed))
        self.assertIn("JV013", rules(r_assumed))


if __name__ == "__main__":
    unittest.main()

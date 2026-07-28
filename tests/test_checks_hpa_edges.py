"""HPA rule edges: malformed specs, target-resolution corner cases, and the
metric shapes (v1 API, averageValue, external) the main suite never builds.

The recurring theme is three-valued resolution: an HPA's target can be found,
provably absent, or unresolvable - and each answer licenses a different rule
(nothing, HP041, or a fallback pairing). These tests pin which answer each
chart shape produces.
"""

import unittest

from hpaanalyzer import checks_hpa
from hpaanalyzer.discovery import discover
from hpaanalyzer.engine import analyze
from hpaanalyzer.models import AnalysisResult, Basis, Severity

from .util import CHART_YAML, make_tree


def rules(result):
    return {f.rule_id for f in result.findings}


def find(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


DEP = """apiVersion: apps/v1
kind: Deployment
metadata: {name: myapp}
spec:
  selector: {matchLabels: {app: t}}
  template:
    metadata: {labels: {app: t}}
    spec:
      containers:
        - name: app
          image: "repo/app:1.0"
          resources:
            requests: {cpu: 500m, memory: 1Gi}
            limits: {memory: 1Gi}
"""

GOOD_TAIL = ("  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
             "  metrics:\n    - type: Resource\n"
             "      resource: {name: cpu, target: {type: Utilization, "
             "averageUtilization: 70}}\n")


def chart(hpa_body, dep=DEP, extra=None):
    files = {
        "Chart.yaml": CHART_YAML,
        "values.yaml": "x: 1\n",
        "templates/deployment.yaml": dep,
    }
    if hpa_body is not None:
        files["templates/hpa.yaml"] = (
            "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
            "metadata: {name: myhpa}\n" + hpa_body)
    files.update(extra or {})
    return make_tree(files)


class TestMalformedSpec(unittest.TestCase):
    def test_non_mapping_spec_produces_no_hpa_findings(self):
        # a spec that is a list cannot be inspected; inventing HP003/HP021
        # against it would be findings about fields that cannot exist
        r = analyze(chart("spec: [1, 2]\n"), helm_mode="off")
        self.assertFalse({rid for rid in rules(r) if rid.startswith("HP")})

    def test_missing_scaletargetref_and_missing_max(self):
        r = analyze(chart("spec:\n  minReplicas: 1\n"), helm_mode="off")
        self.assertIn("HP040", rules(r))     # nothing to scale
        self.assertIn("HP003", rules(r))     # required field absent
        self.assertIn("HP006", rules(r))     # minReplicas=1 still judged
        self.assertIn("HP021", rules(r))     # no metrics either
        # min>max / min==max need both bounds; neither may be guessed
        self.assertFalse({"HP004", "HP005"} & rules(r))


class TestNoHpaAtAll(unittest.TestCase):
    def _run(self, values):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": values,
                          "templates/deployment.yaml": DEP})
        return analyze(root, helm_mode="off")

    def test_autoscaling_enabled_with_no_template_is_high(self):
        # values promise scaling the chart cannot deliver - worse when the
        # flag is on, because the chart then silently never scales
        r = self._run("autoscaling:\n  enabled: true\n")
        hits = find(r, "HP001")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)
        self.assertNotIn("HP002", rules(r))

    def test_autoscaling_disabled_with_no_template_is_medium(self):
        r = self._run("autoscaling:\n  enabled: false\n")
        hits = find(r, "HP001")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.MEDIUM)


class TestReplicaBoundsEdges(unittest.TestCase):
    def test_min_equals_max_cannot_scale(self):
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
            "name: myapp}\n  minReplicas: 3\n  maxReplicas: 3\n" + GOOD_TAIL),
            helm_mode="off")
        hits = find(r, "HP005")
        self.assertEqual(len(hits), 1)
        self.assertIn("minReplicas = maxReplicas = 3", hits[0].detail)
        self.assertNotIn("HP004", rules(r))


class TestMetricsEdges(unittest.TestCase):
    def test_v1_hpa_with_no_cpu_target_relies_on_cluster_default(self):
        r = analyze(chart(None, extra={"templates/hpa.yaml": (
            "apiVersion: autoscaling/v1\nkind: HorizontalPodAutoscaler\n"
            "metadata: {name: myhpa}\nspec:\n"
            "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: myapp}\n"
            "  minReplicas: 2\n  maxReplicas: 4\n")}), helm_mode="off")
        self.assertEqual(len(find(r, "HP020")), 1)
        self.assertNotIn("HP021", rules(r))

    def test_v1_target_percentage_feeds_the_quality_check(self):
        # targetCPUUtilizationPercentage is the v1 spelling; 95% must reach
        # the same headroom rule the v2 metric form does
        r = analyze(chart(None, extra={"templates/hpa.yaml": (
            "apiVersion: autoscaling/v1\nkind: HorizontalPodAutoscaler\n"
            "metadata: {name: myhpa}\nspec:\n"
            "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: myapp}\n"
            "  minReplicas: 2\n  maxReplicas: 4\n"
            "  targetCPUUtilizationPercentage: 95\n")}), helm_mode="off")
        self.assertEqual(len(find(r, "HP023")), 1)
        self.assertNotIn("HP020", rules(r))

    def test_very_conservative_target_is_low(self):
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
            "name: myapp}\n  minReplicas: 2\n  maxReplicas: 4\n"
            "  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
            "  metrics:\n    - type: Resource\n"
            "      resource: {name: cpu, target: {type: Utilization, "
            "averageUtilization: 30}}\n"), helm_mode="off")
        hits = find(r, "HP024")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.LOW)

    def test_external_metric_and_cpu_averagevalue_get_no_static_verdict(self):
        # an External metric is not statically checkable, and a cpu metric by
        # AverageValue has no utilization percentage to judge - neither may
        # produce a target-quality finding. scaleDown window 0 still must.
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
            "name: myapp}\n  minReplicas: 2\n  maxReplicas: 4\n"
            "  behavior: {scaleDown: {stabilizationWindowSeconds: 0}}\n"
            "  metrics:\n"
            "    - type: External\n"
            "      external: {metric: {name: rps}, target: {type: Value, value: '100'}}\n"
            "    - type: Resource\n"
            "      resource: {name: cpu, target: {type: AverageValue, "
            "averageValue: 500m}}\n"), helm_mode="off")
        self.assertFalse({"HP023", "HP024", "HP026"} & rules(r))
        self.assertEqual(len(find(r, "HP031")), 1)
        self.assertNotIn("HP030", rules(r))


class TestTargetResolution(unittest.TestCase):
    def test_ref_without_kind_is_dangling_but_not_called_unscalable(self):
        # kind absent: HP042 (unscalable-kind) must stay silent - there is no
        # kind to judge - while the name mismatch still surfaces as HP041
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {name: elsewhere}\n"
            "  minReplicas: 2\n  maxReplicas: 4\n" + GOOD_TAIL),
            helm_mode="off")
        self.assertIn("HP041", rules(r))
        self.assertNotIn("HP042", rules(r))

    def test_ref_without_name_falls_back_to_the_single_workload(self):
        # an empty name is not a resolvable literal, so with exactly one
        # workload of the right kind the obvious pairing is taken: no HP041
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment}\n"
            "  minReplicas: 2\n  maxReplicas: 4\n" + GOOD_TAIL),
            helm_mode="off")
        self.assertNotIn("HP041", rules(r))
        self.assertNotIn("HP022", rules(r))

    def test_templated_name_of_the_wrong_kind_is_dangling(self):
        # the name is a template marker (unresolvable), but the kind does not
        # match the only workload, so the single-workload fallback must not
        # paper over it
        r = analyze(chart(
            'spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: StatefulSet, '
            'name: {{ include "t.fullname" . }}}\n'
            "  minReplicas: 2\n  maxReplicas: 4\n" + GOOD_TAIL),
            helm_mode="off")
        self.assertEqual(len(find(r, "HP041")), 1)

    def test_two_hpas_on_one_workload_fight_each_other(self):
        second = ("apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
                  "metadata: {name: otherhpa}\nspec:\n"
                  "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
                  "name: myapp}\n  minReplicas: 2\n  maxReplicas: 6\n"
                  + GOOD_TAIL)
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
            "name: myapp}\n  minReplicas: 2\n  maxReplicas: 4\n" + GOOD_TAIL,
            extra={"templates/hpa2.yaml": second}), helm_mode="off")
        hits = find(r, "HP010")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)
        self.assertIn("myhpa", hits[0].detail)
        self.assertIn("otherhpa", hits[0].detail)


MEM_METRIC = ("  metrics:\n    - type: Resource\n"
              "      resource: {name: memory, target: {type: %s}}\n")


class TestMemoryMetricBasis(unittest.TestCase):
    def test_observed_non_jvm_target_is_medium(self):
        # the target resolves to an nginx container: positive evidence this
        # is NOT a JVM, so the finding is the lenient one and OBSERVED
        nginx = DEP.replace('"repo/app:1.0"', '"nginx:1.25"')\
                   .replace("name: app", "name: web")
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
            "name: myapp}\n  minReplicas: 2\n  maxReplicas: 4\n"
            "  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
            + MEM_METRIC % "AverageValue, averageValue: 512Mi", dep=nginx),
            helm_mode="off")
        hits = find(r, "HP025")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.MEDIUM)
        self.assertIs(hits[0].basis, Basis.OBSERVED)
        # AverageValue has no utilization percentage: no ratchet arithmetic
        self.assertIsNone(hits[0].math)

    def test_observed_jvm_target_is_critical(self):
        # the target's own container sets JAVA_TOOL_OPTIONS - evidence the
        # JVM reads unaided - so the memory ratchet is asserted as OBSERVED
        # fact at full severity, not as the single-workload guess (ASSUMED)
        jvm = DEP.replace(
            '          image: "repo/app:1.0"\n',
            '          image: "repo/app:1.0"\n'
            "          env:\n            - name: JAVA_TOOL_OPTIONS\n"
            '              value: "-XX:MaxRAMPercentage=75"\n')
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
            "name: myapp}\n  minReplicas: 2\n  maxReplicas: 4\n"
            "  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
            + MEM_METRIC % "Utilization, averageUtilization: 70", dep=jvm),
            helm_mode="off")
        hits = find(r, "HP025")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)
        self.assertIs(hits[0].basis, Basis.OBSERVED)
        self.assertIsNone(hits[0].assumes)
        self.assertIn("JVM workload", hits[0].title)

    def test_unresolvable_target_is_undetermined_not_false(self):
        # the ref names a workload that is not in the chart: the tool read
        # nothing about the target, so the finding must be DERIVED with the
        # gap named in 'assumes' - not OBSERVED-false (the pre-R8 collapse)
        r = analyze(chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
            "name: elsewhere}\n  minReplicas: 2\n  maxReplicas: 4\n"
            "  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
            + MEM_METRIC % "Utilization, averageUtilization: 70"),
            helm_mode="off")
        hits = find(r, "HP025")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.MEDIUM)
        self.assertIs(hits[0].basis, Basis.DERIVED)
        self.assertIn("could not be resolved", hits[0].assumes)
        self.assertIn("HP041", rules(r))


DEP_REPLICAS = DEP.replace("spec:\n  selector:",
                           "spec:\n  replicas: 2\n  selector:")


class TestReplicasConflictEdges(unittest.TestCase):
    def test_refless_hpa_still_pairs_with_the_only_workload(self):
        # the HPA has no scaleTargetRef at all (HP040), but it is the only
        # HPA and there is one Deployment: the replicas conflict is still the
        # obvious reading and HP050 must fire alongside HP040
        r = analyze(chart("spec:\n  minReplicas: 2\n  maxReplicas: 4\n",
                          dep=DEP_REPLICAS), helm_mode="off")
        self.assertIn("HP040", rules(r))
        hits = find(r, "HP050")
        self.assertEqual(len(hits), 1)
        self.assertIn("no guard at all", hits[0].detail)

    def test_unrendered_workload_is_exempt_from_the_conflict(self):
        # rendered=False marks a template that does NOT render with the
        # analyzed values (helm-mode fact); its replicas field exists only in
        # a branch that is off, so HP050 may not claim a live conflict
        root = chart(
            "spec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, "
            "name: myapp}\n  minReplicas: 2\n  maxReplicas: 8\n" + GOOD_TAIL,
            dep=DEP_REPLICAS)
        ctx = discover(root, helm_mode="off")
        res = AnalysisResult(context=ctx)
        checks_hpa.run(ctx, res)
        self.assertEqual(len([f for f in res.findings
                              if f.rule_id == "HP050"]), 1)
        for w in ctx.workloads:
            w.rendered = False
        res2 = AnalysisResult(context=ctx)
        checks_hpa.run(ctx, res2)
        self.assertEqual([f.rule_id for f in res2.findings
                          if f.rule_id.startswith("HP05")], [])


if __name__ == "__main__":
    unittest.main()

"""Chart-structure rule edges: broken Chart.yaml fields, values-file shapes,
version-scope ranking (TP010/TP013), and the two render-divergence rules.

CH015/CH016 exist to keep the tool from presenting one render arm as the
whole truth. CH016's static half is reachable here; CH015's evidence dict is
only produced by a helm double-render, so those tests feed the recorded probe
outcome to the rule directly and assert what it may and may not claim.
"""

import unittest

from hpaanalyzer import checks_chart
from hpaanalyzer.checks_chart import _gv_exists_at
from hpaanalyzer.discovery import discover
from hpaanalyzer.engine import analyze
from hpaanalyzer.models import (AnalysisResult, ChartContext, ManifestDoc,
                                Severity)

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


def chart(files):
    base = {"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
            "templates/deployment.yaml": DEP}
    base.update(files)
    return make_tree(base)


class TestChartYamlRequiredFields(unittest.TestCase):
    def test_missing_apiversion_name_and_version_each_fire(self):
        r = analyze(chart({"Chart.yaml": "description: incomplete\n"}),
                    helm_mode="off")
        for rid in ("CH003", "CH004", "CH005"):
            hits = find(r, rid)
            self.assertEqual(len(hits), 1, rid)
            self.assertIs(hits[0].severity, Severity.HIGH, rid)
        # apiVersion is absent, not 'v1': the Helm-2 finding must not fire
        self.assertNotIn("CH002", rules(r))


class TestValuesFileShapes(unittest.TestCase):
    def test_list_valued_values_file_is_va001_not_a_crash(self):
        r = analyze(chart({"values.yaml": "- a\n- b\n"}), helm_mode="off")
        hits = find(r, "VA001")
        self.assertEqual(len(hits), 1)
        self.assertIn("list", hits[0].detail)

    def test_pull_always_with_pinned_tag_is_wasteful(self):
        r = analyze(chart({"values.yaml":
                           'image:\n  tag: "1.2.3"\n  pullPolicy: Always\n'}),
                    helm_mode="off")
        hits = find(r, "VA003")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.LOW)
        # the tag itself is pinned: VA002 must stay silent
        self.assertNotIn("VA002", rules(r))

    def test_single_replica_without_autoscaling(self):
        r = analyze(chart({"values.yaml": "replicaCount: 1\n"}),
                    helm_mode="off")
        self.assertEqual(len(find(r, "VA005")), 1)

    def test_template_syntax_inside_values_is_never_rendered(self):
        r = analyze(chart({"values.yaml":
                           'note: "{{ .Release.Name }}"\n'}), helm_mode="off")
        hits = find(r, "VA006")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)


class TestTemplateTextEdges(unittest.TestCase):
    def test_tab_character_in_template(self):
        svc = ("apiVersion: v1\nkind: Service\nmetadata: {name: s}\n"
               "# comment with a\ttab\n"
               "spec:\n  selector: {app: t}\n  ports: [{port: 80}]\n")
        r = analyze(chart({"templates/svc.yaml": svc}), helm_mode="off")
        hits = find(r, "TP001")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].file, "templates/svc.yaml")

    def test_hardcoded_latest_image_in_template(self):
        dep = DEP.replace('"repo/app:1.0"', "repo/app:latest")
        r = analyze(chart({"templates/deployment.yaml": dep}), helm_mode="off")
        self.assertEqual(len(find(r, "TP004")), 1)


class TestVersionScopeEdges(unittest.TestCase):
    PDB_BETA = ("apiVersion: policy/v1beta1\nkind: PodDisruptionBudget\n"
                "metadata: {name: t}\nspec: {maxUnavailable: 1}\n")

    def test_removed_api_with_no_declared_range_is_worst_case_critical(self):
        no_kv = CHART_YAML.replace('kubeVersion: ">=1.23.0-0"\n', "")
        r = analyze(chart({"Chart.yaml": no_kv,
                           "templates/pdb.yaml": self.PDB_BETA}),
                    helm_mode="off")
        self.assertIn("CH010", rules(r))
        hits = find(r, "TP010")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)
        self.assertIn("declares no kubeVersion", hits[0].detail)

    def test_removed_api_with_unparseable_range_names_the_parse_failure(self):
        bad_kv = CHART_YAML.replace('">=1.23.0-0"', '"not a range"')
        r = analyze(chart({"Chart.yaml": bad_kv,
                           "templates/pdb.yaml": self.PDB_BETA}),
                    helm_mode="off")
        self.assertIn("CH013", rules(r))
        hits = find(r, "TP010")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)
        self.assertIn("does not parse", hits[0].detail)

    def test_removed_api_with_reversed_range_names_the_empty_match(self):
        # '>=1.30 <1.20' parses but matches nothing: distinct from the
        # unparseable case, and TP010 must quote the right failure
        rev_kv = CHART_YAML.replace('">=1.23.0-0"', '">=1.30.0-0 <1.20.0-0"')
        r = analyze(chart({"Chart.yaml": rev_kv,
                           "templates/pdb.yaml": self.PDB_BETA}),
                    helm_mode="off")
        self.assertIn("CH013", rules(r))
        hits = find(r, "TP010")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)
        self.assertIn("matches no cluster version", hits[0].detail)

    def test_psp_fix_carries_the_no_replacement_note(self):
        # PodSecurityPolicy has no successor apiVersion; the fix must carry
        # the recorded note instead of a fabricated replacement-since claim
        old_kv = CHART_YAML.replace('">=1.23.0-0"', '">=1.20.0-0 <1.23.0-0"')
        psp = ("apiVersion: policy/v1beta1\nkind: PodSecurityPolicy\n"
               "metadata: {name: t}\nspec: {privileged: false}\n")
        r = analyze(chart({"Chart.yaml": old_kv, "templates/psp.yaml": psp}),
                    helm_mode="off")
        hits = find(r, "TP010")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.LOW)   # range ends below 1.25
        self.assertIn("removed outright", hits[0].fix)
        self.assertNotIn("exists from Kubernetes", hits[0].fix)

    def test_garbage_kube_version_flag_falls_back_to_the_chart_range(self):
        # an unparseable --kube-version must be ignored (not crash, not
        # become a fake cluster): the chart's own >=1.23 range straddles the
        # 1.25 removal, so TP010 ranks HIGH against the declaration
        r = analyze(chart({"templates/pdb.yaml": self.PDB_BETA}),
                    helm_mode="off", kube_version="banana")
        hits = find(r, "TP010")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)
        self.assertIn("chart's kubeversion (>=1.23.0-0)",
                      hits[0].detail.lower())


class TestKindlessDocsAreSkipped(unittest.TestCase):
    def test_a_doc_without_kind_contributes_nothing(self):
        # a parseable template that is not a k8s object: no apiVersion rules,
        # no label rules, and the CH010 fix derivation must skip it silently
        no_kv = CHART_YAML.replace('kubeVersion: ">=1.23.0-0"\n', "")
        r = analyze(chart({"Chart.yaml": no_kv,
                           "templates/data.yaml": "foo: bar\nbaz: 1\n"}),
                    helm_mode="off")
        self.assertIn("CH010", rules(r))
        for f in r.findings:
            self.assertNotEqual(f.file, "templates/data.yaml",
                                f"{f.rule_id} fired on a kindless doc")


class TestLabels(unittest.TestCase):
    def test_labels_missing_every_recommended_key(self):
        dep = DEP.replace("metadata: {name: myapp}",
                          "metadata:\n  name: myapp\n  labels: {app: t}")
        r = analyze(chart({"templates/deployment.yaml": dep}), helm_mode="off")
        hits = find(r, "TP011")
        self.assertEqual(len(hits), 1)
        self.assertNotIn("TP012", rules(r))

    def test_helper_supplied_labels_key_suppresses_tp011(self):
        # a scrubbed include marker among the label KEYS is evidence the
        # labels come from _helpers.tpl - a file this run never expanded, so
        # 'missing labels' would be a claim about unread content
        ctx = ChartContext(root=".")
        ctx.docs = [ManifestDoc(
            file="templates/d.yaml", kind="Deployment", api_version="apps/v1",
            data={"metadata": {"name": "t",
                               "labels": {"HELMINC@t.labels": None}}})]
        res = AnalysisResult(context=ctx)
        checks_chart._labels(ctx, res)
        self.assertEqual([f.rule_id for f in res.findings], [])


class TestApiVersionGateStatic(unittest.TestCase):
    def test_capability_gate_is_reported_without_a_render(self):
        gated_hpa = (
            '{{- if .Capabilities.APIVersions.Has "autoscaling/v2" }}\n'
            "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
            "metadata: {name: myapp}\nspec:\n"
            "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: myapp}\n"
            "  minReplicas: 2\n  maxReplicas: 8\n"
            "  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
            "  metrics:\n    - type: Resource\n"
            "      resource: {name: cpu, target: {type: Utilization, "
            "averageUtilization: 70}}\n"
            "{{- end }}\n")
        r = analyze(chart({"templates/hpa.yaml": gated_hpa}), helm_mode="off")
        hits = find(r, "CH016")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.INFO)
        self.assertEqual(hits[0].file, "templates/hpa.yaml")
        self.assertIn("autoscaling/v2", hits[0].detail)
        # static mode evaluates no branch, and must say that - not claim a
        # single-render arm was analyzed
        self.assertIn("static scrubbing", hits[0].detail)
        self.assertNotIn("exactly one arm", hits[0].detail)


class TestGvExistsAt(unittest.TestCase):
    """The fact table behind CH016's 'impossible at this version' clause."""

    def test_core_group_kind_with_no_recorded_fact_returns_none(self):
        # v1/Pod appears in neither table: the answer is 'no recorded fact',
        # never a guessed yes/no that CH016 would print as impossibility
        self.assertIsNone(_gv_exists_at("v1/Pod", (1, 25)))

    def test_known_group_is_dated_correctly_on_both_sides(self):
        self.assertFalse(_gv_exists_at("autoscaling/v2", (1, 22)))
        self.assertTrue(_gv_exists_at("autoscaling/v2", (1, 23)))

    def test_removed_gvk_form_is_false_after_removal(self):
        self.assertFalse(
            _gv_exists_at("policy/v1beta1/PodDisruptionBudget", (1, 26)))


class TestRenderDivergence(unittest.TestCase):
    """CH015 judges the recorded double-render outcome; the dict below is the
    exact evidence discovery stores after probing the declared range."""

    def _ctx(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/deployment.yaml": DEP})
        return discover(root, helm_mode="off")

    def _run(self, divergence, kube_version=None):
        ctx = self._ctx()
        if kube_version:
            ctx.render_kube_version = kube_version
        ctx.render_divergence = divergence
        res = AnalysisResult(context=ctx)
        checks_chart.run(ctx, res)
        return res

    def test_failed_probe_is_an_info_gap_not_a_pass(self):
        # the comparison render failed: 'could not check' must surface as
        # INFO naming the error - silence here would read as consistency
        res = self._run({"checked": False, "probe": "1.23.0",
                         "error": "helm exploded"}, kube_version="1.31.0")
        hits = [f for f in res.findings if f.rule_id == "CH015"]
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.INFO)
        self.assertIn("helm exploded", hits[0].detail)
        self.assertIn("1.23.0", hits[0].detail)

    def test_object_only_at_the_probe_end_is_medium(self):
        res = self._run({"checked": True, "diverges": True, "at": "1.31.0",
                         "probe": "1.23.0", "n_at": 1, "n_probe": 2,
                         "only_at": [],
                         "only_at_probe": ["PodDisruptionBudget/x"]})
        hits = [f for f in res.findings if f.rule_id == "CH015"]
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.MEDIUM)
        self.assertIn("only at 1.23.0: PodDisruptionBudget/x", hits[0].detail)
        self.assertNotIn("only at 1.31.0", hits[0].detail)

    def test_object_only_at_the_analyzed_end_is_medium(self):
        res = self._run({"checked": True, "diverges": True, "at": "1.31.0",
                         "probe": "1.23.0", "n_at": 2, "n_probe": 1,
                         "only_at": ["HorizontalPodAutoscaler/x"],
                         "only_at_probe": []})
        hits = [f for f in res.findings if f.rule_id == "CH015"]
        self.assertEqual(len(hits), 1)
        self.assertIn("only at 1.31.0: HorizontalPodAutoscaler/x",
                      hits[0].detail)
        self.assertNotIn("only at 1.23.0", hits[0].detail)

    def test_consistent_double_render_stays_silent(self):
        res = self._run({"checked": True, "diverges": False, "at": "1.31.0",
                         "probe": "1.23.0"})
        self.assertEqual([f for f in res.findings if f.rule_id == "CH015"], [])


if __name__ == "__main__":
    unittest.main()

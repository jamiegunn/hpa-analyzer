"""Workload rule edges: quantity typos in odd places, malformed spec shapes,
pod-total arithmetic caveats, and the near-miss negatives of threshold rules.

Several tests assert SILENCE: a rule whose input could not be parsed (cpu:
banana) or whose threshold is not met (a 1.1x init container) must say
nothing, because the positive case is already pinned elsewhere and the
negative is what a threshold means.
"""

import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer.models import Severity

from .util import CHART_YAML, make_tree


def rules(result):
    return {f.rule_id for f in result.findings}


def find(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def dep(podspec, head="spec:"):
    return ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: myapp}\n"
            + head + "\n  selector: {matchLabels: {app: t}}\n"
            "  template:\n    metadata: {labels: {app: t}}\n"
            "    spec:\n" + podspec)


def container(res_block):
    return ("      containers:\n        - name: app\n"
            "          image: repo/app:1.0\n" + res_block)


def chart(template, values="x: 1\n", extra=None):
    files = {"Chart.yaml": CHART_YAML, "values.yaml": values,
             "templates/d.yaml": template}
    files.update(extra or {})
    return make_tree(files)


class TestMemoryQuantityTypos(unittest.TestCase):
    def test_millibytes_literal_in_the_template_points_at_the_template(self):
        r = analyze(chart(dep(container(
            "          resources:\n"
            "            requests: {cpu: 500m, memory: 512m}\n"
            "            limits: {memory: 1Gi}\n"))), helm_mode="off")
        hits = find(r, "RS002")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)
        self.assertEqual(hits[0].file, "templates/d.yaml")
        self.assertIsNotNone(hits[0].line)

    def test_millibytes_via_a_renamed_values_key_still_fires_without_a_line(self):
        # the literal reaches the pod through .Values.mem, so the text
        # 'memory: 512m' exists in NEITHER file; the finding must still fire
        # and honestly carry no line number rather than a wrong one
        r = analyze(chart(dep(container(
            "          resources:\n"
            "            requests: {cpu: 500m, memory: {{ .Values.mem }}}\n"
            "            limits: {memory: 1Gi}\n")),
            values="mem: 512m\n"), helm_mode="off")
        hits = find(r, "RS002")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].file, "templates/d.yaml")
        self.assertIsNone(hits[0].line)

    def test_decimal_units_are_a_low_not_a_critical(self):
        r = analyze(chart(dep(container(
            "          resources:\n"
            "            requests: {cpu: 500m, memory: 512M}\n"
            "            limits: {memory: 512M}\n"))), helm_mode="off")
        hits = find(r, "RS003")
        self.assertEqual(len(hits), 2)      # request and limit
        self.assertIs(hits[0].severity, Severity.LOW)
        self.assertFalse({"RS002", "RS013"} & rules(r))


class TestMalformedResourceShapes(unittest.TestCase):
    def test_unparseable_cpu_request_is_not_reported_as_missing(self):
        # 'cpu: banana' is present but unreadable; RS004 says 'missing' and
        # may not claim that about a value the author wrote
        r = analyze(chart(dep(container(
            "          resources:\n"
            "            requests: {cpu: banana, memory: 1Gi}\n"
            "            limits: {memory: 1Gi}\n"))), helm_mode="off")
        self.assertNotIn("RS004", rules(r))
        self.assertNotIn("RS001", rules(r))

    def test_scalar_resources_block_reads_as_no_requests(self):
        # 'resources: small' is neither a mapping nor a template marker:
        # every quantity lookup must come back empty, so both requests are
        # reported missing - without a crash and without RS001, which is
        # reserved for a genuinely absent/unresolved block
        r = analyze(chart(dep(container(
            "          resources: small\n"))), helm_mode="off")
        hits = find(r, "RS004")
        self.assertEqual(len(hits), 1)
        self.assertIn("cpu, memory", hits[0].detail)
        self.assertNotIn("RS001", rules(r))

    def test_scalar_requests_section_reads_as_no_requests(self):
        # 'requests: tiny' has no cpu/memory fields at all: both are missing
        r = analyze(chart(dep(container(
            "          resources:\n"
            "            requests: tiny\n"
            "            limits: {memory: 1Gi}\n"))), helm_mode="off")
        hits = find(r, "RS004")
        self.assertEqual(len(hits), 1)
        self.assertIn("cpu, memory", hits[0].detail)

    def test_unresolved_resources_block_names_the_template_expression(self):
        # resources templated from a values path nothing defines: RS001 fires
        # with the unresolved-expression wording, not 'no block at all'
        r = analyze(chart(dep(container(
            "          resources: {{ toYaml .Values.notset }}\n"))),
            helm_mode="off")
        hits = find(r, "RS001")
        self.assertEqual(len(hits), 1)
        self.assertIn("unresolved template expression", hits[0].detail)

    def test_memory_limit_below_request_is_invalid(self):
        r = analyze(chart(dep(container(
            "          resources:\n"
            "            requests: {cpu: 500m, memory: 2Gi}\n"
            "            limits: {memory: 1Gi}\n"))), helm_mode="off")
        hits = find(r, "RS007")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)


TWO_CONTAINERS = ("      containers:\n        - name: app\n"
                  "          image: repo/app:1.0\n"
                  "          resources:\n"
                  "            requests: {cpu: 500m, memory: 500Mi}\n"
                  "            limits: {cpu: 1, memory: 2Gi}\n"
                  "        - name: web\n          image: myco/web:1.0\n"
                  "%s")


class TestOvercommitMathCaveats(unittest.TestCase):
    """RS008's worked example totals the POD; when it cannot, it must say so
    instead of printing a fabricated pods-per-node number."""

    def test_unresolvable_second_container_blocks_the_capacity_claim(self):
        r = analyze(chart(dep(TWO_CONTAINERS % (
            "          resources:\n"
            "            requests: {cpu: 100m, memory: {{ .Values.no.mem }}}\n"
            "            limits: {cpu: 200m, memory: 128Mi}\n"))),
            helm_mode="off")
        hits = find(r, "RS008")
        self.assertEqual(len(hits), 1)
        self.assertIn("could not be totalled here", hits[0].math)
        self.assertNotIn("packs", hits[0].math)

    def test_missing_limit_on_a_neighbour_makes_worst_case_unbounded(self):
        r = analyze(chart(dep(TWO_CONTAINERS % (
            "          resources:\n"
            "            requests: {cpu: 100m, memory: 128Mi}\n"))),
            helm_mode="off")
        hits = find(r, "RS008")
        self.assertEqual(len(hits), 1)
        self.assertIn("packs", hits[0].math)      # pod request WAS totalled
        self.assertIn("cannot be bounded", hits[0].math)


def init_chart(init_mem, app_mem):
    return chart(dep(
        "      initContainers:\n        - name: mig\n"
        "          image: repo/mig:1\n"
        "          resources:\n"
        f"            requests: {{cpu: 100m, memory: {init_mem}}}\n"
        f"            limits: {{memory: {init_mem}}}\n"
        "      containers:\n        - name: app\n"
        "          image: repo/app:1.0\n"
        "          resources:\n"
        f"            requests: {{cpu: 500m, memory: {app_mem}}}\n"
        f"            limits: {{memory: {app_mem}}}\n"))


class TestInitReservationThreshold(unittest.TestCase):
    def test_init_at_double_the_steady_state_fires_high(self):
        r = analyze(init_chart("2Gi", "1Gi"), helm_mode="off")
        hits = find(r, "RS016")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)

    def test_init_a_hair_above_steady_state_is_not_worth_a_page(self):
        # peak > steady but ratio 1.1 < 1.25: arithmetically the deciding
        # term, deliberately below the reporting threshold
        r = analyze(init_chart("1100Mi", "1000Mi"), helm_mode="off")
        self.assertNotIn("RS016", rules(r))


class TestAvailabilityEdges(unittest.TestCase):
    def test_single_replica_without_hpa(self):
        tpl = dep(container(
            "          resources:\n"
            "            requests: {cpu: 500m, memory: 1Gi}\n"
            "            limits: {memory: 1Gi}\n"), head="spec:\n  replicas: 1")
        r = analyze(chart(tpl), helm_mode="off")
        hits = find(r, "AV001")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.MEDIUM)

    def test_scalar_workload_spec_gets_no_availability_findings(self):
        # 'spec: nope' on a Deployment: nothing to read, nothing to claim -
        # and no crash. Only the QoS-undetermined INFO may mention the file.
        tpl = ("apiVersion: apps/v1\nkind: Deployment\n"
               "metadata: {name: t}\nspec: nope\n")
        r = analyze(chart(tpl), helm_mode="off")
        self.assertFalse({"AV001", "AV002", "AV003", "SC001", "PB001"}
                         & rules(r))
        self.assertIn("RS014", rules(r))

    def test_spec_without_pod_template_skips_pod_level_rules(self):
        tpl = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: t}\n"
               "spec:\n  replicas: 2\n  selector: {matchLabels: {app: t}}\n")
        r = analyze(chart(tpl), helm_mode="off")
        self.assertFalse({"AV001", "AV003", "SC001", "SC005", "PB001"}
                         & rules(r))


GOOD_POD = container("          resources:\n"
                     "            requests: {cpu: 500m, memory: 1Gi}\n"
                     "            limits: {memory: 1Gi}\n")


class TestPdbEdges(unittest.TestCase):
    def _run(self, pdb_body, head="spec:"):
        return analyze(chart(dep(GOOD_POD, head=head), extra={
            "templates/pdb.yaml": ("apiVersion: policy/v1\n"
                                   "kind: PodDisruptionBudget\n"
                                   "metadata: {name: t}\n" + pdb_body)}),
            helm_mode="off")

    def test_empty_pdb_spec_protects_nothing(self):
        r = self._run("spec: {}\n")
        self.assertEqual(len(find(r, "AV012")), 1)
        self.assertNotIn("AV010", rules(r))     # a PDB exists

    def test_scalar_pdb_spec_is_skipped_silently(self):
        r = self._run("spec: broken\n")
        self.assertFalse({"AV011", "AV012"} & rules(r))

    def test_min_available_equal_to_replicas_blocks_all_disruption(self):
        r = self._run("spec: {minAvailable: 2, selector: {matchLabels: {app: t}}}\n",
                      head="spec:\n  replicas: 2")
        hits = find(r, "AV011")
        self.assertEqual(len(hits), 1)
        self.assertIn("replicas(2) - minAvailable(2) = 0", hits[0].math)


class TestSecurityEdges(unittest.TestCase):
    def test_host_namespaces_are_high(self):
        tpl = dep("      hostNetwork: true\n" + GOOD_POD)
        r = analyze(chart(tpl), helm_mode="off")
        hits = find(r, "SC005")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)

    def test_pull_always_on_a_pinned_image_raises_nothing_here(self):
        # imagePullPolicy is a values-level concern (VA003); the pod-spec
        # walk must pass over the combination without inventing a finding
        tpl = dep(container("          imagePullPolicy: Always\n"
                            "          resources:\n"
                            "            requests: {cpu: 500m, memory: 1Gi}\n"
                            "            limits: {memory: 1Gi}\n"))
        r = analyze(chart(tpl), helm_mode="off")
        self.assertNotIn("SC005", rules(r))
        self.assertNotIn("VA003", rules(r))


if __name__ == "__main__":
    unittest.main()

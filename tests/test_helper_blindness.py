"""Helper (.tpl) blindness: what the static path may and may not claim.

THE DEFECT THIS PINS
--------------------
`{{- include "t.resources" . | nindent 12 }}` collapses to the leaf marker
`HELMINC@t.resources` because .tpl bodies are never expanded on the static
path. Three checks read that marker as "no resources were set" and said so
with the severity of a fact:

    [RS001] CRITICAL  Container has no resource requests/limits
    [HP022] CRITICAL  HPA scales on CPU but target workload has no CPU request
    [RS011] HIGH      Pod QoS class is BestEffort

Measured on a chart pair whose ONLY difference is the spelling of the
resources block (values-supplied vs helper-supplied, rendering identically
under helm): 87.1 B+ / 21 findings in both modes for the values chart, but
87.1 B+ under helm vs 72.5 C- / 24 findings statically for the helper chart.
Three CRITICAL/HIGH accusations of absence, from a file that was never read,
stamped OBSERVED.

The distinction the fix turns on, and the reason it is narrower than
helmyaml.is_unresolved():

    HELMVAL@x   the .Values path is unset in every values file read. helm
                renders an empty block from the same inputs, so "no resources"
                is TRUE and RS001 is right to say it.
    HELMINC@x   the body is in a file this run did not open. Nothing about
                absence has been established - only blindness.
"""

import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer import qos as qosmod
from hpaanalyzer.helmyaml import INC_PREFIX
from hpaanalyzer.kube import (HELPER_PREFIX, helper_resources_ref,
                              workload_resources_all_helper)
from hpaanalyzer.models import Basis, Category, Severity
from hpaanalyzer.scoring import unassessed_reason

from .util import CHART_YAML, make_tree

_DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
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
            %(resources)s
"""

_HELPERS = """{{- define "t.resources" -}}
requests:
  cpu: 500m
  memory: 1Gi
limits:
  memory: 1Gi
{{- end }}
"""

_HPA = """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ .Release.Name }}-app
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: {{ .Release.Name }}-app}
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource: {name: cpu, target: {type: Utilization, averageUtilization: 70}}
"""

_VALUES = "resources: {}\n"


def _tree(resources_block: str, helpers: bool = True):
    files = {
        "Chart.yaml": CHART_YAML,
        "values.yaml": _VALUES,
        "templates/deployment.yaml": _DEPLOY % {"resources": resources_block},
        "templates/hpa.yaml": _HPA,
    }
    if helpers:
        files["templates/_helpers.tpl"] = _HELPERS
    return make_tree(files)


def _run(root):
    # helm="off": this whole module is about what the STATIC path is allowed
    # to claim. With helm on PATH the include is expanded and there is no
    # question to answer.
    return analyze(root, helm_mode="off")


def _ids(r):
    return {f.rule_id for f in r.findings}


def _by_id(r, rid):
    return [f for f in r.findings if f.rule_id == rid]


HELPER_BLOCK = '{{- include "t.resources" . | nindent 12 }}'
TEMPLATE_BLOCK = '{{- template "t.resources" . }}'
VALUES_BLOCK = '{{- toYaml .Values.resources | nindent 12 }}'


class TestMarkerConstantsAgree(unittest.TestCase):
    """kube.HELPER_PREFIX is a deliberate duplicate of helmyaml.INC_PREFIX
    (kube.py must not import the parser). If they ever drift, every branch in
    this module silently stops firing and the CRITICALs come back."""

    def test_prefixes_identical(self):
        self.assertEqual(HELPER_PREFIX, INC_PREFIX)

    def test_qos_prefix_identical(self):
        self.assertEqual(qosmod._INC_PREFIX, INC_PREFIX)


class TestHelperRef(unittest.TestCase):

    def test_include_marker_is_recognised(self):
        self.assertEqual(
            helper_resources_ref({"resources": "HELMINC@t.resources"}),
            "t.resources")

    def test_values_marker_is_not_a_helper(self):
        """The whole point of the fix: an unresolved .Values path means the
        path is UNSET, not unread, so this must stay None and RS001 must
        still fire for it."""
        self.assertIsNone(helper_resources_ref({"resources": "HELMVAL@resources"}))

    def test_real_block_is_not_a_helper(self):
        self.assertIsNone(helper_resources_ref(
            {"resources": {"requests": {"cpu": "500m"}}}))

    def test_absent_is_not_a_helper(self):
        self.assertIsNone(helper_resources_ref({"name": "app"}))


class TestNoAccusationFromUnreadHelper(unittest.TestCase):

    def setUp(self):
        self.r = _run(_tree(HELPER_BLOCK))

    def test_rs001_absence_claim_is_withdrawn(self):
        self.assertNotIn("RS001", _ids(self.r))

    def test_rs011_besteffort_claim_is_withdrawn(self):
        self.assertNotIn("RS011", _ids(self.r))

    def test_hp022_never_scales_claim_is_withdrawn(self):
        self.assertNotIn("HP022", _ids(self.r))

    def test_rs018_reports_the_blindness_instead(self):
        f = _by_id(self.r, "RS018")
        self.assertEqual(len(f), 1)
        self.assertIs(f[0].severity, Severity.INFO)
        self.assertIs(f[0].category, Category.RESOURCES)
        self.assertIs(f[0].basis, Basis.DERIVED)
        self.assertIn("t.resources", f[0].detail)

    def test_rs018_names_what_it_suppressed(self):
        """A reader must be able to tell WHICH verdicts were withheld -
        otherwise silence is indistinguishable from a pass."""
        why = _by_id(self.r, "RS018")[0].why
        for rid in ("RS001", "RS011", "HP022"):
            self.assertIn(rid, why)

    def test_rs014_reports_qos_as_undetermined(self):
        f = _by_id(self.r, "RS014")
        self.assertEqual(len(f), 1)
        self.assertIs(f[0].severity, Severity.INFO)
        self.assertIn("t.resources", f[0].detail)

    def test_hp032_reports_the_uncheckable_hpa(self):
        f = _by_id(self.r, "HP032")
        self.assertEqual(len(f), 1)
        self.assertIs(f[0].severity, Severity.INFO)
        self.assertIs(f[0].category, Category.HPA)
        self.assertIs(f[0].basis, Basis.DERIVED)
        self.assertIn("t.resources", f[0].detail)

    def test_no_critical_or_high_from_invisibility(self):
        loud = [f.rule_id for f in self.r.findings
                if f.category in (Category.RESOURCES,)
                and f.severity in (Severity.CRITICAL, Severity.HIGH)]
        self.assertEqual(loud, [])


class TestTemplateKeywordTreatedTheSame(unittest.TestCase):
    """`template "x" .` emits content exactly like `include`; helmyaml routes
    both to the same marker, so the suppression must cover both spellings."""

    def test_template_action_also_suppresses(self):
        r = _run(_tree(TEMPLATE_BLOCK))
        self.assertNotIn("RS001", _ids(r))
        self.assertIn("RS018", _ids(r))


class TestValuesMarkerStillAccused(unittest.TestCase):
    """The other half of the fix, and the one that keeps it honest: an unset
    .Values path is a REAL absence - helm renders an empty block too - so the
    CRITICAL must survive, at full severity, stated as observed."""

    def setUp(self):
        self.r = _run(_tree(VALUES_BLOCK, helpers=False))

    def test_rs001_still_fires(self):
        f = _by_id(self.r, "RS001")
        self.assertEqual(len(f), 1)
        self.assertIs(f[0].severity, Severity.CRITICAL)

    def test_no_helper_finding(self):
        self.assertNotIn("RS018", _ids(self.r))
        self.assertNotIn("HP032", _ids(self.r))

    def test_cascade_still_fires(self):
        self.assertIn("HP022", _ids(self.r))


class TestEmptyValuesBlockInference(unittest.TestCase):
    """VA004 reads `resources: {}` in values.yaml and concludes something
    about the PODS ("every pod is scheduled as BestEffort"). That inference
    needs a template that consumes .Values.resources. With a helper supplying
    every block the key is inert, and the HIGH is unfounded."""

    def test_helper_chart_gets_the_documentation_finding(self):
        r = _run(_tree(HELPER_BLOCK))
        self.assertNotIn("VA004", _ids(r))
        f = _by_id(r, "VA011")
        self.assertEqual(len(f), 1)
        self.assertIs(f[0].severity, Severity.LOW)
        self.assertIs(f[0].basis, Basis.DERIVED)

    def test_values_chart_still_gets_the_high(self):
        r = _run(_tree(VALUES_BLOCK, helpers=False))
        f = _by_id(r, "VA004")
        self.assertEqual(len(f), 1)
        self.assertIs(f[0].severity, Severity.HIGH)
        self.assertNotIn("VA011", _ids(r))


class TestQoSPort(unittest.TestCase):

    def test_include_marker_is_unknown_not_besteffort(self):
        q, per, undet, _ = qosmod.requirements_qos("HELMINC@t.resources")
        self.assertEqual(q, qosmod.UNKNOWN)
        self.assertTrue(any("t.resources" in u for u in undet))

    def test_values_marker_is_still_besteffort(self):
        """_section() maps it to {} and every quantity is the zero Quantity -
        which is CORRECT here, because the values really are unset."""
        q, _, _, _ = qosmod.requirements_qos("HELMVAL@resources")
        self.assertEqual(q, qosmod.BESTEFFORT)

    def test_pod_with_one_unreadable_container_is_unknown(self):
        ps = {"containers": [
            {"name": "a", "resources": {"requests": {"cpu": "1", "memory": "1Gi"},
                                        "limits": {"cpu": "1", "memory": "1Gi"}}},
            {"name": "b", "resources": "HELMINC@t.resources"},
        ]}
        pq = qosmod.pod_qos(ps)
        self.assertEqual(pq.qos, qosmod.UNKNOWN)

    def test_mixed_known_classes_are_still_burstable(self):
        """The UNKNOWN branch must not swallow the real mix rule."""
        ps = {"containers": [
            {"name": "a", "resources": {"requests": {"cpu": "1", "memory": "1Gi"},
                                        "limits": {"cpu": "1", "memory": "1Gi"}}},
            {"name": "b"},
        ]}
        self.assertEqual(qosmod.pod_qos(ps).qos, qosmod.BURSTABLE)

    def test_reason_says_unexpanded_not_unparseable(self):
        pq = qosmod.pod_qos({"containers": [
            {"name": "b", "resources": "HELMINC@t.resources"}]})
        self.assertIn("not expanded", pq.reason)


class TestScoreDenominator(unittest.TestCase):

    def test_resources_leaves_the_mean_when_nothing_was_legible(self):
        r = _run(_tree(HELPER_BLOCK))
        reason = unassessed_reason(Category.RESOURCES, r.context)
        self.assertIsNotNone(reason)
        self.assertIn("named template", reason)

    def test_resources_stays_when_a_container_was_legible(self):
        """One readable init container is enough to keep the category in the
        denominator - dropping it would delete that container's real findings
        from the score, which is the PB004/Dockerfile mistake all over again."""
        dep = _DEPLOY % {"resources": HELPER_BLOCK}
        dep = dep.replace(
            "      containers:",
            "      initContainers:\n"
            "        - name: setup\n"
            "          image: busybox:1.36\n"
            "          resources:\n"
            "            requests: {cpu: 4, memory: 8Gi}\n"
            "            limits: {cpu: 4, memory: 8Gi}\n"
            "      containers:")
        r = _run(make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": _VALUES,
            "templates/_helpers.tpl": _HELPERS,
            "templates/deployment.yaml": dep,
        }))
        self.assertFalse(workload_resources_all_helper(r.context))
        self.assertIsNone(unassessed_reason(Category.RESOURCES, r.context))


class TestModeParity(unittest.TestCase):
    """The measurement that justified the whole change: a chart must not be
    graded differently for spelling its resources as a helper, EXCEPT through
    a denominator the report prints."""

    def test_helper_and_values_charts_agree_on_findings_that_remain(self):
        helper = _run(_tree(HELPER_BLOCK))
        # same chart, resources written out longhand
        longhand = _run(_tree("requests: {cpu: 500m, memory: 1Gi}\n"
                              "            limits: {memory: 1Gi}", helpers=False))
        # everything the helper chart says, minus the three findings that
        # exist only to report the blindness, must be a subset of what the
        # legible chart says.
        extra = _ids(helper) - _ids(longhand) - {"RS018", "RS014", "HP032",
                                                 "VA011"}
        self.assertEqual(extra, set())


if __name__ == "__main__":
    unittest.main()

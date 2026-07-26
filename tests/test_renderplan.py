"""R4: which cluster is `helm template` being told it is, and what follows.

Everything here that concerns helm's behaviour runs the real helm binary and
skips when it is absent (C5.3). The pure-policy parts - which version the plan
picks, where comment stripping starts and ends - are unit-tested directly,
because they are this tool's own arithmetic and no subprocess is involved.
"""

import os
import shutil
import unittest

from hpaanalyzer import kubeversion as kv
from hpaanalyzer import renderplan as rp
from hpaanalyzer.engine import analyze
from hpaanalyzer.helmrender import rendered_object_ids, render_chart

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")
HELM = shutil.which("helm")


def _ids(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


class TestPlanPolicy(unittest.TestCase):
    def test_user_override_always_wins(self):
        p = rp.plan(">=1.21.0-0 <1.33.0-0", override="1.28.4")
        self.assertEqual(p.version, "1.28.4")
        self.assertEqual(p.source, "user")

    def test_closed_range_uses_the_ceiling(self):
        p = rp.plan(">=1.21.0-0 <1.33.0-0")
        self.assertEqual(p.source, "chart-ceiling")
        self.assertEqual(p.version, "1.32.0")
        self.assertEqual(p.probe, "1.21.0")

    def test_open_range_uses_known_latest_clamped_up_to_the_floor(self):
        p = rp.plan(">=1.23.0-0")
        self.assertEqual(p.source, "known-latest")
        self.assertEqual(p.version, rp._v(rp.KNOWN_LATEST_MINOR))
        # a floor ABOVE everything the tool knows must not be rendered below
        # it: clamping DOWN to known-latest would render a chart at a version
        # it has explicitly said it does not support, and helm would refuse.
        p2 = rp.plan(">=1.40.0-0")
        self.assertEqual(p2.effective_minor, (1, 40))
        self.assertGreater(p2.effective_minor, rp.KNOWN_LATEST_MINOR)

    def test_floor_beyond_the_domain_horizon_is_named_not_called_unusable(self):
        """kubeversion caps its enumeration at DOMAIN_MAX_MINOR. A floor above
        that yields no candidate minors, and no version can be chosen - but
        the REASON is a limit of this analyzer's sampling, not a defect in the
        constraint, and R5 stopped conflating the two. `unparseable` is
        reserved for constraints that really are unusable.

        (This test previously asserted `source == "unparseable"` and its own
        docstring called the horizon an R5 item. It was pinning the wrong
        behaviour at the right place: the point of pinning the edge is that
        moving the horizon cannot change the answer silently, and that still
        holds.)"""
        p = rp.plan(">=1.99.0-0")
        self.assertEqual(p.source, "above-horizon")
        self.assertIsNone(p.version)
        self.assertIn(f"1.{kv.DOMAIN_MAX_MINOR}", p.reason)
        self.assertTrue(p.declared.parsed)
        self.assertTrue(p.declared.above_domain)

    def test_a_genuinely_contradictory_range_is_still_unparseable(self):
        """The other side of the same distinction: a reversed pair of bounds
        is satisfiable by nothing at any version, above the horizon or below
        it, and must NOT be excused as a sampling limit."""
        p = rp.plan(">=1.30.0-0 <1.20.0-0")
        self.assertEqual(p.source, "unparseable")
        self.assertFalse(p.declared.above_domain)

    def test_undeclared_passes_no_version_and_says_so(self):
        p = rp.plan(None)
        self.assertIsNone(p.version)
        self.assertEqual(p.source, "undeclared")
        self.assertIn("1.20.0", p.reason)
        # and the report must be able to name what helm will silently use
        self.assertEqual(p.effective_minor, rp.HELM_DEFAULT_MINOR)

    def test_unparseable_range_renders_at_nothing(self):
        p = rp.plan(">=v1.2x")
        self.assertIsNone(p.version)
        self.assertEqual(p.source, "unparseable")

    def test_known_latest_is_derived_from_the_tables_not_typed(self):
        """If someone adds a 1.34 fact to kube.py, the render version must
        follow without anyone remembering to edit a literal."""
        from hpaanalyzer import kube
        highest = max(list(kube.API_AVAILABLE_SINCE.values()) +
                      [f.removed_in for f in kube.DEPRECATED_APIS.values()])
        self.assertEqual(rp.KNOWN_LATEST_MINOR, highest)


class TestStripInert(unittest.TestCase):
    def test_go_comment_is_not_a_branch(self):
        raw = ('{{- /* explains .Capabilities.APIVersions.Has "autoscaling/v2"\n'
               '   over several lines */ -}}\n'
               'kind: Service\n')
        self.assertEqual(rp.capability_gates({"templates/s.yaml": raw}), [])

    def test_yaml_comment_is_not_a_branch(self):
        raw = '# see .Capabilities.APIVersions.Has "policy/v1"\nkind: Service\n'
        self.assertEqual(rp.capability_gates({"templates/s.yaml": raw}), [])

    def test_stripping_preserves_line_numbers(self):
        raw = ('{{- /* a\nb\nc */ -}}\n'
               '{{- if .Capabilities.APIVersions.Has "batch/v1" }}\n')
        hits = rp.capability_gates({"templates/s.yaml": raw})
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][1], 4)          # the real line, not 1
        self.assertEqual(hits[0][2], "batch/v1")

    def test_both_spellings_detected(self):
        a = '{{- if .Capabilities.APIVersions.Has "autoscaling/v2" }}\n'
        b = '{{- if has "policy/v1" .Capabilities.APIVersions }}\n'
        self.assertEqual([h[2] for h in rp.capability_gates({"t/a.yaml": a})],
                         ["autoscaling/v2"])
        self.assertEqual([h[2] for h in rp.capability_gates({"t/b.yaml": b})],
                         ["policy/v1"])

    def test_unliteral_reference_still_reported_with_none(self):
        raw = '{{- if .Capabilities.APIVersions.Has $gv }}\n'
        hits = rp.capability_gates({"templates/s.yaml": raw})
        self.assertEqual(len(hits), 1)
        self.assertIsNone(hits[0][2])

    def test_notes_txt_ignored(self):
        raw = '.Capabilities.APIVersions.Has "batch/v1"\n'
        self.assertEqual(rp.capability_gates({"templates/NOTES.txt": raw}), [])


@unittest.skipUnless(HELM, "helm not installed")
class TestAgainstRealHelm(unittest.TestCase):
    """The claims renderplan's docstring makes, re-checked against the binary.

    These are deliberately assertions about HELM, not about this tool. If a
    future helm changes any of them, this tool's reasoning changes with it and
    the failure should land here rather than in a report a user is reading.
    """

    def _caps(self, kube_version):
        """Render a probe chart that prints what helm believes."""
        import tempfile
        d = tempfile.mkdtemp(prefix="hpa-caps-")
        os.makedirs(os.path.join(d, "templates"))
        with open(os.path.join(d, "Chart.yaml"), "w") as f:
            f.write("apiVersion: v2\nname: caps\nversion: 1.0.0\n")
        with open(os.path.join(d, "templates", "cm.yaml"), "w") as f:
            f.write(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: caps\n"
                "data:\n"
                '  kubeVersion: {{ .Capabilities.KubeVersion.Version | quote }}\n'
                '  v2: {{ .Capabilities.APIVersions.Has "autoscaling/v2" | quote }}\n'
                '  v2beta1: {{ .Capabilities.APIVersions.Has "autoscaling/v2beta1" | quote }}\n'
                '  crd: {{ .Capabilities.APIVersions.Has "monitoring.coreos.com/v1" | quote }}\n')
        out, err = render_chart(d, kube_version=kube_version)
        self.assertIsNone(err, err)
        import yaml
        return yaml.safe_load(out)["data"]

    def test_kube_version_controls_KubeVersion(self):
        for v in ("1.16.0", "1.21.0", "1.32.0"):
            self.assertEqual(self._caps(v)["kubeVersion"], "v" + v)

    def test_kube_version_does_NOT_control_APIVersions(self):
        """The assumption R4 falsified, pinned so it cannot be re-made.

        autoscaling/v2 arrived in 1.23 and v2beta1 was removed in 1.26; helm
        answers true for both at every version, so its APIVersions set
        describes a cluster that has never existed.
        """
        for v in ("1.16.0", "1.21.0", "1.32.0"):
            caps = self._caps(v)
            self.assertEqual(caps["v2"], "true", f"at {v}")
            self.assertEqual(caps["v2beta1"], "true", f"at {v}")

    def test_APIVersions_is_false_for_CRDs_at_every_version(self):
        """The same defect in the other direction: a group that IS on the
        user's cluster reads as absent, so the chart renders the fallback arm
        of a branch it would not take in production."""
        for v in ("1.21.0", "1.32.0"):
            self.assertEqual(self._caps(v)["crd"], "false", f"at {v}")

    def test_helm_refuses_a_modern_chart_without_kube_version(self):
        """D1: the whole rendered-truth path, dead on arrival for any chart
        with a floor above helm's compiled-in v1.20.0."""
        chart = os.path.join(FIXTURES, "good-chart")
        out, err = render_chart(chart)            # no --kube-version
        self.assertIsNone(out)
        self.assertIn("kubeVersion", err)
        out2, err2 = render_chart(chart, kube_version="1.32.0")
        self.assertIsNone(err2, err2)
        self.assertTrue(out2.strip())

    def test_error_text_is_single_line(self):
        """D5: this string lands in single-line report fields and table cells.
        helm's real error is multi-line ('Error: ...\\n\\nUse --debug ...')."""
        _out, err = render_chart(os.path.join(FIXTURES, "good-chart"))
        self.assertNotIn("\n", err)


@unittest.skipUnless(HELM, "helm not installed")
class TestDivergenceCH015(unittest.TestCase):
    def test_capability_chart_really_diverges(self):
        """The fixture's premise, verified against helm rather than asserted.

        An earlier version of this fixture gated on .Capabilities.APIVersions
        and did NOT diverge - identical output at both ends - which would have
        made every CH015 test below vacuously green.
        """
        chart = os.path.join(FIXTURES, "capability-chart")
        lo, e1 = render_chart(chart, kube_version="1.21.0")
        hi, e2 = render_chart(chart, kube_version="1.32.0")
        self.assertIsNone(e1, e1)
        self.assertIsNone(e2, e2)
        self.assertNotEqual(rendered_object_ids(lo), rendered_object_ids(hi))

    def test_ch015_fires_medium_with_both_directions(self):
        r = analyze(os.path.join(FIXTURES, "capability-chart"))
        f = _ids(r, "CH015")
        self.assertEqual(len(f), 1, [x.detail for x in f])
        self.assertEqual(f[0].severity.label, "MEDIUM")
        self.assertIn("HorizontalPodAutoscaler", f[0].detail)
        self.assertIn("PodDisruptionBudget", f[0].detail)

    def test_ch015_silent_when_the_object_set_is_stable(self):
        r = analyze(os.path.join(FIXTURES, "apiversion-chart"))
        self.assertEqual(_ids(r, "CH015"), [])

    def test_probe_records_both_ends(self):
        r = analyze(os.path.join(FIXTURES, "capability-chart"))
        div = r.context.render_divergence
        self.assertTrue(div["checked"])
        self.assertTrue(div["diverges"])
        self.assertEqual(div["at"], "1.32.0")
        self.assertEqual(div["probe"], "1.21.0")


@unittest.skipUnless(HELM, "helm not installed")
class TestCH016(unittest.TestCase):
    def test_fires_on_a_chart_that_gates_on_APIVersions(self):
        r = analyze(os.path.join(FIXTURES, "apiversion-chart"))
        f = _ids(r, "CH016")
        self.assertEqual(len(f), 1)
        self.assertIn("autoscaling/v2", f[0].detail)
        self.assertIn("templates/hpa.yaml", f[0].detail)

    def test_is_always_INFO_so_it_cannot_cost_the_chart_a_grade(self):
        """Withhold-asymmetry: this rule reports a limit of the ANALYSER, and
        the idiom it names is the recommended one. A tool that docks marks for
        its own blind spot is punishing the user for its own limitation."""
        r = analyze(os.path.join(FIXTURES, "apiversion-chart"))
        f = _ids(r, "CH016")[0]
        self.assertEqual(f.severity.label, "INFO")
        self.assertEqual(f.effective_deduction(), 0)

    def test_silent_on_a_chart_that_gates_on_KubeVersion(self):
        """CH015's fixture branches too - on semverCompare, which
        --kube-version DOES control - so there is nothing to withhold."""
        r = analyze(os.path.join(FIXTURES, "capability-chart"))
        self.assertEqual(_ids(r, "CH016"), [])

    def test_names_a_queried_group_version_that_cannot_exist_at_the_render(self):
        r = analyze(os.path.join(FIXTURES, "apiversion-chart"),
                    kube_version="1.21.0")
        f = _ids(r, "CH016")[0]
        # autoscaling/v2 first exists in 1.23
        self.assertIn("does not exist on a real 1.21.0 cluster", f.detail)
        self.assertIn("autoscaling/v2", f.detail)

    def test_no_such_claim_when_the_group_version_does_exist(self):
        r = analyze(os.path.join(FIXTURES, "apiversion-chart"),
                    kube_version="1.30.0")
        f = _ids(r, "CH016")[0]
        self.assertNotIn("does not exist on a real", f.detail)


class TestGvExistsAt(unittest.TestCase):
    """The lookup CH016's strongest sentence rests on."""

    def test_not_yet_introduced(self):
        from hpaanalyzer.checks_chart import _gv_exists_at
        self.assertFalse(_gv_exists_at("autoscaling/v2", (1, 21)))
        self.assertTrue(_gv_exists_at("autoscaling/v2", (1, 23)))

    def test_already_removed(self):
        from hpaanalyzer.checks_chart import _gv_exists_at
        self.assertTrue(_gv_exists_at("autoscaling/v2beta1", (1, 24)))
        self.assertFalse(_gv_exists_at("autoscaling/v2beta1", (1, 25)))

    def test_unknown_group_version_returns_None_not_False(self):
        """C2.2: 'no recorded fact' is not 'does not exist'. A CRD must never
        be reported as impossible just because kube.py has never heard of it."""
        from hpaanalyzer.checks_chart import _gv_exists_at
        self.assertIsNone(_gv_exists_at("monitoring.coreos.com/v1", (1, 30)))

    def test_kind_qualified_form(self):
        from hpaanalyzer.checks_chart import _gv_exists_at
        self.assertTrue(_gv_exists_at(
            "autoscaling/v2/HorizontalPodAutoscaler", (1, 30)))
        self.assertFalse(_gv_exists_at(
            "autoscaling/v2/HorizontalPodAutoscaler", (1, 21)))

    def test_group_version_survives_while_any_kind_survives(self):
        """policy/v1beta1 holds two kinds with different histories; the
        group/version is present while either one is."""
        from hpaanalyzer.checks_chart import _gv_exists_at
        self.assertTrue(_gv_exists_at("policy/v1beta1", (1, 21)))
        self.assertFalse(_gv_exists_at("policy/v1beta1", (1, 25)))


@unittest.skipUnless(HELM, "helm not installed")
class TestRenderVersionPlumbing(unittest.TestCase):
    def test_modern_chart_now_renders(self):
        """D1 fixed, end to end: three of five fixtures used to fall back to
        static scrubbing purely because nobody passed --kube-version."""
        for name in ("good-chart", "sidecar-chart", "initheavy-chart"):
            r = analyze(os.path.join(FIXTURES, name))
            self.assertEqual(r.context.render_mode, "helm", name)
            self.assertTrue(r.context.render_kube_version, name)

    def test_cli_override_reaches_the_render(self):
        r = analyze(os.path.join(FIXTURES, "good-chart"), kube_version="1.27.3")
        self.assertEqual(r.context.render_kube_version, "1.27.3")
        self.assertEqual(r.context.render_version_source, "user")

    def test_helm_present_is_recorded_separately_from_success(self):
        """D2 rests on this: 'helm is missing' and 'helm refused' are
        different states and only one is fixed by installing helm."""
        r = analyze(os.path.join(FIXTURES, "good-chart"))
        self.assertTrue(r.context.helm_present)


if __name__ == "__main__":
    unittest.main()

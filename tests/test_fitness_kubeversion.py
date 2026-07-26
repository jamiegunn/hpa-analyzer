"""Bar 2 (docs/SPEC.md S4) for iteration 3: does the ranking help anybody?

tests/test_kubeversion.py is Bar 1 - the constraint engine answers what helm
answers, checked against the real Go library. That bar is necessary and not
sufficient. A perfectly correct version comparison that never changes what the
user is told is a perfectly correct waste of everyone's time.

The defect R3 set out to fix was not a wrong number. It was that the tool held
Kubernetes versions as decoration: TP010 was CRITICAL unconditionally, so a
chart pinned to 1.20-1.21 shipping a networking.k8s.io/v1beta1 Ingress - which
works on every cluster it claims to support - occupied the same top-of-list
slot as a chart that cannot work anywhere. When everything is critical the
fix-first list stops being an order, and the user's actual outage sits below
three portability notes.

So this suite asks the fitness questions:
  * does the real failure now outrank the portability note (and vice versa)?
  * is the downgrade honest - does a LOW finding still say what to do?
  * did the reconciliation buy the ranking at the cost of MISSING things? A
    tool that downgraded everything would pass the first question and be
    worse than what it replaced.

Everything here runs the real engine over a real directory on disk
(contract C5.3). No mocks, no monkeypatching, no hand-fed ChartContext.
"""

import os
import shutil
import tempfile
import unittest

from hpaanalyzer import kubeversion as kv
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import render, stdout_summary

FIXTURES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "fixtures"))
LEGACY = os.path.join(FIXTURES, "legacy-chart")


class _ChartCase(unittest.TestCase):
    """Builds a throwaway chart directory and runs the real analyzer on it."""

    VALUES = "replicaCount: 2\n"

    def make(self, kube_version, manifests, extra_chart=""):
        d = tempfile.mkdtemp(prefix="hpa-r3-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        kv_line = "" if kube_version is None else f'kubeVersion: "{kube_version}"\n'
        with open(os.path.join(d, "Chart.yaml"), "w") as f:
            f.write("apiVersion: v2\nname: r3\nversion: 1.0.0\n"
                    'appVersion: "1.0.0"\ndescription: fitness fixture\n'
                    + kv_line + extra_chart)
        with open(os.path.join(d, "values.yaml"), "w") as f:
            f.write(self.VALUES)
        os.makedirs(os.path.join(d, "templates"))
        with open(os.path.join(d, "templates", "objects.yaml"), "w") as f:
            f.write("\n---\n".join(manifests))
        return d

    def run_chart(self, kube_version, manifests):
        d = self.make(kube_version, manifests)
        result = analyze(d, helm_mode="off")
        return result, stdout_summary(result, "/tmp/r3.txt")

    def finding(self, result, rule_id, contains=None):
        hits = [f for f in result.findings if f.rule_id == rule_id
                and (contains is None or contains in f.detail)]
        if not hits:
            self.fail(f"{rule_id} was not raised"
                      + (f" for {contains!r}" if contains else "")
                      + f"; got {sorted({x.rule_id for x in result.findings})}")
        return hits[0]

    def severities(self, result, rule_id):
        return sorted(f.severity.name for f in result.findings
                      if f.rule_id == rule_id)


CRONJOB = """apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: nightly
  labels: {app.kubernetes.io/name: r3}
spec:
  schedule: "0 2 * * *"
"""


class TestSeverityTracksTheDeclaredRange(_ChartCase):
    """The same object, four different cluster ranges, four different answers.

    This is the whole of R3 in one test class. The apiVersion never changes;
    only the chart's own statement about where it runs changes. If severity
    did not move with it, the field would be decoration - which is exactly
    what it was.
    """

    def test_range_entirely_above_the_removal_is_critical(self):
        result, summary = self.run_chart(">=1.33.0-0", [CRONJOB])
        f = self.finding(result, "TP010")
        self.assertEqual(f.severity.name, "CRITICAL")
        self.assertIn("TP010", summary)      # and it reaches the terminal

    def test_range_straddling_the_removal_is_high(self):
        result, _ = self.run_chart(">=1.23.0-0 <1.28.0-0", [CRONJOB])
        self.assertEqual(self.finding(result, "TP010").severity.name, "HIGH")

    def test_range_entirely_below_the_removal_is_low(self):
        result, _ = self.run_chart(">=1.20.0-0 <1.25.0-0", [CRONJOB])
        self.assertEqual(self.finding(result, "TP010").severity.name, "LOW")

    def test_undeclared_range_is_critical_and_says_why(self):
        # Conservative, not confident. The difference has to be visible, or
        # the user cannot tell a measurement from a default.
        result, _ = self.run_chart(None, [CRONJOB])
        f = self.finding(result, "TP010")
        self.assertEqual(f.severity.name, "CRITICAL")
        self.assertIn("no kubeVersion", f.detail)
        self.assertIn("conservative", f.why)

    def test_the_boundary_minor_counts_as_removed(self):
        # batch/v1beta1 CronJob is gone AS OF 1.25. A chart admitting exactly
        # 1.25 must not be told it is fine.
        result, _ = self.run_chart(">=1.25.0-0 <1.26.0-0", [CRONJOB])
        self.assertEqual(self.finding(result, "TP010").severity.name, "CRITICAL")


class TestTheFixFirstListIsAnOrderAgain(unittest.TestCase):
    """The user-facing consequence, measured on the shipped fixture.

    fixtures/legacy-chart pins 1.20-1.21 and ships three APIs removed in 1.22
    plus one HPA that does not exist until 1.23. Before R3 the three removals
    were CRITICAL and the too-new HPA was not detected at all - so the list
    the user was shown was, top to bottom, three things that cannot break on
    their cluster, and the thing that WILL break was missing entirely.
    """

    @classmethod
    def setUpClass(cls):
        cls.result = analyze(LEGACY, helm_mode="off")
        cls.summary = stdout_summary(cls.result, "/tmp/r3.txt")
        cls.report = render(cls.result, LEGACY)

    def test_the_real_outage_is_in_the_fix_first_list(self):
        self.assertIn("TP013", self.summary,
                      "The one finding on this chart that WILL fail at apply "
                      "time never reached the terminal - Bar 2 failure")

    def test_the_portability_notes_are_not(self):
        # stdout_summary prints only CRITICAL/HIGH. Three LOW deprecations
        # must not be competing for those five slots.
        fix_first = self.summary.split("Fix first:")[1]
        self.assertNotIn("TP010", fix_first)

    def test_the_portability_notes_are_still_reported_somewhere(self):
        # Downgrading is not the same as hiding. If the only way to stop
        # over-ranking a finding were to drop it, that would be a worse tool.
        self.assertEqual(self.severities_of("TP010"), ["LOW", "LOW", "LOW"])
        self.assertIn("TP010", self.report)

    def test_the_chart_is_not_graded_clean(self):
        # The counterpart failure mode: a severity reconciliation that
        # quietly turns a broken chart into an A+.
        self.assertIn("TP013", [f.rule_id for f in self.result.findings])
        self.assertNotIn("GRADE A+", self.summary)

    def severities_of(self, rule_id):
        return sorted(f.severity.name for f in self.result.findings
                      if f.rule_id == rule_id)


class TestTheTableNoLongerGoesSilentHalfway(unittest.TestCase):
    """Role and RoleBinding are removed in the same release and sit three
    lines apart in fixtures/legacy-chart/templates/rbac.yaml. The pre-R3 table
    listed one of them. A lookup miss in that table produces SILENCE, and
    silence is indistinguishable from a clean bill of health - so the user was
    shown a chart where one of two identically-doomed objects was fine."""

    @classmethod
    def setUpClass(cls):
        cls.result = analyze(LEGACY, helm_mode="off")

    def kinds_reported(self):
        return {f.title.rsplit(" ", 1)[-1] for f in self.result.findings
                if f.rule_id == "TP010"}

    def test_both_rbac_objects_are_reported(self):
        self.assertIn("Role", self.kinds_reported())
        self.assertIn("RoleBinding", self.kinds_reported())

    def test_they_are_reported_identically(self):
        got = [f for f in self.result.findings if f.rule_id == "TP010"
               and "rbac.authorization.k8s.io/v1beta1" in f.detail]
        self.assertEqual(len(got), 2)
        self.assertEqual(len({f.severity for f in got}), 1)


class TestTooNewIsCheckedAtAll(_ChartCase):
    """TP013. CH010's own 'why' text cites 'autoscaling/v2 requires Kubernetes
    >= 1.23' as the reason to set a kubeVersion - and then the tool never
    checked it. Advice about a failure mode you do not detect is a slogan."""

    HPA = """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: r3
  labels: {app.kubernetes.io/name: r3}
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: r3}
  minReplicas: 2
  maxReplicas: 8
"""

    def test_floor_below_availability_is_reported(self):
        result, summary = self.run_chart(">=1.20.0-0 <1.22.0-0", [self.HPA])
        f = self.finding(result, "TP013")
        self.assertEqual(f.severity.name, "CRITICAL")
        self.assertIn("TP013", summary)

    def test_partial_overlap_is_high_not_critical(self):
        # 1.21-1.24 has the API on 1.23-1.24 and not on 1.21-1.22. Real, but
        # not "works nowhere".
        result, _ = self.run_chart(">=1.21.0-0 <1.25.0-0", [self.HPA])
        self.assertEqual(self.finding(result, "TP013").severity.name, "HIGH")

    def test_exactly_at_the_floor_is_silent(self):
        # Precision matters as much as recall here: autoscaling/v2 IS present
        # on 1.23, and a tool that cries wolf on a correct chart gets muted.
        result, _ = self.run_chart(">=1.23.0-0", [self.HPA])
        self.assertNotIn("TP013", [f.rule_id for f in result.findings])

    def test_no_declared_range_means_no_claim(self):
        # With no kubeVersion there is no statement to contradict. Inventing
        # one would be a guess, and a guess printed as a finding is the thing
        # this project is trying not to be.
        result, _ = self.run_chart(None, [self.HPA])
        self.assertNotIn("TP013", [f.rule_id for f in result.findings])

    def test_the_finding_names_the_version_and_the_fix(self):
        result, _ = self.run_chart(">=1.20.0-0 <1.22.0-0", [self.HPA])
        f = self.finding(result, "TP013")
        self.assertIn("1.23", f.detail)        # when the API appeared
        self.assertIn("1.20-1.21", f.detail)   # what the chart claims
        self.assertIn("1.23.0-0", f.fix)       # the literal line to write


class TestConstraintsThatSilentlyInstallNowhere(_ChartCase):
    """CH013/CH014. Both are invisible in review - the Chart.yaml looks like
    it says something sensible - and both stop the chart installing on
    clusters the author believes are supported."""

    DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: r3
  labels: {app.kubernetes.io/name: r3}
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3
"""

    def test_unparseable_constraint_is_critical(self):
        result, summary = self.run_chart(">=1.24 and <1.26", [self.DEPLOY])
        f = self.finding(result, "CH013")
        self.assertEqual(f.severity.name, "CRITICAL")
        self.assertIn("CH013", summary)
        self.assertIn("and", f.detail)          # quotes what the author wrote

    def test_reversed_bounds_are_critical(self):
        result, _ = self.run_chart(">=1.30.0-0 <1.20.0-0", [self.DEPLOY])
        self.assertEqual(self.finding(result, "CH013").severity.name, "CRITICAL")

    def test_missing_prerelease_comparator_is_reported(self):
        result, _ = self.run_chart(">=1.29.0", [self.DEPLOY])
        f = self.finding(result, "CH014")
        self.assertEqual(f.severity.name, "MEDIUM")
        self.assertIn("gke", f.detail.lower())
        self.assertIn("-0", f.fix)

    def test_a_correct_constraint_produces_neither(self):
        result, _ = self.run_chart(">=1.29.0-0", [self.DEPLOY])
        ids = [f.rule_id for f in result.findings]
        self.assertNotIn("CH013", ids)
        self.assertNotIn("CH014", ids)


class TestAFloorAboveEveryReleaseIsNotCalledAContradiction(_ChartCase):
    """CH017. R4 left this open and named it: the analyzer enumerates minors
    up to DOMAIN_MAX_MINOR, so '>=1.61.0-0' - which parses fine and is
    satisfiable by 1.61 onwards - produced an empty minor set and fell into
    CH013, whose text asserts 'no Kubernetes 1.x release satisfies it ...
    usually a reversed or overlapping pair of bounds'.

    Both halves of that were wrong about this chart. The constraint is not
    reversed, and the analyzer had not established that nothing satisfies it
    - it had stopped looking at 1.60 and reported the edge of its own
    sampling as a property of the world. That is the C2.2 failure this
    project keeps finding in other people's tools, committed by this one.

    The consequence for the user is not cosmetic. CH013 sends you hunting a
    bound conflict that does not exist; the real bug is one transposed digit
    in the floor."""

    DEPLOY = TestConstraintsThatSilentlyInstallNowhere.DEPLOY

    def test_floor_above_the_horizon_is_ch017_not_ch013(self):
        result, summary = self.run_chart(">=1.61.0-0", [self.DEPLOY])
        f = self.finding(result, "CH017")
        self.assertEqual(f.severity.name, "CRITICAL")
        self.assertIn("CH017", summary)
        self.assertNotIn("CH013", [x.rule_id for x in result.findings])

    def test_it_says_which_claim_it_is_not_making(self):
        # The two findings have the same symptom - helm install fails
        # everywhere - and different causes. If CH017 does not disown the
        # contradiction reading, the user re-derives the confusion the rule
        # exists to remove.
        f = self.finding(self.run_chart(">=1.99.0-0", [self.DEPLOY])[0], "CH017")
        self.assertIn("CH013", f.detail)
        self.assertIn("NOT", f.detail)
        self.assertIn("1.99.0-0", f.detail)          # quotes what was written

    def test_the_horizon_is_named_as_this_tools_limit(self):
        # C2.2: where the answer depends on how far we sampled, say so at the
        # point of use rather than leaving the reader to infer it.
        f = self.finding(self.run_chart(">=1.61.0-0", [self.DEPLOY])[0], "CH017")
        horizon = f"1.{kv.DOMAIN_MAX_MINOR}"
        self.assertIn(horizon, f.detail)
        self.assertIn(horizon, f.fix)

    def test_a_reversed_range_is_still_ch013_and_not_ch017(self):
        # The precision half. CH017 must not swallow the case CH013 is right
        # about, or the fix has traded one misdiagnosis for another.
        result, _ = self.run_chart(">=1.30.0-0 <1.20.0-0", [self.DEPLOY])
        ids = [f.rule_id for f in result.findings]
        self.assertIn("CH013", ids)
        self.assertNotIn("CH017", ids)

    def test_an_in_domain_constraint_produces_neither(self):
        result, _ = self.run_chart(">=1.29.0-0", [self.DEPLOY])
        ids = [f.rule_id for f in result.findings]
        self.assertNotIn("CH017", ids)
        self.assertNotIn("CH013", ids)

    def test_a_2_x_floor_is_the_same_defect_on_the_other_axis(self):
        # The first cut of this fix probed minors only, because the sampled
        # majors are (1,) - so '>=2.0.0-0' still landed in CH013 and the
        # render plan still called a well-formed constraint 'unparseable'.
        #
        # It was easy to miss because CH013's HEADLINE is true here: no 2.x
        # exists, so nothing does satisfy it. A rule can be accidentally right
        # and still mislead - CH013 blames reversed bounds, which is not the
        # bug, and 'unparseable' is a plain falsehood about a string that
        # parses. Being right for the wrong reason is not being right.
        result, _ = self.run_chart(">=2.0.0-0", [self.DEPLOY])
        ids = [f.rule_id for f in result.findings]
        self.assertIn("CH017", ids)
        self.assertNotIn("CH013", ids)

    def test_the_2_x_case_says_2_x_and_not_the_minor_horizon(self):
        # Two edges, two sentences. Telling a '>=2.0.0-0' author that their
        # floor is "above 1.60" is precise-sounding and wrong, and emitting
        # those is the thing CH017 was split off CH013 to stop.
        f = self.finding(self.run_chart(">=2.0.0-0", [self.DEPLOY])[0], "CH017")
        self.assertIn("2.0", f.detail)
        self.assertNotIn(f"only by versions above 1.{kv.DOMAIN_MAX_MINOR}",
                         f.detail)
        self.assertIn("2.0", f.fix)          # advice is about the major, too
        self.assertNotIn("digit-by-digit", f.fix)

    def test_the_two_edges_are_distinguishable_by_a_caller(self):
        # Not just in prose - in the data, so report surfaces and the render
        # planner can branch without string-matching a finding.
        self.assertEqual(kv.declared_range(">=2.0.0-0").above_domain_edge,
                         kv.AboveDomain.MAJOR)
        self.assertEqual(kv.declared_range(">=1.61.0-0").above_domain_edge,
                         kv.AboveDomain.MINOR)
        self.assertEqual(kv.declared_range(">=1.29.0-0").above_domain_edge,
                         kv.AboveDomain.NO)
        self.assertEqual(kv.declared_range(">=1.30.0-0 <1.20.0-0")
                         .above_domain_edge, kv.AboveDomain.NO)

    def test_the_ceiling_case_is_a_contradiction_not_a_horizon(self):
        # '<1.0.0-0' admits nothing at OR above the horizon either, so the
        # above-domain probe must come back false and CH013 must keep it.
        result, _ = self.run_chart("<1.0.0-0", [self.DEPLOY])
        ids = [f.rule_id for f in result.findings]
        self.assertIn("CH013", ids)
        self.assertNotIn("CH017", ids)


class TestTheAdviceIsDerivedFromTheChart(_ChartCase):
    """CH010 used to print a constant: 'Add e.g. kubeVersion: ">=1.23.0-0"'.
    That figure had nothing to do with the chart in front of it. Advice you
    have to check before following is not advice."""

    HPA = TestTooNewIsCheckedAtAll.HPA

    def test_floor_is_taken_from_the_apis_the_chart_uses(self):
        result, _ = self.run_chart(None, [self.HPA])
        f = self.finding(result, "CH010")
        self.assertIn(">=1.23.0-0", f.fix)
        self.assertIn("autoscaling/v2", f.fix)   # and says where it got it

    def test_ceiling_is_taken_from_removals_in_the_chart(self):
        result, _ = self.run_chart(None, [CRONJOB])
        f = self.finding(result, "CH010")
        self.assertIn("<1.25.0-0", f.fix)
        self.assertIn("batch/v1beta1", f.fix)

    def test_both_bounds_when_both_are_known(self):
        result, _ = self.run_chart(None, [self.HPA, CRONJOB.replace(
            "batch/v1beta1", "policy/v1beta1").replace(
            "kind: CronJob", "kind: PodDisruptionBudget")])
        f = self.finding(result, "CH010")
        self.assertIn(">=1.23.0-0 <1.25.0-0", f.fix)

    def test_a_contradiction_is_stated_not_papered_over(self):
        # autoscaling/v2 needs >= 1.23; batch/v1beta1 CronJob is gone at 1.25
        # - fine together. Pair it with something removed BEFORE 1.23 and no
        # constraint can satisfy both. Printing a range anyway would be worse
        # than saying so.
        ingress = ("apiVersion: networking.k8s.io/v1beta1\nkind: Ingress\n"
                   "metadata:\n  name: r3\n  labels: {app.kubernetes.io/name: r3}\n")
        result, _ = self.run_chart(None, [self.HPA, ingress])
        f = self.finding(result, "CH010")
        self.assertIn("no consistent range", f.fix)
        self.assertIn("autoscaling/v2", f.fix)
        self.assertIn("networking.k8s.io/v1beta1", f.fix)

    def test_an_unknown_chart_says_the_number_is_an_example(self):
        # No apiVersion in either table -> no bound can be derived. The old
        # constant is still the best available suggestion, but it must be
        # labelled as a guess rather than passed off as a measurement
        # (contract C2.3).
        cm = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: r3\n"
              "  labels: {app.kubernetes.io/name: r3}\ndata: {a: b}\n")
        result, _ = self.run_chart(None, [cm])
        f = self.finding(result, "CH010")
        self.assertIn("example, not a measurement", f.fix)


class TestNoFabricationOnHealthyCharts(unittest.TestCase):
    """The precision half of the bargain. Three of the four shipped fixtures
    declare a correct kubeVersion and use current APIs; R3 added four new
    ways to be wrong, and none of them may fire here."""

    # CH017 arrived in R5, not R3, but it belongs to the same bargain: it is
    # a new way to be wrong about kubeVersion, and the fixtures that declare
    # a correct one must stay silent under it too.
    NEW_RULES = {"TP013", "CH013", "CH014", "CH017"}

    def test_clean_fixtures_gain_no_r3_findings(self):
        for name in ("good-chart", "sidecar-chart", "initheavy-chart"):
            with self.subTest(chart=name):
                r = analyze(os.path.join(FIXTURES, name), helm_mode="off")
                fired = self.NEW_RULES & {f.rule_id for f in r.findings}
                self.assertEqual(fired, set())

    def test_good_chart_has_no_deprecated_api_findings_either(self):
        r = analyze(os.path.join(FIXTURES, "good-chart"), helm_mode="off")
        self.assertNotIn("TP010", [f.rule_id for f in r.findings])


class TestTheDowngradeStaysHonest(unittest.TestCase):
    """A LOW finding still has to be worth reading. If the reconciliation
    turned 'this API is dead' into a shrug with no explanation, the ranking
    would be better and the tool would be worse."""

    @classmethod
    def setUpClass(cls):
        cls.result = analyze(LEGACY, helm_mode="off")

    def test_it_still_names_the_replacement(self):
        f = [x for x in self.result.findings if x.rule_id == "TP010"][0]
        self.assertIn("Move to", f.fix)

    def test_it_explains_why_it_is_low(self):
        f = [x for x in self.result.findings if x.rule_id == "TP010"][0]
        self.assertIn("refuses to install", f.why)
        self.assertIn("upgrade blocker", f.why)

    def test_it_shows_the_range_the_decision_was_based_on(self):
        # The severity is a derived number. The user has to be able to check
        # the derivation without reading the source.
        f = [x for x in self.result.findings if x.rule_id == "TP010"][0]
        self.assertIn(">=1.20.0-0 <1.22.0-0", f.detail)
        self.assertIn("1.20-1.21", f.detail)


if __name__ == "__main__":
    unittest.main()

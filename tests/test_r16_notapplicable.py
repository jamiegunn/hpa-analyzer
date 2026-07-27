"""R16: NOT APPLICABLE, a third coverage state, and the two it is not.

`proof/p18_notapplicable.py` argues this round end to end, through the CLI, on
nine charts. These tests pin the parts of it that a future edit could break
without breaking that script - and one part the script deliberately cannot
reach.

The distinction the whole round turns on, restated so a failure here reads
correctly: NOT ASSESSED means the tool did not look, or looked and found no
evidence, and naming the missing input is useful because supplying it changes
the answer. NOT APPLICABLE means the tool looked, holds the evidence, and the
question does not arise - no input exists that would change it. Their
ARITHMETIC is identical (both leave numerator and denominator together) which
is exactly why they are easy to conflate and worth pinning apart.

The three-valued fact underneath is `kube.scale_class`. Two of these tests
exist only because it used to be two-valued, and the third value joined
whichever branch the `if` fell through to.
"""

import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer.html_report import render_html
from hpaanalyzer.kube import scale_candidates, scale_class
from hpaanalyzer.models import Category
from hpaanalyzer.report import render
from hpaanalyzer.scoring import (WEIGHTS, category_scores, coverage,
                                 not_applicable_reason, unassessed_reason)

from .util import CHART_YAML, make_tree

_POD = ("      containers:\n        - name: app\n"
        "          image: repo/app:1.0\n"
        "          resources:\n            requests: {cpu: 500m, memory: 1Gi}\n"
        "            limits: {memory: 1Gi}\n")
_SEL = ("  selector:\n    matchLabels: {app: t}\n"
        "  template:\n    metadata:\n      labels: {app: t}\n    spec:\n")

# One object per kind, differing ONLY in `kind:`, the apiVersion that kind
# requires, and the spec fields that apiVersion makes mandatory.
BODIES = {
    "Deployment": ("apps/v1", "  replicas: 2\n" + _SEL + _POD),
    "StatefulSet": ("apps/v1", "  serviceName: t\n  replicas: 2\n" + _SEL + _POD),
    "ReplicaSet": ("apps/v1", "  replicas: 2\n" + _SEL + _POD),
    "ReplicationController": (
        "v1", "  replicas: 2\n  selector: {app: t}\n"
              "  template:\n    metadata:\n      labels: {app: t}\n    spec:\n" + _POD),
    "DaemonSet": ("apps/v1", _SEL + _POD),
    "Job": ("batch/v1", "  template:\n    metadata:\n      labels: {app: t}\n"
                        "    spec:\n      restartPolicy: Never\n" + _POD),
    "CronJob": ("batch/v1", '  schedule: "*/5 * * * *"\n  jobTemplate:\n'
                            "    spec:\n      template:\n        spec:\n"
                            "          restartPolicy: Never\n"
                            "          containers:\n            - name: app\n"
                            "              image: repo/app:1.0\n"),
    "Pod": ("v1", "  containers:\n    - name: app\n      image: repo/app:1.0\n"),
    "Rollout": ("argoproj.io/v1alpha1", "  replicas: 2\n" + _SEL + _POD),
}

HPA = ("apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
       "metadata: {name: t}\nspec:\n"
       "  scaleTargetRef: {apiVersion: %s, kind: %s, name: t}\n"
       "  minReplicas: 2\n  maxReplicas: 8\n"
       "  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
       "  metrics:\n    - type: Resource\n"
       "      resource: {name: cpu, target: {type: Utilization, averageUtilization: 70}}\n")


def chart(kind, with_hpa=False):
    api, spec = BODIES[kind]
    files = {
        "Chart.yaml": CHART_YAML,
        "values.yaml": "{}\n",
        "templates/w.yaml": (f"apiVersion: {api}\nkind: {kind}\n"
                             f"metadata: {{name: t}}\nspec:\n{spec}"),
    }
    if with_hpa:
        files["templates/hpa.yaml"] = HPA % (api, kind)
    return make_tree(files)


JVM_POD = ("      containers:\n        - name: app\n"
           "          image: eclipse-temurin:17-jre\n"
           "          env:\n            - name: JAVA_TOOL_OPTIONS\n"
           '              value: "-XX:MaxRAMPercentage=75"\n'
           "          resources:\n            requests: {cpu: 500m, memory: 1Gi}\n"
           "            limits: {memory: 1Gi}\n")


def only_hpa_excluded():
    """A chart where HPA-not-applicable is the ONLY thing out of the mean.

    CORRECTION, recorded rather than quietly fixed. The first version of this
    helper took the bare DaemonSet chart above and dropped a Dockerfile beside
    it, on the reasoning that DOCKERFILE was the missing input. Running it
    disproved that in one line:

        unassessed: ['JAVA', 'CROSS']    complete: False

    A Dockerfile makes DOCKERFILE assessable; it does nothing for JAVA or
    CROSS, which need JVM evidence and had none - so `complete` was False for
    two reasons that predate R16, and every assertion built on that fixture was
    measuring something other than what its name said. This one carries a JVM
    image, JAVA_TOOL_OPTIONS and a matching Dockerfile, and measures
    unassessed=[] / not_applicable=[HPA] / complete=True / all_scored=False /
    weight_assessed=85. The failure mattered: the test that caught it is
    test_text_report_does_not_tell_the_reader_to_supply_an_input, and it caught
    a bad FIXTURE while asserting correct behaviour of the code - which is the
    only way round that is worth anything.
    """
    return make_tree({
        "Chart.yaml": CHART_YAML,
        "values.yaml": "{}\n",
        "Dockerfile": ("FROM eclipse-temurin:17-jre\nUSER 1000\n"
                       'CMD ["java", "-jar", "/app.jar"]\n'),
        "templates/w.yaml": ("apiVersion: apps/v1\nkind: DaemonSet\n"
                             "metadata: {name: t}\nspec:\n" + _SEL + JVM_POD),
    })


def _hpa_state(result):
    """'scored' | 'unassessed' | 'not_applicable' for Category.HPA."""
    cov = coverage(result)
    if Category.HPA in {c for c, _ in cov.unassessed}:
        return "unassessed"
    if Category.HPA in {c for c, _ in cov.not_applicable}:
        return "not_applicable"
    return "scored"


def _ids(result):
    return {f.rule_id for f in result.findings}


class ScaleClassTests(unittest.TestCase):
    """kube.scale_class: the three-valued fact the round is built on."""

    def test_three_answers_and_they_are_distinct(self):
        for kind in ("Deployment", "StatefulSet", "ReplicaSet",
                     "ReplicationController"):
            self.assertEqual(scale_class(kind), "scalable", kind)
        for kind in ("DaemonSet", "Job", "CronJob", "Pod"):
            self.assertEqual(scale_class(kind), "unscalable", kind)
        # Rollout DOES implement /scale. The point is not that the tool is
        # wrong about it - the point is that the tool has no statement about
        # it either way, and must say so rather than pick a default.
        self.assertEqual(scale_class("Rollout"), "unknown")
        self.assertEqual(scale_class(None), "unknown")

    def test_case_is_not_significant(self):
        self.assertEqual(scale_class("DEPLOYMENT"), "scalable")
        self.assertEqual(scale_class("daemonset"), "unscalable")

    def test_scale_candidates_excludes_non_workloads(self):
        """A Service must not be able to make the scale question look answered.

        Before R16 the candidate list was `ChartContext.workloads`, which is a
        different set for a different purpose. This asserts the narrow set:
        objects for which "could an HPA target this?" is a question at all.
        """
        root = chart("Deployment")
        result = analyze(root)
        docs = result.context.docs
        self.assertTrue(any(d.kind == "Deployment" for d in docs))
        cands = scale_candidates(docs)
        self.assertEqual([d.kind for d in cands], ["Deployment"])

    def test_replicationcontroller_survives_the_second_filter(self):
        """The bug that the first fix did not reach: two copies of the list, in
        series. Swapping the copy inside `_no_hpa` for SCALABLE_KINDS left RC
        filtered out one level above, in `ChartContext.workloads`.
        scale_candidates reads ctx.docs, which is the level below both.

        R17 INVERTED HALF OF THIS TEST, and it is rewritten here rather than
        deleted because the inversion is the point. As written in R16 the
        assertion was:

            self.assertNotIn("ReplicationController",
                             [d.kind for d in result.context.workloads])

        - a true statement about the code, pinned as if it were a requirement.
        It was neither: it was the DEFECT, recorded by a test whose name says
        "survives the second filter" while its body asserted that it does not.
        R17 measured what that exclusion cost (a ReplicationController chart
        got no RS001, no PB001, no SC001 and no grade at all) and added the
        kind, so the old line now fails - correctly.

        The lesson worth keeping is the one about two filters in series, so
        that is what this asserts now: RC must clear BOTH levels, and the HPA
        category must still be scored rather than silently dropped. A test
        that pins current behaviour without asking whether the behaviour is
        right is a regression detector for bugs.
        """
        result = analyze(chart("ReplicationController"))
        self.assertIn("ReplicationController",
                      [d.kind for d in result.context.workloads])
        self.assertEqual([d.kind for d in scale_candidates(result.context.docs)],
                         ["ReplicationController"])
        self.assertEqual(_hpa_state(result), "scored")


class HpaStateTests(unittest.TestCase):
    """One chart per kind: which of the three states, and why."""

    def test_every_scalable_kind_raises_hp002_and_is_scored(self):
        for kind in ("Deployment", "StatefulSet", "ReplicaSet",
                     "ReplicationController"):
            with self.subTest(kind=kind):
                result = analyze(chart(kind))
                self.assertEqual(_hpa_state(result), "scored")
                self.assertIn("HP002", _ids(result))

    def test_every_unscalable_kind_is_not_applicable_and_silent(self):
        for kind in ("DaemonSet", "Job", "CronJob", "Pod"):
            with self.subTest(kind=kind):
                result = analyze(chart(kind))
                self.assertEqual(_hpa_state(result), "not_applicable")
                # Silence on the FINDINGS axis is the correct behaviour here
                # and always was: telling an operator to autoscale a DaemonSet
                # is worse than saying nothing. Only the SCORING axis moved.
                self.assertNotIn("HP002", _ids(result))

    def test_unknown_kind_is_not_assessed_and_names_itself(self):
        result = analyze(chart("Rollout"))
        self.assertEqual(_hpa_state(result), "unassessed")
        reason = dict(coverage(result).unassessed)[Category.HPA]
        self.assertIn("Rollout", reason)
        self.assertIn("not something this tool knows", reason)

    def test_the_two_exclusions_make_different_claims(self):
        na = dict(coverage(analyze(chart("DaemonSet"))).not_applicable)[Category.HPA]
        ua = dict(coverage(analyze(chart("Rollout"))).unassessed)[Category.HPA]
        # NOT APPLICABLE says: no input would change this.
        self.assertIn("no change to the chart would create one", na)
        # NOT ASSESSED says: the tool does not know. It must NOT claim
        # finality, because the reader can settle it in ten seconds.
        self.assertNotIn("no change to the chart", ua)

    def test_reason_quotes_the_written_reason_not_a_generic_string(self):
        for kind, fragment in (("DaemonSet", "one pod per eligible node"),
                               ("Job", "parallelism"),
                               ("Pod", "bare Pod")):
            with self.subTest(kind=kind):
                cov = coverage(analyze(chart(kind)))
                self.assertIn(fragment, dict(cov.not_applicable)[Category.HPA])


class NegativeControlTests(unittest.TestCase):
    """The R14b bug, which this round could have re-committed and did not.

    A predicate keyed on workload kind alone drops HPA from the mean on
    `CronJob + HPA` - a chart where HP042 has just deducted a CRITICAL 25
    points. Dropping a category that deducted is a score-RAISING bug wearing a
    coverage note's clothing. Condition 1 of not_applicable_reason (the chart
    contains no HPA object) exists for this and nothing else.
    """

    def test_unscalable_kind_WITH_an_hpa_stays_in_the_mean(self):
        for kind in ("DaemonSet", "Job", "CronJob", "Pod"):
            with self.subTest(kind=kind):
                result = analyze(chart(kind, with_hpa=True))
                self.assertEqual(_hpa_state(result), "scored")
                self.assertTrue(any(r.startswith("HP04") for r in _ids(result)),
                                sorted(_ids(result)))

    def test_the_deduction_actually_reaches_the_score(self):
        """Not just 'stays scored' - stays scored AND below 100.

        A category can be in `assessed` and still score 100 if the findings
        were filtered out downstream, which would leave the state assertion
        above green while the points went missing anyway.
        """
        result = analyze(chart("CronJob", with_hpa=True))
        hpa = dict((c, s) for c, s, _ in category_scores(result))[Category.HPA]
        self.assertIsNotNone(hpa)
        self.assertLess(hpa, 100.0)

    def test_predicate_and_gate_agree_so_no_backstop_warning_is_needed(self):
        """R14b's backstop must not FIRE here - it must be unnecessary.

        A green run that only stays green because the backstop keeps rescuing
        it is not a working predicate. `coverage()` routes the new gate through
        `_warn_gate_contradiction`; this asserts the two never disagree, which
        is a different claim from asserting the final numbers came out right.
        """
        for kind in ("DaemonSet", "Job", "CronJob", "Pod"):
            with self.subTest(kind=kind):
                result = analyze(chart(kind, with_hpa=True))
                ctx = result.context
                self.assertIsNone(not_applicable_reason(Category.HPA, ctx))
                self.assertIsNone(unassessed_reason(Category.HPA, ctx))

    def test_mixed_chart_with_one_scalable_workload_is_scored(self):
        """One scalable object is enough to make the question real.

        A chart that ships a DaemonSet AND a Deployment and no HPA has a
        genuine HP002; excluding it because four of five objects are
        unscalable would hide a real finding behind a coverage note.
        """
        api, spec = BODIES["Deployment"]
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "{}\n",
            "templates/ds.yaml": ("apiVersion: apps/v1\nkind: DaemonSet\n"
                                  "metadata: {name: ds}\nspec:\n"
                                  + BODIES["DaemonSet"][1]),
            "templates/dep.yaml": (f"apiVersion: {api}\nkind: Deployment\n"
                                   f"metadata: {{name: t}}\nspec:\n{spec}"),
        })
        result = analyze(root)
        self.assertEqual(_hpa_state(result), "scored")
        self.assertIn("HP002", _ids(result))

    def test_a_chart_with_no_objects_at_all_is_not_applicable_to_nothing(self):
        """Blindness is not inapplicability.

        If nothing rendered, the tool holds no evidence about workload kinds
        and must not claim the question does not arise. Condition 2.
        """
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "{}\n"})
        result = analyze(root)
        self.assertEqual(_hpa_state(result), "unassessed")


class CoverageShapeTests(unittest.TestCase):
    """`complete` vs `all_scored`, and why they had to become two properties."""

    def test_complete_is_true_and_all_scored_is_false_on_an_isolating_chart(self):
        """The claim `complete` vs `all_scored` exists to make, isolated.

        On a chart with no other exclusion: the tool has no blind spot
        (complete), and the mean still ran over 85 weight points and not 100
        (not all_scored). `--require-coverage` reads `complete`, so it passes -
        a gate that failed here would be demanding the user put an HPA on a
        DaemonSet, which is the advice this whole round exists to stop.
        """
        cov = coverage(analyze(only_hpa_excluded()))
        self.assertEqual([c.name for c, _ in cov.unassessed], [])
        self.assertEqual([c.name for c, _ in cov.not_applicable], ["HPA"])
        self.assertTrue(cov.complete)
        self.assertFalse(cov.all_scored)
        self.assertEqual(cov.weight_assessed, cov.weight_total - WEIGHTS[Category.HPA])

    def test_complete_and_all_scored_are_different_claims(self):
        result = analyze(chart("DaemonSet"))
        cov = coverage(result)
        # all_scored is strictly narrower: it can never be True where
        # complete is False, and here it is False where complete may be either.
        self.assertFalse(cov.all_scored)
        self.assertTrue(cov.not_applicable)
        # The gate `--require-coverage` reads `complete`, and `complete` must
        # NOT count the not-applicable bucket - a build that failed here would
        # be demanding an HPA on a DaemonSet.
        self.assertEqual(cov.complete, not cov.unassessed)

    def test_not_applicable_is_not_folded_into_unassessed(self):
        """The old field keeps its old meaning exactly.

        Every consumer reading `cov.unassessed` today is enumerating the
        tool's blind spots. Widening that list would have filed a category the
        tool answered completely under a heading it had just disproved.
        """
        cov = coverage(analyze(chart("DaemonSet")))
        self.assertNotIn(Category.HPA, [c for c, _ in cov.unassessed])
        self.assertIn(Category.HPA, [c for c, _ in cov.not_applicable])

    def test_weight_leaves_the_denominator_exactly_as_unassessed_does(self):
        cov = coverage(analyze(chart("DaemonSet")))
        dropped = sum(WEIGHTS[c] for c, _ in cov.unassessed)
        dropped += sum(WEIGHTS[c] for c, _ in cov.not_applicable)
        self.assertEqual(cov.weight_assessed, cov.weight_total - dropped)
        self.assertEqual(cov.n_total, len(Category))

    def test_category_scores_yields_none_for_both_exclusions(self):
        for kind in ("DaemonSet", "Rollout"):
            with self.subTest(kind=kind):
                result = analyze(chart(kind))
                scores = {c: s for c, s, _ in category_scores(result)}
                self.assertIsNone(scores[Category.HPA])

    def test_one_line_names_the_two_buckets_separately(self):
        line = coverage(analyze(chart("DaemonSet"))).one_line()
        self.assertIn("not applicable: HPA", line)
        self.assertNotIn("NOT assessed: HPA", line)


class RenderTests(unittest.TestCase):
    """An exclusion that were true only inside the data structure fixes nothing.

    The defect this round removes is a STRING a human reads - "| Horizontal Pod
    Autoscaling | 100.0 | A+ |" - so the assertions have to reach the rendered
    artefacts too.
    """

    def _cells(self, text, label="Horizontal Pod Autoscaling"):
        return [ln for ln in text.splitlines()
                if label in ln and ln.lstrip().startswith("|")]

    def test_text_scorecard_says_not_applicable_not_a_number(self):
        root = chart("DaemonSet")
        result = analyze(root)
        text = render(result, root)
        rows = self._cells(text)
        self.assertEqual(len(rows), 1, rows)
        self.assertIn("not applicable", rows[0])
        self.assertNotIn("100.0", rows[0])
        self.assertIn("NOT applicable", text)

    def test_text_report_does_not_tell_the_reader_to_supply_an_input(self):
        """The comparability paragraph is conditional for a reason.

        "Adding the missing input can move it in either direction" is true of
        NOT ASSESSED and false of NOT APPLICABLE, and printing it here would
        send the reader looking for a file that does not exist.
        """
        root = only_hpa_excluded()
        text = render(analyze(root), root)
        self.assertNotIn("Adding the missing input", text)
        self.assertIn("the exclusion is a property of the chart", text)

    def test_the_advice_DOES_print_when_something_really_is_missing(self):
        """The control for the test above, and it is not optional.

        "the sentence is absent" passes just as well if the sentence was
        deleted outright, or if the paragraph stopped rendering. This asserts
        the same chart plus one genuine blind spot brings it back.
        """
        root = chart("DaemonSet")  # no Dockerfile, no JVM: JAVA/CROSS/DF out
        text = render(analyze(root), root)
        self.assertIn("Adding the missing input", text)
        self.assertIn("NOT applicable", text)
        self.assertIn("NOT assessed", text)

    def test_html_scorecard_separates_the_two_lists(self):
        root = chart("DaemonSet")
        result = analyze(root)
        html = render_html(result, root)
        self.assertIn("Not applicable", html)
        self.assertIn("not applicable", html)
        # and the badge must not claim a full-coverage run
        self.assertNotIn(">10 of 10 categories<", html)

    def test_rollout_report_still_says_not_assessed(self):
        root = chart("Rollout")
        text = render(analyze(root), root)
        self.assertIn("NOT assessed", text)
        rows = self._cells(text)
        self.assertEqual(len(rows), 1, rows)
        self.assertIn("not assessed", rows[0])


if __name__ == "__main__":
    unittest.main()

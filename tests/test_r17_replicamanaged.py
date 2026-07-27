"""R17: one defect, one verdict, whatever the kind is called.

`proof/p19_replicamanaged.py` argues the round end to end through the CLI.
These tests pin the parts a future edit could break silently, and they are
written as EQUALITY between kinds rather than as absolute numbers, on purpose:
the round's claim is not "a Rollout scores 85.7", it is "a Rollout scores what
a Deployment scores, because it is the same mistake". A rule added next month
should move all five rows together or the assertion should fail.

The set under test is `kube.REPLICA_MANAGED_KINDS`, and it answers a question
none of the tool's other kind sets answer: does this object carry a replica
count that the CHART AUTHOR chose? Not "can an HPA target it" - that is
SCALABLE_KINDS and the /scale subresource. Not "is the scale question
meaningful" - that is SCALE_CANDIDATE_KINDS, which includes DaemonSet
precisely so R16 can answer "not applicable". Rollout is in this set and not
in the other two; DaemonSet is in the others and not in this one. If those
three sets ever collapse into one, these tests should fail.
"""

import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer.kube import (REPLICA_MANAGED_KINDS, SCALABLE_KINDS,
                              SCALE_CANDIDATE_KINDS)
from hpaanalyzer.scoring import overall_grade, overall_score

from .util import CHART_YAML, make_tree

_POD = ("      containers:\n        - name: app\n"
        "          image: repo/app:1.0\n"
        "          resources:\n            requests: {cpu: 500m, memory: 1Gi}\n"
        "            limits: {cpu: 500m, memory: 1Gi}\n")
_JVM_POD = ("      containers:\n        - name: app\n"
            "          image: eclipse-temurin:21-jre\n"
            "          env:\n            - name: JAVA_TOOL_OPTIONS\n"
            '              value: "-Xmx6g"\n'
            "          resources:\n            requests: {cpu: 500m, memory: 4Gi}\n"
            "            limits: {cpu: 500m, memory: 4Gi}\n")
_SEL = ("  selector:\n    matchLabels: {app: t}\n"
        "  template:\n    metadata:\n      labels: {app: t}\n    spec:\n")
_RC_SEL = ("  selector: {app: t}\n"
           "  template:\n    metadata:\n      labels: {app: t}\n    spec:\n")

# apiVersion + the spec fields each kind's schema makes mandatory, and nothing
# else. Every chart below is the same chart with one word changed.
BODIES = {
    "Deployment": ("apps/v1", "  replicas: 3\n" + _SEL),
    "StatefulSet": ("apps/v1", "  serviceName: t\n  replicas: 3\n" + _SEL),
    "ReplicaSet": ("apps/v1", "  replicas: 3\n" + _SEL),
    "ReplicationController": ("v1", "  replicas: 3\n" + _RC_SEL),
    "Rollout": ("argoproj.io/v1alpha1", "  replicas: 3\n" + _SEL),
    "DaemonSet": ("apps/v1", _SEL),
    "Job": ("batch/v1",
            "  template:\n    metadata:\n      labels: {app: t}\n"
            "    spec:\n      restartPolicy: Never\n"),
}

REPLICA_MANAGED = ["Deployment", "StatefulSet", "ReplicaSet",
                   "ReplicationController", "Rollout"]
NOT_REPLICA_MANAGED = ["DaemonSet", "Job"]

# The advice that only makes sense for an object whose replica count someone
# chose. R16 deleted the DaemonSet version of exactly this advice; if any of
# these reappears on a DaemonSet, R17 has put it back under new rule IDs.
REPLICA_RULES = {"HP050", "HP051", "AV001", "AV002", "AV003", "AV010"}

HPA = ("apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
       "metadata: {name: t}\nspec:\n"
       "  scaleTargetRef: {apiVersion: %s, kind: %s, name: t}\n"
       "  minReplicas: 2\n  maxReplicas: 8\n"
       "  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
       "  metrics:\n    - type: Resource\n"
       "      resource: {name: cpu, target: {type: Utilization, "
       "averageUtilization: 70}}\n")


def chart(kind, with_hpa=True, pod=_POD, second=None):
    api, spec = BODIES[kind]
    files = {
        "Chart.yaml": CHART_YAML,
        "values.yaml": "{}\n",
        "templates/w.yaml": (f"apiVersion: {api}\nkind: {kind}\n"
                             f"metadata: {{name: t}}\nspec:\n{spec}{pod}"),
    }
    if with_hpa:
        files["templates/hpa.yaml"] = HPA % (api, kind)
    if second:
        api2, spec2 = BODIES[second]
        files["templates/w2.yaml"] = (f"apiVersion: {api2}\nkind: {second}\n"
                                      f"metadata: {{name: t2}}\nspec:\n{spec2}{pod}")
    return make_tree(files)


def ids(result):
    return {f.rule_id for f in result.findings}


class KindSetsAreThreeDifferentQuestions(unittest.TestCase):
    """The sets must not be interchangeable, or the fix collapses back."""

    def test_rollout_is_replica_managed_but_not_scalable(self):
        # An Argo Rollout has spec.replicas that a chart author wrote, and no
        # /scale subresource this tool has any business assuming.
        self.assertIn("rollout", REPLICA_MANAGED_KINDS)
        self.assertNotIn("rollout", SCALABLE_KINDS)

    def test_daemonset_is_a_scale_candidate_but_not_replica_managed(self):
        # R16 needs DaemonSet in SCALE_CANDIDATE_KINDS so it can print "not
        # applicable" instead of scoring silence at 100. R17 needs it OUT of
        # REPLICA_MANAGED_KINDS so nothing tells it to add replicas.
        self.assertIn("daemonset", SCALE_CANDIDATE_KINDS)
        self.assertNotIn("daemonset", REPLICA_MANAGED_KINDS)

    def test_replicationcontroller_is_in_all_three(self):
        for s in (REPLICA_MANAGED_KINDS, SCALABLE_KINDS, SCALE_CANDIDATE_KINDS):
            self.assertIn("replicationcontroller", s)


class OneDefectOneVerdict(unittest.TestCase):
    """`replicas: 3` plus an HPA on the same object is HP050 on every kind."""

    def setUp(self):
        self.res = {k: analyze(chart(k)) for k in REPLICA_MANAGED}

    def test_hp050_fires_on_every_replica_managed_kind(self):
        for k, r in self.res.items():
            self.assertIn("HP050", ids(r), f"{k} did not get HP050")

    def test_the_score_does_not_depend_on_the_kind_name(self):
        base = overall_score(self.res["Deployment"])
        for k, r in self.res.items():
            self.assertEqual(overall_score(r), base,
                             f"{k} scored {overall_score(r)}, Deployment {base}")

    def test_the_finding_set_does_not_depend_on_the_kind_name(self):
        base = ids(self.res["Deployment"])
        for k, r in self.res.items():
            self.assertEqual(ids(r), base,
                             f"{k} differs by {ids(r) ^ base}")

    def test_the_critical_grade_cap_engages_on_every_kind(self):
        # This is the part that a "just a missing finding" reading misses.
        # HP050 is CRITICAL and R14 caps the OVERALL grade at C for a
        # non-ASSUMED critical, so ReplicaSet and Rollout were not losing a
        # deduction, they were escaping the cap: 92.5 / A- for the defect that
        # gets a Deployment capped at C.
        for k, r in self.res.items():
            _g, reason = overall_grade(r, overall_score(r))
            self.assertTrue(reason,
                            f"{k} was not grade-capped despite a CRITICAL")
            self.assertEqual(_g, "C", f"{k} graded {_g}")

    def test_replicationcontroller_is_graded_at_all(self):
        # It used to be filtered out by ChartContext.workloads before any rule
        # ran, which set ungradeable_reason (F9) and printed NOT GRADED - a
        # report the reader cannot distinguish from "this chart has no
        # workload in it".
        r = self.res["ReplicationController"]
        self.assertIsNotNone(overall_score(r))
        self.assertIn("ReplicationController",
                      [d.kind for d in r.context.workloads])


class TheKindsThatMustNotMove(unittest.TestCase):
    """Over-correction is the failure mode of this fix, so it gets its own test."""

    def test_no_replica_advice_on_kinds_that_do_not_choose_their_replicas(self):
        for k in NOT_REPLICA_MANAGED:
            got = REPLICA_RULES & ids(analyze(chart(k)))
            self.assertFalse(got, f"{k} was given replica-managed advice: {got}")


class Av010NamesWhatIsActuallyThere(unittest.TestCase):
    """The detail string was a constant naming two kinds that might be absent."""

    def _detail(self, result):
        return [f.detail for f in result.findings if f.rule_id == "AV010"]

    def test_a_single_kind_chart_names_that_kind(self):
        for k in REPLICA_MANAGED:
            self.assertEqual(self._detail(analyze(chart(k))),
                             [f"Chart ships {k} but no PDB."])

    def test_a_two_kind_chart_names_both_sorted(self):
        r = analyze(chart("Deployment", second="StatefulSet"))
        self.assertEqual(self._detail(r),
                         ["Chart ships Deployment, StatefulSet but no PDB."])

    def test_no_pdb_advice_at_all_when_nothing_is_replica_managed(self):
        self.assertEqual(self._detail(analyze(chart("DaemonSet"))), [])


class JvmArithmeticIsKindBlind(unittest.TestCase):
    """`proofs._pairs()` gates every XF rule; its kind list is now gone."""

    def test_every_workload_kind_gets_the_same_cross_file_verdict(self):
        # -Xmx6g under a 4Gi limit is the same OOM whoever creates the pod.
        # The literal deleted here was `ctx.workloads`' own contents as of
        # R15, hand-copied; R17 added ReplicationController to that list and
        # this copy went stale the same day. Measured before the fix:
        # Deployment 88.9/C with XF001, ReplicationController 92.7/A- silent.
        seen = {}
        for k in REPLICA_MANAGED + NOT_REPLICA_MANAGED:
            r = analyze(chart(k, with_hpa=False, pod=_JVM_POD))
            seen[k] = {i for i in ids(r) if i.startswith("XF")}
        self.assertTrue(all(v for v in seen.values()),
                        f"some kind got no XF finding at all: {seen}")
        self.assertEqual(len(set(map(frozenset, seen.values()))), 1, str(seen))


class BasisDoesNotTurnOnAnUnrelatedKind(unittest.TestCase):
    """ASSUMED is arithmetic, not a label: effective_deduction() caps it at HIGH."""

    _DOCKERFILE = ('FROM eclipse-temurin:21-jre\n'
                   'ENV JAVA_OPTS="-XX:MaxRAMPercentage=75"\n'
                   'ENTRYPOINT ["java","-jar","/app.jar"]\n')
    _MEM_HPA = ("apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
                "metadata: {name: t}\nspec:\n"
                "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: t}\n"
                "  minReplicas: 2\n  maxReplicas: 8\n"
                "  behavior: {scaleDown: {stabilizationWindowSeconds: 300}}\n"
                "  metrics:\n    - type: Resource\n"
                "      resource: {name: memory, target: {type: Utilization, "
                "averageUtilization: 70}}\n")

    def _chart(self, second=None):
        # A NEUTRAL container image is load-bearing. With a JVM image
        # _target_is_jvm returns OBSERVED from the container itself and never
        # reaches the branch under test - the first attempt at this
        # measurement did exactly that and proved nothing.
        api, spec = BODIES["Deployment"]
        files = {
            "Chart.yaml": CHART_YAML,
            "values.yaml": "{}\n",
            "Dockerfile": self._DOCKERFILE,
            "templates/w.yaml": (f"apiVersion: {api}\nkind: Deployment\n"
                                 f"metadata: {{name: t}}\nspec:\n{spec}{_POD}"),
            "templates/hpa.yaml": self._MEM_HPA,
        }
        if second:
            api2, spec2 = BODIES[second]
            files["templates/w2.yaml"] = (f"apiVersion: {api2}\nkind: {second}\n"
                                          f"metadata: {{name: t2}}\nspec:\n"
                                          f"{spec2}{_POD}")
        return make_tree(files)

    def _basis(self, result):
        return [f.basis.value for f in result.findings if f.rule_id == "HP025"]

    def test_a_genuinely_single_workload_chart_is_still_assumed(self):
        # The ASSUMED branch is honest where it applies and must survive.
        self.assertEqual(self._basis(analyze(self._chart())), ["assumed"])

    def test_a_second_workload_makes_it_derived_whatever_its_kind_is(self):
        for second in ["Deployment", "StatefulSet", "ReplicaSet", "Rollout"]:
            with self.subTest(second=second):
                self.assertEqual(self._basis(analyze(self._chart(second))),
                                 ["derived"],
                                 f"a second {second} did not remove the guess")


if __name__ == "__main__":
    unittest.main()

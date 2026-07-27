"""R15: six defects where the tool accepted an input and then did not act on it.

Each test here pins one of them. They are worth pinning as unit tests rather
than leaving to `proof/p17_flagmatrix.py` for one reason: four of the six are
invisible in any single report. A flag that did nothing produces output that
looks exactly like a flag that worked, so the only thing that catches it is
comparing two runs that differ ONLY in that flag - which is a shape a test can
express and a reader of one report cannot.
"""

import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer.html_report import render_html
from hpaanalyzer.models import Severity
from hpaanalyzer.report import render
from hpaanalyzer.scoring import coverage, overall_score

from .util import CHART_YAML, make_tree

DEPLOY = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web}\n"
    "spec:\n  replicas: 2\n  selector: {matchLabels: {app: a}}\n"
    "  template:\n    metadata: {labels: {app: a}}\n    spec:\n"
    "      containers:\n        - name: app\n          image: %s\n"
    "%s"
    "          resources:\n            requests: {cpu: 500m, memory: 1Gi}\n"
    "            limits: {memory: 1Gi}\n")


def deploy(image="eclipse-temurin:17-jre", extra=""):
    return DEPLOY % (image, extra)


def _ids(r):
    return {f.rule_id for f in r.findings}


def _sev(r, rid):
    return sorted({f.severity for f in r.findings if f.rule_id == rid})


# The API here is real: extensions/v1beta1 Ingress was removed in 1.22, and
# policy/v1beta1 PodDisruptionBudget in 1.25. The chart declares a kubeVersion
# that stops before either removal, so the chart's own opinion and the operator's
# --kube-version disagree - which is the whole point.
OLD_KV_CHART = CHART_YAML.replace('kubeVersion: ">=1.23.0-0"',
                                  'kubeVersion: ">=1.19.0-0 <1.21.0-0"')
INGRESS = ("apiVersion: extensions/v1beta1\nkind: Ingress\n"
           "metadata: {name: web}\nspec: {rules: []}\n")


def _kv_chart():
    return make_tree({
        "Chart.yaml": OLD_KV_CHART,
        "values.yaml": "x: 1\n",
        "templates/deployment.yaml": deploy(),
        "templates/ingress.yaml": INGRESS,
    })


class TestKubeVersionReachesDeprecatedApiRanking(unittest.TestCase):
    """D1. The flag was accepted, stored, printed in the mode line - and never
    consulted by the rule whose severity it exists to decide. Two runs of the
    same chart eleven minor versions apart were byte-identical in outcome."""

    def test_flag_changes_severity_and_score(self):
        root = _kv_chart()
        old = analyze(root, helm_mode="off", kube_version="1.20.0")
        new = analyze(root, helm_mode="off", kube_version="1.31.0")
        self.assertIn("TP010", _ids(old))
        self.assertIn("TP010", _ids(new))
        self.assertEqual(_sev(old, "TP010"), [Severity.LOW])
        self.assertEqual(_sev(new, "TP010"), [Severity.CRITICAL])
        self.assertLess(overall_score(new), overall_score(old),
                        "naming a cluster where the API is gone must cost "
                        "something; if it does not, the flag is decoration")

    def test_the_conflict_is_stated_not_resolved_silently(self):
        """The chart says <1.21 and the operator says 1.31. Picking the operator
        is correct - doing it without saying so is not, because the reader has
        no way to tell the finding was ranked against something other than the
        file in front of them."""
        r = analyze(_kv_chart(), helm_mode="off", kube_version="1.31.0")
        txt = " ".join(" ".join((f.detail + " " + f.why).split())
                       for f in r.findings if f.rule_id == "TP010")
        self.assertIn("does not admit 1.31", txt)
        self.assertIn("you have stated otherwise", txt)

    def test_without_the_flag_the_chart_is_still_believed(self):
        """The override is an override. With no flag the chart's declared range
        is the only evidence there is, and R3's behaviour must survive."""
        r = analyze(_kv_chart(), helm_mode="off")
        self.assertEqual(_sev(r, "TP010"), [Severity.LOW])


class TestAssumeJavaStatesAVersionNotARuntime(unittest.TestCase):
    """D2. `--assume-java 17` on an nginx chart moved JAVA and CROSS out of the
    unassessed list, filed JVM findings against nginx, and RAISED the score,
    because two categories holding nothing joined the mean at their starting
    100. The flag answers "which Java", not "is there a Java"."""

    def _nginx(self):
        return make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": deploy(image="nginx:1.27-alpine"),
        })

    def test_no_jvm_evidence_means_the_flag_is_declined(self):
        root = self._nginx()
        base = analyze(root, helm_mode="off")
        flag = analyze(root, helm_mode="off", assume_java="17")
        self.assertEqual(overall_score(base), overall_score(flag))
        self.assertEqual(_ids(base), _ids(flag))
        self.assertFalse([i for i in _ids(flag) if i.startswith(("JV", "XF"))])
        cov = coverage(flag)
        self.assertIn("JAVA", str(cov.unassessed))
        self.assertIn("CROSS", str(cov.unassessed))

    def test_and_the_refusal_is_explained_rather_than_silent(self):
        r = analyze(self._nginx(), helm_mode="off", assume_java="17")
        joined = " ".join(" ".join(str(x).split()) for row in r.context.coverage
                          for x in row)
        self.assertIn("NOT applied", joined)
        self.assertIn("--assume-java 17", joined)

    def test_with_jvm_evidence_the_flag_still_works(self):
        """The fix must not have been "ignore the flag". A chart with a JVM in
        the pod spec but an unreadable version is exactly what it is for."""
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "Dockerfile": "FROM corp.registry/base:4.2\n"
                          'ENTRYPOINT ["java","-jar","a.jar"]\n',
            "templates/deployment.yaml": deploy(
                image="corp.registry/payments-api:4.2",
                extra="          env:\n"
                      "            - {name: JAVA_TOOL_OPTIONS, value: -Xmx512m}\n"),
        })
        r = analyze(root, helm_mode="off", assume_java="8u102")
        self.assertEqual(r.context.assumed_java, "8u102")
        joined = " ".join(" ".join(str(x).split()) for row in r.context.coverage
                          for x in row)
        self.assertIn("ASSUMED 8u102", joined)


class TestHtmlHeadlineDoesNotRoundAcrossAGradeBoundary(unittest.TestCase):
    """D3. `{score:.0f}` printed 93/100 beside the letter A- for a chart the
    text report scored 92.9 - and 93 is exactly the A threshold, so the first
    thing a reader saw was one document disagreeing with itself."""

    def test_one_decimal_in_the_badge(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": deploy(),
        })
        r = analyze(root, helm_mode="off")
        score = overall_score(r)
        html = render_html(r, "t")
        self.assertIn(f"{score:.1f}/100", html)
        # The specific failure: the rounded form must not appear as the badge.
        if abs(score - round(score)) > 0.04:
            self.assertNotIn(f">{score:.0f}/100<", html)

    def test_the_badge_and_the_text_report_agree(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": deploy(),
        })
        r = analyze(root, helm_mode="off")
        score = overall_score(r)
        self.assertIn(f"{score:5.1f} / 100", render(r, "t"))
        self.assertIn(f"{score:.1f}/100", render_html(r, "t"))


CRONJOB = """apiVersion: batch/v1
kind: CronJob
metadata: {name: batch}
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: app
              image: eclipse-temurin:17-jre
              env:
                - {name: JAVA_TOOL_OPTIONS, value: "-Xmx6g"}
              resources:
                requests: {cpu: 500m, memory: 2Gi}
                limits: {memory: 4Gi}
"""

HPA_ON_CRONJOB = """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: batch}
spec:
  scaleTargetRef: {apiVersion: batch/v1, kind: CronJob, name: batch}
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource: {name: cpu, target: {type: Utilization, averageUtilization: 70}}
"""


def _cronjob_chart():
    return make_tree({
        "Chart.yaml": CHART_YAML,
        "values.yaml": "x: 1\n",
        "templates/cronjob.yaml": CRONJOB,
        "templates/hpa.yaml": HPA_ON_CRONJOB,
    })


class TestWorkloadKindFilterIsNotACoverageGate(unittest.TestCase):
    """D4, and the fourth appearance of the R8/R11/R13/R14b fault. proofs._pairs()
    admitted only Deployment/StatefulSet/DaemonSet, so a CronJob setting -Xmx6g
    under a 4Gi limit got no heap arithmetic at all - while Cross-File
    Consistency still scored 100.0/A+ at fourteen weight points, because a
    category with no findings is indistinguishable from a category with nothing
    wrong."""

    def test_the_guaranteed_oom_is_found_on_a_cronjob(self):
        r = analyze(_cronjob_chart(), helm_mode="off")
        self.assertIn("XF001", _ids(r))
        self.assertIn(Severity.CRITICAL, _sev(r, "XF001"))

    def test_the_jvm_proof_tables_render_for_a_cronjob(self):
        r = analyze(_cronjob_chart(), helm_mode="off")
        self.assertTrue(any("CronJob" in p.title and "app" in p.title
                            for p in r.proofs),
                        "no proof table names the CronJob's container; the "
                        "JVM pass did not run at all")

    def test_the_grade_reflects_it(self):
        r = analyze(_cronjob_chart(), helm_mode="off")
        self.assertIsNotNone(overall_score(r))
        self.assertIn("GRADE", render(r, "t"))
        self.assertNotIn("| 100.0 | A+ |", render(r, "t").replace("  ", " "))


class TestScaleTargetRefKindIsChecked(unittest.TestCase):
    """D5. The target resolved by NAME, so nothing complained - and a CronJob
    has no `scale` subresource, so the controller reports FailedGetScale and
    never scales anything. The tool printed a full scaling table for behaviour
    that cannot occur."""

    def test_unscalable_kind_is_critical(self):
        r = analyze(_cronjob_chart(), helm_mode="off")
        self.assertIn("HP042", _ids(r))
        self.assertEqual(_sev(r, "HP042"), [Severity.CRITICAL])

    def test_the_scaling_table_says_none_of_this_happens(self):
        r = analyze(_cronjob_chart(), helm_mode="off")
        tables = [p for p in r.proofs if "INERT" in p.title]
        self.assertTrue(tables, "the scaling table still presents itself as "
                                "a description of what will happen")
        self.assertIn("NONE OF THIS HAPPENS", tables[0].conclusion)
        self.assertIn("HP042", tables[0].conclusion)

    def test_a_scalable_kind_is_left_alone(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": deploy(),
            "templates/hpa.yaml": HPA_ON_CRONJOB.replace(
                "{apiVersion: batch/v1, kind: CronJob, name: batch}",
                "{apiVersion: apps/v1, kind: Deployment, name: web}"),
        })
        self.assertNotIn("HP042", _ids(analyze(root, helm_mode="off")))

    def test_an_unrecognised_kind_gets_no_finding(self):
        """Argo Rollouts, KEDA ScaledObjects and any number of CRDs implement
        `scale` properly. Withholding a claim never becomes asserting one."""
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": deploy(),
            "templates/hpa.yaml": HPA_ON_CRONJOB.replace(
                "{apiVersion: batch/v1, kind: CronJob, name: batch}",
                "{apiVersion: argoproj.io/v1alpha1, kind: Rollout, name: web}"),
        })
        self.assertNotIn("HP042", _ids(analyze(root, helm_mode="off")))


class TestHelmRefusalAdviceReadsTheArguments(unittest.TestCase):
    """D6. One canned paragraph, wrong two ways at once: it explained every helm
    refusal as a kubeVersion problem, and it interpolated the run's own
    --kube-version into its example, so a run invoked with --kube-version 1.31.0
    ended by advising the operator to re-run with --kube-version 1.31.0."""

    def _ctx_with_error(self, err, kv=None):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": deploy(),
        })
        r = analyze(root, helm_mode="off", kube_version=kv)
        r.context.helm_error = err
        return r

    def test_a_non_kubeversion_refusal_is_not_called_one(self):
        r = self._ctx_with_error(
            "helm template exited 1: Error: execution error at "
            "(t/templates/deployment.yaml:19:52): image.tag must be set")
        flat = " ".join(render(r, "t").split())
        self.assertIn("not a kubeVersion problem", flat)
        self.assertIn("names the actual cause", flat)

    def test_it_does_not_advise_re_running_with_the_flag_already_given(self):
        r = self._ctx_with_error(
            "helm template exited 1: Error: chart requires kubeVersion: "
            ">=1.19.0-0 <1.21.0-0 which is incompatible with Kubernetes v1.31.0",
            kv="1.31.0")
        flat = " ".join(render(r, "t").split())
        self.assertNotIn("Re-run with an explicit --kube-version", flat)
        self.assertIn("You already supplied `--kube-version 1.31.0`", flat)

    def test_with_no_flag_the_default_cluster_explanation_survives(self):
        r = self._ctx_with_error(
            "helm template exited 1: Error: chart requires kubeVersion: "
            ">=1.19.0-0 <1.21.0-0 which is incompatible with Kubernetes v1.33.0")
        flat = " ".join(render(r, "t").split())
        self.assertIn("--kube-version", flat)
        self.assertNotIn("You already supplied", flat)


if __name__ == "__main__":
    unittest.main()

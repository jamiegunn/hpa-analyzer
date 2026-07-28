"""Dockerfile/JVM rule edges: version-specific branches and flag-reality cases.

The JDK container-awareness timeline in checks_docker is a set of version
fences (8u131 / 8u191 / 8u372 / 11.0.16 / 14 / 15); the main suite exercises
one point on it (8u151). These tests pin the other fences - including the
NEGATIVE side of each, because a fence that fires everywhere is as wrong as
one that fires nowhere.
"""

import unittest

from hpaanalyzer import checks_docker
from hpaanalyzer.discovery import discover
from hpaanalyzer.engine import analyze
from hpaanalyzer.models import AnalysisResult, Severity

from .util import CHART_YAML, make_tree


def rules(result):
    return {f.rule_id for f in result.findings}


def find(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def df_chart(dockerfile):
    return make_tree({"Dockerfile": dockerfile})


JAVA_EP = 'ENTRYPOINT ["java","-jar","a.jar"]\n'


class TestBaseImageEdges(unittest.TestCase):
    def test_dockerfile_without_from_is_unparseable_base(self):
        r = analyze(df_chart("RUN echo hi\n"), helm_mode="off")
        hits = find(r, "DF001")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)
        # no base image -> no Java version claims of any kind
        self.assertFalse({"JV001", "JV002", "DF003"} & rules(r))

    def test_non_lts_release_is_flagged(self):
        r = analyze(df_chart("FROM openjdk:15-jre\n" + JAVA_EP), helm_mode="off")
        hits = find(r, "JV002")
        self.assertEqual(len(hits), 1)
        self.assertIn("15", hits[0].detail)

    def test_lts_17_is_not_called_non_lts(self):
        r = analyze(df_chart("FROM eclipse-temurin:17-jre\n" + JAVA_EP),
                    helm_mode="off")
        self.assertNotIn("JV002", rules(r))


class TestJava8UpdateFences(unittest.TestCase):
    def test_unpinned_8_tag_gets_the_unverifiable_finding(self):
        # 'openjdk:8' reveals no update level: container support cannot be
        # placed on the 131/191 timeline, so JV012 - and NOT JV010/JV011,
        # which would each be a claim about an update nobody stated.
        r = analyze(df_chart("FROM openjdk:8\n" + JAVA_EP), helm_mode="off")
        self.assertIn("JV012", rules(r))
        self.assertFalse({"JV010", "JV011", "JV013"} & rules(r))

    def test_modern_8u392_passes_every_container_awareness_fence(self):
        # 8u392 is past the UseContainerSupport backport (191) AND past the
        # cgroup-v2 fence (372): the Java 8 finding stays (JV001), the
        # awareness ones must not.
        r = analyze(df_chart("FROM openjdk:8u392-jre\n" + JAVA_EP),
                    helm_mode="off")
        self.assertIn("JV001", rules(r))
        self.assertFalse({"JV010", "JV011", "JV012", "JV013"} & rules(r))

    def test_8u151_with_experimental_flags_applied_downgrades_to_high(self):
        r = analyze(df_chart(
            "FROM openjdk:8u151-jre\n"
            'ENV JAVA_TOOL_OPTIONS="-XX:+UnlockExperimentalVMOptions '
            '-XX:+UseCGroupMemoryLimitForHeap"\n' + JAVA_EP), helm_mode="off")
        hits = find(r, "JV011")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)
        self.assertIn("ARE present and applied", hits[0].detail)

    def test_8u151_with_experimental_flags_only_in_inert_var_stays_critical(self):
        # the flags exist in JAVA_OPTS but nothing expands JAVA_OPTS - the JVM
        # runs exactly like a flagless one, and JV011 must say so
        r = analyze(df_chart(
            "FROM openjdk:8u151-jre\n"
            'ENV JAVA_OPTS="-XX:+UnlockExperimentalVMOptions '
            '-XX:+UseCGroupMemoryLimitForHeap"\n' + JAVA_EP), helm_mode="off")
        hits = find(r, "JV011")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)
        self.assertIn("INERT", hits[0].detail)
        self.assertIn("DF013", rules(r))


class TestCgroupV2Fences(unittest.TestCase):
    def test_java_11_below_11_0_16_is_blind_to_cgroup_v2(self):
        r = analyze(df_chart("FROM eclipse-temurin:11.0.9-jre\n" + JAVA_EP),
                    helm_mode="off")
        hits = find(r, "JV013")
        self.assertEqual(len(hits), 1)
        self.assertIn("11.0.9", hits[0].title)

    def test_java_14_never_received_cgroup_v2(self):
        r = analyze(df_chart("FROM openjdk:14-jre\n" + JAVA_EP), helm_mode="off")
        hits = find(r, "JV013")
        self.assertEqual(len(hits), 1)
        self.assertIn("added in 15", hits[0].title)

    def test_java_17_gets_no_cgroup_v2_finding(self):
        r = analyze(df_chart("FROM eclipse-temurin:17-jre\n" + JAVA_EP),
                    helm_mode="off")
        self.assertNotIn("JV013", rules(r))


class TestRemovedAndDisabledFlags(unittest.TestCase):
    def test_disabled_container_support_and_removed_flags_on_17(self):
        # three independent CRITICALs from one env var: support explicitly
        # off, a flag removed in 11 (start-up abort), CMS removed in 14
        r = analyze(df_chart(
            "FROM openjdk:17-jdk\n"
            'ENV JAVA_TOOL_OPTIONS="-XX:-UseContainerSupport '
            '-XX:+UseCGroupMemoryLimitForHeap -XX:+UseConcMarkSweepGC"\n'
            + JAVA_EP), helm_mode="off")
        for rid in ("JV014", "JV015", "JV016"):
            hits = find(r, rid)
            self.assertEqual(len(hits), 1, rid)
            self.assertIs(hits[0].severity, Severity.CRITICAL, rid)

    def test_clean_17_image_raises_none_of_the_removed_flag_findings(self):
        r = analyze(df_chart("FROM eclipse-temurin:17-jre\n" + JAVA_EP),
                    helm_mode="off")
        self.assertFalse({"JV014", "JV015", "JV016"} & rules(r))


class TestHeapFlagQuality(unittest.TestCase):
    def _run(self, opts):
        return analyze(df_chart(
            "FROM eclipse-temurin:17-jre\n"
            f'ENV JAVA_TOOL_OPTIONS="{opts}"\n' + JAVA_EP), helm_mode="off")

    def test_maxrampercentage_at_90_leaves_no_nonheap_room(self):
        r = self._run("-XX:MaxRAMPercentage=90")
        hits = find(r, "JV022")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)

    def test_unparseable_maxrampercentage_makes_no_percentage_claim(self):
        # 'abc' is not a percentage: JV022 (too high) would be an invented
        # number, and JV021 (nothing applied) would deny a flag that IS there.
        r = self._run("-XX:MaxRAMPercentage=abc")
        self.assertNotIn("JV022", rules(r))
        self.assertNotIn("JV021", rules(r))

    def test_deprecated_maxramfraction(self):
        r = self._run("-XX:MaxRAMFraction=2")
        self.assertEqual(len(find(r, "JV023")), 1)

    def test_both_xmx_and_percentage_is_flagged_redundant(self):
        r = self._run("-Xmx512m -XX:MaxRAMPercentage=50")
        hits = find(r, "JV025")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.LOW)

    def test_exitonoom_defined_but_inert_is_named_in_jv026(self):
        r = analyze(df_chart(
            "FROM eclipse-temurin:17-jre\n"
            'ENV JAVA_OPTS="-XX:+ExitOnOutOfMemoryError"\n' + JAVA_EP),
            helm_mode="off")
        hits = find(r, "JV026")
        self.assertEqual(len(hits), 1)
        self.assertIn("inert variable", hits[0].detail)


class TestEntrypointForms(unittest.TestCase):
    def test_shell_form_entrypoint_loses_sigterm(self):
        r = analyze(df_chart("FROM eclipse-temurin:17-jre\n"
                             "ENTRYPOINT java -Xmx512m -jar a.jar\n"),
                    helm_mode="off")
        hits = find(r, "DF011")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.HIGH)
        self.assertNotIn("DF012", rules(r))

    def test_exec_form_with_variable_is_never_expanded(self):
        r = analyze(df_chart("FROM eclipse-temurin:17-jre\n"
                             'ENTRYPOINT ["java", "$JAVA_OPTS", "-jar", "a.jar"]\n'),
                    helm_mode="off")
        hits = find(r, "DF012")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.CRITICAL)
        self.assertNotIn("DF011", rules(r))


class TestHygieneEdges(unittest.TestCase):
    def test_apt_without_list_cleanup_and_healthcheck(self):
        r = analyze(df_chart(
            "FROM eclipse-temurin:17-jre\n"
            "RUN apt-get update && apt-get install -y curl\n"
            "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n" + JAVA_EP),
            helm_mode="off")
        self.assertEqual(len(find(r, "DF023")), 1)
        hits = find(r, "DF024")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.INFO)

    def test_apt_with_cleanup_in_same_layer_passes(self):
        r = analyze(df_chart(
            "FROM eclipse-temurin:17-jre\n"
            "RUN apt-get update && apt-get install -y curl "
            "&& rm -rf /var/lib/apt/lists/*\n" + JAVA_EP), helm_mode="off")
        self.assertNotIn("DF023", rules(r))


DEP_PLAIN = """apiVersion: apps/v1
kind: Deployment
metadata: {name: plain}
spec:
  selector: {matchLabels: {app: p}}
  template:
    metadata: {labels: {app: p}}
    spec:
      containers:
        - name: web
          image: "myco/webapp:1.0"
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {memory: 128Mi}
"""

DEP_JVM = """apiVersion: apps/v1
kind: Deployment
metadata: {name: japp}
spec:
  selector: {matchLabels: {app: j}}
  template:
    metadata: {labels: {app: j}}
    spec:
      containers:
        - name: istio-proxy
          image: istio/proxyv2:1.20
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {memory: 128Mi}
        - name: app
          image: "repo/japp:1.0"
          env:
            - name: JAVA_TOOL_OPTIONS
              value: "%(opts)s"
          resources:
            requests: {cpu: 500m, memory: 1Gi}
            limits: {memory: 1Gi}
"""


class TestNoDockerfileJvmPath(unittest.TestCase):
    """R8/F4: JVM checks run from the pod spec alone - and their findings must
    point at the template carrying the evidence, not at a blank location."""

    def _chart(self, opts):
        return make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            # alphabetically first: a workload with NO JVM evidence, so the
            # anchor search has to walk past it (and past the sidecar) to the
            # container that actually carries JAVA_TOOL_OPTIONS
            "templates/a-plain.yaml": DEP_PLAIN,
            "templates/b-app.yaml": DEP_JVM % {"opts": opts},
        })

    def test_flag_findings_anchor_on_the_evidencing_template(self):
        r = analyze(self._chart("-Xmx4g"), helm_mode="off")
        df000 = find(r, "DF000")
        self.assertEqual(len(df000), 1)
        self.assertIn("STILL CHECKED", df000[0].detail)
        hits = find(r, "JV026")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].file, "templates/b-app.yaml")

    def test_no_heap_sizing_without_dockerfile_is_held_at_medium(self):
        # a flag is applied (G1) but no heap bound: JV021 fires, and with no
        # Dockerfile the JDK version is unknown, so the HIGH variant - argued
        # from old-JVM behaviour - may not be asserted
        r = analyze(self._chart("-XX:+UseG1GC"), helm_mode="off")
        hits = find(r, "JV021")
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].severity, Severity.MEDIUM)
        self.assertIn("No Dockerfile was in scope", hits[0].detail)
        self.assertEqual(hits[0].file, "templates/b-app.yaml")


class TestCoverageRowIdempotence(unittest.TestCase):
    def test_no_jvm_coverage_row_is_written_at_most_once(self):
        # the guard in _no_jvm_evidence exists so re-running the module on a
        # context can never duplicate the coverage row a reader greps for
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/d.yaml": DEP_PLAIN,
        })
        ctx = discover(root, helm_mode="off")
        res = AnalysisResult(context=ctx)
        checks_docker.run(ctx, res)
        checks_docker.run(ctx, res)
        rows = [row for row in ctx.coverage if row and row[0] == "Java / JVM checks"]
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()

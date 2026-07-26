"""Regression tests for defects found in adversarial review - each test
pins a bug that shipped once and must never ship again."""

import unittest
from unittest import mock

from hpaanalyzer import discovery
from hpaanalyzer.dockerparse import (effective_flags, inert_opt_vars,
                                     parse_dockerfile)
from hpaanalyzer.engine import analyze
from hpaanalyzer.helmyaml import (deep_merge, enclosing_conditions,
                                  load_yaml_docs, resolve_markers,
                                  scrub_template)
from hpaanalyzer.kube import container_jvm_evidence, dockerfile_jvm_evidence
from hpaanalyzer.models import Basis, Category, Severity
from hpaanalyzer.scoring import overall_score, unassessed_reason

from .util import CHART_YAML, DEPLOYMENT_TPL, HPA_TPL, make_tree


def _ids(r):
    return {f.rule_id for f in r.findings}


def _by_id(r, rid):
    return [f for f in r.findings if f.rule_id == rid]


def parse(text):
    return parse_dockerfile("Dockerfile", text)


class TestNestedChartHelmMapping(unittest.TestCase):
    """Defect: chart in a subdirectory made every rendered doc appear
    duplicated as 'not rendered' because Source paths didn't match."""

    RENDERED = """---
# Source: t/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: release-name-app}
spec:
  replicas: 2
  selector: {matchLabels: {app: t}}
  template:
    metadata: {labels: {app: t}}
    spec:
      containers:
        - name: app
          image: repo/app:1
          resources: {requests: {cpu: 500m, memory: 1Gi}, limits: {memory: 1Gi}}
"""

    def test_subdir_chart_docs_not_duplicated(self):
        root = make_tree({
            "mychart/Chart.yaml": CHART_YAML,
            "mychart/values.yaml": "replicaCount: 2\n",
            "mychart/templates/deployment.yaml": DEPLOYMENT_TPL % {
                "replicas_block": "replicas: 2"},
        })
        with mock.patch.object(discovery, "find_helm", return_value="/x/helm"), \
             mock.patch.object(discovery, "render_chart",
                               return_value=(self.RENDERED, None)):
            r = analyze(root, helm_mode="auto")
        deployments = [d for d in r.context.docs if d.kind == "Deployment"]
        self.assertEqual(len(deployments), 1, "phantom duplicate doc")
        self.assertTrue(deployments[0].rendered)
        self.assertEqual(deployments[0].file, "mychart/templates/deployment.yaml")

    def test_subchart_render_output_skipped_with_coverage_note(self):
        rendered = self.RENDERED + """---
# Source: t/charts/postgres/templates/sts.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: pg}
spec:
  selector: {matchLabels: {app: pg}}
  template:
    metadata: {labels: {app: pg}}
    spec: {containers: [{name: pg, image: postgres:16}]}
"""
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "replicaCount: 2\n",
            "templates/deployment.yaml": DEPLOYMENT_TPL % {
                "replicas_block": "replicas: 2"},
        })
        with mock.patch.object(discovery, "find_helm", return_value="/x/helm"), \
             mock.patch.object(discovery, "render_chart",
                               return_value=(rendered, None)):
            r = analyze(root, helm_mode="auto")
        self.assertFalse(any(d.kind == "StatefulSet" for d in r.context.docs),
                         "subchart object analyzed despite out-of-scope promise")
        self.assertTrue(any("subchart" in row[1].lower()
                            for row in r.context.coverage))


class TestZeroTargetNoCrash(unittest.TestCase):
    """Defect: averageUtilization: 0 crashed the whole run (ZeroDivision)."""

    def test_zero_cpu_target(self):
        hpa = HPA_TPL.replace("averageUtilization: 70", "averageUtilization: 0")
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "replicaCount: 2\nautoscaling:\n  enabled: true\n",
            "templates/deployment.yaml": DEPLOYMENT_TPL % {
                "replicas_block": "{{- if not .Values.autoscaling.enabled }}\n"
                                  "  replicas: 2\n  {{- end }}"},
            "templates/hpa.yaml": hpa,
        })
        r = analyze(root, helm_mode="off")   # must not raise
        self.assertIn("HP026", {f.rule_id for f in r.findings})


class TestNoDockerfileNoJvmFiction(unittest.TestCase):
    """Defect: charts with no Dockerfile got invented JVM memory budgets
    and un-scored XF findings."""

    def test_no_jvm_tables_or_xf_without_dockerfile(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "replicaCount: 2\n",
            "templates/deployment.yaml": DEPLOYMENT_TPL % {
                "replicas_block": "replicas: 2"},
        })
        r = analyze(root, helm_mode="off")
        self.assertFalse(any("JVM" in p.title for p in r.proofs),
                         "JVM proof tables invented without a Dockerfile")
        self.assertFalse(any(f.rule_id.startswith("XF") for f in r.findings),
                         "cross-file JVM findings without a Dockerfile")


class TestDockerfileParsing(unittest.TestCase):
    def test_legacy_env_with_equals_in_value(self):
        # Defect: legacy 'ENV KEY value-with=' was dropped entirely
        df = parse("FROM eclipse-temurin:17-jre\n"
                   "ENV JAVA_TOOL_OPTIONS -Xmx512m -XX:MaxRAMPercentage=75.0\n"
                   'ENTRYPOINT ["java","-jar","a.jar"]\n')
        self.assertIn("JAVA_TOOL_OPTIONS", df.java_opts)
        self.assertIn("-Xmx512m", effective_flags(df))

    def test_app_version_tags_not_java_versions(self):
        # Defect: myco/javaservice:1.2.3 detected as "Java 2"
        self.assertIsNone(parse("FROM myco/javaservice:1.2.3\n").java_major)
        self.assertIsNone(parse("FROM corp/javalin-app:3.4.5\n").java_major)

    def test_legacy_1_8_0_tag_keeps_update(self):
        # Defect: 1.8.0_131-style tags lost the update level
        df = parse("FROM java:1.8.0_60\n")
        self.assertEqual((df.java_major, df.java_update), (8, 60))

    def test_builder_jdk_not_attributed_to_distroless_final(self):
        # Defect: openjdk-17 fallback scanned the WHOLE file
        df = parse("FROM openjdk-17-builder AS build\nRUN make\n"
                   "FROM gcr.io/distroless/base\nCOPY --from=build /a /a\n")
        self.assertIsNone(df.java_major)

    def test_cmd_ignored_under_shell_entrypoint(self):
        # Defect: CMD flags counted although docker ignores CMD there
        df = parse("FROM eclipse-temurin:17-jre\n"
                   "ENTRYPOINT java -Xmx256m -jar a.jar\n"
                   'CMD ["java","-Xmx4g","-XX:+UseZGC"]\n')
        eff = effective_flags(df)
        self.assertIn("-Xmx256m", eff)
        self.assertNotIn("-Xmx4g", eff)

    def test_overridden_entrypoint_flags_discarded(self):
        # Defect: jvm_flags accumulated across overridden ENTRYPOINTs
        df = parse("FROM eclipse-temurin:17-jre\n"
                   "ENTRYPOINT java -Xmx256m -jar a.jar\n"
                   'ENTRYPOINT ["java","-jar","a.jar"]\n')
        self.assertNotIn("-Xmx256m", effective_flags(df))

    def test_builder_stage_env_and_user_ignored(self):
        # Defect: ENV/USER from the builder stage counted as runtime facts
        df = parse("FROM eclipse-temurin:17-jdk AS build\n"
                   'ENV JAVA_TOOL_OPTIONS="-Xmx4g"\nUSER app\nRUN make\n'
                   "FROM eclipse-temurin:17-jre\n"
                   'ENTRYPOINT ["java","-jar","a.jar"]\n')
        self.assertEqual(df.java_opts, {})
        self.assertIsNone(df.user)


class TestTemplateActionHandling(unittest.TestCase):
    def test_template_keyword_treated_like_include(self):
        # Defect: {{ template "x" . }} was dropped as control flow
        src = 'labels:\n  {{- template "mychart.labels" . }}\n'
        docs, _, err = load_yaml_docs(scrub_template(src))
        self.assertIsNone(err)
        self.assertEqual(docs[0]["labels"], "HELMINC@mychart.labels")

    def test_default_literal_resolves_when_value_missing(self):
        # Defect: `| default 3` never resolved (dead regex)
        src = "replicas: {{ .Values.replicaCount | default 3 }}\n"
        docs, _, _ = load_yaml_docs(scrub_template(src))
        self.assertEqual(resolve_markers(docs[0], {}), {"replicas": 3})
        self.assertEqual(resolve_markers(docs[0], {"replicaCount": 7}),
                         {"replicas": 7})

    def test_define_scope_is_not_a_condition(self):
        # Defect: define-wrapped replicas downgraded HP050 to 'verify'
        src = ('{{- define "d.tpl" }}\nspec:\n  replicas: 2\n{{- end }}\n')
        conds = enclosing_conditions(src, r"^\s{0,4}replicas\s*:")
        self.assertEqual(conds, [])


class TestProbeTableCoverage(unittest.TestCase):
    def test_probe_table_found_on_second_workload(self):
        # Defect: unconditional break meant only the FIRST workload was
        # ever examined for the probe-budget table
        no_probe = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: a}\n"
            "spec:\n  selector: {matchLabels: {app: a}}\n"
            "  template:\n    metadata: {labels: {app: a}}\n"
            "    spec: {containers: [{name: a, image: r/a:1}]}\n")
        with_probe = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: b}\n"
            "spec:\n  selector: {matchLabels: {app: b}}\n"
            "  template:\n    metadata: {labels: {app: b}}\n"
            "    spec:\n      containers:\n"
            "        - name: b\n          image: r/b:1\n"
            "          livenessProbe:\n            httpGet: {path: /h, port: 80}\n"
            "            initialDelaySeconds: 1\n            periodSeconds: 1\n")
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "Dockerfile": "FROM eclipse-temurin:17-jre\n"
                          'ENTRYPOINT ["java","-jar","a.jar"]\n',
            "templates/a.yaml": no_probe,
            "templates/b.yaml": with_probe,
        })
        r = analyze(root, helm_mode="off")
        self.assertTrue(any("Probe budget" in p.title and "'b'" in p.title
                            for p in r.proofs),
                        "probe table missing for second workload")


class TestDeepMergeNullDeletes(unittest.TestCase):
    def test_override_null_deletes_key(self):
        self.assertEqual(deep_merge({"a": 1, "b": 2}, {"a": None}), {"b": 2})

    def test_new_null_key_kept(self):
        self.assertEqual(deep_merge({"b": 2}, {"a": None}), {"b": 2, "a": None})


DEPLOY = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: %(name)s}\n"
    "spec:\n  replicas: %(replicas)s\n  selector: {matchLabels: {app: a}}\n"
    "  template:\n    metadata: {labels: {app: a}}\n    spec:\n"
    "      containers:\n        - name: %(cname)s\n          image: %(image)s\n"
    "%(extra)s"
    "          resources:\n            requests: {cpu: 500m, memory: 1Gi}\n"
    "            limits: {memory: 1Gi}\n")


def deploy(name="web", replicas=2, cname="app", image="eclipse-temurin:17-jre",
           extra=""):
    return DEPLOY % dict(name=name, replicas=replicas, cname=cname,
                         image=image, extra=extra)


class TestF1MultiChartNoCrossContamination(unittest.TestCase):
    """F1: two charts under one root must never merge one's overlay onto the
    other's templates and fabricate criticals against the healthy chart."""

    def test_second_chart_scoped_out_no_fabricated_findings(self):
        root = make_tree({
            "a/Chart.yaml": CHART_YAML,
            "a/values.yaml": "replicaCount: 2\n",
            "a/values-prod.yaml": "hpa: {min: 25, max: 12}\n",
            "a/templates/deployment.yaml": deploy(name="a-app"),
            "b/Chart.yaml": CHART_YAML,
            "b/values.yaml": "replicaCount: 2\n",
            "b/templates/deployment.yaml": deploy(name="b-app"),
        })
        r = analyze(root, helm_mode="off")
        # only one chart analyzed; the other is recorded, never merged
        self.assertTrue(r.context.foreign_charts)
        self.assertIn("CH030", _ids(r))
        # deterministic tie-break: equal-depth charts select lexicographically
        self.assertEqual(r.context.chart_yaml_path, "a/Chart.yaml")
        self.assertEqual(r.context.foreign_charts, ["b"])
        # no finding may reference files of the UN-analyzed chart, whichever
        # one that is - derive it from the context, never hardcode it
        foreign = r.context.foreign_charts[0] + "/"
        files = {f.file for f in r.findings if f.file}
        self.assertFalse(any(fp.startswith(foreign) for fp in files),
                         "findings leaked into the un-analyzed sibling chart")


class TestF2HeredocBodiesNotInstructions(unittest.TestCase):
    """F2: BuildKit heredoc bodies must not be parsed as Dockerfile lines."""

    def test_heredoc_body_user_and_env_ignored(self):
        df = parse_dockerfile("Dockerfile",
            "FROM eclipse-temurin:17-jre\n"
            "RUN <<EOT cat > /d/readme\n"
            "USER 10001\n"
            "ENV JAVA_TOOL_OPTIONS=-XX:MaxRAMPercentage=75\n"
            "EOT\n"
            'ENTRYPOINT ["java","-jar","/a.jar"]\n')
        self.assertIsNone(df.user, "heredoc-body USER leaked as a real USER")
        self.assertEqual(df.java_opts, {},
                         "heredoc-body ENV leaked as a real ENV")

    def test_real_instructions_after_heredoc_still_parsed(self):
        df = parse_dockerfile("Dockerfile",
            "FROM eclipse-temurin:17-jre\n"
            "RUN <<EOT cat >/d\nhello\nEOT\n"
            "USER 4000\n")
        self.assertEqual(df.user, "4000")


class TestF3HpaLiteralMismatch(unittest.TestCase):
    """F3: an HPA naming a workload that does not exist is a dangling target
    (HP041), never a replicas-vs-HPA conflict paired by the single-workload
    fallback."""

    def test_literal_mismatch_yields_hp041_not_hp050(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": deploy(name="web"),
            "templates/hpa.yaml":
                "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
                "metadata: {name: h}\nspec:\n"
                "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: worker}\n"
                "  minReplicas: 2\n  maxReplicas: 10\n"
                "  metrics: [{type: Resource, resource: {name: cpu, target: "
                "{type: Utilization, averageUtilization: 70}}}]\n",
        })
        r = analyze(root, helm_mode="off")
        self.assertIn("HP041", _ids(r))
        self.assertNotIn("HP050", _ids(r))


class TestF4PodEnvJvmFlags(unittest.TestCase):
    """F4: JVM options set via pod-spec env are read by the JVM; the tool must
    neither invent 'missing' findings nor falsely absolve an oversized heap."""

    def _root(self):
        env = ("          env:\n            - name: JAVA_TOOL_OPTIONS\n"
               "              value: '-XX:MaxRAMPercentage=75 "
               "-XX:+ExitOnOutOfMemoryError'\n")
        return make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "Dockerfile": "FROM eclipse-temurin:17-jre\n"
                          'ENTRYPOINT ["java","-jar","/a.jar"]\n',
            "templates/deployment.yaml": deploy(name="web", extra=env),
        })

    def test_env_flags_suppress_false_findings(self):
        r = analyze(self._root(), helm_mode="off")
        self.assertNotIn("JV021", _ids(r))   # heap IS sized
        self.assertNotIn("JV026", _ids(r))   # ExitOnOOM IS applied
        self.assertNotIn("XF005", _ids(r))   # heap not defaulted to 25%

    def test_env_heap_counted_in_budget_no_false_absolution(self):
        # 75% of 1Gi heap + non-heap > 1Gi -> the REAL XF002 must fire
        r = analyze(self._root(), helm_mode="off")
        self.assertIn("XF002", _ids(r))


class TestR1ChartYamlShapeGuard(unittest.TestCase):
    """R1: a list/scalar Chart.yaml is a finding (CH012), never a crash."""

    def test_list_chart_yaml(self):
        root = make_tree({"Chart.yaml": "- oops\n",
                          "templates/deployment.yaml": deploy()})
        r = analyze(root, helm_mode="off")     # must not raise
        self.assertIn("CH012", _ids(r))

    def test_scalar_chart_yaml(self):
        root = make_tree({"Chart.yaml": "justastring\n",
                          "templates/deployment.yaml": deploy()})
        r = analyze(root, helm_mode="off")
        self.assertIn("CH012", _ids(r))


class TestR2LauncherScript(unittest.TestCase):
    """R2: a JAVA_OPTS applied by an in-directory entrypoint script is NOT
    inert - the script disproves the DF013 assertion."""

    def test_script_applying_java_opts_not_inert(self):
        info = parse_dockerfile("Dockerfile",
            'FROM eclipse-temurin:17-jre\n'
            'ENV JAVA_OPTS="-XX:MaxRAMPercentage=60"\n'
            'ENTRYPOINT ["/docker-entrypoint.sh"]\n')
        info.launcher_script_text = "#!/bin/sh\nexec java $JAVA_OPTS -jar /a.jar\n"
        self.assertEqual(inert_opt_vars(info), [])

    def test_no_script_still_inert(self):
        info = parse_dockerfile("Dockerfile",
            'FROM eclipse-temurin:17-jre\n'
            'ENV JAVA_OPTS="-XX:MaxRAMPercentage=60"\n'
            'ENTRYPOINT ["/docker-entrypoint.sh"]\n')
        self.assertEqual(inert_opt_vars(info), ["JAVA_OPTS"])


class TestR3TargetScopedJvm(unittest.TestCase):
    """R3: a memory-metric HPA targeting nginx must not get the JVM-ratchet
    CRITICAL just because a Java Dockerfile exists elsewhere."""

    def test_memory_hpa_on_nginx_not_jvm_critical(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "Dockerfile": "FROM eclipse-temurin:17-jre\n"
                          'ENTRYPOINT ["java","-jar","/a.jar"]\n',
            "templates/api.yaml": deploy(name="java-api", cname="app",
                                         image="eclipse-temurin:17-jre"),
            "templates/cache.yaml": deploy(name="nginx-cache", cname="nginx",
                                           image="nginx:1.25"),
            "templates/hpa.yaml":
                "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
                "metadata: {name: h}\nspec:\n"
                "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: nginx-cache}\n"
                "  minReplicas: 2\n  maxReplicas: 10\n"
                "  metrics: [{type: Resource, resource: {name: memory, target: "
                "{type: Utilization, averageUtilization: 70}}}]\n",
        })
        r = analyze(root, helm_mode="off")
        hp025 = _by_id(r, "HP025")
        self.assertTrue(hp025)
        self.assertIs(hp025[0].severity, Severity.MEDIUM)
        self.assertNotIn("JVM", hp025[0].title)


class TestF5SidecarByImage(unittest.TestCase):
    """F5: a renamed sidecar (image fluent-bit-fork) gets no JVM budget."""

    def test_fluentbit_fork_excluded(self):
        sidecar = ("        - name: log-shipper\n"
                   "          image: fluent-bit-fork:2.1\n"
                   "          resources: {requests: {memory: 64Mi}, "
                   "limits: {memory: 64Mi}}\n")
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "Dockerfile": "FROM eclipse-temurin:17-jre\n"
                          'ENTRYPOINT ["java","-jar","/a.jar"]\n',
            "templates/deployment.yaml": deploy(name="web") + sidecar,
        })
        r = analyze(root, helm_mode="off")
        self.assertFalse(any("log-shipper" in (p.title or "") for p in r.proofs),
                         "JVM budget table built for a sidecar")
        self.assertFalse(any(f.rule_id == "RS010" and "log-shipper" in f.detail
                             for f in r.findings))


class TestF6ByteScaleMemory(unittest.TestCase):
    """F6: `memory: 512` (bytes) is a CRITICAL typo, like `512m`."""

    def test_bare_integer_memory_is_critical(self):
        d = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web}\n"
             "spec:\n  replicas: 2\n  selector: {matchLabels: {app: a}}\n"
             "  template:\n    metadata: {labels: {app: a}}\n    spec:\n"
             "      containers:\n        - name: a\n          image: nginx:1.25\n"
             "          resources: {requests: {memory: 512}, limits: {memory: 512}}\n")
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/deployment.yaml": d})
        r = analyze(root, helm_mode="off")
        rs013 = _by_id(r, "RS013")
        self.assertTrue(rs013)
        self.assertIs(rs013[0].severity, Severity.CRITICAL)


class TestF9NotGradedWithoutWorkload(unittest.TestCase):
    """F9: templates present but zero workload objects -> NOT GRADED."""

    def test_library_chart_not_graded(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": '{{ include "x.deployment" . }}\n',
        })
        r = analyze(root, helm_mode="off")
        self.assertIsNotNone(r.context.ungradeable_reason)
        self.assertIsNone(overall_score(r))


class TestN1QuotedHpaNumerics(unittest.TestCase):
    """N1: quoted min/max still get sanity-checked, and the quoting is flagged."""

    def test_quoted_min_gt_max(self):
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "x: 1\n",
            "templates/deployment.yaml": deploy(name="web"),
            "templates/hpa.yaml":
                "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
                "metadata: {name: h}\nspec:\n"
                "  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: web}\n"
                '  minReplicas: "6"\n  maxReplicas: "2"\n'
                "  metrics: [{type: Resource, resource: {name: cpu, target: "
                "{type: Utilization, averageUtilization: 70}}}]\n",
        })
        r = analyze(root, helm_mode="off")
        self.assertIn("HP004", _ids(r))   # min>max still caught
        self.assertIn("HP008", _ids(r))   # quoting flagged


class TestBasisMechanism(unittest.TestCase):
    """The epistemic backbone: estimate/assumption findings must not render or
    score like observed facts."""

    def test_estimate_findings_are_derived_or_assumed(self):
        # small limit + big heap default -> estimate-based XF finding
        d = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web}\n"
             "spec:\n  replicas: 2\n  selector: {matchLabels: {app: a}}\n"
             "  template:\n    metadata: {labels: {app: a}}\n    spec:\n"
             "      containers:\n        - name: a\n"
             "          image: eclipse-temurin:8u102-jre\n"
             "          resources: {requests: {memory: 256Mi}, limits: {memory: 256Mi}}\n")
        root = make_tree({
            "Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
            "Dockerfile": "FROM eclipse-temurin:8u102-jre\n"
                          'ENTRYPOINT ["java","-jar","/a.jar"]\n',
            "templates/deployment.yaml": d})
        r = analyze(root, helm_mode="off")
        xf = [f for f in r.findings if f.rule_id.startswith("XF")]
        self.assertTrue(xf)
        self.assertTrue(all(f.basis in (Basis.DERIVED, Basis.ASSUMED)
                            for f in xf),
                        "a cross-file estimate finding rendered as OBSERVED fact")

    def test_assumed_critical_deduction_capped_at_high(self):
        from hpaanalyzer.models import Finding, Category
        obs = Finding(rule_id="X", severity=Severity.CRITICAL,
                      category=Category.CROSS, title="t", file="", detail="d",
                      why="w", fix="f", basis=Basis.OBSERVED)
        asm = Finding(rule_id="X", severity=Severity.CRITICAL,
                      category=Category.CROSS, title="t", file="", detail="d",
                      why="w", fix="f", basis=Basis.ASSUMED)
        self.assertEqual(obs.effective_deduction(), Severity.CRITICAL.deduction)
        self.assertEqual(asm.effective_deduction(), Severity.HIGH.deduction)


class TestTheToolDoesNotDescribeItsOwnOldBehaviour(unittest.TestCase):
    """Prose goes stale silently, and stale prose about YOUR OWN output is a
    worse lie than stale prose about the world - the reader has no way to
    check it except by disbelieving the tool.

    `clusterprobes.py` printed "This report shows QoS per container;
    Kubernetes assigns QoS per POD" for two iterations AFTER R1 made the
    report pod-level. Every test passed the whole time, because no test read
    the sentences. These do."""

    SIDECAR_DEP = (
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata: {name: web, labels: {app.kubernetes.io/name: web}}\n"
        "spec:\n  replicas: 2\n  selector: {matchLabels: {app: a}}\n"
        "  template:\n    metadata: {labels: {app: a}}\n    spec:\n"
        "      initContainers:\n        - name: side\n"
        "          restartPolicy: Always\n          image: envoy:v1.29\n"
        "          resources: {requests: {cpu: 100m, memory: 128Mi}}\n"
        "      containers:\n        - name: a\n"
        "          image: eclipse-temurin:17-jre\n"
        "          resources: {requests: {cpu: '1', memory: 1Gi}, "
        "limits: {cpu: '1', memory: 1Gi}}\n")

    def _report(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/deployment.yaml": self.SIDECAR_DEP})
        from hpaanalyzer.report import render
        return render(analyze(root, helm_mode="off"), "/tmp/stale.txt",
                      show_all=True, level="full")

    def test_the_report_does_not_claim_it_shows_qos_per_container(self):
        self.assertNotIn("shows QoS per container", self._report())

    def test_the_report_does_not_claim_sidecars_are_uncounted(self):
        txt = self._report()
        for phrase in ("budget math does not yet count",
                       "budget math ignores"):
            self.assertNotIn(phrase, txt)

    def test_the_pod_row_exists_to_back_that_up(self):
        # Not just absence of the false sentence - presence of the thing that
        # makes it false.
        self.assertIn("=> POD", self._report())

    def test_removed_api_severity_still_tracks_the_declared_range(self):
        # The third stale README bullet. Pinned as behaviour so the docs can
        # be checked against it instead of against memory.
        ing = ("apiVersion: networking.k8s.io/v1beta1\nkind: Ingress\n"
               "metadata: {name: web, labels: {app.kubernetes.io/name: web}}\n")
        sev = {}
        for tag, kube_line in (("old", 'kubeVersion: ">=1.19.0-0 <1.21.0-0"\n'),
                               ("new", 'kubeVersion: ">=1.29.0-0"\n')):
            root = make_tree({"Chart.yaml": CHART_YAML + kube_line,
                              "values.yaml": "x: 1\n",
                              "templates/ing.yaml": ing})
            hits = _by_id(analyze(root, helm_mode="off"), "TP010")
            self.assertTrue(hits, f"TP010 did not fire for the {tag} range")
            sev[tag] = hits[0].severity
        self.assertLess(sev["old"].deduction, sev["new"].deduction,
                        "a chart pinned below the removal is penalised as "
                        "hard as one pinned above it - R3's reconciliation "
                        "has regressed")


class TestTruncationDoesNotSilentlyUndercut(unittest.TestCase):
    """R6, found by a test rather than by reading.

    `_trunc` cut validator output at 1500 bytes and marked the cut with the
    bare word "(truncated)". The tally printed above it is counted over the
    whole output. So a kube-score summary reading "12 critical" sat directly
    on top of an excerpt containing five `[CRITICAL]` lines. Neither number
    was wrong; the report was still misleading, because it asks the reader to
    audit its transcription against that block.

    This is the arithmetic-free half of the fix, so it holds even in a
    container with no validators installed - which is where the binary-backed
    version of this test skips.
    """

    def test_short_output_is_untouched(self):
        from hpaanalyzer.external import _trunc
        s = "a\nb\nc"
        self.assertEqual(_trunc(s), s)

    def test_long_output_states_what_it_dropped(self):
        from hpaanalyzer.external import _trunc
        blob = "\n".join(f"line {i}" for i in range(500))
        out = _trunc(blob)
        self.assertIn("more line(s)", out)
        self.assertIn("more byte(s) not shown", out)
        self.assertIn("FULL output", out)

    def test_the_dropped_line_count_is_correct(self):
        from hpaanalyzer.external import _trunc
        import re as _re
        blob = "\n".join(f"line {i}" for i in range(500))
        out = _trunc(blob)
        dropped = int(_re.search(r"\((\d+) more line\(s\)", out).group(1))
        kept = out.split("\n... (")[0].count("\n") + 1
        self.assertEqual(kept + dropped, blob.count("\n") + 1)


class TestSubchartBoundaryIsNotEvidence(unittest.TestCase):
    """R7. The tool declares subcharts out of scope, then threw away the
    objects `helm template` rendered from them - so HP041 asked "does any
    workload match this HPA's scaleTargetRef?", could not see the Deployment
    helm had just produced from charts/worker, and reported the user's correct
    HPA as dangling at HIGH severity, labelled OBSERVED.

    C2.2: never report a limit of the method as a finding about the target.

    Both directions are pinned here, because the cheap way to make the false
    positive go away is to stop firing HP041, and that trades it for a false
    negative - the worse bug, since nobody notices a finding that is absent.
    """

    def _ctx(self, subcharts, docs, names=("worker",)):
        from hpaanalyzer.models import ChartContext, ManifestDoc
        c = ChartContext(root="/x", render_mode="helm")
        c.subcharts_present = subcharts
        c.subchart_names = list(names) if subcharts else []
        c.subchart_docs = [
            ManifestDoc(file=f"charts/{names[0]}/templates/deploy.yaml",
                        kind=k, api_version="apps/v1",
                        data={"kind": k, "metadata": {"name": n}})
            for k, n in docs]
        return c

    def test_a_ref_a_subchart_satisfies_is_not_a_finding(self):
        from hpaanalyzer.checks_hpa import _target_is_out_of_scope
        ctx = self._ctx(True, [("Deployment", "umbrella-worker")])
        ref = {"kind": "Deployment", "name": "umbrella-worker"}
        self.assertTrue(_target_is_out_of_scope(ctx, ref, "hpa-1"))

    def test_suppression_leaves_an_itemised_coverage_row(self):
        from hpaanalyzer.checks_hpa import _target_is_out_of_scope
        ctx = self._ctx(True, [("Deployment", "umbrella-worker")])
        _target_is_out_of_scope(ctx, {"kind": "Deployment",
                                      "name": "umbrella-worker"}, "hpa-1")
        flat = " ".join(" ".join(r) for r in ctx.coverage)
        # Silence is not the fix. The row has to carry enough for a reader to
        # check the claim themselves: which HPA, which target, which subchart.
        self.assertIn("hpa-1", flat)
        self.assertIn("umbrella-worker", flat)
        self.assertIn("worker", flat)
        self.assertIn("NOT graded", flat)

    def test_a_ref_no_subchart_satisfies_still_fires(self):
        """The subchart WAS read, and the name is not in it. That is a real
        dangling reference and must survive the fix untouched."""
        from hpaanalyzer.checks_hpa import _target_is_out_of_scope
        ctx = self._ctx(True, [("Deployment", "umbrella-worker")])
        self.assertFalse(_target_is_out_of_scope(
            ctx, {"kind": "Deployment", "name": "umbrella-typo"}, "hpa-1"))

    def test_kind_must_match_too(self):
        from hpaanalyzer.checks_hpa import _target_is_out_of_scope
        ctx = self._ctx(True, [("ConfigMap", "umbrella-worker")])
        self.assertFalse(_target_is_out_of_scope(
            ctx, {"kind": "Deployment", "name": "umbrella-worker"}, "hpa-1"))

    def test_a_chart_with_no_subcharts_is_unaffected(self):
        from hpaanalyzer.checks_hpa import _target_is_out_of_scope
        ctx = self._ctx(False, [])
        self.assertFalse(_target_is_out_of_scope(
            ctx, {"kind": "Deployment", "name": "anything"}, "hpa-1"))

    def test_unrendered_subcharts_are_undetermined_not_a_finding(self):
        """Static mode renders nothing. The tool then cannot distinguish a
        dangling ref from one satisfied inside a subchart it never read, and
        C2.2 says which of those it may print."""
        from hpaanalyzer.checks_hpa import _target_is_out_of_scope
        ctx = self._ctx(True, [])
        ctx.render_mode = "static"
        self.assertTrue(_target_is_out_of_scope(
            ctx, {"kind": "Deployment", "name": "umbrella-worker"}, "hpa-1"))
        flat = " ".join(" ".join(r) for r in ctx.coverage)
        self.assertIn("UNDETERMINED", flat)
        self.assertIn("static", flat)

    def test_coverage_note_names_objects_rather_than_counting_them(self):
        from hpaanalyzer.discovery import _subchart_coverage_note
        ctx = self._ctx(True, [("Deployment", "umbrella-worker"),
                               ("ConfigMap", "worker-cfg")])
        note = _subchart_coverage_note(ctx)
        self.assertIn("Deployment/umbrella-worker", note)
        self.assertIn("ConfigMap/worker-cfg", note)
        self.assertIn("NOT graded", note)

    def test_coverage_note_caps_the_list_and_says_it_capped(self):
        """A coverage cell is not a manifest dump; a subchart with 60 objects
        must not push the rest of the table off the page. But a silent cap
        reads as a complete list, so the overflow is stated."""
        from hpaanalyzer.discovery import _subchart_coverage_note
        ctx = self._ctx(True, [("ConfigMap", f"c{i}") for i in range(12)])
        note = _subchart_coverage_note(ctx)
        self.assertIn("12 object(s)", note)
        self.assertIn("+4 more", note)


@unittest.skipUnless(__import__("shutil").which("helm"), "helm not installed")
class TestSubchartBoundaryEndToEnd(unittest.TestCase):
    """The same defect through the real pipeline against a real chart, so the
    unit tests above cannot pass while the wiring is wrong (which is how R6's
    two validators went four iterations without ever being executed)."""

    FIXTURE = __import__("os").path.join(
        __import__("os").path.dirname(__file__), "..", "fixtures",
        "umbrella-chart")

    def test_correct_hpa_into_a_subchart_raises_no_finding(self):
        r = analyze(self.FIXTURE, helm_mode="auto")
        self.assertEqual(r.context.render_mode, "helm")
        self.assertNotIn("HP041", _ids(r))

    def test_the_subchart_workload_is_recorded_but_not_graded(self):
        ctx = analyze(self.FIXTURE, helm_mode="auto").context
        parked = {(d.kind or "") + "/" +
                  str((d.data.get("metadata") or {}).get("name"))
                  for d in ctx.subchart_docs}
        self.assertIn("Deployment/umbrella-worker", parked)
        graded = {(d.kind or "") + "/" +
                  str((d.data.get("metadata") or {}).get("name"))
                  for d in ctx.docs}
        self.assertNotIn("Deployment/umbrella-worker", graded)
        self.assertIn("worker", ctx.subchart_names)


DEPLOY_ENV_XMX = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: w
spec:
  selector: {matchLabels: {app: w}}
  template:
    metadata: {labels: {app: w}}
    spec:
      containers:
        - name: app
          image: "repo/app:1.0"
          env:
            - name: JAVA_TOOL_OPTIONS
              value: "-Xmx4g"
          resources:
            requests: {cpu: 100m, memory: 2Gi}
            limits: {cpu: 200m, memory: 2Gi}
"""

DEPLOY_NGINX = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: n
spec:
  selector: {matchLabels: {app: n}}
  template:
    metadata: {labels: {app: n}}
    spec:
      containers:
        - name: web
          image: "nginx:1.27.0-alpine"
          readinessProbe: {httpGet: {path: /, port: 80}}
          livenessProbe: {httpGet: {path: /, port: 80}}
          resources:
            requests: {cpu: 100m, memory: 256Mi}
            limits: {cpu: 200m, memory: 256Mi}
"""


class TestJvmAnalysisIsGatedOnEvidenceNotOnAFilename(unittest.TestCase):
    """R8. Three modules asked "is this a JVM workload?" by asking "is there a
    Dockerfile?" - `checks_docker.run`, `proofs._pairs`, and the scoring
    denominator in `scoring.unassessed_reason`. That test is wrong in both
    directions at once, so both directions are pinned here.

    FACE A (silence): a pod spec asking for a 4 GiB heap inside a 2 GiB limit
    was never compared against anything, because the chart shipped no
    Dockerfile. The JVM reads JAVA_TOOL_OPTIONS unaided; whether a Dockerfile
    sits next to the chart has nothing to do with the arithmetic.

    FACE B (invention): a chart running nothing but nginx was told to set
    -XX:MaxRAMPercentage, at HIGH, because it happened to contain a file named
    Dockerfile - and was then graded in a category named for a runtime it does
    not run.

    Pinning only FACE A would be met by "analyze everything as a JVM"; pinning
    only FACE B would be met by "analyze nothing". Neither is a fix.
    """

    def _tree(self, deployment, dockerfile=None):
        files = {"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                 "templates/deployment.yaml": deployment}
        if dockerfile is not None:
            files["Dockerfile"] = dockerfile
        return make_tree(files)

    # -- FACE A -----------------------------------------------------------
    def test_env_supplied_heap_is_compared_against_the_limit_with_no_dockerfile(self):
        r = analyze(self._tree(DEPLOY_ENV_XMX), helm_mode="off")
        self.assertIn("XF001", _ids(r))
        f = _by_id(r, "XF001")[0]
        self.assertIs(f.severity, Severity.CRITICAL)

    def test_that_finding_is_observed_because_both_numbers_were_read(self):
        r = analyze(self._tree(DEPLOY_ENV_XMX), helm_mode="off")
        f = _by_id(r, "XF001")[0]
        self.assertIs(f.basis, Basis.OBSERVED)
        # C2.2 forbids downgrading a fact for want of context, and equally
        # forbids hiding the context that could overturn it.
        self.assertIsNotNone(f.assumes)
        self.assertIn("-Xmx", f.assumes)

    def test_the_report_names_the_env_var_that_made_the_flag_apply(self):
        r = analyze(self._tree(DEPLOY_ENV_XMX), helm_mode="off")
        budget = [p for p in r.proofs if "memory budget" in p.title]
        self.assertTrue(budget, "no JVM memory budget table was produced")
        cells = " ".join(c for row in budget[0].rows for c in row)
        self.assertIn("JAVA_TOOL_OPTIONS", cells)

    def test_java_and_cross_are_scored_so_the_critical_moves_the_number(self):
        ctx = analyze(self._tree(DEPLOY_ENV_XMX), helm_mode="off").context
        self.assertIsNone(unassessed_reason(Category.JAVA, ctx))
        self.assertIsNone(unassessed_reason(Category.CROSS, ctx))
        # ...and DOCKERFILE genuinely cannot be graded: it IS a property of
        # a file, and the file is absent.
        self.assertIsNotNone(unassessed_reason(Category.DOCKERFILE, ctx))

    def test_coverage_still_states_which_image_level_checks_were_skipped(self):
        r = analyze(self._tree(DEPLOY_ENV_XMX), helm_mode="off")
        self.assertIn("DF000", _ids(r))

    # -- FACE B -----------------------------------------------------------
    def test_a_dockerfile_alone_does_not_make_an_nginx_chart_java(self):
        r = analyze(self._tree(DEPLOY_NGINX, "FROM nginx:1.27.0-alpine\n"),
                    helm_mode="off")
        left = sorted(i for i in _ids(r)
                      if i.startswith(("JV", "XF")) or i == "DF003")
        self.assertEqual(left, [], f"invented JVM findings: {left}")

    def test_the_ungraded_java_category_says_so_instead_of_scoring_100(self):
        ctx = analyze(self._tree(DEPLOY_NGINX, "FROM nginx:1.27.0-alpine\n"),
                      helm_mode="off").context
        for cat in (Category.JAVA, Category.CROSS):
            reason = unassessed_reason(cat, ctx)
            self.assertIsNotNone(reason, f"{cat.name} was scored anyway")
            self.assertIn("JVM", reason)
        # C2.6: the coverage table has to say it was not graded, or silence
        # and a clean bill of health look identical.
        rows = " ".join(" ".join(row) for row in ctx.coverage)
        self.assertIn("scope, not a pass", rows)

    def test_no_dockerfile_and_no_jvm_stays_quiet_but_not_silent(self):
        ctx = analyze(self._tree(DEPLOY_NGINX), helm_mode="off").context
        rows = " ".join(" ".join(row) for row in ctx.coverage)
        self.assertIn("Java / JVM checks", rows)

    def test_the_file_inventory_does_not_call_an_nginx_image_a_jvm(self):
        """The fifth site: the 'Files analyzed' line at the top of the report.

        It read `Dockerfile [Java version unknown]` for `FROM nginx:alpine`,
        which asserts a JVM is present and merely unidentified. It is the
        first line a reader sees, so it frames every finding beneath it - and
        it is the one place the invention survived after the checks, the
        modelling, the score and the coverage table were all fixed. Unknown
        version and no version are different facts.
        """
        from hpaanalyzer.report import render
        tree = self._tree(DEPLOY_NGINX, "FROM nginx:1.27.0-alpine\n")
        nginx = render(analyze(tree, helm_mode="off"), tree, level="summary")
        head = nginx.split("EXECUTIVE SUMMARY")[0]
        self.assertIn("no JVM detected", head)
        self.assertNotIn("Java version unknown", head)
        # ...and the honest "unknown" is still reachable, or this would be a
        # fix by deletion: a JRE base image whose version cannot be parsed.
        jtree = self._tree(DEPLOY_NGINX, "FROM corp/internal-jre:latest\n")
        java = render(analyze(jtree, helm_mode="off"), jtree, level="summary")
        self.assertIn("Java version unknown",
                      java.split("EXECUTIVE SUMMARY")[0])

    # -- sites 9 and 10: the surfaces either side of the report ------------
    def test_the_cluster_probe_follows_the_jvm_not_the_dockerfile(self):
        """The ninth site, and the costliest one to get backwards.

        "Does the JVM see the cgroup limit?" is the one question in the whole
        report that NO file can answer - it depends on the JDK build and the
        node's cgroup version. So the probe that hands the operator the
        `kubectl exec ... -XX:+PrintFlagsFinal` command is the tool's only
        move, and it was aimed by the presence of a Dockerfile: a pod spec
        setting -Xmx1g got no probe, while a pure nginx pod beside a Java
        Dockerfile got one.
        """
        from hpaanalyzer.clusterprobes import build_probes

        def keys(r):
            return {p.key for p in build_probes(r)}

        # FACE A: the JVM is right there in the pod spec, no Dockerfile.
        jvm = analyze(self._tree(DEPLOY_ENV_XMX), helm_mode="off")
        self.assertIn("jvm-sees-limit", keys(jvm))
        # and it says why, quoting evidence rather than asserting "JVM".
        probe = [p for p in build_probes(jvm) if p.key == "jvm-sees-limit"][0]
        self.assertTrue(any("JAVA_TOOL_OPTIONS" in t
                            for t in probe.triggered_by), probe.triggered_by)

        # FACE B: nginx, with a Dockerfile that has no JVM in it.
        plain = analyze(self._tree(DEPLOY_NGINX, "FROM nginx:1.27.0-alpine\n"),
                        helm_mode="off")
        self.assertNotIn("jvm-sees-limit", keys(plain))

    def test_preflight_does_not_demand_a_java_version_for_an_nginx_file(self):
        """The tenth site - and the first thing printed on every run.

        `FROM nginx:alpine` produced "Java version undeterminable ... re-run
        with --assume-java", which asserts a JVM and then asks the reader to
        name its version. The honest "undeterminable" must survive, or this
        is a fix by deletion: a JRE base image with an unreadable tag is
        exactly what --assume-java is for.
        """
        from hpaanalyzer.preflight import build_preflight

        def block(tree):
            pf = build_preflight(analyze(tree, helm_mode="off").context)
            return "\n".join(f"{i.status} {i.label} {i.hint}" for i in pf.items)

        nginx = block(self._tree(DEPLOY_NGINX, "FROM nginx:1.27.0-alpine\n"))
        self.assertNotIn("--assume-java", nginx)
        self.assertIn("no JVM detected", nginx)

        jre = block(self._tree(DEPLOY_NGINX, "FROM corp/internal-jre:latest\n"))
        self.assertIn("--assume-java", jre)
        self.assertIn("version undeterminable", jre)

    def test_preflight_does_not_claim_the_jvm_checks_were_skipped_when_they_ran(self):
        """Same site, other branch, and a false statement rather than an
        invented one: "The Java/JVM and cross-file (heap-vs-limit) categories
        will be N/A" was printed for a chart whose pod spec sets -Xmx. After
        R8 those categories are assessed and scored on that chart, so the
        preflight was telling the reader to go find a Dockerfile to enable a
        check that had already run.
        """
        from hpaanalyzer.preflight import build_preflight
        from hpaanalyzer.scoring import category_scores

        r = analyze(self._tree(DEPLOY_ENV_XMX), helm_mode="off")
        scored = {c.name: s for c, s, _ in category_scores(r)}
        self.assertIsNotNone(scored["JAVA"])   # it ran...
        self.assertIsNotNone(scored["CROSS"])
        text = "\n".join(f"{i.label} {i.hint}"
                         for i in build_preflight(r.context).items)
        self.assertNotIn("categories will be N/A", text)  # ...so don't say it
        self.assertIn("JVM evidenced in the chart itself", text)

    # -- sites 11-13: prose that ASSUMED a JVM without ever gating on one ---
    def test_security_findings_do_not_explain_themselves_in_terms_of_a_jvm(self):
        """The eleventh site, and the smallest - which is why it outlived the
        first ten. Nothing here gated on a Dockerfile; the rationale text
        simply assumed the reader ran Java. On a pure nginx chart SC004 read
        "JVMs typically only need /tmp" and its fix said "add
        -Djava.io.tmpdir if needed".

        The finding itself is correct, which is the problem: a false sentence
        welded to a true finding is FACE B in miniature. It costs the finding
        its credibility and buys nothing, and unlike a false FINDING it
        survives every test that counts rule IDs.
        """
        def prose(tree):
            r = analyze(tree, helm_mode="off")
            return " ".join(f"{f.why} {f.fix}"
                            for f in _by_id(r, "SC003") + _by_id(r, "SC004"))

        nginx = prose(self._tree(DEPLOY_NGINX, "FROM nginx:1.27.0-alpine\n"))
        self.assertNotIn("JVM", nginx)
        self.assertNotIn("java.io.tmpdir", nginx)
        self.assertIn("/tmp", nginx)      # the advice itself must survive

        jvm = prose(self._tree(DEPLOY_ENV_XMX))
        self.assertIn("JVM", jvm)
        self.assertIn("java.io.tmpdir", jvm)

    def test_the_file_inventory_states_the_jvm_verdict_even_with_no_dockerfile(self):
        """Thirteenth site, and a gap rather than a wrong answer: the
        inventory lists FILES, so a chart whose JVM is declared in its pod
        spec got no JVM line at all - while the report below it computed
        heap-vs-limit arithmetic and raised a CRITICAL. The reader's first
        block has to state the fact the rest of the page rests on.
        """
        from hpaanalyzer.report import render
        t = self._tree(DEPLOY_ENV_XMX)
        head = render(analyze(t, helm_mode="off"), t,
                      level="summary").split("EXECUTIVE SUMMARY")[0]
        self.assertIn("jvm", head)
        self.assertIn("JAVA_TOOL_OPTIONS", head)

        n = self._tree(DEPLOY_NGINX, "FROM nginx:1.27.0-alpine\n")
        nhead = render(analyze(n, helm_mode="off"), n,
                       level="summary").split("EXECUTIVE SUMMARY")[0]
        # C2.6: say it was looked for and not found, and say where it looked -
        # silence here is indistinguishable from "not checked".
        self.assertIn("none detected", nhead)
        self.assertIn("pod-spec env", nhead)

    def test_the_jvm_primer_says_whether_it_applies_to_this_chart(self):
        """Twelfth site, and the one where deleting the JVM material would be
        the WRONG fix. Sections 6.2-6.4 are a manual, not a claim - but four
        JVM chapters in a report about nginx read as a claim anyway. They stay
        (the opaque-image Java service this tool cannot detect is exactly the
        reader who needs them) and are labelled with the detection result.
        """
        from hpaanalyzer.report import _education
        from hpaanalyzer.kube import jvm_evidence

        nginx = analyze(self._tree(DEPLOY_NGINX, "FROM nginx:1.27.0-alpine\n"),
                        helm_mode="off")
        text = _education(jvm_evidence(nginx.context))
        self.assertIn("reference only", text)
        self.assertIn("NOT detected here", text)
        self.assertIn("MaxRAMPercentage", text)   # still there, still taught

        jvm = analyze(self._tree(DEPLOY_ENV_XMX), helm_mode="off")
        jtext = _education(jvm_evidence(jvm.context))
        self.assertIn("applies to this chart", jtext)
        self.assertNotIn("reference only", jtext)

    # -- the evidence function itself --------------------------------------
    def test_evidence_is_quotable_text_not_a_boolean(self):
        ev = container_jvm_evidence(
            {"name": "app", "image": "repo/app:1",
             "env": [{"name": "JAVA_TOOL_OPTIONS", "value": "-Xmx1g"}]})
        self.assertIsNotNone(ev)
        self.assertIn("JAVA_TOOL_OPTIONS", ev)
        self.assertIn("app", ev)

    def test_a_jre_image_is_evidence_even_with_no_env_and_no_dockerfile(self):
        self.assertIsNotNone(container_jvm_evidence(
            {"name": "app", "image": "eclipse-temurin:21-jre"}))

    def test_plain_images_are_not_evidence(self):
        for img in ("nginx:1.27.0-alpine", "node:20", "repo/app:1",
                    "javascript-runtime:1", "alpine"):
            self.assertIsNone(
                container_jvm_evidence({"name": "app", "image": img}), img)

    def test_a_java_entrypoint_is_evidence_in_either_dockerfile_form(self):
        for text in ('FROM registry.corp/base/x:1\n'
                     'ENTRYPOINT ["java","-jar","a.jar"]\n',
                     'FROM registry.corp/base/x:1\n'
                     'ENTRYPOINT java -jar a.jar\n'):
            df = parse_dockerfile("Dockerfile", text)
            self.assertIsNotNone(dockerfile_jvm_evidence(df), text)

    def test_sidecars_cannot_drag_a_chart_into_jvm_grading(self):
        dep = DEPLOY_NGINX.replace(
            "          resources:\n"
            "            requests: {cpu: 100m, memory: 256Mi}\n"
            "            limits: {cpu: 200m, memory: 256Mi}\n",
            "          resources:\n"
            "            requests: {cpu: 100m, memory: 256Mi}\n"
            "            limits: {cpu: 200m, memory: 256Mi}\n"
            "        - name: istio-proxy\n"
            "          image: eclipse-temurin:21-jre\n"
            "          resources:\n"
            "            requests: {cpu: 10m, memory: 64Mi}\n"
            "            limits: {cpu: 20m, memory: 64Mi}\n")
        ctx = analyze(self._tree(dep), helm_mode="off").context
        self.assertIsNotNone(unassessed_reason(Category.JAVA, ctx))


@unittest.skipUnless(__import__("shutil").which("helm"), "helm not installed")
class TestJvmEvidenceEndToEnd(unittest.TestCase):
    """The same defect through the real pipeline against the real fixtures,
    for the reason recorded on TestSubchartBoundaryEndToEnd: unit tests over
    synthetic contexts pass happily while the wiring is wrong."""

    import os as _os
    FIX = _os.path.join(_os.path.dirname(__file__), "..", "fixtures")

    def test_the_worker_subchart_ooms_and_the_tool_now_says_so(self):
        r = analyze(self._os.path.join(self.FIX, "umbrella-chart", "charts",
                                       "worker"), helm_mode="auto")
        self.assertIn("XF001", _ids(r))
        self.assertEqual(r.context.dockerfiles, [],
                         "fixture grew a Dockerfile; the case is no longer "
                         "about env-supplied flags")

    def test_the_nginx_fixture_gets_no_java_findings_and_no_java_score(self):
        r = analyze(self._os.path.join(self.FIX, "nojvm-chart"),
                    helm_mode="auto")
        self.assertTrue(r.context.dockerfiles,
                        "fixture lost its Dockerfile; FACE B is no longer "
                        "isolated")
        self.assertEqual([i for i in _ids(r)
                          if i.startswith(("JV", "XF"))], [])
        self.assertIsNotNone(unassessed_reason(Category.JAVA, r.context))

    def test_the_java_fixtures_are_unchanged_by_the_widening(self):
        r = analyze(self._os.path.join(self.FIX, "bad-chart"),
                    helm_mode="auto")
        self.assertIn("XF001", _ids(r))
        self.assertIn("JV021", _ids(r))


# ---------------------------------------------------------------------------
# R9
# ---------------------------------------------------------------------------

def _r9_dep(env=None, mem="1Gi"):
    """One container, optionally given JVM flags the way a chart really does.

    JAVA_TOOL_OPTIONS rather than a Dockerfile ENTRYPOINT, because R8 proved
    the Dockerfile is not what makes a workload a JVM and these cases must not
    quietly re-acquire that dependency.
    """
    envblock = ("          env:\n"
                "            - name: JAVA_TOOL_OPTIONS\n"
                f'              value: "{env}"\n') if env else ""
    return ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: w\n"
            "spec:\n  selector: {matchLabels: {app: w}}\n  template:\n"
            "    metadata: {labels: {app: w}}\n    spec:\n      containers:\n"
            '        - name: app\n          image: "repo/app:1.0"\n'
            + envblock +
            "          resources:\n"
            f"            requests: {{cpu: 100m, memory: {mem}}}\n"
            f"            limits: {{cpu: 200m, memory: {mem}}}\n")


class _R9Case(unittest.TestCase):
    """Shared plumbing. The four subclasses below differ only in the fixture,
    and every one of them has to reach the same table."""

    def tree(self, env=None, mem="1Gi"):
        return make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/deployment.yaml": _r9_dep(env, mem)})

    def budget(self, r):
        t = [p for p in r.proofs if "memory budget" in p.title]
        self.assertTrue(t, "no JVM memory budget table was produced - the "
                            "case under test was never reached")
        return t[0]

    def cells(self, r):
        return " ".join(c for row in self.budget(r).rows for c in row)

    def row(self, r, label):
        hit = [row for row in self.budget(r).rows if label in row[0]]
        self.assertTrue(hit, f"no {label!r} row in the budget table")
        return hit[0]

    def has_row(self, r, label):
        return any(label in row[0] for row in self.budget(r).rows)

    def fit_coverage(self, r):
        return [c for c in r.context.coverage if "JVM memory fit" in str(c[0])]

    def everything(self, r):
        """Every word the tool says about this chart, in one string.

        The point of several checks below is that a word appears NOWHERE, and
        a search of only the verdict would pass while the same word sat in a
        coverage row two inches lower.
        """
        parts = [p.title + " " + p.intro + " " + p.conclusion
                 + " " + " ".join(c for row in p.rows for c in row)
                 for p in r.proofs]
        parts += [" ".join(str(x) for x in row) for row in r.context.coverage]
        parts += [f"{f.rule_id} {f.title} {f.detail} {f.why} {f.assumes or ''}"
                  for f in r.findings]
        return " ".join(parts)


class TestJvmFitHasThreeStatesNotTwo(_R9Case):
    """R9. The budget printed a single number T, compared it to the limit, and
    announced "fits" or "does not fit". Five of the seven terms in T are
    constants the tool invented; on a chart whose limit sits inside the range
    those constants can produce, BOTH answers are available from the same
    evidence and the tool was picking one by the accident of where the point
    estimates happened to land.

    FACE A (false confidence): limit 1 GiB, heap 512 MiB. T is 916 MiB at
    typical values and the tool said "fits, +108 MiB". Move metaspace and the
    thread count to the top of their OWN documented bands - values the tool
    itself prints as plausible - and T is 1.2 GiB, an OOM kill. The verdict
    was not a finding about the chart; it was a finding about the constants.

    FACE B (manufactured doubt): the cure must not eat the cases the tool CAN
    decide. -Xmx4g inside a 2 GiB limit is over the limit before a single
    estimate is added, and must stay a CRITICAL no matter what the constants
    are set to. A tool that answers "it depends" to `4 > 2` has replaced one
    kind of dishonesty with another.

    Pinning only FACE A would be met by "report everything as undetermined";
    pinning only FACE B would be met by reverting R9. Neither is a fix.
    """

    # -- FACE A: the straddling case is reported as straddling -------------
    def test_a_limit_inside_the_model_range_is_undetermined_not_a_fit(self):
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off")
        self.assertIn("UNDETERMINED", self.budget(r).conclusion)
        self.assertIn("722 MiB - 1.2 GiB", self.budget(r).conclusion)

    def test_it_still_prints_the_point_estimate_and_labels_it_as_one(self):
        """C2.2 says report the ignorance, not that the tool goes silent.
        916 MiB is the tool's best guess and the reader wants it; what R9
        forbids is presenting it as the answer."""
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off")
        self.assertIn("916 MiB", self.row(r, "ESTIMATED PEAK RSS")[1])
        self.assertIn("typical values", self.row(r, "ESTIMATED PEAK RSS")[2])
        self.assertIn("as a claim about typical values only",
                      self.budget(r).conclusion)

    def test_the_range_that_makes_it_undetermined_is_shown_not_just_asserted(self):
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off")
        self.assertEqual(self.row(r, "T RANGE")[1], "722 MiB - 1.2 GiB")
        self.assertIn("MARGIN RANGE", self.cells(r))

    def test_it_names_which_estimates_decide_it_rather_than_saying_it_depends(self):
        """The difference between a useful UNDETERMINED and a shrug. The
        reader is told exactly which numbers to go and measure, and how far
        they would have to move."""
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off")
        v = self.budget(r).conclusion
        self.assertIn("Thread stacks at its high end (200 MiB)", v)
        self.assertIn("JIT code cache at its high end (128 MiB)", v)
        self.assertIn("164 MiB", v)      # movement available
        self.assertIn("108 MiB", v)      # gap it has to close
        self.assertIn("jcmd", v)
        self.assertIn("--measured", v)

    def test_undetermined_goes_to_coverage_and_never_becomes_a_finding(self):
        """C2.5. Manufacturing a MEDIUM out of the tool's own ignorance is the
        same error as manufacturing a pass out of it."""
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off")
        self.assertEqual(len(self.fit_coverage(r)), 1)
        self.assertIn("Not reported as a fit or a misfit either way",
                      self.fit_coverage(r)[0][1])
        self.assertEqual([i for i in _ids(r) if i.startswith("XF")], [])

    def test_the_coverage_row_states_the_fact_once_and_grammatically(self):
        """It used to `.rstrip('.')` the verdict sentence and glue it onto its
        own clause, producing '...inside its own band No single estimate
        crosses the limit on its own inside its documented band; ...' - the
        same fact twice, once ungrammatically. Two renderings of one
        computation, not one rendering edited into another."""
        row = self.fit_coverage(analyze(
            self.tree("-XX:MaxRAMPercentage=50", "1Gi"), helm_mode="off"))[0]
        self.assertEqual(row[1].count("No single estimate"), 0)
        self.assertIn("decided by no single estimate but by", row[1])
        self.assertNotIn("band No single", row[1])

    # -- FACE B: the decidable cases stay decided --------------------------
    # These are PRESERVATION claims, and they pass against the pre-R9 tree by
    # design - measured, not assumed: `git archive f806890` + this file runs
    # 43 R9 tests, of which 37 fail there (20 failures, 17 errors) and these
    # are among the six that do not. A guard test that FAILED before the fix
    # would mean R9 invented the guarantee rather than kept it, which is a
    # different (and worse) claim than the one being made here.
    #
    # Re-measure after adding any R9 test. An earlier revision of this comment
    # said a test passing at f806890 is "either a preservation claim or
    # vacuous"; re-running it after adding TestTheRemedyNamesWhatIsStillMissing
    # refuted that, so the rule is corrected from the measurement rather than
    # the measurement excused. There is a third category: the NEGATIVE FACE of
    # a paired claim. `test_a_run_with_nothing_measured_does_not_credit_a_
    # measurement` asserts a sentence is absent when nothing was measured, and
    # it passes at f806890 for the degenerate reason that the sentence did not
    # exist there at all. It is not vacuous - it is what stops the sentence
    # becoming decoration that prints either way - but it carries content only
    # together with the partner that fails at f806890. So: a new passer must be
    # one of the three, named as such next to the test, and the count here is
    # how the difference gets noticed rather than assumed.
    def test_a_heap_larger_than_the_limit_is_critical_not_undetermined(self):
        r = analyze(self.tree("-Xmx4g", "2Gi"), helm_mode="off")
        self.assertIn("XF001", _ids(r))
        self.assertIs(_by_id(r, "XF001")[0].severity, Severity.CRITICAL)
        self.assertNotIn("UNDETERMINED", self.everything(r))
        self.assertEqual(self.fit_coverage(r), [])

    def test_that_verdict_says_the_estimates_had_no_part_in_it(self):
        r = analyze(self.tree("-Xmx4g", "2Gi"), helm_mode="off")
        self.assertIn("This follows from your own numbers alone",
                      self.budget(r).conclusion)

    def test_no_value_of_the_constants_can_turn_that_critical_into_a_maybe(self):
        """The guard, perturbed rather than asserted. Every estimate at one
        byte, then every estimate at 4 GiB and 100k threads: the finding, its
        severity and the absence of any hedging are identical, because the
        comparison that raises it never touched them."""
        from hpaanalyzer import proofs as P
        tiny = P.Est(1, 1, 1, "perturbed")
        huge = P.Est(4096 * 1024**2, 4096 * 1024**2, 4096 * 1024**2, "perturbed")
        threads_lo, threads_hi = P.Est(1, 1, 1, "p"), P.Est(10**5, 10**5, 10**5, "p")
        for est, thr in ((tiny, threads_lo), (huge, threads_hi)):
            with mock.patch.multiple(P, EST_METASPACE=est, EST_CODECACHE=est,
                                     EST_DIRECT=est, EST_GC_OTHER=est,
                                     EST_THREADS=thr):
                r = analyze(self.tree("-Xmx4g", "2Gi"), helm_mode="off")
                self.assertIn("XF001", _ids(r))
                self.assertIs(_by_id(r, "XF001")[0].severity, Severity.CRITICAL)
                self.assertNotIn("UNDETERMINED", self.everything(r))

    def test_a_range_entirely_below_the_limit_is_a_fit_not_a_maybe(self):
        r = analyze(self.tree("-XX:MaxRAMPercentage=25", "4Gi"),
                    helm_mode="off")
        v = self.budget(r).conclusion
        self.assertTrue(v.startswith("Fits with"), v)
        self.assertIn("with every estimate at its high end", v)
        self.assertIn("does not depend on which value inside the ranges", v)
        self.assertNotIn("UNDETERMINED", self.everything(r))


class TestAThinMarginIsAFindingNotAnUncertainty(_R9Case):
    """R9's own error, caught by measurement during R9.

    A first draft chose the "fits" state with `t_hi <= lim - 10%`, folding a
    comfort judgement into an epistemic one. -Xmx3364m under a 4 GiB limit
    puts t_hi at exactly 4 GiB: the JVM fits at EVERY value the model can
    produce, and the tool printed "the limit 4 GiB falls INSIDE the range this
    model can produce (4 GiB - 4 GiB)" - a sentence refuted by the two numbers
    inside its own parentheses.

    Whether the JVM fits and whether the margin is comfortable are different
    questions. The first picks the state; the second is XF004's; the 10%
    threshold belongs only to the second.
    """

    THIN = ("-Xmx3364m", "4Gi")

    def test_the_boundary_case_fits_because_its_whole_range_fits(self):
        r = analyze(self.tree(*self.THIN), helm_mode="off")
        self.assertNotIn("UNDETERMINED", self.everything(r))
        self.assertEqual(self.fit_coverage(r), [])

    def test_and_the_thin_margin_is_still_reported_as_the_finding(self):
        r = analyze(self.tree(*self.THIN), helm_mode="off")
        self.assertIn("XF004", _ids(r))
        v = self.budget(r).conclusion
        self.assertIn("<10% of limit", v)
        self.assertIn("the thin margin is the finding, not the uncertainty", v)

    def test_the_verdict_never_contradicts_the_numbers_beside_it(self):
        """The specific shape of the bug: prose asserting the limit lies
        inside a range whose two ends are printed as equal, or as both below
        it. Cheap to state, and it is what a reader would have noticed."""
        r = analyze(self.tree(*self.THIN), helm_mode="off")
        lo, hi = [s.strip() for s in self.row(r, "T RANGE")[1].split(" - ")]
        self.assertEqual((lo, hi), ("3.5 GiB", "4 GiB"))
        self.assertNotIn(f"falls INSIDE the range this model can produce "
                         f"({lo} - {hi})", self.budget(r).conclusion)

    def test_the_worst_case_headroom_is_stated_as_a_number_not_a_hedge(self):
        r = analyze(self.tree(*self.THIN), helm_mode="off")
        self.assertIn("worst case 0 B spare", self.budget(r).conclusion)


class TestEveryEstimateIsLabelledWhereItIsUsed(_R9Case):
    """C2.3. The old table printed `Thread stacks (100 x 1 MiB)` over the
    Basis `-Xss x thread count` - two invented constants rendered in the
    typography of measurement, with the word "estimate" nowhere near them.
    A caveat in the report preamble is not a label at the point of use."""

    def test_each_estimated_row_carries_est_and_its_own_band(self):
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off")
        for label, band in (("Metaspace", "80 MiB-180 MiB"),
                            ("JIT code cache", "32 MiB-128 MiB"),
                            ("Direct buffers", "16 MiB-128 MiB"),
                            ("GC + JVM internal", "32 MiB-96 MiB"),
                            ("Thread count", "50-200")):
            row = self.row(r, label)
            self.assertIn("(est.)", row[0], f"{label} row is not labelled")
            self.assertIn(band, row[2], f"{label} row omits its band")

    def test_a_stack_size_the_chart_never_set_is_not_cited_as_a_flag(self):
        """`xss = xss or MiB` collapsed "the chart sets -Xss1m" and "the chart
        sets no -Xss at all" into the same integer, after which the Basis cell
        cited "-Xss x thread count" on charts containing no -Xss anywhere -
        the tool quoting a flag back at a user who never wrote it."""
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off")
        basis = self.row(r, "Thread stack size")[2]
        self.assertIn("HotSpot ThreadStackSize default", basis)
        self.assertNotIn("from the applied JVM flags", basis)

    def test_but_a_stack_size_the_chart_did_set_is_cited_as_observed(self):
        """The other face. Silencing the citation everywhere would pass the
        test above and lose a fact the user supplied."""
        r = analyze(self.tree("-XX:MaxRAMPercentage=50 -Xss512k", "1Gi"),
                    helm_mode="off")
        basis = self.row(r, "Thread stack size")[2]
        self.assertIn("from the applied JVM flags", basis)
        self.assertIn("512 KiB", basis)
        self.assertNotIn("(est.)", self.row(r, "Thread stack size")[0])


class TestMeasuredValuesReplaceEstimatesAndTheRangeWithThem(_R9Case):
    """`--measured`. The tool's answer to its own UNDETERMINED verdict has to
    exist, or the verdict is a dead end.

    The second half is the same overstatement pointed the other way: once
    every non-heap component is measured there are no estimates left in the
    sum, and printing "T RANGE 772 MiB - 772 MiB" over "still fits with every
    estimate at its high end" invites the reader to discount a number they
    measured themselves.
    """

    ALL = {"metaspace": 100 * 1024**2, "codecache": 40 * 1024**2,
           "threads": 60, "xss": 1024**2, "direct": 20 * 1024**2,
           "gc": 40 * 1024**2}

    def test_measuring_everything_settles_the_undetermined_case(self):
        tree = self.tree("-XX:MaxRAMPercentage=50", "1Gi")
        self.assertIn("UNDETERMINED",
                      self.everything(analyze(tree, helm_mode="off")))
        r = analyze(tree, helm_mode="off", measured=dict(self.ALL))
        self.assertNotIn("UNDETERMINED", self.everything(r))
        self.assertIn("772 MiB", self.row(r, "ESTIMATED PEAK RSS")[1])

    def test_a_sum_with_no_estimates_in_it_is_not_given_a_range(self):
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off", measured=dict(self.ALL))
        self.assertFalse(self.has_row(r, "T RANGE"))
        self.assertFalse(self.has_row(r, "MARGIN RANGE"))
        self.assertIn("all measured, no estimates",
                      self.row(r, "ESTIMATED PEAK RSS")[2])
        v = self.budget(r).conclusion
        self.assertNotIn("every estimate at its high end", v)
        self.assertNotIn("at typical values", v)
        self.assertIn("no estimate enters this sum", v)

    def test_each_measured_row_says_which_flag_supplied_it(self):
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off", measured=dict(self.ALL))
        self.assertIn("MEASURED: --measured metaspace=",
                      self.row(r, "Metaspace")[2])
        self.assertNotIn("(est.)", self.row(r, "Metaspace")[0])
        # including the thread COUNT, which is not a byte quantity and took a
        # different path through parse_measured.
        self.assertIn("MEASURED: --measured threads=60",
                      self.row(r, "Thread count")[2])

    def test_the_citation_quotes_what_was_typed_not_what_it_parsed_to(self):
        """`MEASURED: --measured metaspace=...` is a claim about PROVENANCE -
        it says "this number is here because you passed that". Rendering the
        value back from the parsed integer cited `metaspace=220200960` at a
        user who wrote `210Mi`: a string they never typed and would have to do
        arithmetic to recognise as their own.

        Re-rendering through the tool's own formatter would only move the
        defect - `256M` would come back as `244.1Mi`, a different string they
        did not type, and one that reads as the tool disagreeing with them. So
        the literal is carried, and the unit-mismatch case is pinned here
        precisely because it is the one where the two differ: the VALUE cell
        shows the tool's reading (244.1 MiB) and the SOURCE cell shows the
        user's words (256M), which is what lets a reader catch a
        misunderstanding instead of only the tool catching it.
        """
        from hpaanalyzer.proofs import parse_measured
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off",
                    measured=parse_measured(["metaspace=256M,threads=180"]))
        self.assertIn("MEASURED: --measured metaspace=256M",
                      self.row(r, "Metaspace")[2])
        self.assertNotIn("268435456", self.row(r, "Metaspace")[2])
        self.assertNotIn("244.1Mi", self.row(r, "Metaspace")[2])
        self.assertEqual("244.1 MiB", self.row(r, "Metaspace")[1])

    def test_a_plain_dict_still_works_and_cites_the_only_truth_it_has(self):
        """The library API and most of these tests pass a plain dict, which
        never had a literal to lose. That path must keep working rather than
        raising on a missing attribute, and the integer is then genuinely the
        whole truth about where the number came from."""
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off", measured={"metaspace": 256_000_000})
        self.assertIn("MEASURED: --measured metaspace=256000000",
                      self.row(r, "Metaspace")[2])

    def test_the_literals_survive_the_defensive_copy_in_discovery(self):
        """Pinned as its own claim because the first attempt at the fix was
        correct in the parser and did nothing at all in the report: discovery
        took `dict(measured)`, which returns a plain dict and drops the
        subclass. A test of `parse_measured` alone would have passed."""
        from hpaanalyzer.proofs import parse_measured
        from hpaanalyzer.discovery import discover
        ctx = discover(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                       helm_mode="off",
                       measured=parse_measured(["metaspace=210Mi"]))
        self.assertEqual(ctx.measured.literals, {"metaspace": "210Mi"})
        self.assertEqual(ctx.measured, {"metaspace": 210 * 1024**2})

    def test_a_rejected_spec_leaves_no_literal_behind(self):
        """The literal is recorded only after the value validates, so a bad
        component in the middle of a list cannot leave a stale citation for a
        later key to print."""
        from hpaanalyzer.proofs import parse_measured
        with self.assertRaises(ValueError):
            parse_measured(["metaspace=210Mi,threads=banana"])
        ok = parse_measured(["metaspace=210Mi"])
        self.assertEqual(ok.literals, {"metaspace": "210Mi"})

    def test_measuring_some_of_them_narrows_the_band_without_closing_it(self):
        """The partial case is the common one, and it must not be treated as
        either extreme: still a range, but a smaller one."""
        r = analyze(self.tree("-XX:MaxRAMPercentage=50", "1Gi"),
                    helm_mode="off",
                    measured={"metaspace": 100 * 1024**2, "gc": 40 * 1024**2})
        self.assertTrue(self.has_row(r, "T RANGE"))
        self.assertNotIn("(est.)", self.row(r, "Metaspace")[0])
        self.assertIn("(est.)", self.row(r, "JIT code cache")[0])

    def test_an_unparseable_measurement_is_an_error_not_a_silent_estimate(self):
        """A user who passes a measurement and gets the estimate anyway has
        been told the opposite of the truth by a tool whose whole subject is
        not doing that."""
        from hpaanalyzer.proofs import parse_measured
        for bad, needle in (("metaspace", "not KEY=VALUE"),
                            ("metaspace=banana", "not a positive memory"),
                            ("nonesuch=100Mi", "not a measurable component"),
                            ("threads=0", "positive whole number"),
                            ("threads=1.5", "positive whole number")):
            with self.assertRaises(ValueError, msg=bad) as cm:
                parse_measured([bad])
            self.assertIn(needle, str(cm.exception), bad)

    def test_the_good_forms_parse_including_several_in_one_flag(self):
        from hpaanalyzer.proofs import parse_measured
        self.assertEqual(parse_measured(["metaspace=210Mi,threads=180"]),
                         {"metaspace": 210 * 1024**2, "threads": 180})
        self.assertEqual(parse_measured(["gc=1Gi", "direct=256M"])["gc"],
                         1024**3)


class TestUndeterminedReachesTheElevenLinesPeopleActuallyRead(_R9Case):
    """R9, second half. Found by writing R9's own Bar 2 proof, not by reading
    the code.

    C2.5 says the tool must not score its own ignorance, so an UNDETERMINED
    fit deliberately leaves the number alone. That was right, and on its own
    it produced this on the flagship clean fixture:

        GRADE A+  (100.0/100)   0 critical, 0 high, 0 medium, 0 low
        No critical or high findings.

    while page 3 of the same report said the tool could not tell whether the
    workload OOMs. Both lines are true. Together they are the pre-R9 defect
    exactly, moved one screen up - a categorical answer where there is none,
    in the eleven lines almost every reader sees and the only ones a CI job
    prints. Fixing the table and leaving the summary is not fixing the tool;
    R8 taught the same lesson across thirteen surfaces.
    """

    STRADDLE = ("-XX:MaxRAMPercentage=50", "1Gi")

    def tree(self, env=None, mem="1Gi"):
        """A chart with nothing else wrong with it.

        The shared fixture trips PB001 and SC001, and the summary lines under
        test here only render when there is no CRITICAL or HIGH to print
        instead - so testing them on that fixture would have exercised the
        `Fix first:` branch and passed while asserting nothing. The subject is
        what a reader sees when the ONLY thing the tool cannot vouch for is
        the memory fit, so the fixture has to be otherwise clean.
        """
        dep = _r9_dep(env, mem).replace(
            '          image: "repo/app:1.0"\n',
            '          image: "repo/app:1.0"\n'
            "          securityContext:\n"
            "            runAsNonRoot: true\n"
            "            runAsUser: 1000\n"
            "            allowPrivilegeEscalation: false\n"
            "            readOnlyRootFilesystem: true\n"
            "            capabilities: {drop: [ALL]}\n"
            "          readinessProbe: {httpGet: {path: /r, port: 8080}}\n"
            "          livenessProbe: {httpGet: {path: /l, port: 8080}}\n"
            "          startupProbe:\n"
            "            httpGet: {path: /r, port: 8080}\n"
            "            failureThreshold: 30\n"
            "            periodSeconds: 10\n")
        return make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/deployment.yaml": dep})

    def assertNoCritHigh(self, r):
        loud = [f.rule_id for f in r.findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        self.assertEqual(loud, [], "fixture is no longer otherwise clean, so "
                                   "the summary branch under test is dead")

    def summary(self, r):
        from hpaanalyzer.report import stdout_summary
        return stdout_summary(r, "/tmp/r.txt")

    def test_the_terminal_summary_says_it_could_not_decide(self):
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off")
        s = self.summary(r)
        self.assertIn("JVM fit UNDETERMINED", s)
        self.assertIn("NOT a pass", s)
        self.assertIn("--measured", s)

    def test_it_carries_the_range_because_undetermined_alone_sounds_small(self):
        """`722 MiB-1.2 GiB` against a 1 GiB limit tells the reader the doubt
        spans the answer. A first draft ended the capture at `\\S+` and
        printed `model range 722` - not a range, not a quantity, and the one
        number in the sentence that means nothing on its own."""
        s = self.summary(analyze(self.tree(*self.STRADDLE), helm_mode="off"))
        self.assertIn("model range 722 MiB-1.2 GiB", s)
        self.assertIn("limit 1 GiB", s)

    def test_no_critical_or_high_no_longer_reads_as_a_clean_bill(self):
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off")
        self.assertNoCritHigh(r)
        self.assertIn("No critical or high findings - but see the "
                      "UNDETERMINED item above.", self.summary(r))

    def test_the_score_is_still_not_moved_by_it(self):
        """The fix must not become the other error. Deducting for an
        undetermined fit would convert the tool's ignorance into the user's
        defect, which is what C2.5 forbids and what the coverage row exists
        to avoid."""
        from hpaanalyzer.scoring import overall_score
        det = analyze(self.tree("-XX:MaxRAMPercentage=25", "4Gi"),
                      helm_mode="off")
        und = analyze(self.tree(*self.STRADDLE), helm_mode="off")
        self.assertEqual(_ids(und), _ids(det))
        self.assertEqual(overall_score(und), overall_score(det))

    def test_a_chart_with_a_decidable_fit_keeps_the_plain_wording(self):
        """The other face: every clean chart must not acquire a warning."""
        r = analyze(self.tree("-XX:MaxRAMPercentage=25", "4Gi"),
                    helm_mode="off")
        self.assertNoCritHigh(r)
        s = self.summary(r)
        self.assertNotIn("UNDETERMINED", s)
        self.assertIn("No critical or high findings.", s)

    def test_all_three_surfaces_agree_not_just_the_terminal_one(self):
        """R8's lesson: a reader does not experience modules. The full report
        header, the terminal block and the HTML all state the grade, so all
        three have to qualify it."""
        from hpaanalyzer.html_report import render_html
        from hpaanalyzer.report import render
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off")
        self.assertNoCritHigh(r)
        full = " ".join(render(r, "t", level="full").replace("|", " ").split())
        self.assertIn("UNDETERMINED, which is not the same as a pass", full)
        self.assertIn("JVM fit UNDETERMINED", render_html(r, "t"))
        self.assertIn("JVM fit UNDETERMINED", self.summary(r))

    def test_measuring_it_away_removes_the_qualifier_too(self):
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off",
                    measured={"metaspace": 100 * 1024**2,
                              "codecache": 40 * 1024**2, "threads": 60,
                              "xss": 1024**2, "direct": 20 * 1024**2,
                              "gc": 40 * 1024**2})
        self.assertNotIn("UNDETERMINED", self.summary(r))


class TestTheBudgetVerdictsAreExhaustiveAndDisjoint(_R9Case):
    """Three states, and every chart lands in exactly one of them. Written as
    a sweep rather than four separate assertions because the defect R9 fixed
    was a MISSING state, and a per-case test cannot see a gap between cases.
    """

    CASES = [("-XX:MaxRAMPercentage=50", "1Gi", "undetermined"),
             ("-Xmx4g", "2Gi", "over"),
             ("-XX:MaxRAMPercentage=25", "4Gi", "fits"),
             ("-Xmx3364m", "4Gi", "fits")]

    def test_every_case_lands_in_exactly_one_state(self):
        for env, mem, want in self.CASES:
            r = analyze(self.tree(env, mem), helm_mode="off")
            v = self.budget(r).conclusion
            got = {"undetermined": v.startswith("UNDETERMINED"),
                   "over": v.startswith("T exceeds the limit"),
                   "fits": v.startswith("Fits with") or v.startswith("Margin ")}
            self.assertEqual([k for k, hit in got.items() if hit], [want],
                             f"{env} @ {mem}: {v[:120]}")

    def test_the_undetermined_state_is_the_only_one_that_adds_coverage(self):
        for env, mem, want in self.CASES:
            r = analyze(self.tree(env, mem), helm_mode="off")
            self.assertEqual(bool(self.fit_coverage(r)),
                             want == "undetermined", f"{env} @ {mem}")


class TestTheRemedyNamesWhatIsStillMissing(_R9Case):
    """R9, third defect - found by running the README's own example.

    C2.8(e) requires the undetermined verdict to name "the observation that
    would settle it and the flag that accepts that observation". R9's first
    implementation satisfied the letter of that by ending every undetermined
    verdict with the same hand-written sentence:

        ... then pass the numbers back with --measured
        metaspace=...,threads=...,direct=...

    Run against `--measured metaspace=210Mi,threads=180` - the invocation the
    README prints - that sentence named two components the reader had just
    supplied, omitted two of the three still deciding the answer, and the
    terminal block said "Settle it with `--measured`." to somebody who had
    just used `--measured`. The tool was telling a user to go and do the
    thing they had done while staying silent about the thing that would have
    worked.

    That is not a wording defect. A canned remedy cannot be correct after a
    partial measurement, because which observation settles the question is a
    property of the run and not of the sentence. So the fix derives the list
    from the same `Comp` records the table prints, and this class pins the
    property on all three surfaces a reader can reach it from - the verdict,
    the coverage row and the terminal summary - because R8's lesson was that
    fixing one surface and leaving the others is not fixing the tool.

    Both faces are pinned: the flags must name what is missing (or a partial
    run is a dead end), and they must NOT name what was supplied (or a full
    run would be told to measure everything again). A test of only the first
    would be met by reverting to the canned string, which named metaspace.
    """

    STRADDLE = ("-XX:MaxRAMPercentage=50", "1Gi")
    PARTIAL = {"metaspace": 210 * 1024**2, "threads": 180}
    # key -> the label the table prints for it, so a check on the flags can be
    # reconciled against the rows rather than against another hardcoded list.
    LABELS = {"metaspace": "Metaspace", "codecache": "JIT code cache",
              "threads": "Thread count", "direct": "Direct buffers",
              "gc": "GC + JVM internal"}

    def surfaces(self, r):
        """The three places a reader can meet the remedy, as one dict.

        Asserting on each separately would let a fix land on two of them and
        still pass two thirds of this class; naming them together makes the
        omission the failure message.
        """
        from hpaanalyzer.report import stdout_summary
        return {"verdict": self.budget(r).conclusion,
                "coverage": str(self.fit_coverage(r)[0][1]),
                "summary": stdout_summary(r, "/tmp/r.txt")}

    def flags(self, text):
        """The component list out of `--measured a=...,b=...`, or None."""
        import re
        m = re.search(r"--measured ([a-z]+=\.\.\.(?:,[a-z]+=\.\.\.)*)", text)
        return None if m is None else [p.split("=")[0]
                                       for p in m.group(1).split(",")]

    def test_with_nothing_measured_every_component_is_named(self):
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off")
        for where, text in self.surfaces(r).items():
            self.assertEqual(
                self.flags(text),
                ["metaspace", "codecache", "threads", "direct", "gc"],
                f"{where}: {text[-160:]}")

    def test_after_a_partial_measurement_only_the_rest_is_named(self):
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off",
                    measured=dict(self.PARTIAL))
        for where, text in self.surfaces(r).items():
            got = self.flags(text)
            self.assertEqual(got, ["codecache", "direct", "gc"],
                             f"{where}: {text[-160:]}")
            for supplied in self.PARTIAL:
                self.assertNotIn(supplied, got or [], where)

    def test_the_named_flags_are_exactly_the_rows_still_labelled_est(self):
        """The list is checked against the table rather than against a second
        copy of the answer. A hardcoded expectation would keep passing if the
        estimate labelling and the remedy drifted apart - which is precisely
        the failure being fixed, one level up.
        """
        for measured in (None, dict(self.PARTIAL)):
            kw = {"measured": measured} if measured else {}
            r = analyze(self.tree(*self.STRADDLE), helm_mode="off", **kw)
            named = self.flags(self.budget(r).conclusion)
            est = [k for k, label in self.LABELS.items()
                   if "(est.)" in self.row(r, label)[0]]
            self.assertEqual(sorted(named), sorted(est), f"measured={measured}")

    def test_the_verdict_credits_what_the_reader_already_did(self):
        """Naming the remainder is necessary but not sufficient: a reader who
        passed two flags and sees three different ones has to be told why the
        list changed, or the tool looks like it ignored the measurement."""
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off",
                    measured=dict(self.PARTIAL))
        v = self.budget(r).conclusion
        self.assertIn("You have already measured metaspace, threads", v)
        self.assertIn("decided by the components you have not: "
                      "codecache, direct, gc", v)

    def test_a_run_with_nothing_measured_does_not_credit_a_measurement(self):
        """The other face of the sentence above: it must be a report of what
        happened, not decoration that prints either way."""
        v = self.budget(analyze(self.tree(*self.STRADDLE),
                                helm_mode="off")).conclusion
        self.assertNotIn("already measured", v)

    def test_the_deciding_set_never_names_a_component_the_user_measured(self):
        """C2.8(d) and (e) have to agree. "The smallest set that decides it"
        is computed from band widths and "what is left to measure" from the
        estimate flag; if those two ever disagree the verdict would ask the
        reader to check a number they had already pinned to a single value.
        Measured here rather than assumed from the implementation sharing a
        field, because the two are computed by different functions.
        """
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off",
                    measured=dict(self.PARTIAL))
        head = self.budget(r).conclusion.split("You have already")[0]
        for supplied in self.PARTIAL:
            self.assertNotIn(self.LABELS[supplied], head,
                             f"{supplied} was measured but still appears in "
                             f"the deciding set: {head[-200:]}")

    def test_measuring_everything_leaves_no_remedy_to_print(self):
        """The terminating case. With nothing estimated the verdict is not
        undetermined at all, so a `--measured ...` instruction anywhere in the
        report would be an instruction to settle a question already settled.
        """
        r = analyze(self.tree(*self.STRADDLE), helm_mode="off",
                    measured={"metaspace": 100 * 1024**2,
                              "codecache": 40 * 1024**2, "threads": 60,
                              "xss": 1024**2, "direct": 20 * 1024**2,
                              "gc": 40 * 1024**2})
        self.assertIsNone(self.flags(self.everything(r)))
        self.assertEqual(self.fit_coverage(r), [])


if __name__ == "__main__":
    unittest.main()

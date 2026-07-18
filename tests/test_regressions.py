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
from hpaanalyzer.models import Basis, Severity
from hpaanalyzer.scoring import overall_score

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


if __name__ == "__main__":
    unittest.main()

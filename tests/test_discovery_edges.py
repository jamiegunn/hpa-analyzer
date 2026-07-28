"""Discovery edge behaviour: what the coverage table and parse-error list say
when the input directory is degenerate, partially unreadable, or shaped in a
way the happy-path fixtures never are.

Every test asserts on the SURFACED record - a coverage row, a parse error, a
context field the report prints - because discovery's contract is not "cope
silently" but "cope and say so".
"""

import os
import shutil
import stat
import unittest

from hpaanalyzer.discovery import discover, is_hook_doc
from hpaanalyzer.engine import analyze

from .util import CHART_YAML, make_tree

DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: app
          image: "repo/app:1.0"
          resources:
            requests: {cpu: 500m, memory: 1Gi}
            limits: {memory: 1Gi}
"""

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def _chart(extra=None):
    files = {"Chart.yaml": CHART_YAML, "values.yaml": "replicaCount: 2\n",
             "templates/deployment.yaml": DEPLOYMENT}
    files.update(extra or {})
    return make_tree(files)


def _unreadable(path):
    os.chmod(path, 0o000)


def _restore(path):
    os.chmod(path, stat.S_IRWXU)


def _rows(ctx, needle):
    return [r for r in ctx.coverage if needle in r[0] or needle in r[1]]


class TestChartsDirectory(unittest.TestCase):
    @unittest.skipIf(IS_ROOT, "root ignores file permissions")
    def test_unreadable_charts_dir_is_not_reported_as_subcharts(self):
        """An unlistable charts/ dir yields no subchart names, so the report
        must not claim vendored subcharts exist when it could not see any."""
        root = _chart()
        cdir = os.path.join(root, "charts")
        os.makedirs(cdir)
        _unreadable(cdir)
        try:
            ctx = discover(root, helm_mode="off")
        finally:
            _restore(cdir)
        self.assertFalse(ctx.subcharts_present)
        self.assertEqual(_rows(ctx, "subchart"), [])

    def test_empty_charts_dir_is_not_subcharts(self):
        """charts/ existing but empty is not 'subcharts present': there is
        nothing behind the scope boundary, so no NOT-graded row is owed."""
        root = _chart()
        os.makedirs(os.path.join(root, "charts"))
        ctx = discover(root, helm_mode="off")
        self.assertFalse(ctx.subcharts_present)
        self.assertEqual(_rows(ctx, "subchart"), [])

    def test_tgz_named_and_stray_file_ignored(self):
        """A packaged worker.tgz is a subchart named 'worker'; a stray
        charts/README.md is neither a directory nor a package and must not be
        invented into a subchart name. Static mode still prints the
        out-of-scope coverage row naming what was not read."""
        root = _chart({"charts/worker.tgz": "not-a-real-archive",
                       "charts/README.md": "docs\n"})
        ctx = discover(root, helm_mode="off")
        self.assertEqual(ctx.subchart_names, ["worker"])
        rows = _rows(ctx, "charts/ (subcharts)")
        self.assertEqual(len(rows), 1)
        self.assertIn("worker", rows[0][1])
        self.assertIn("NOT graded", rows[0][1])
        self.assertNotIn("README", rows[0][1])


class TestChartYaml(unittest.TestCase):
    def test_chart_yml_spelling_is_found(self):
        """Chart.yml (the .yml spelling) identifies the chart root exactly as
        Chart.yaml does; helm accepts both and so must discovery."""
        root = make_tree({"Chart.yml": CHART_YAML,
                          "values.yaml": "a: 1\n",
                          "templates/deployment.yaml": DEPLOYMENT})
        ctx = discover(root, helm_mode="off")
        self.assertEqual(ctx.chart_yaml_path, "Chart.yml")
        self.assertEqual((ctx.chart or {}).get("name"), "t")

    def test_broken_chart_yaml_is_a_recorded_parse_error(self):
        """Unparseable Chart.yaml must land in parse_errors (which preflight
        surfaces), not vanish - chart-metadata checks silently not running
        would look identical to the checks passing."""
        root = make_tree({"Chart.yaml": "name: [unclosed\n",
                          "values.yaml": "a: 1\n",
                          "templates/deployment.yaml": DEPLOYMENT})
        ctx = discover(root, helm_mode="off")
        self.assertTrue(any("Chart.yaml" in e for e in ctx.parse_errors),
                        ctx.parse_errors)


class TestValuesFiles(unittest.TestCase):
    def test_unparseable_values_gets_a_parse_failed_row(self):
        """A values file that fails YAML parsing produced no analysis input;
        the coverage table must say PARSE FAILED for it rather than letting
        the reader assume their values were considered."""
        root = _chart({"values.yaml": "a: [broken\n"})
        ctx = discover(root, helm_mode="off")
        rows = _rows(ctx, "PARSE FAILED - values not analyzed")
        self.assertEqual([r[0] for r in rows], ["values.yaml"])
        self.assertTrue(any("values.yaml" in e for e in ctx.parse_errors))

    @unittest.skipIf(IS_ROOT, "root ignores file permissions")
    def test_unreadable_values_recorded_as_parse_error(self):
        """An OS-level read failure on values.yaml is recorded in
        parse_errors; the run continues with the rest of the chart."""
        root = _chart()
        vpath = os.path.join(root, "values.yaml")
        _unreadable(vpath)
        try:
            ctx = discover(root, helm_mode="off")
        finally:
            _restore(vpath)
        self.assertTrue(any("values.yaml" in e and "Permission" in e
                            for e in ctx.parse_errors), ctx.parse_errors)

    def test_list_valued_base_values_excluded_and_said_so(self):
        """A values.yaml that parses to a list cannot be merged; the primary
        analysis then runs with an EMPTY value set and the coverage row must
        state exactly that (F11: silence here hides a guarantee breach)."""
        root = _chart({"values.yaml": "- a\n- b\n"})
        ctx = discover(root, helm_mode="off")
        rows = _rows(ctx, "NOT a mapping (list)")
        self.assertEqual([r[0] for r in rows], ["values.yaml"])
        self.assertIn("EMPTY value set", rows[0][1])
        self.assertEqual(ctx.values, {})

    def test_list_valued_overlay_not_analyzed_as_variant(self):
        """An overlay that parses to a list is not a variant value set; it is
        excluded with its own coverage row and never joins overlay_values."""
        root = _chart({"values-prod.yaml": "- x\n"})
        ctx = discover(root, helm_mode="off")
        rows = [r for r in ctx.coverage if r[0] == "values-prod.yaml"]
        self.assertEqual(len(rows), 1)
        self.assertIn("NOT analyzed as a variant", rows[0][1])
        self.assertNotIn("values-prod.yaml", ctx.overlay_values)

    def test_no_base_values_fallback_merge_skips_non_mappings(self):
        """With no base values.yaml the merge falls back to every mapping
        values file; a list-valued file in that set is skipped, not merged
        into (or crashing) the effective values."""
        root = make_tree({"Chart.yaml": CHART_YAML,
                          "values-a.yaml": "- not\n- a\n- mapping\n",
                          "values-b.yaml": "replicaCount: 2\n",
                          "templates/deployment.yaml": DEPLOYMENT})
        ctx = discover(root, helm_mode="off")
        self.assertEqual(ctx.values.get("replicaCount"), 2)


class TestHookPredicate(unittest.TestCase):
    def test_non_mapping_documents_are_not_hooks(self):
        """is_hook_doc answers 'is this a helm hook object'; a scalar or None
        document is not an object at all, so the answer is False - not an
        AttributeError inside a check that trusted the predicate."""
        self.assertFalse(is_hook_doc(None))
        self.assertFalse(is_hook_doc("just a string"))
        self.assertTrue(is_hook_doc(
            {"metadata": {"annotations": {"helm.sh/hook": "test"}}}))


class TestTemplateScrubParse(unittest.TestCase):
    def test_oversized_template_skipped_with_row_and_error(self):
        """F11 size guard: a template past 1,000,000 bytes is skipped, and
        BOTH surfaces say so - the coverage row (no checks ran on it) and the
        parse-error list (so preflight counts it as a problem)."""
        big = "x: 1\n" + ("# pad\n" * 200_000)
        root = _chart({"templates/huge.yaml": big})
        ctx = discover(root, helm_mode="off")
        rows = [r for r in ctx.coverage if r[0] == "templates/huge.yaml"]
        self.assertEqual(len(rows), 1)
        self.assertIn("SKIPPED", rows[0][1])
        self.assertIn("NO checks ran", rows[0][1])
        self.assertTrue(any("size guard" in e for e in ctx.parse_errors))

    def test_unparseable_template_gets_parse_failed_row(self):
        """A template the static parser cannot read produced no findings;
        the coverage row must say so, and the error names the file."""
        root = _chart({"templates/bad.yaml": "foo: [unclosed\n"})
        ctx = discover(root, helm_mode="off")
        rows = [r for r in ctx.coverage if r[0] == "templates/bad.yaml"]
        self.assertEqual(len(rows), 1)
        self.assertIn("PARSE FAILED", rows[0][1])
        self.assertTrue(any("templates/bad.yaml" in e
                            and "could not statically parse" in e
                            for e in ctx.parse_errors))

    def test_duplicate_key_in_template_is_reported(self):
        """YAML silently keeps the LAST duplicate key; the chart author almost
        never means that, so the duplicate is reported with its line."""
        dup = ("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"
               "data: {x: '1'}\ndata: {x: '2'}\n")
        root = _chart({"templates/dup.yaml": dup})
        ctx = discover(root, helm_mode="off")
        self.assertTrue(any("duplicate key 'data'" in e
                            and "later value silently wins" in e
                            for e in ctx.parse_errors), ctx.parse_errors)

    def test_hook_object_not_counted_as_workload(self):
        """A helm.sh/hook Job is lifecycle plumbing, not a workload; the
        static parse records the file with zero objects rather than grading a
        pre-install hook as if it served traffic."""
        hook = ("apiVersion: batch/v1\nkind: Job\n"
                "metadata:\n  name: hook\n  annotations:\n"
                "    \"helm.sh/hook\": pre-install\n"
                "spec: {template: {spec: {containers: []}}}\n")
        root = _chart({"templates/hook.yaml": hook})
        ctx = discover(root, helm_mode="off")
        rows = [r for r in ctx.coverage if r[0] == "templates/hook.yaml"]
        self.assertEqual(rows, [["templates/hook.yaml",
                                 "statically parsed (0 object(s))"]])
        self.assertFalse(any(d.file == "templates/hook.yaml"
                             for d in ctx.workloads))

    def test_tests_dir_only_yaml_collected(self):
        """templates/tests/ holds helm test hooks: .yaml files are recorded
        as lint-only, and a stray .txt there is not a template at all."""
        root = _chart({"templates/tests/test-conn.yaml":
                       "apiVersion: v1\nkind: Pod\nmetadata: {name: t}\n",
                       "templates/tests/notes.txt": "not yaml\n"})
        ctx = discover(root, helm_mode="off")
        self.assertTrue(ctx.tests_dir)
        self.assertIn("templates/tests/test-conn.yaml", ctx.template_files)
        self.assertNotIn("templates/tests/notes.txt", ctx.template_files)
        rows = [r for r in ctx.coverage
                if r[0] == "templates/tests/test-conn.yaml"]
        self.assertEqual(len(rows), 1)
        self.assertIn("helm test hook", rows[0][1])

    @unittest.skipIf(IS_ROOT, "root ignores file permissions")
    def test_unreadable_template_recorded(self):
        """A template the OS refuses to read is a coverage gap and must be a
        recorded parse error, not a silently shorter template list."""
        root = _chart()
        tpath = os.path.join(root, "templates", "deployment.yaml")
        _unreadable(tpath)
        try:
            ctx = discover(root, helm_mode="off")
        finally:
            _restore(tpath)
        self.assertTrue(any("templates/deployment.yaml" in e
                            for e in ctx.parse_errors), ctx.parse_errors)


class TestRenderModeRecording(unittest.TestCase):
    def test_helm_on_without_chart_dir_names_the_reason(self):
        """helm_mode='on' against a directory with no Chart.yaml cannot
        render; the recorded mode states which precondition was missing."""
        root = make_tree({"templates/deployment.yaml": DEPLOYMENT})
        ctx = discover(root, helm_mode="on")
        self.assertEqual(ctx.render_mode,
                         "static (helm requested but no chart directory)")

    def test_helm_absent_from_path_names_the_reason(self):
        """With no helm binary reachable on PATH the run falls back to static
        parsing and the render mode says why. PATH is genuinely emptied for
        the call - no fake binary, no stubbed renderer."""
        root = _chart()
        empty = make_tree({".keep": ""})
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = empty
        try:
            ctx = discover(root, helm_mode="on")
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(ctx.render_mode, "static (helm not found on PATH)")
        self.assertFalse(ctx.helm_present)
        # the fallback still analyzed the chart
        self.assertTrue(any(d.kind == "Deployment" for d in ctx.docs))


class TestDockerfileDiscovery(unittest.TestCase):
    def test_launcher_script_next_to_dockerfile_is_read(self):
        """R2: ENTRYPOINT ['./start.sh'] with start.sh in the same directory
        means the flags analysis must see what the script execs - here it
        applies $JAVA_OPTS, so -Xmx512m counts as an applied flag."""
        root = _chart({
            "Dockerfile": ("FROM eclipse-temurin:17-jre\n"
                           "ENV JAVA_OPTS=\"-Xmx512m\"\n"
                           "COPY start.sh /start.sh\n"
                           "ENTRYPOINT [\"./start.sh\"]\n"),
            "start.sh": "#!/bin/sh\nexec java $JAVA_OPTS -jar /app.jar\n"})
        ctx = discover(root, helm_mode="off")
        self.assertEqual(len(ctx.dockerfiles), 1)
        self.assertIn("exec java $JAVA_OPTS",
                      ctx.dockerfiles[0].launcher_script_text)

    @unittest.skipIf(IS_ROOT, "root ignores file permissions")
    def test_unreadable_launcher_script_leaves_text_empty(self):
        """If the referenced launch script cannot be read, the analysis holds
        no script text (rather than crashing or inventing one); the JAVA_OPTS
        var then stays unproven as applied."""
        root = _chart({
            "Dockerfile": ("FROM eclipse-temurin:17-jre\n"
                           "ENV JAVA_OPTS=\"-Xmx512m\"\n"
                           "ENTRYPOINT [\"./start.sh\"]\n"),
            "start.sh": "#!/bin/sh\nexec java $JAVA_OPTS -jar /app.jar\n"})
        spath = os.path.join(root, "start.sh")
        _unreadable(spath)
        try:
            ctx = discover(root, helm_mode="off")
        finally:
            _restore(spath)
        self.assertEqual(ctx.dockerfiles[0].launcher_script_text, "")

    def test_bad_assume_java_spec_is_a_recorded_error(self):
        """--assume-java takes 8 / 8u151 / 11.0.16 / 17; anything else is
        reported with the accepted forms, never silently ignored."""
        root = _chart()
        ctx = discover(root, helm_mode="off", assume_java="banana")
        self.assertTrue(any("--assume-java 'banana' not understood" in e
                            for e in ctx.parse_errors), ctx.parse_errors)

    def test_assume_java_refused_when_nothing_is_a_jvm(self):
        """R15: --assume-java states a version, not the existence of a
        runtime. On a chart with zero JVM evidence the flag is refused and
        the coverage row explains why, so Java checks stay unassessed."""
        root = _chart({"Dockerfile": "FROM nginx:1.25\n"})
        ctx = discover(root, helm_mode="off", assume_java="17")
        rows = [r for r in ctx.coverage if r[0] == "Dockerfile"]
        self.assertEqual(len(rows), 1)
        self.assertIn("NOT applied", rows[0][1])
        self.assertIn("no JVM is", rows[0][1])
        self.assertIsNone(ctx.dockerfiles[0].java_major)

    @unittest.skipIf(IS_ROOT, "root ignores file permissions")
    def test_unreadable_dockerfile_recorded(self):
        """A Dockerfile the OS refuses to read is a recorded parse error and
        the image-level checks simply have no file, not a phantom one."""
        root = _chart({"Dockerfile": "FROM nginx:1.25\n"})
        dpath = os.path.join(root, "Dockerfile")
        _unreadable(dpath)
        try:
            ctx = discover(root, helm_mode="off")
        finally:
            _restore(dpath)
        self.assertTrue(any("Dockerfile" in e for e in ctx.parse_errors))
        self.assertEqual(ctx.dockerfiles, [])


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class TestHelmRenderEdges(unittest.TestCase):
    """Paths only a real `helm template` run reaches."""

    def test_chart_in_subdirectory_keeps_root_relative_paths(self):
        """When the chart lives in a subdirectory of the analysis root, the
        rendered docs' paths are re-prefixed so coverage rows match the
        on-disk layout instead of duplicating every object as unrendered."""
        root = make_tree({
            "mychart/Chart.yaml": CHART_YAML,
            "mychart/values.yaml": "replicaCount: 2\n",
            "mychart/templates/deployment.yaml": DEPLOYMENT})
        ctx = discover(root, helm_mode="on")
        self.assertEqual(ctx.render_mode, "helm")
        self.assertIn(["mychart/templates/deployment.yaml",
                       "rendered by helm"], ctx.coverage)
        self.assertTrue(all(d.file.startswith("mychart/") for d in ctx.docs))

    def test_duplicate_key_in_rendered_output_is_reported(self):
        """helm renders duplicate mapping keys without complaint (later value
        silently wins at apply time), so the duplicate must be reported as a
        fact about the RENDERED output."""
        dup = ("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"
               "data: {x: '1'}\ndata: {x: '2'}\n")
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "replicaCount: 2\n",
            "templates/deployment.yaml": DEPLOYMENT,
            "templates/dup.yaml": dup})
        ctx = discover(root, helm_mode="on")
        self.assertEqual(ctx.render_mode, "helm")
        self.assertTrue(any("RENDERED output" in e and "duplicate key 'data'"
                            in e for e in ctx.parse_errors), ctx.parse_errors)
        # the real workload still rendered and was kept
        self.assertTrue(any(d.kind == "Deployment" and d.rendered
                            for d in ctx.docs))

    def test_conditional_template_without_kind_not_added(self):
        """A template disabled by current values whose static parse yields a
        mapping with no `kind` is not an analyzable object; it must not be
        appended as a phantom conditional doc."""
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "replicaCount: 2\n",
            "templates/deployment.yaml": DEPLOYMENT,
            "templates/maybe.yaml": ("{{- if .Values.extras }}\n"
                                     "foo: bar\n"
                                     "{{- end }}\n")})
        ctx = discover(root, helm_mode="on")
        self.assertEqual(ctx.render_mode, "helm")
        self.assertFalse(any(d.file == "templates/maybe.yaml"
                             for d in ctx.docs))
        self.assertFalse(any("templates/maybe.yaml" in r[0]
                             and "conditional" in r[1] for r in ctx.coverage))

    def test_subchart_output_parked_not_graded_and_not_errored(self):
        """Subchart render output is recorded but never graded: parse
        failures inside charts/ are deliberately NOT user-facing parse errors
        (out of scope), hook objects and scalar docs are dropped, and the
        coverage note names what was parked - including a kind-only entry for
        an object with no metadata.name."""
        sub_chart = ("apiVersion: v2\nname: sub\nversion: 0.1.0\n")
        root = make_tree({
            "Chart.yaml": CHART_YAML,
            "values.yaml": "replicaCount: 2\n",
            "templates/deployment.yaml": DEPLOYMENT,
            "charts/sub/Chart.yaml": sub_chart,
            "charts/sub/values.yaml": "x: 1\n",
            "charts/sub/templates/deploy.yaml":
                DEPLOYMENT.replace("name: web", "name: subapp"),
            "charts/sub/templates/noname.yaml":
                "apiVersion: v1\nkind: ConfigMap\ndata: {a: '1'}\n",
            "charts/sub/templates/hook.yaml":
                ("apiVersion: batch/v1\nkind: Job\n"
                 "metadata:\n  name: subhook\n  annotations:\n"
                 "    \"helm.sh/hook\": test\n"
                 "spec: {template: {spec: {containers: []}}}\n")})
        ctx = discover(root, helm_mode="on")
        self.assertEqual(ctx.render_mode, "helm")
        kinds = [(d.kind, (d.data.get("metadata") or {}).get("name"))
                 for d in ctx.subchart_docs]
        self.assertIn(("Deployment", "subapp"), kinds)
        self.assertIn(("ConfigMap", None), kinds)
        # the hook object was dropped, not parked as a gradeable doc
        self.assertNotIn("Job", [k for k, _ in kinds])
        self.assertFalse(any("charts/" in e for e in ctx.parse_errors),
                         ctx.parse_errors)
        rows = _rows(ctx, "charts/ (subcharts)")
        self.assertEqual(len(rows), 1)
        note = rows[0][1]
        self.assertIn("Deployment/subapp", note)
        self.assertIn("ConfigMap", note)
        self.assertIn("NOT graded", note)
        # nothing from the subchart leaked into the graded docs
        self.assertFalse(any(d.file.startswith("charts/") for d in ctx.docs))

    def test_failed_divergence_probe_is_recorded_not_dropped(self):
        """The floor-of-range probe render failing is a recorded fact
        ('we could not check divergence'), which is a different statement
        from 'we checked and the chart is version-stable' (C2.2)."""
        gated = ("{{- if semverCompare \"<1.25-0\" "
                 ".Capabilities.KubeVersion.Version }}\n"
                 "{{- fail \"needs 1.25+\" }}\n"
                 "{{- end }}\n"
                 "apiVersion: v1\nkind: ConfigMap\n"
                 "metadata: {name: gate}\ndata: {}\n")
        root = make_tree({
            "Chart.yaml": CHART_YAML,   # kubeVersion ">=1.23.0-0" -> probe 1.23
            "values.yaml": "replicaCount: 2\n",
            "templates/deployment.yaml": DEPLOYMENT,
            "templates/gate.yaml": gated})
        ctx = discover(root, helm_mode="on")
        self.assertEqual(ctx.render_mode, "helm")
        self.assertIsNotNone(ctx.render_divergence)
        self.assertFalse(ctx.render_divergence.get("checked"))
        self.assertEqual(ctx.render_divergence.get("probe"), "1.23.0")
        self.assertTrue(ctx.render_divergence.get("error"))


class TestHelmOutputParser(unittest.TestCase):
    """helm_parse_output on its documented input format, driven directly.

    helm 4.2 refuses to render invalid YAML, but the parser's input contract
    is any `helm template` stdout: `helm template --debug` renders invalid
    YAML out verbatim, and other helm builds validate differently. The parser
    must degrade per-chunk with a recorded error, never by discarding the
    whole render - so the degenerate chunks are fed to it as text.
    """

    OUTPUT = """---
# Source: t/templates/ok.yaml
apiVersion: v1
kind: ConfigMap
metadata: {name: ok}
data: {}
---
# Source: t/templates/broken.yaml
key: [1,
---
# Source: t/templates/scalar.yaml
just-a-string
---
# Source: t/charts/sub/templates/bad.yaml
b: [oops
---
# Source: t/charts/sub/templates/scalar.yaml
sub-scalar
"""

    def _parse(self):
        from hpaanalyzer.discovery import helm_parse_output
        root = _chart()
        ctx = discover(root, helm_mode="off")
        return ctx, helm_parse_output(ctx, self.OUTPUT)

    def test_unparseable_chunk_is_a_recorded_error_not_a_lost_render(self):
        """One chunk failing YAML parsing loses THAT chunk, records which
        source file it came from, and keeps every other rendered object."""
        ctx, docs = self._parse()
        self.assertEqual([(d.kind, d.file) for d in docs],
                         [("ConfigMap", "templates/ok.yaml")])
        self.assertTrue(any("helm output (templates/broken.yaml)" in e
                            for e in ctx.parse_errors), ctx.parse_errors)

    def test_scalar_document_is_not_an_object(self):
        """A rendered document that is a bare scalar has no kind and no spec;
        it is skipped without an error - there is nothing to analyze and
        nothing to warn about."""
        ctx, docs = self._parse()
        self.assertFalse(any(d.file == "templates/scalar.yaml" for d in docs))
        self.assertFalse(any("scalar" in e for e in ctx.parse_errors))

    def test_subchart_parse_failures_are_swallowed_by_design(self):
        """A charts/ chunk that fails to parse is deliberately NOT a
        user-facing parse error: the object was never in scope, and reporting
        it would present a subchart's problem as a gap in the user's own
        analysis. The subchart is still named."""
        ctx, _ = self._parse()
        self.assertIn("sub", ctx.subchart_names)
        self.assertFalse(any("charts/" in e for e in ctx.parse_errors),
                         ctx.parse_errors)
        # neither degenerate subchart chunk was parked as a doc
        self.assertEqual(ctx.subchart_docs, [])


class TestEngineIntegration(unittest.TestCase):
    def test_broken_values_still_produces_a_report_result(self):
        """A chart with a broken values file must still analyze the templates
        it can read - degraded coverage, not a crash or an empty result."""
        root = _chart({"values.yaml": "a: [broken\n"})
        r = analyze(root, helm_mode="off")
        self.assertTrue(any(d.kind == "Deployment" for d in r.context.docs))


if __name__ == "__main__":
    unittest.main()

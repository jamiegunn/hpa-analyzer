"""Guided preflight + external cross-check."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

import hpaanalyzer.external as ext
from hpaanalyzer.__main__ import main
from hpaanalyzer.helmrender import render_chart
from hpaanalyzer.engine import analyze
from hpaanalyzer.preflight import build_preflight

from .util import CHART_YAML, make_tree

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")

DEP = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: w}\n"
       "spec:\n  selector: {matchLabels: {app: w}}\n"
       "  template:\n    metadata: {labels: {app: w}}\n"
       "    spec:\n      containers:\n        - name: app\n          image: r/a:1\n"
       "          resources: {requests: {cpu: 500m, memory: 1Gi}, "
       "limits: {memory: 1Gi}}\n")


def _statuses(pf):
    return [(i.status, i.label) for i in pf.items]


class TestPreflight(unittest.TestCase):
    def test_complete_chart_is_ok_no_errors(self):
        pf = build_preflight(analyze(os.path.join(FIXTURES, "good-chart"),
                                     helm_mode="off").context)
        self.assertTrue(pf.is_chart)
        self.assertFalse(any(i.status == "error" for i in pf.items))
        self.assertTrue(any(i.status == "ok" and "Helm chart" in i.label
                            for i in pf.items))

    def test_non_chart_directory_flagged_as_error(self):
        root = make_tree({"readme.txt": "hi\n"})
        pf = build_preflight(analyze(root, helm_mode="off").context)
        self.assertFalse(pf.is_chart)
        self.assertTrue(any(i.status == "error" for i in pf.items))

    def test_missing_dockerfile_warns_with_scope_note(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": DEP})
        pf = build_preflight(analyze(root, helm_mode="off").context)
        self.assertTrue(pf.is_chart)   # still analyzable
        self.assertTrue(any(i.status == "warn" and "No Dockerfile" in i.label
                            for i in pf.items))

    def test_undeterminable_java_suggests_assume_java(self):
        root = make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                          "templates/d.yaml": DEP,
                          "Dockerfile": "FROM corp/base:v1\n"
                                        'ENTRYPOINT ["java","-jar","/a.jar"]\n'})
        pf = build_preflight(analyze(root, helm_mode="off").context)
        item = next(i for i in pf.items if "Dockerfile" in i.label)
        self.assertEqual(item.status, "warn")
        self.assertIn("--assume-java", item.hint)

    def test_multiple_charts_warned(self):
        root = make_tree({
            "a/Chart.yaml": CHART_YAML, "a/values.yaml": "x: 1\n",
            "a/templates/d.yaml": DEP,
            "b/Chart.yaml": CHART_YAML, "b/values.yaml": "x: 1\n",
            "b/templates/d.yaml": DEP})
        pf = build_preflight(analyze(root, helm_mode="off").context)
        self.assertTrue(any(i.status == "warn" and "other chart" in i.label
                            for i in pf.items))


class TestExternalCrossCheck(unittest.TestCase):
    """C5.3 applied to OTHER programs' output.

    The version of this class that R4 deleted mocked `ext._run` and asserted
    against strings it had invented:

        if "lint" in cmd:  return (0, "1 chart(s) linted, 0 failed", "")
        if "kubeconform" ...: return (1, "Summary: 0 valid, 1 invalid", "")

    Real helm prints "1 chart(s) linted, 0 chart(s) failed". Real kubeconform
    prints "Summary: 5 resources found in 1 file - Valid: 2, Invalid: 0,
    Errors: 3, Skipped: 0". Neither invented string is a substring of the real
    one, and the kubeconform mock does not match _KUBECONFORM_SUMMARY at all -
    so the suite could go green while the parser was blind to every input it
    would ever see in production. A test that authors both sides of an
    integration tests nothing but the author's memory.

    These run the real binaries and skip honestly when one is absent. The
    absence cases below are still exercised, but by emptying PATH rather than
    by patching `_which`, so even "the tool is missing" is a real observation.
    """

    @staticmethod
    def _path_with(*binaries):
        """A real PATH directory containing only `binaries` (symlinked)."""
        d = tempfile.mkdtemp(prefix="hpa-path-")
        for b in binaries:
            real = shutil.which(b)
            if real:
                os.symlink(real, os.path.join(d, b))
        return d

    def test_no_binaries_on_path_reports_install_hints(self):
        empty = self._path_with()
        with mock.patch.dict(os.environ, {"PATH": empty}):
            res = ext.run_cross_check(os.path.join(FIXTURES, "good-chart"))
        names = {e.name for e in res}
        self.assertEqual(names, {"helm lint", "kubeconform", "kube-score",
                                 "polaris"})
        for e in res:
            self.assertFalse(e.installed, e.name)
            self.assertFalse(e.ran, e.name)
            self.assertTrue(e.manual_cmd, e.name)
            self.assertEqual(e.verdict, "not run", e.name)
        self.assertTrue(any(e.name == "kubeconform" and e.install_hint
                            for e in res))

    @unittest.skipUnless(shutil.which("helm"), "helm not installed")
    def test_helm_lint_runs_for_real_and_passes(self):
        path = self._path_with("helm")
        with mock.patch.dict(os.environ, {"PATH": path}):
            res = {e.name: e for e in ext.run_cross_check(
                os.path.join(FIXTURES, "good-chart"), kube_version="1.32.0")}
        lint = res["helm lint"]
        self.assertTrue(lint.installed)
        self.assertTrue(lint.ran)
        self.assertEqual(lint.verdict, "PASS")
        # pinned against what helm ACTUALLY prints, not what it was
        # remembered as printing
        self.assertIn("chart(s) linted", lint.summary)

    @unittest.skipUnless(shutil.which("helm"), "helm not installed")
    def test_kube_version_reaches_helm_lint(self):
        """The plumbing D3 was about: the cross-check must lint the same
        cluster the report describes, not helm's compiled-in v1.20.0."""
        path = self._path_with("helm")
        with mock.patch.dict(os.environ, {"PATH": path}):
            res = {e.name: e for e in ext.run_cross_check(
                os.path.join(FIXTURES, "good-chart"), kube_version="1.32.0")}
        self.assertIn("--kube-version 1.32.0", res["helm lint"].manual_cmd)

    @unittest.skipUnless(shutil.which("kubeconform") and shutil.which("helm"),
                         "kubeconform/helm not installed")
    def test_kubeconform_summary_regex_matches_real_output(self):
        """Pin the parser to the real format.

        If kubeconform ever changes its summary line this test fails here,
        loudly, instead of _indeterminacy silently returning '' forever and
        every UNKNOWN quietly reverting to FAIL.
        """
        out, err = render_chart(os.path.join(FIXTURES, "legacy-chart"),
                                kube_version="1.21.0")
        self.assertIsNone(err, err)
        d = tempfile.mkdtemp(prefix="hpa-kc-")
        p = os.path.join(d, "rendered.yaml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(out)
        rc, so, se = ext._run([shutil.which("kubeconform"), "-strict",
                               "-summary", p])
        blob = (so + "\n" + se)
        self.assertIsNotNone(ext._KUBECONFORM_SUMMARY.search(blob),
                             f"regex no longer matches kubeconform output:\n{blob}")

    @unittest.skipUnless(shutil.which("kubeconform") and shutil.which("helm"),
                         "kubeconform/helm not installed")
    def test_unreachable_schema_is_unknown_not_fail(self):
        """D4, proven against the real binary.

        legacy-chart renders Role/RoleBinding/Ingress at apiVersions whose
        schemas this sandbox cannot fetch. kubeconform exits 1 and says so
        precisely: Invalid: 0, Errors: 3. Nothing failed validation. Reporting
        FAIL there tells the reader their chart is broken when the truth is
        that the checker learned nothing - the C2.2 conflation, committed
        about another program's output.
        """
        path = self._path_with("helm", "kubeconform")
        with mock.patch.dict(os.environ, {"PATH": path}):
            res = {e.name: e for e in ext.run_cross_check(
                os.path.join(FIXTURES, "legacy-chart"),
                kube_version="1.21.0")}
        kc = res["kubeconform"]
        self.assertTrue(kc.ran)
        m = ext._KUBECONFORM_SUMMARY.search(kc.detail)
        self.assertIsNotNone(m, kc.detail)
        invalid, errors = int(m.group(2)), int(m.group(3))
        if invalid == 0 and errors > 0:
            self.assertFalse(kc.ok, "raw exit status should still be non-zero")
            self.assertEqual(kc.verdict, "UNKNOWN")
            self.assertTrue(kc.indeterminate_why)
        elif invalid > 0:
            # a real validation failure is present: FAIL must survive
            self.assertEqual(kc.verdict, "FAIL")
        else:
            self.assertEqual(kc.verdict, "PASS")

    def test_indeterminacy_never_upgrades_a_real_failure(self):
        """Asymmetry, stated as a test: Invalid > 0 stays FAIL even when
        Errors > 0 too. This one uses a literal because it is a statement
        about _indeterminacy's arithmetic, not about kubeconform's output -
        and the format that literal is in is pinned by the real-binary test
        above."""
        blob = ("Summary: 9 resources found in 1 file - Valid: 4, Invalid: 2, "
                "Errors: 3, Skipped: 0")
        self.assertEqual(ext._indeterminacy("kubeconform", blob), "")
        blob2 = blob.replace("Invalid: 2", "Invalid: 0")
        self.assertTrue(ext._indeterminacy("kubeconform", blob2))

    @unittest.skipUnless(shutil.which("kubeconform"), "kubeconform not installed")
    def test_render_needing_tool_skipped_without_helm(self):
        path = self._path_with("kubeconform")
        with mock.patch.dict(os.environ, {"PATH": path}):
            res = {e.name: e for e in ext.run_cross_check(
                os.path.join(FIXTURES, "good-chart"))}
        kc = res["kubeconform"]
        self.assertTrue(kc.installed)
        self.assertFalse(kc.ran)
        self.assertIn("helm", kc.summary)
        self.assertEqual(kc.verdict, "not run")

    @unittest.skipUnless(shutil.which("helm"), "helm not installed")
    def test_unrenderable_chart_does_not_advise_installing_helm(self):
        """D2: helm is present and REFUSED the chart. The skip reason must say
        so; advising an install sends the reader to do the one thing that
        cannot possibly help."""
        path = self._path_with("helm", "kubeconform")
        with mock.patch.dict(os.environ, {"PATH": path}):
            # deliberately render at a version the chart excludes
            res = {e.name: e for e in ext.run_cross_check(
                os.path.join(FIXTURES, "good-chart"), kube_version="1.20.0")}
        kc = res.get("kubeconform")
        if kc is None or kc.ran:
            self.skipTest("chart rendered after all")
        self.assertIn("could not be rendered", kc.summary)
        self.assertNotIn("not on PATH", kc.summary)


class TestKubeScoreAndPolarisForReal(unittest.TestCase):
    """The two validators no test had ever run.

    R4 replaced the mocked helm/kubeconform tests with real-binary ones and
    stopped there. `kube-score` and `polaris` were not mocked - they were
    simply never executed by any test in any iteration, while `--cross-check`
    offered to run both for the user. Nothing was pinning their verdicts, and
    both were wrong:

      * polaris exits 0 unconditionally in audit mode. Reading `ok = rc == 0`
        made every polaris run PASS - including a chart polaris itself scored
        66/100 with three danger-severity failures, and including a file that
        was not YAML at all.
      * kube-score exits 1 both for "I found a CRITICAL" and for "I could not
        parse your files". Reading the exit code reported the second as a
        failure of the chart: C2.2, committed about another program's output.

    These tests run both binaries for real and pin the verdict to each tool's
    own printed tally. They skip honestly when a binary is absent - polaris in
    particular is not shipped with this project.
    """

    GARBAGE = "this: [is, not\n  a: manifest\n"

    @staticmethod
    def _path_with(*binaries):
        d = tempfile.mkdtemp(prefix="hpa-path-")
        for b in binaries:
            real = shutil.which(b)
            if real:
                os.symlink(real, os.path.join(d, b))
        return d

    def _cross(self, *binaries, **kw):
        with mock.patch.dict(os.environ, {"PATH": self._path_with(*binaries)}):
            return {e.name: e for e in ext.run_cross_check(
                os.path.join(FIXTURES, "good-chart"), **kw)}

    def _rendered(self):
        out, err = render_chart(os.path.join(FIXTURES, "good-chart"),
                               kube_version="1.32.0")
        self.assertIsNone(err, err)
        return out

    # --- polaris ---------------------------------------------------------

    @unittest.skipUnless(shutil.which("polaris") and shutil.which("helm"),
                         "polaris/helm not installed")
    def test_polaris_exit_code_is_zero_even_on_input_it_rejects(self):
        """The measurement the pre-R6 verdict logic was missing.

        This asserts a property of polaris, not of this project: if polaris
        ever starts encoding a verdict in its exit status, this test fails and
        the comment explaining why the exit code is ignored becomes wrong and
        must be revisited. That is the point of pinning it.
        """
        argv = next(a for n, a, _, _ in ext.NEEDS_RENDER if n == "polaris")
        d = tempfile.mkdtemp(prefix="hpa-pol-")
        junk = os.path.join(d, "junk.yaml")
        with open(junk, "w", encoding="utf-8") as f:
            f.write(self.GARBAGE)
        rc_good, good_blob = self._raw("polaris")
        rc_junk, _, _ = ext._run(argv(junk))
        self.assertEqual(rc_good, 0)
        self.assertEqual(rc_junk, 0, "polaris exits 0 on unparseable input too")
        # ...and it exits 0 on the good chart while reporting danger-severity
        # failures, so the exit code and the finding disagree in the same run.
        self.assertIn("❌ Danger", good_blob)

    @unittest.skipUnless(shutil.which("polaris") and shutil.which("helm"),
                         "polaris/helm not installed")
    def test_polaris_verdict_comes_from_its_danger_tally(self):
        res = self._cross("helm", "polaris", kube_version="1.32.0")
        p = res["polaris"]
        self.assertTrue(p.ran)
        self.assertIn("danger", p.verdict_basis)
        # against the FULL output, not the excerpt in p.detail - see
        # test_truncated_detail_says_how_much_it_dropped for why that
        # distinction cost a defect
        _, full = self._raw("polaris")
        self.assertEqual(p.tally["danger"], full.count("❌ Danger"))
        self.assertEqual(p.tally["controllers"],
                         int(ext._POLARIS_CONTROLLERS.search(full).group(1)))
        self.assertEqual(p.verdict, "FAIL" if p.tally["danger"] else "PASS")
        self.assertIs(p.ok, p.tally["danger"] == 0)

    @unittest.skipUnless(shutil.which("polaris"), "polaris not installed")
    def test_polaris_on_unparseable_input_is_unknown_not_pass(self):
        """polaris scores only what it could read, so on garbage it prints a
        perfect score and exits 0. Transcribing that as PASS tells the reader
        their manifests are clean when nothing was audited."""
        res = self._cross("polaris", rendered_text=self.GARBAGE)
        p = res["polaris"]
        self.assertTrue(p.ran)
        self.assertEqual(p.verdict, "UNKNOWN")
        self.assertIsNone(p.ok)
        self.assertTrue(p.indeterminate_why)

    @unittest.skipUnless(shutil.which("polaris") and shutil.which("helm"),
                         "polaris/helm not installed")
    def test_polaris_summary_regexes_match_real_output(self):
        """Pin both parsers to the real format. If polaris renames 'Final
        score' or 'Controllers', this fails here instead of every polaris
        verdict silently degrading to UNKNOWN."""
        _, full = self._raw("polaris")
        self.assertIsNotNone(ext._POLARIS_SCORE.search(full), full[:400])
        self.assertIsNotNone(ext._POLARIS_CONTROLLERS.search(full), full[:400])
        self.assertIn("❌ Danger", full)
        self.assertIn("😬 Warning", full)

    @unittest.skipUnless(shutil.which("polaris") and shutil.which("helm"),
                         "polaris/helm not installed")
    def test_polaris_detail_carries_no_ansi_and_no_temp_path(self):
        """polaris colours its output and names the file it was handed. Both
        end up in a plain-text report: the escapes as visible garbage, the
        path as a /tmp directory that no longer exists by the time anyone
        reads it."""
        res = self._cross("helm", "polaris", kube_version="1.32.0")
        blob = res["polaris"].detail
        self.assertNotIn("\x1b[", blob)
        self.assertNotIn("/tmp/hpa-xcheck-", blob)
        self.assertIn("<rendered manifests>", blob)

    # --- kube-score ------------------------------------------------------

    def _raw(self, binary):
        """Run a validator directly on the same bytes run_cross_check renders,
        using that module's OWN argv builder, and return its FULL output.

        Two things this must not do. It must not rebuild the command line:
        the first draft did, dropped polaris's `--format pretty`, got JSON
        back and counted zero danger markers in output that had two - a test
        passing judgement on a command the tool never runs. And it must not
        read `result.detail`: that is a 1500-byte excerpt, so comparing a
        tally against it measures the excerpt.
        """
        argv_fn = next(a for n, a, _, _ in ext.NEEDS_RENDER if n == binary)
        d = tempfile.mkdtemp(prefix="hpa-raw-")
        p = os.path.join(d, "rendered.yaml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(self._rendered())
        rc, so, se = ext._run(argv_fn(p))
        return rc, ext._clean(so + "\n" + se, p)

    @unittest.skipUnless(shutil.which("kube-score") and shutil.which("helm"),
                         "kube-score/helm not installed")
    def test_kube_score_verdict_comes_from_its_own_severity_tally(self):
        res = self._cross("helm", "kube-score", kube_version="1.32.0")
        k = res["kube-score"]
        self.assertTrue(k.ran)
        self.assertIn("not its exit code", k.verdict_basis)
        rc, full = self._raw("kube-score")
        self.assertEqual(k.tally["critical"], full.count("[CRITICAL]"))
        self.assertEqual(k.tally["warning"], full.count("[WARNING]"))
        self.assertEqual(k.tally["objects_scored"],
                         full.count("✅") + full.count("💥"))
        self.assertEqual(k.verdict, "FAIL" if k.tally["critical"] else "PASS")

    @unittest.skipUnless(shutil.which("kube-score") and shutil.which("helm"),
                         "kube-score/helm not installed")
    def test_truncated_detail_says_how_much_it_dropped(self):
        """The defect the test above found on its first run.

        kube-score's summary reads '12 critical' over output whose printed
        excerpt contains five [CRITICAL] lines, because _trunc cut it at 1500
        bytes and said only '(truncated)'. Both numbers were correct and the
        pairing was still misleading: a reader who counts what is in front of
        them gets 5 and concludes the summary is wrong. An excerpt has to
        admit it is one.
        """
        res = self._cross("helm", "kube-score", kube_version="1.32.0")
        k = res["kube-score"]
        _, full = self._raw("kube-score")
        if len(full.strip()) <= 1500:
            self.skipTest("output no longer long enough to be truncated")
        self.assertLess(k.detail.count("[CRITICAL]"), k.tally["critical"],
                        "precondition: the excerpt undercounts")
        self.assertIn("more line(s)", k.detail)
        self.assertIn("not shown", k.detail)
        self.assertIn("FULL output", k.detail)

    @unittest.skipUnless(shutil.which("kube-score"), "kube-score not installed")
    def test_kube_score_parse_failure_is_unknown_not_fail(self):
        """C2.2 about another program: kube-score exits 1 when it cannot parse
        its input. That is a fact about the file it was handed, not about the
        chart, and must not be reported as the chart failing."""
        res = self._cross("kube-score", rendered_text=self.GARBAGE)
        k = res["kube-score"]
        self.assertTrue(k.ran)
        self.assertEqual(k.verdict, "UNKNOWN")
        self.assertIsNone(k.ok)
        self.assertIn("not about the chart", k.indeterminate_why)

    @unittest.skipUnless(shutil.which("kube-score"), "kube-score not installed")
    def test_kube_score_parse_error_pattern_matches_real_output(self):
        d = tempfile.mkdtemp(prefix="hpa-ks-")
        p = os.path.join(d, "junk.yaml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.GARBAGE)
        rc, so, se = ext._run([shutil.which("kube-score"), "score", p])
        blob = ext._clean(so + "\n" + se)
        self.assertNotEqual(rc, 0, "kube-score signals parse failure by exiting 1")
        self.assertIsNotNone(ext._KUBESCORE_PARSE_ERR.search(blob), blob[:400])

    # --- what the reader is shown ----------------------------------------

    @unittest.skipUnless(shutil.which("polaris") and shutil.which("helm"),
                         "polaris/helm not installed")
    def test_report_prints_the_basis_for_each_verdict(self):
        """A prose test, deliberately. The Status column is this project's
        transcription of someone else's finding; if the report does not say
        which signal it read, the reader cannot check the transcription - and
        for two iterations it was wrong."""
        from hpaanalyzer.report import render
        res = self._cross("helm", "polaris", "kube-score", kube_version="1.32.0")
        result = analyze(os.path.join(FIXTURES, "good-chart"), helm_mode="off")
        txt = render(result, os.path.join(FIXTURES, "good-chart"),
                     external=list(res.values()), show_all=True, level="full")
        # the report hard-wraps, so assert on the unwrapped text - a prose
        # test that only passes at one column width is a formatting test
        flat = " ".join(txt.split())
        self.assertIn("polaris status derived from:", flat)
        self.assertIn("its exit code is always 0 and carries no verdict", flat)
        self.assertIn("kube-score status derived from:", flat)
        self.assertIn("not its exit code", flat)
        self.assertIn("Status column is NOT a re-reading of each tool's exit",
                      flat)
        self.assertNotIn("\x1b[", txt)

    @unittest.skipUnless(shutil.which("polaris") and shutil.which("helm"),
                         "polaris/helm not installed")
    def test_json_exposes_the_tally_the_verdict_came_from(self):
        import json
        fd, jout = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        fd, out = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with mock.patch.dict(os.environ,
                             {"PATH": self._path_with("helm", "polaris",
                                                      "kube-score")}):
            rc = main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                       "--cross-check", "--json", jout, "--quiet"])
        self.assertIn(rc, (0, 1))
        with open(jout, encoding="utf-8") as f:
            payload = json.load(f)
        pol = next(c for c in payload["cross_check"] if c["tool"] == "polaris")
        self.assertEqual(pol["verdict"], "FAIL" if pol["tally"]["danger"]
                         else "PASS")
        self.assertTrue(pol["verdict_basis"])
        self.assertIn("controllers", pol["tally"])


class TestCliFlags(unittest.TestCase):
    def _tmp(self):
        fd, p = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        return p

    def test_check_on_chart_exits_0_no_report_written(self):
        out = self._tmp()
        os.remove(out)
        rc = main([os.path.join(FIXTURES, "good-chart"), "--check",
                   "--helm", "off", "-o", out])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(out), "--check must not write a report")

    def test_check_on_non_chart_exits_2(self):
        root = make_tree({"readme.txt": "hi\n"})
        rc = main([root, "--check", "--helm", "off"])
        self.assertEqual(rc, 2)

    def test_cross_check_adds_json_block(self):
        import json
        out, jout = self._tmp(), self._tmp()
        with mock.patch.object(ext, "find_helm", return_value=None), \
             mock.patch.object(ext, "_which", return_value=None):
            rc = main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                       "--helm", "off", "--cross-check", "--json", jout,
                       "--quiet"])
        self.assertIn(rc, (0, 1))
        payload = json.load(open(jout))
        self.assertTrue(payload["cross_check"])
        self.assertEqual({c["tool"] for c in payload["cross_check"]},
                         {"helm lint", "kubeconform", "kube-score", "polaris"})


if __name__ == "__main__":
    unittest.main()

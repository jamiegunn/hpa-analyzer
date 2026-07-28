"""CLI edges: usage errors, IO failures, gate branches, and the image guard.

All of main()'s error paths promise two things at once - a distinguishing
exit code (2 usage/IO/environment vs 1 gate vs 0) and a message naming what
went wrong - and CI can only see the first, so both are asserted everywhere
here. main() is called in-process exactly as test_cli.py does; the image
guard lives in the `__main__` block and is therefore tested as the function
it is, with explicit env/marker arguments, not by spawning a native run.
"""

import contextlib
import io
import os
import tempfile
import unittest

from hpaanalyzer import __version__
from hpaanalyzer.__main__ import NATIVE_OVERRIDE, _require_image, main

from .util import CHART_YAML, make_tree

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")

DEP = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: w}\n"
       "spec:\n  selector: {matchLabels: {app: w}}\n"
       "  template:\n    metadata: {labels: {app: w}}\n"
       "    spec:\n      containers:\n        - name: app\n          image: r/a:1\n"
       "          resources: {requests: {cpu: 500m, memory: 1Gi}, "
       "limits: {memory: 1Gi}}\n")


def tmpfile(suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def run_main(argv):
    """main() with captured stdout/stderr, so the tests can assert on the
    printed message as well as the exit code."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def chart_without_dockerfile():
    """A valid chart whose coverage is incomplete for a fixable reason (no
    Dockerfile), so the coverage gates have something real to react to."""
    return make_tree({"Chart.yaml": CHART_YAML, "values.yaml": "x: 1\n",
                      "templates/d.yaml": DEP})


class TestUsageErrors(unittest.TestCase):
    def test_bad_kube_version_is_usage_error_not_fallback(self):
        """Falling back would render for a cluster the user did not ask for
        and call it 'rendered truth'; the CLI promises exit 2 plus the
        accepted forms instead."""
        rc, _, err = run_main([os.path.join(FIXTURES, "good-chart"),
                               "--helm", "off", "--kube-version", "banana"])
        self.assertEqual(rc, 2)
        self.assertIn("--kube-version 'banana' is not a version", err)
        self.assertIn("1.31", err)   # the message teaches the accepted forms

    def test_valid_kube_version_is_accepted(self):
        """The flip side of the rejection above: a value in one of the forms
        the error message advertises must pass validation and the run must
        proceed - otherwise the message teaches forms the parser refuses."""
        rc, _, _ = run_main([os.path.join(FIXTURES, "good-chart"),
                             "--helm", "off", "--kube-version", "1.31.0",
                             "--quiet", "-o", tmpfile(".txt")])
        self.assertEqual(rc, 0)

    def test_bad_measured_is_usage_error_naming_the_component(self):
        """Silently ignoring a bad --measured would print 'est.' beside a
        number the user believes they measured - the exact inversion this
        tool exists to prevent. Exit 2, and the message names the offending
        key so a comma-separated list is debuggable."""
        rc, _, err = run_main([os.path.join(FIXTURES, "good-chart"),
                               "--helm", "off",
                               "--measured", "metaspace=banana"])
        self.assertEqual(rc, 2)
        self.assertIn("error: --measured", err)
        self.assertIn("metaspace", err)

    def test_helm_on_that_cannot_render_aborts_loudly(self):
        """--helm on is a demand for rendered truth. When rendering is
        impossible the run must abort at exit 2 (environment), not silently
        downgrade to static analysis and grade a different thing than the
        user required."""
        root = make_tree({"readme.txt": "hi\n"})
        rc, _, err = run_main([root, "--helm", "on", "--quiet",
                               "-o", tmpfile(".txt")])
        self.assertEqual(rc, 2)
        self.assertIn("--helm on but rendering failed", err)


class TestWriteFailures(unittest.TestCase):
    """Each unwritable output is exit 2 with a message naming WHICH artifact
    could not be written - three different flags, three different messages,
    because 'the report' and 'the json a CI step parses' fail differently."""

    BAD = "/nonexistent-hpa-test-dir/out"

    def test_unwritable_report_path(self):
        rc, _, err = run_main([os.path.join(FIXTURES, "good-chart"),
                               "--helm", "off", "--quiet",
                               "-o", self.BAD + ".txt"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot write report", err)

    def test_unwritable_html_path(self):
        rc, _, err = run_main([os.path.join(FIXTURES, "good-chart"),
                               "--helm", "off", "--quiet",
                               "-o", tmpfile(".txt"),
                               "--html", self.BAD + ".html"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot write html", err)

    def test_unwritable_json_path(self):
        rc, _, err = run_main([os.path.join(FIXTURES, "good-chart"),
                               "--helm", "off", "--quiet",
                               "-o", tmpfile(".txt"),
                               "--json", self.BAD + ".json"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot write json", err)


class TestOutputAndGates(unittest.TestCase):
    def test_stdout_flag_prints_the_full_report(self):
        """--stdout exists for pipelines with no filesystem to keep: the
        complete report - not just the summary line - must land on stdout."""
        rc, out, _ = run_main([os.path.join(FIXTURES, "good-chart"),
                               "--helm", "off", "--quiet", "--stdout",
                               "-o", tmpfile(".txt")])
        self.assertEqual(rc, 0)
        self.assertIn("HELM CHART / KUBERNETES / JVM QUALITY ANALYSIS", out)

    def test_min_score_met_on_reduced_scale_still_prints_the_scale_note(self):
        """The R5 concern from the passing side: a green --min-score over 7
        of 10 categories is a different comparison than the one the user
        configured. The gate passes (exit 0) but the CI log must carry the
        note and point at --require-coverage, on every run, not only on red
        ones - a note that appears only on failure cannot warn anyone."""
        rc, _, err = run_main([chart_without_dockerfile(), "--helm", "off",
                               "--quiet", "--min-score", "1",
                               "-o", tmpfile(".txt")])
        self.assertEqual(rc, 0)
        self.assertIn("different set of categories", err)
        self.assertIn("--require-coverage", err)

    def test_require_coverage_fails_on_a_missing_input(self):
        """The note above, turned into an actual gate: a deleted Dockerfile
        must be able to stop a deploy, because a log line does not."""
        rc, _, err = run_main([chart_without_dockerfile(), "--helm", "off",
                               "--quiet", "--require-coverage",
                               "-o", tmpfile(".txt")])
        self.assertEqual(rc, 1)
        self.assertIn("gate: --require-coverage:", err)
        self.assertIn("DOCKERFILE", err)

    def test_require_coverage_passes_when_every_input_is_present(self):
        """The gate's other half: complete coverage must not fail it, or the
        flag becomes unusable and gets removed from CI configs."""
        rc, _, err = run_main([os.path.join(FIXTURES, "good-chart"),
                               "--helm", "off", "--quiet",
                               "--require-coverage", "-o", tmpfile(".txt")])
        self.assertEqual(rc, 0)
        self.assertNotIn("gate:", err)

    def test_version_prints_the_package_version_and_exits_zero(self):
        """The string a bug report quotes; it must match the package's own
        __version__, not a copy that can drift."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as cm:
                main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(__version__, out.getvalue())


class TestRequireImage(unittest.TestCase):
    """The native-run refusal, tested as the function the __main__ block
    calls. Explicit env and marker arguments keep these hermetic: no test
    here depends on whether this machine happens to have the override
    exported or the marker file present."""

    def _guard(self, argv, env, marker):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = _require_image(argv=argv, env=env, marker=marker)
        return rc, err.getvalue()

    def test_inside_the_image_proceeds_silently(self):
        """The marker file is the image's signature; when it exists the guard
        must get out of the way without a word - a warning inside the
        supported environment would train users to ignore warnings."""
        rc, err = self._guard(["chart"], {}, tmpfile(".marker"))
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

    def test_documented_override_proceeds(self):
        """The escape hatch this repo's own evidence layer uses (see
        docs/DEVELOPING.md); exactly '1', matching the documentation."""
        rc, err = self._guard(["chart"], {NATIVE_OVERRIDE: "1"},
                              "/nonexistent-hpa-test/marker")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

    def test_refusal_explains_and_echoes_the_users_arguments(self):
        """Exit 2 (environment error, distinguishable from a failed gate),
        with the user's own argv spliced into the wrapper command so the fix
        is copy-pasteable - retyping flags is where they get dropped."""
        rc, err = self._guard(["./my-chart", "--summary"], {},
                              "/nonexistent-hpa-test/marker")
        self.assertEqual(rc, 2)
        self.assertIn("not the supported entry point", err)
        self.assertIn("./bin/hpa-analyzer ./my-chart --summary", err)

    def test_refusal_does_not_advertise_the_override(self):
        """The deliberate asymmetry NATIVE_OVERRIDE's docstring commits to: a
        bypass printed in every refusal becomes the folk-standard way to run
        the tool, and then the guard prevents nothing. This test makes that
        promise enforceable."""
        rc, err = self._guard([], {}, "/nonexistent-hpa-test/marker")
        self.assertEqual(rc, 2)
        self.assertNotIn(NATIVE_OVERRIDE, err)
        # with no argv, the wrapper line shows a placeholder, not a blank
        self.assertIn("./bin/hpa-analyzer <chart-directory>", err)


if __name__ == "__main__":
    unittest.main()

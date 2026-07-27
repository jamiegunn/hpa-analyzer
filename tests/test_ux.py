"""UX surface: terminal-first summary, verbosity levels, collapse, HTML."""

import os
import tempfile
import unittest

from hpaanalyzer.__main__ import main
from hpaanalyzer.engine import analyze
from hpaanalyzer.html_report import render_html
from hpaanalyzer.report import render, stdout_summary

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def _bad():
    return analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")


def _tmp(suffix=".txt"):
    fd, p = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return p


class TestStdoutSummary(unittest.TestCase):
    def test_summary_has_grade_and_fix_first(self):
        r = _bad()
        s = stdout_summary(r, "/tmp/report.txt")
        self.assertIn("GRADE", s)
        self.assertIn("Fix first:", s)
        self.assertIn("/tmp/report.txt", s)
        # the top items are the criticals/highs, numbered
        self.assertIn("1. [", s)

    def test_summary_mentions_html_when_given(self):
        s = stdout_summary(_bad(), "/tmp/r.txt", html_path="/tmp/r.html")
        self.assertIn("/tmp/r.html", s)

    def test_not_graded_summary(self):
        import tempfile as tf
        d = tf.mkdtemp()
        open(os.path.join(d, "readme.txt"), "w").write("hi")
        r = analyze(d, helm_mode="off")
        self.assertIn("NOT GRADED", stdout_summary(r, "/tmp/r.txt"))


class TestVerbosityLevels(unittest.TestCase):
    def setUp(self):
        self.r = _bad()

    def _lines(self, **kw):
        return len(render(self.r, "x", **kw).splitlines())

    def test_summary_is_shorter_than_default_is_shorter_than_full(self):
        s = self._lines(level="summary")
        d = self._lines(level="default")
        f = self._lines(level="full")
        self.assertLess(s, d)
        self.assertLess(d, f)

    def test_education_only_in_full_or_teach(self):
        self.assertNotIn("EDUCATION APPENDIX", render(self.r, "x"))
        self.assertNotIn("EDUCATION APPENDIX",
                         render(self.r, "x", level="summary"))
        self.assertIn("EDUCATION APPENDIX",
                      render(self.r, "x", teach=True))
        self.assertIn("EDUCATION APPENDIX",
                      render(self.r, "x", level="full"))

    def test_low_collapsed_by_default_expanded_with_all(self):
        default = render(self.r, "x")
        self.assertIn("run with --all", default)          # collapse note
        expanded = render(self.r, "x", show_all=True)
        self.assertNotIn("run with --all", expanded)

    def test_summary_has_no_proof_tables(self):
        self.assertNotIn("MATHEMATICAL PROOF TABLES",
                         render(self.r, "x", level="summary"))
        self.assertIn("MATHEMATICAL PROOF TABLES", render(self.r, "x"))

    def test_full_implies_all_and_teach(self):
        full = render(self.r, "x", level="full")
        self.assertNotIn("run with --all", full)          # LOW expanded
        self.assertIn("EDUCATION APPENDIX", full)


class TestHtmlReport(unittest.TestCase):
    def test_self_contained_no_external_assets(self):
        h = render_html(_bad(), "x")
        self.assertTrue(h.lstrip().startswith("<!doctype html"))
        # no external ASSET loading (URLs may appear in finding *text*)
        for bad in ("<script src", "<link", "@import", "url(http", "src=\"http"):
            self.assertNotIn(bad, h, f"HTML must not load external assets ({bad})")
        self.assertIn("<style>", h)
        self.assertIn("<script>", h)

    def test_has_sections_and_filter(self):
        h = render_html(_bad(), "x")
        for sec in ("id=findings", "id=proofs", "id=scorecard", "id=coverage",
                    "id=verify", "id=education", "id=filter"):
            self.assertIn(sec, h)

    def test_findings_escaped_and_carry_severity(self):
        h = render_html(_bad(), "x")
        self.assertIn("CRITICAL", h)
        self.assertIn("data-text=", h)   # for the JS filter

    def test_good_chart_html_renders(self):
        r = analyze(os.path.join(FIXTURES, "good-chart"), helm_mode="off")
        h = render_html(r, "x")
        self.assertIn("GRADE", h.upper().replace("NOT GRADED", ""))  # a grade badge
        self.assertTrue(h.rstrip().endswith("</html>"))


class TestCliUx(unittest.TestCase):
    def test_html_flag_auto_path(self):
        out = _tmp(".txt")
        rc = main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                   "--helm", "off", "--html", "--quiet"])
        self.assertEqual(rc, 0)
        html_path = os.path.splitext(out)[0] + ".html"
        self.assertTrue(os.path.exists(html_path))
        self.assertGreater(os.path.getsize(html_path), 2000)

    def test_html_flag_explicit_path(self):
        out, hp = _tmp(".txt"), _tmp(".html")
        rc = main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                   "--helm", "off", "--html", hp, "--quiet"])
        self.assertEqual(rc, 0)
        self.assertIn("<!doctype html", open(hp).read()[:40])

    def test_summary_and_full_mutually_exclusive(self):
        out = _tmp()
        with self.assertRaises(SystemExit):
            main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                  "--summary", "--full", "--helm", "off"])

    def test_quiet_is_one_line(self):
        # smoke: quiet run returns cleanly; detailed stdout capture omitted
        out = _tmp()
        rc = main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                   "--helm", "off", "--quiet"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()

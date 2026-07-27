"""R5: the score's denominator must travel with the score.

The defect these tests lock down: overall_score() is a weighted mean over the
categories that could be assessed, and an unassessed category leaves BOTH the
numerator and the denominator. So removing an input file moves the score with
no Kubernetes manifest changing - and on bad-chart it moves it UP. Nothing in
the pre-R5 output said the two numbers were computed over different sets.

Every test here runs the real engine over a real directory on disk (C5.3);
the CLI paths go through main() with real files, not a mocked argv parser.
"""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from hpaanalyzer.__main__ import main
from hpaanalyzer.engine import analyze
from hpaanalyzer.html_report import render_html
from hpaanalyzer.models import Category
from hpaanalyzer.report import render, stdout_summary
from hpaanalyzer.scoring import (WEIGHTS, coverage, overall_score,
                                 unassessed_reason)

FIXTURES = os.path.abspath(os.path.join(os.path.dirname(__file__), "..",
                                        "fixtures"))


def _copy_without_dockerfile(src_name):
    """A real copy of a real fixture, minus the Dockerfile.

    The Kubernetes templates, values and Chart.yaml are byte-identical to the
    original - that is the whole point of the comparison.
    """
    d = tempfile.mkdtemp()
    dst = os.path.join(d, src_name)
    shutil.copytree(os.path.join(FIXTURES, src_name), dst)
    os.remove(os.path.join(dst, "Dockerfile"))
    return d, dst


class TestCoverageObject(unittest.TestCase):
    def test_full_fixture_is_complete(self):
        r = analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")
        cov = coverage(r)
        self.assertTrue(cov.complete)
        self.assertEqual(cov.n_assessed, len(list(Category)))
        self.assertEqual(cov.weight_assessed, sum(WEIGHTS.values()))
        self.assertEqual(cov.unassessed, [])
        for cat in Category:
            self.assertIsNone(unassessed_reason(cat, r.context))

    def test_missing_dockerfile_drops_three_categories_with_reasons(self):
        tmp, dst = _copy_without_dockerfile("bad-chart")
        try:
            r = analyze(dst, helm_mode="off")
            cov = coverage(r)
            self.assertFalse(cov.complete)
            dropped = {c for c, _ in cov.unassessed}
            self.assertEqual(dropped, {Category.JAVA, Category.DOCKERFILE,
                                       Category.CROSS})
            # every drop carries a reason a human can act on, and the reason
            # names the missing input rather than saying "not applicable"
            for cat, reason in cov.unassessed:
                self.assertTrue(reason, f"{cat} dropped with no reason")
                self.assertIn("Dockerfile", reason)
            self.assertEqual(
                cov.weight_assessed,
                sum(WEIGHTS.values()) - WEIGHTS[Category.JAVA]
                - WEIGHTS[Category.DOCKERFILE] - WEIGHTS[Category.CROSS])
        finally:
            shutil.rmtree(tmp)

    def test_one_line_names_the_missing_categories(self):
        tmp, dst = _copy_without_dockerfile("bad-chart")
        try:
            line = coverage(analyze(dst, helm_mode="off")).one_line()
            self.assertIn("7 of 10 categories", line)
            for name in ("JAVA", "DOCKERFILE", "CROSS"):
                self.assertIn(name, line)
        finally:
            shutil.rmtree(tmp)


class TestTheDefectItself(unittest.TestCase):
    """The measurement that motivated the fix, kept as a regression lock."""

    def test_deleting_the_dockerfile_moves_the_score_upward(self):
        tmp, dst = _copy_without_dockerfile("bad-chart")
        try:
            with_docker = overall_score(
                analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off"))
            without = overall_score(analyze(dst, helm_mode="off"))
            # This is NOT a bug being asserted as correct behaviour: the mean
            # over a smaller set is the only honest arithmetic available (see
            # scoring.py). What is asserted is that the movement is real and
            # therefore that the denominator MUST be printed - the tests below
            # check that it is.
            self.assertGreater(without, with_docker)
        finally:
            shutil.rmtree(tmp)

    def test_manifests_were_actually_identical(self):
        """Guard on the guard: if the copy differed, the delta proves nothing."""
        tmp, dst = _copy_without_dockerfile("bad-chart")
        try:
            src = os.path.join(FIXTURES, "bad-chart")
            for root, _dirs, files in os.walk(src):
                for fn in sorted(files):
                    if fn == "Dockerfile":
                        continue
                    rel = os.path.relpath(os.path.join(root, fn), src)
                    with open(os.path.join(src, rel), "rb") as a, \
                         open(os.path.join(dst, rel), "rb") as b:
                        self.assertEqual(a.read(), b.read(), rel)
            self.assertFalse(os.path.exists(os.path.join(dst, "Dockerfile")))
        finally:
            shutil.rmtree(tmp)


class TestDenominatorIsPrinted(unittest.TestCase):
    """Every surface that shows the number must show what it is over."""

    def setUp(self):
        self.tmp, self.dst = _copy_without_dockerfile("bad-chart")
        self.result = analyze(self.dst, helm_mode="off")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_stdout_summary(self):
        s = stdout_summary(self.result, "/tmp/report.txt")
        self.assertIn("GRADE", s)
        self.assertIn("7 of 10 categories", s)
        self.assertIn("NOT assessed", s)

    def test_text_report(self):
        t = render(self.result, self.dst, level="full")
        self.assertIn("OVERALL QUALITY SCORE", t)
        self.assertIn("7 of 10 categories", t)
        # the reasons, not just the count
        self.assertIn("no Dockerfile was found under the target", t)
        # and the comparability warning
        self.assertIn("NOT comparable", t)
        # the score is described for what it is
        self.assertIn("not an estimate of risk", t)

    def test_text_report_complete_case_says_so(self):
        r = analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")
        t = render(r, os.path.join(FIXTURES, "bad-chart"), level="full")
        self.assertIn("all 10 categories", t)
        self.assertNotIn("NOT comparable", t)

    def test_html_report(self):
        h = render_html(self.result, self.dst)
        self.assertIn("7/10 cats", h)         # on the badge itself
        self.assertIn("Not assessed, and why", h)
        self.assertIn("no Dockerfile was found under the target", h)

    def test_scorecard_no_longer_claims_exclusion_is_free(self):
        t = render(self.result, self.dst, level="full")
        # the pre-R5 wording, which told the reader exclusion was harmless
        self.assertNotIn("not free points", t)
        self.assertIn("no honest number for 'not looked at'", t)

    def test_quiet_cli_one_liner(self):
        out = io.StringIO()
        rpt = os.path.join(self.tmp, "r.txt")
        with redirect_stdout(out):
            rc = main([self.dst, "-o", rpt, "--quiet", "--helm", "off"])
        self.assertEqual(rc, 0)
        line = out.getvalue().strip()
        self.assertIn("score", line)
        self.assertIn("over 7/10 categories", line)

    def test_quiet_cli_omits_qualifier_when_complete(self):
        out = io.StringIO()
        rpt = os.path.join(self.tmp, "r2.txt")
        with redirect_stdout(out):
            rc = main([os.path.join(FIXTURES, "bad-chart"), "-o", rpt,
                       "--quiet", "--helm", "off"])
        self.assertEqual(rc, 0)
        self.assertNotIn("categories", out.getvalue())

    def test_json_carries_coverage(self):
        rpt = os.path.join(self.tmp, "r3.txt")
        jpath = os.path.join(self.tmp, "r3.json")
        with redirect_stdout(io.StringIO()):
            rc = main([self.dst, "-o", rpt, "--json", jpath, "--helm", "off"])
        self.assertEqual(rc, 0)
        with open(jpath) as fh:
            payload = json.load(fh)
        cov = payload["score_coverage"]
        self.assertFalse(cov["complete"])
        self.assertEqual(len(cov["assessed"]), 7)
        self.assertEqual({u["category"] for u in cov["unassessed"]},
                         {"JAVA", "DOCKERFILE", "CROSS"})
        for u in cov["unassessed"]:
            self.assertIn("Dockerfile", u["reason"])
        self.assertEqual(cov["weight_total"], sum(WEIGHTS.values()))
        self.assertLess(cov["weight_assessed"], cov["weight_total"])

    def test_two_scores_cannot_be_compared_without_seeing_the_difference(self):
        """The invariant, stated as a test.

        Take the two runs whose scores differ only because of the missing
        Dockerfile. Every surface that prints both numbers must also print
        something that differs between them. If a surface printed the score
        and nothing else, a reader could diff the two outputs and see only
        `45.5` vs `51.8` - which is the misreading the whole fix exists to
        prevent.
        """
        full = analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")
        a = stdout_summary(full, "/tmp/r.txt")
        b = stdout_summary(self.result, "/tmp/r.txt")
        self.assertNotEqual(
            [l for l in a.splitlines() if "categor" in l],
            [l for l in b.splitlines() if "categor" in l])
        self.assertIn("7 of 10 categories", b)


class TestGateCannotDeleteDeductions(unittest.TestCase):
    """R14b. A coverage gate may not drop a category that lost points.

    Found by this file, not by reading code. R13 added a gate that drops CROSS
    when no JVM container sets limits.memory, reading the BASE context - but
    engine.py also analyzes every values overlay and merges those findings in.
    bad-chart sets no limit in values.yaml and 4 GiB in values-prod.yaml, where
    XF001 and XF003 both fire, so the gate declared "not assessable" about a
    category holding two criticals and removed fourteen weight points of real
    deductions from the denominator. The score of a chart with two critical
    cross-file faults went UP.

    Two defences went in, and both are tested here, because either alone would
    leave the other's failure silent:

      - the gate learned about overlays (proofs._overlay_sets_mem_limit), and
      - coverage() refuses to drop any category something deducted from,
        whatever the gate says.

    The second is the one that generalises. A gate predicts whether a category
    COULD deduct; the findings record whether it DID. Where they disagree the
    measurement wins.
    """

    def test_bad_chart_keeps_cross_because_an_overlay_deducts_from_it(self):
        r = analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")
        cross = [f for f in r.findings if f.category is Category.CROSS]
        self.assertTrue(cross, "fixture no longer raises CROSS findings - this "
                               "test cannot fail and must not silently pass")
        cov = coverage(r)
        self.assertIn(Category.CROSS, cov.assessed,
                      f"CROSS was dropped from the denominator while "
                      f"{sorted({f.rule_id for f in cross})} deducted from it")

    def test_a_lying_gate_is_overridden_and_announced(self):
        """The backstop, exercised directly rather than trusted.

        The gate is monkeypatched to claim RESOURCES is unassessable on a chart
        that has RESOURCES findings. Without the backstop this silently deletes
        fifteen weight points; with it, the category stays and stderr says so.
        """
        import hpaanalyzer.scoring as sc
        r = analyze(os.path.join(FIXTURES, "bad-chart"), helm_mode="off")
        deducting = [f for f in r.findings
                     if f.category is Category.RESOURCES
                     and f.effective_deduction() > 0]
        self.assertTrue(deducting, "fixture no longer deducts from RESOURCES")

        real = sc.unassessed_reason
        sc._GATE_WARNED.clear()
        err = io.StringIO()
        try:
            sc.unassessed_reason = (
                lambda cat, ctx: "a gate that is simply wrong"
                if cat is Category.RESOURCES else real(cat, ctx))
            with redirect_stderr(err):
                cov = coverage(r)
        finally:
            sc.unassessed_reason = real
        self.assertIn(Category.RESOURCES, cov.assessed)
        self.assertEqual(cov.weight_assessed,
                         coverage(r).weight_assessed,
                         "the lying gate still moved the denominator")
        self.assertIn("internal inconsistency", err.getvalue())
        self.assertIn(sorted({f.rule_id for f in deducting})[0], err.getvalue())

    def test_a_zero_point_finding_does_not_force_a_category_back_in(self):
        """DF000 is INFO: it reports that no Dockerfile was found.

        It fires on exactly the charts where DOCKERFILE cannot be assessed, so
        a backstop keyed on 'has a finding' rather than 'lost points' would
        score DOCKERFILE 100.0/A+ on a chart with no Dockerfile - the clean
        bill of health this module's docstring forbids. A first draft did
        exactly that and three tests above caught it.
        """
        d, dst = _copy_without_dockerfile("bad-chart")
        try:
            r = analyze(dst, helm_mode="off")
            df = [f for f in r.findings if f.category is Category.DOCKERFILE]
            self.assertTrue(df, "expected the no-Dockerfile INFO finding")
            self.assertTrue(all(f.effective_deduction() == 0 for f in df),
                            f"{[f.rule_id for f in df]} now deducts, so this "
                            f"test no longer covers the zero-point case")
            self.assertNotIn(Category.DOCKERFILE, coverage(r).assessed)
        finally:
            shutil.rmtree(d)


class TestNotGradedStillHonest(unittest.TestCase):
    def test_empty_directory_is_not_graded_and_says_why(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "readme.txt"), "w") as fh:
                fh.write("hi")
            r = analyze(d, helm_mode="off")
            self.assertIsNone(overall_score(r))
            t = render(r, d, level="full")
            self.assertIn("NOT GRADED", t)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()

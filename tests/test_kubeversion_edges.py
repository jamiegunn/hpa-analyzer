"""Corners of the Masterminds port the oracle replay happens not to reach.

The frozen oracle (tests/oracle_semver.json) is the primary conformance
evidence for kubeversion.py; these cases pin down operator branches and
prerelease-comparison rules that its sample does not exercise, plus the
human-facing DeclaredRange.describe() wording, which is this tool's own
contract rather than the library's.

Expected values for the constraint checks were derived from the upstream
semantics the module documents (Masterminds/semver v3.3.0 constraints.go),
not from running the port against itself: each case states what the Go
library answers.
"""

import unittest

from hpaanalyzer import kubeversion as kv


class TestPrereleaseCompare(unittest.TestCase):
    """Version.compare over prereleases - the release-beats-prerelease rule
    and the per-part comparison from semver spec item 11, as Go implements it."""

    def _cmp(self, a, b):
        va, vb = kv.parse_version(a), kv.parse_version(b)
        self.assertIsNotNone(va, a)
        self.assertIsNotNone(vb, b)
        return va.compare(vb)

    def test_prerelease_sorts_below_its_release(self):
        # Both directions: 1.0.0-alpha < 1.0.0, and 1.0.0 > 1.0.0-alpha.
        self.assertEqual(self._cmp("1.0.0-alpha", "1.0.0"), -1)
        self.assertEqual(self._cmp("1.0.0", "1.0.0-alpha"), 1)

    def test_identical_prereleases_are_equal(self):
        self.assertEqual(self._cmp("1.0.0-alpha.1", "1.0.0-alpha.1"), 0)

    def test_shorter_prerelease_sorts_first(self):
        # "alpha" vs "alpha.1": equal first part, then the missing part loses.
        self.assertEqual(self._cmp("1.0.0-alpha", "1.0.0-alpha.1"), -1)
        self.assertEqual(self._cmp("1.0.0-alpha.1", "1.0.0-alpha"), 1)

    def test_numeric_parts_compare_numerically(self):
        self.assertEqual(self._cmp("1.0.0-rc.2", "1.0.0-rc.10"), -1)

    def test_numeric_part_sorts_below_alphanumeric_part(self):
        # semver spec: numeric identifiers always have lower precedence.
        self.assertEqual(self._cmp("1.0.0-1", "1.0.0-beta"), -1)
        self.assertEqual(self._cmp("1.0.0-beta", "1.0.0-1"), 1)

    def test_alphanumeric_parts_compare_lexically(self):
        self.assertEqual(self._cmp("1.0.0-alpha", "1.0.0-beta"), -1)


class TestDirtyOperatorBranches(unittest.TestCase):
    """Operators applied to 'dirty' (partial/wildcard) constraints, where the
    Go code takes branches the exact-version path never sees."""

    def _check(self, constraint, version):
        return kv.parse_constraint(constraint).check(version)

    def test_gt_partial_minor_excludes_the_named_major(self):
        # `>1` means "any 2.x or later": within major 1 nothing qualifies,
        # below it nothing qualifies either.
        self.assertTrue(self._check(">1", "2.0.0"))
        self.assertFalse(self._check(">1", "1.5.0"))
        self.assertFalse(self._check(">1", "0.9.0"))

    def test_gt_partial_patch_compares_the_minor(self):
        # `>1.2` requires a strictly greater minor within the major.
        self.assertTrue(self._check(">1.2", "1.5.0"))
        self.assertFalse(self._check(">1.2", "1.2.9"))
        self.assertFalse(self._check(">1.2", "1.1.0"))

    def test_caret_on_zero_zero_pins_the_patch(self):
        # `^0.0.3` admits exactly 0.0.3: with major and minor both 0, caret
        # compatibility collapses to the patch.
        self.assertTrue(self._check("^0.0.3", "0.0.3"))
        self.assertFalse(self._check("^0.0.3", "0.0.4"))
        self.assertFalse(self._check("^0.0.3", "0.1.0"))
        self.assertFalse(self._check("^0.0.3", "1.0.0"))

    def test_not_equal_partial_minor_matches_nothing_in_that_minor(self):
        # `!=1` excludes every 1.x.y - the dirty minor absorbs the whole major.
        self.assertFalse(self._check("!=1", "1.5.0"))
        self.assertTrue(self._check("!=1", "2.0.0"))

    def test_not_equal_wildcard_only_differs_on_patch(self):
        # `!=*` normalises to a dirty 0.0.0 with clean minor/patch flags, so -
        # faithfully to upstream - it EXCLUDES 0.0.0 yet matches 0.0.5.
        self.assertTrue(self._check("!=*", "0.0.5"))
        self.assertFalse(self._check("!=*", "0.0.0"))

    def test_not_equal_dirty_patch_with_prerelease_compares_prereleases(self):
        # `!=1.2-beta` has a dirty patch AND a prerelease comparator; upstream
        # then decides by comparing prereleases, so a release 1.2.x differs.
        self.assertTrue(self._check("!=1.2-beta", "1.2.9"))
        self.assertFalse(self._check("!=1.2-beta", "1.2.0-beta"))


class TestDescribe(unittest.TestCase):
    """DeclaredRange.describe() is quoted into findings; each empty-set state
    must render as its own sentence, because the three causes demand three
    different remedies (see kubeversion.py's module docstring)."""

    def test_span_and_truncation_marker(self):
        self.assertEqual(kv.declared_range(">=1.20.0-0 <1.22.0-0").describe(),
                         "1.20-1.21")
        # Open-ended: sampling stopped at the horizon, and the '+' says so.
        self.assertTrue(kv.declared_range(">=1.23.0-0").describe()
                        .endswith("+"))

    def test_single_minor_renders_without_a_dash(self):
        self.assertEqual(kv.declared_range(">=1.21.0-0 <1.22.0-0").describe(),
                         "1.21")

    def test_contradictory_range_is_no_cluster_version(self):
        dr = kv.declared_range(">=1.30.0-0 <1.20.0-0")
        self.assertTrue(dr.parsed)
        self.assertFalse(dr.above_domain)
        self.assertEqual(dr.describe(), "no cluster version")

    def test_above_minor_horizon_names_the_horizon(self):
        dr = kv.declared_range(f">=1.{kv.DOMAIN_MAX_MINOR + 1}.0-0")
        self.assertEqual(dr.above_domain_edge, kv.AboveDomain.MINOR)
        self.assertEqual(dr.describe(),
                         f"nothing at or below 1.{kv.DOMAIN_MAX_MINOR}")

    def test_above_major_edge_names_the_nonexistent_major(self):
        # `>=2.0.0-0` is satisfiable - just not by any Kubernetes ever
        # released. Reporting it as the minor-horizon case (or as
        # contradictory) would blame the wrong thing.
        dr = kv.declared_range(">=2.0.0-0")
        self.assertEqual(dr.above_domain_edge, kv.AboveDomain.MAJOR)
        self.assertEqual(dr.describe(), "nothing in 1.x (only 2.0 and later)")


if __name__ == "__main__":
    unittest.main()

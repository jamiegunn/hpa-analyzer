"""helmrender's edges: helm absent or unrunnable, error flattening, and the
parsing of `helm template` streams.

Absence is real here, per the house pattern in test_preflight_external.py:
PATH is restricted to an empty real directory, or a genuinely nonexistent
binary path is passed, so every 'helm is missing' observation is the OS's
answer, not a patched one. The module's per-binary-path caches make that
safe: a nonexistent path is its own cache key and cannot poison the entry
for the real binary.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from hpaanalyzer.helmrender import (_flatten, find_helm,
                                    helm_default_kube_version, helm_major,
                                    helm_version_string, render_chart,
                                    rendered_object_ids, split_rendered)

HELM = shutil.which("helm")


def _empty_path_dir():
    """A real, empty directory to use as PATH - helm absence by observation."""
    return tempfile.mkdtemp(prefix="hpa-nopath-")


class TestHelmAbsent(unittest.TestCase):
    def test_version_queries_answer_none_not_a_guess(self):
        """With no helm on PATH there is no version fact to report. None is
        the contract every caller (renderplan's per-major pins, the report's
        'helm N' wording) branches on; inventing a default here would turn
        those into claims about a binary that does not exist."""
        with mock.patch.dict(os.environ, {"PATH": _empty_path_dir()}):
            self.assertIsNone(find_helm())
            self.assertIsNone(helm_version_string())
            self.assertIsNone(helm_major())
            self.assertIsNone(helm_default_kube_version())

    def test_render_chart_reports_the_missing_binary_as_the_error(self):
        """render_chart's (None, error) contract: the error must name the
        actual gap - helm itself - because this string is what the report
        shows as the reason analysis fell back to static mode, and 'install
        helm' is its only correct remedy."""
        with mock.patch.dict(os.environ, {"PATH": _empty_path_dir()}):
            out, err = render_chart(tempfile.mkdtemp(prefix="hpa-chart-"))
        self.assertIsNone(out)
        self.assertEqual(err, "helm binary not found on PATH")


class TestVersionCache(unittest.TestCase):
    def test_unrunnable_binary_is_none_and_stays_none(self):
        """An explicit helm_bin that cannot execute must yield None - the
        same answer as absence, because a binary that cannot run has no
        version - and the failure is cached under that path, so repeated
        probes of a broken install do not retry the exec every call."""
        bad = "/nonexistent-hpa-test/helm"
        self.assertIsNone(helm_version_string(bad))
        # second call: served from the per-path cache, same answer
        self.assertIsNone(helm_version_string(bad))
        self.assertIsNone(helm_major(bad))

    @unittest.skipUnless(HELM, "helm not installed")
    def test_real_binary_version_is_stable_across_calls(self):
        """The cache is keyed by binary path and must be transparent: two
        calls for the same binary agree, and the value is a real version
        string a report can print verbatim."""
        first = helm_version_string(HELM)
        self.assertIsNotNone(first)
        self.assertRegex(first, r"v\d+\.\d+\.\d+")
        self.assertEqual(helm_version_string(HELM), first)
        major = helm_major(HELM)
        self.assertIsInstance(major, int)
        self.assertGreaterEqual(major, 3)


class TestFlatten(unittest.TestCase):
    def test_multiline_error_becomes_one_line(self):
        """This string is spliced into single-line report fields and table
        cells; helm's real errors are multi-line ('Error: ...\\n\\nUse
        --debug ...'), and a newline there breaks the report, not the
        wrapping."""
        flat = _flatten("Error: something\n\nUse --debug flag to render out")
        self.assertNotIn("\n", flat)
        self.assertEqual(flat,
                         "Error: something Use --debug flag to render out")

    def test_long_error_truncated_at_the_limit_with_a_marker(self):
        """The 300-char cap keeps a pathological helm error from swallowing
        the table it sits in, and the ' ...' marker admits the cut so the
        reader knows there was more."""
        flat = _flatten("word " * 200)
        self.assertLessEqual(len(flat), 304)
        self.assertTrue(flat.endswith(" ..."))
        # the kept prefix is the original text, not a rewrite
        self.assertTrue(flat.startswith("word word"))

    def test_short_error_passes_through_unmarked(self):
        self.assertEqual(_flatten("Error: no"), "Error: no")


class TestRenderedObjectIds(unittest.TestCase):
    def test_unusable_chunks_are_skipped_not_fatal(self):
        """This function feeds the divergence comparison (CH015): one
        unparseable or non-object chunk in a big render must not abort the
        whole identity list, or a single templated NOTES-style blob would
        blind the check to every other object. Garbage YAML, list documents
        and kindless fragments are each skipped individually; the objects
        around them still count, and a nameless object keeps its kind under
        the explicit '<unnamed>' placeholder rather than vanishing."""
        output = "\n---\n".join([
            "this: [is, not\n  a: manifest",              # YAMLError
            "- just\n- a list",                            # not a dict
            "metadata: {name: kindless}",                  # no kind
            "kind: ConfigMap\nmetadata: notadict",         # metadata not a map
            "kind: Deployment\nmetadata: {name: web}",
        ])
        self.assertEqual(rendered_object_ids(output),
                         [("ConfigMap", "<unnamed>"), ("Deployment", "web")])

    def test_empty_stream_is_an_empty_list(self):
        self.assertEqual(rendered_object_ids(""), [])


class TestSplitRendered(unittest.TestCase):
    def test_source_comment_maps_back_to_the_template_path(self):
        """The chart-name prefix is stripped so findings can point at
        'templates/deployment.yaml' - the path that exists in the user's
        repo - rather than helm's 'mychart/templates/deployment.yaml',
        which exists nowhere on disk."""
        out = ("---\n# Source: mychart/templates/deployment.yaml\n"
               "kind: Deployment\n")
        docs = split_rendered(out)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0][0], "templates/deployment.yaml")
        self.assertIn("kind: Deployment", docs[0][1])

    def test_missing_source_comment_yields_empty_source_not_a_crash(self):
        """helm omits the Source comment for some inputs (e.g. --show-only,
        or hooks from library charts). The document must still be returned -
        dropping it would silently shrink the render - with '' marking the
        unknown origin."""
        docs = split_rendered("kind: Service\nmetadata: {name: s}\n")
        self.assertEqual(docs, [("", "kind: Service\nmetadata: {name: s}\n")])

    def test_unprefixed_source_path_is_kept_verbatim(self):
        """A Source path with no chart-name prefix has nothing to strip;
        inventing a split would corrupt the one path helm gave us."""
        docs = split_rendered("# Source: standalone.yaml\nkind: Pod\n")
        self.assertEqual(docs[0][0], "standalone.yaml")

    def test_blank_chunks_between_separators_are_dropped(self):
        """helm emits '---' between every template, including empty ones;
        blank chunks are noise, not documents, and must not become empty
        entries that downstream parsers trip over."""
        out = "---\n\n---\nkind: Pod\n---\n   \n"
        docs = split_rendered(out)
        self.assertEqual(len(docs), 1)
        self.assertIn("kind: Pod", docs[0][1])


if __name__ == "__main__":
    unittest.main()

"""Edge semantics of the quantity parsers that the main suite leaves implicit.

These are all behavioral contracts of hpaanalyzer/quantity.py: what a parser
does with legal-but-insane input (CPU in Gi), with input that is not a
quantity at all, and what the formatting/lookup helpers promise for None.
"""

import unittest

from hpaanalyzer.quantity import (fmt_millicores, mib, parse_cpu, parse_jvm_size,
                                  parse_memory, resolve_resource)


class TestCpuSuffixes(unittest.TestCase):
    def test_memory_suffix_on_cpu_is_parsed_not_rejected(self):
        # `cpu: 1Ki` is technically legal k8s syntax (1024 cores). Parsing it
        # faithfully instead of returning None is what lets a check FLAG it -
        # a None here would be indistinguishable from garbage input.
        self.assertEqual(parse_cpu("1Ki"), 1024 * 1000)
        self.assertEqual(parse_cpu("2M"), 2 * 1000**2 * 1000)

    def test_unknown_suffix_is_unparseable(self):
        # A suffix that is neither 'm', empty, nor a k8s memory suffix is not
        # a quantity in any unit; it must come back None, never a guess.
        self.assertIsNone(parse_cpu("5cores"))


class TestMemoryEdges(unittest.TestCase):
    def test_empty_and_whitespace_are_unparseable(self):
        self.assertIsNone(parse_memory(""))
        self.assertIsNone(parse_memory("   "))

    def test_unknown_suffix_is_unparseable(self):
        self.assertIsNone(parse_memory("5banana"))


class TestJvmSizeEdges(unittest.TestCase):
    def test_none_in_none_out(self):
        # resolve chains pass raw values straight through; None must not raise.
        self.assertIsNone(parse_jvm_size(None))


class TestFormattingContracts(unittest.TestCase):
    def test_unknown_millicores_render_as_question_mark(self):
        # The proof tables print fmt_millicores over possibly-absent requests;
        # "?" is the documented rendering for "not stated", same as fmt_bytes.
        self.assertEqual(fmt_millicores(None), "?")

    def test_mib_conversion_and_none_passthrough(self):
        self.assertEqual(mib(1024**2), 1.0)
        self.assertEqual(mib(512 * 1024**2), 512.0)
        self.assertIsNone(mib(None))


class TestResolveResource(unittest.TestCase):
    CONTAINER = {
        "name": "app",
        "resources": {"requests": {"cpu": "500m", "memory": "1Gi"}},
    }

    def test_returns_raw_and_parsed_pair(self):
        # Callers need BOTH: the raw string for the report ("what you wrote")
        # and the canonical number for arithmetic.
        self.assertEqual(resolve_resource(self.CONTAINER, "requests", "cpu"),
                         ("500m", 500))
        raw, parsed = resolve_resource(self.CONTAINER, "requests", "memory")
        self.assertEqual((raw, parsed), ("1Gi", 1024**3))

    def test_missing_section_is_none_none(self):
        self.assertEqual(resolve_resource(self.CONTAINER, "limits", "cpu"),
                         (None, None))
        self.assertEqual(resolve_resource({}, "requests", "cpu"), (None, None))

    def test_non_dict_resources_is_none_none_not_a_crash(self):
        # In static mode `resources:` is routinely a HELMVAL@/HELMINC@ string;
        # indexing into it raises TypeError, which must mean "not stated".
        c = {"resources": "HELMINC@t.resources"}
        self.assertEqual(resolve_resource(c, "requests", "memory"), (None, None))


if __name__ == "__main__":
    unittest.main()

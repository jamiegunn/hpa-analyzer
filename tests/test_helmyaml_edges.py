"""helmyaml edge behavior: odd-but-legal templates must degrade, not crash.

The scrubber's whole reason to exist is input that is not YAML yet; these
cases pin what it does at the margins - unusual keys, defaults that are not
themselves YAML, markers embedded where only a scalar could substitute, and
control-flow stacks that do not balance.
"""

import unittest

from hpaanalyzer.helmyaml import (enclosing_conditions, load_yaml_docs,
                                  resolve_markers, scrub_template)


class TestLoaderResilience(unittest.TestCase):
    def test_unhashable_mapping_key_is_stringified(self):
        # YAML allows complex (sequence) mapping keys; Python dicts do not.
        # The duplicate-detecting loader coerces such a key to its string form
        # rather than raising, so one exotic key cannot cost the whole file's
        # coverage. (Shallow construction stringifies the not-yet-populated
        # node, hence the value assertion is on shape, not spelling.)
        docs, dups, err = load_yaml_docs("? [a, b]\n: 1\n")
        self.assertIsNone(err)
        self.assertEqual(len(docs), 1)
        (key, value), = docs[0].items()
        self.assertIsInstance(key, str)
        self.assertEqual(value, 1)
        self.assertEqual(dups, [])


class TestDefaultLiteralResolution(unittest.TestCase):
    def test_unparseable_default_literal_falls_back_to_the_raw_text(self):
        # `| default "["` carries a default that is not valid YAML on its own.
        # Resolution must hand back the literal text instead of raising - the
        # value the template would emit is that text.
        docs, _, _ = load_yaml_docs(scrub_template(
            'tag: {{ .Values.tag | default "[" }}\n'))
        self.assertEqual(resolve_markers(docs[0], {}), {"tag": "["})
        # And a set value still wins over the default.
        self.assertEqual(resolve_markers(docs[0], {"tag": "9"}), {"tag": "9"})


class TestEmbeddedMarkerSubstitution(unittest.TestCase):
    def test_non_scalar_value_is_not_spliced_into_a_string(self):
        # "prefix-HELMVAL@foo" can only absorb a scalar; splicing str(dict)
        # into an image ref would fabricate a value nobody wrote. The marker
        # stays, which is what is_unresolved() keys on downstream.
        s = "img: HELMVAL@foo"
        self.assertEqual(resolve_markers(s, {"foo": {"a": 1}}), s)

    def test_unset_path_leaves_the_marker(self):
        s = "img: HELMVAL@foo"
        self.assertEqual(resolve_markers(s, {}), s)


class TestEnclosingConditionsEdges(unittest.TestCase):
    def test_else_if_replaces_the_innermost_condition(self):
        # An `else if` arm is its own condition, not a negation of the first:
        # the target sits under `if .Values.b`, and reporting
        # "NOT (if .Values.a)" would name the wrong gate.
        src = ("spec:\n  {{- if .Values.a }}\n  x: 1\n"
               "  {{- else if .Values.b }}\n  replicas: 2\n  {{- end }}\n")
        self.assertEqual(enclosing_conditions(src, r"^\s*replicas\s*:"),
                         ["if .Values.b"])

    def test_unbalanced_else_and_end_do_not_underflow(self):
        # `end`/`else` with no open block (a snippet, or a partial the author
        # split across files) must be ignored, not pop an empty stack.
        src = "{{ end }}\n{{ else }}\nreplicas: 2\n"
        self.assertEqual(enclosing_conditions(src, r"^replicas\s*:"), [])


if __name__ == "__main__":
    unittest.main()

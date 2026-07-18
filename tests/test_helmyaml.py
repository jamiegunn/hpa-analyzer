import unittest

from hpaanalyzer.helmyaml import (deep_merge, enclosing_conditions, line_of,
                                  load_yaml_docs, resolve_markers,
                                  scrub_template, values_lookup)


class TestScrub(unittest.TestCase):
    def test_control_flow_dropped_lines_preserved(self):
        src = "a: 1\n{{- if .Values.x }}\nb: 2\n{{- end }}\nc: 3\n"
        out = scrub_template(src)
        self.assertEqual(len(out.split("\n")), len(src.split("\n")))
        docs, _, err = load_yaml_docs(out)
        self.assertIsNone(err)
        self.assertEqual(docs[0], {"a": 1, "b": 2, "c": 3})

    def test_values_marker_and_resolution(self):
        src = "tag: {{ .Values.image.tag }}\n"
        docs, _, _ = load_yaml_docs(scrub_template(src))
        resolved = resolve_markers(docs[0], {"image": {"tag": "1.2.3"}})
        self.assertEqual(resolved["tag"], "1.2.3")

    def test_toyaml_block_resolution(self):
        src = "resources:\n  {{- toYaml .Values.resources | nindent 2 }}\n"
        docs, _, _ = load_yaml_docs(scrub_template(src))
        vals = {"resources": {"requests": {"cpu": "100m"}}}
        resolved = resolve_markers(docs[0], vals)
        self.assertEqual(resolved["resources"]["requests"]["cpu"], "100m")

    def test_release_name_placeholder(self):
        src = "name: {{ .Release.Name }}-app\n"
        docs, _, _ = load_yaml_docs(scrub_template(src))
        self.assertEqual(docs[0]["name"], "RELEASE-NAME-app")

    def test_embedded_string_resolution(self):
        src = 'image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"\n'
        docs, _, _ = load_yaml_docs(scrub_template(src))
        resolved = resolve_markers(
            docs[0], {"image": {"repository": "r/a", "tag": "9"}})
        self.assertEqual(resolved["image"], "r/a:9")

    def test_duplicate_keys_detected(self):
        docs, dups, err = load_yaml_docs("a: 1\nb: 2\na: 3\n")
        self.assertIsNone(err)
        self.assertEqual(dups, [("a", 3)])
        self.assertEqual(docs[0]["a"], 3)  # later wins - the danger


class TestEnclosingConditions(unittest.TestCase):
    TARGET = r"^\s{0,4}replicas\s*:"

    def test_not_inside_any_block(self):
        conds = enclosing_conditions("spec:\n  replicas: 2\n", self.TARGET)
        self.assertEqual(conds, [])

    def test_standard_gate(self):
        src = ("spec:\n  {{- if not .Values.autoscaling.enabled }}\n"
               "  replicas: 2\n  {{- end }}\n")
        conds = enclosing_conditions(src, self.TARGET)
        self.assertEqual(conds, ["if not .Values.autoscaling.enabled"])

    def test_variable_gate_idiom(self):
        src = ("{{- $auto := .Values.hpa.enabled }}\nspec:\n"
               "  {{- if not $auto }}\n  replicas: 2\n  {{- end }}\n")
        conds = enclosing_conditions(src, self.TARGET)
        self.assertEqual(conds, ["if not $auto"])

    def test_else_branch_negates(self):
        src = ("spec:\n  {{- if .Values.autoscaling.enabled }}\n  x: 1\n"
               "  {{- else }}\n  replicas: 2\n  {{- end }}\n")
        conds = enclosing_conditions(src, self.TARGET)
        self.assertEqual(conds, ["NOT (if .Values.autoscaling.enabled)"])

    def test_closed_block_not_counted(self):
        src = ("{{- if .Values.foo }}\nx: 1\n{{- end }}\n"
               "spec:\n  replicas: 2\n")
        self.assertEqual(enclosing_conditions(src, self.TARGET), [])

    def test_target_missing(self):
        self.assertIsNone(enclosing_conditions("a: 1\n", self.TARGET))

    def test_line_of(self):
        self.assertEqual(line_of("a: 1\nreplicas: 2\n", self.TARGET), 2)
        self.assertIsNone(line_of("a: 1\n", self.TARGET))


class TestMergeLookup(unittest.TestCase):
    def test_deep_merge(self):
        out = deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"b": 9}, "d": 3})
        self.assertEqual(out, {"a": {"b": 9, "c": 2}, "d": 3})

    def test_lookup(self):
        self.assertEqual(values_lookup({"a": {"b": 5}}, "a.b"), (True, 5))
        self.assertEqual(values_lookup({}, "a.b"), (False, None))


if __name__ == "__main__":
    unittest.main()

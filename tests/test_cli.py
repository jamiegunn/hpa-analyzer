import json
import os
import tempfile
import unittest

from hpaanalyzer.__main__ import main

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def tmpfile(suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


class TestCli(unittest.TestCase):
    def test_ok_exit_zero(self):
        out = tmpfile(".txt")
        rc = main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                   "--helm", "off"])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.getsize(out) > 1000)

    def test_fail_on_gate(self):
        out = tmpfile(".txt")
        rc = main([os.path.join(FIXTURES, "bad-chart"), "-o", out,
                   "--helm", "off", "--fail-on", "critical"])
        self.assertEqual(rc, 1)

    def test_invalid_assume_java_is_usage_error(self):
        # F7: a bad --assume-java is exit 2 (usage), not a buried finding at 0
        out = tmpfile(".txt")
        rc = main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                   "--helm", "off", "--assume-java", "banana"])
        self.assertEqual(rc, 2)

    def test_valid_assume_java_ok(self):
        out = tmpfile(".txt")
        rc = main([os.path.join(FIXTURES, "bad-chart"), "-o", out,
                   "--helm", "off", "--assume-java", "8u151"])
        self.assertIn(rc, (0, 1))   # runs; may or may not trip default gates

    def test_fail_on_not_triggered_by_clean_chart(self):
        out = tmpfile(".txt")
        rc = main([os.path.join(FIXTURES, "good-chart"), "-o", out,
                   "--helm", "off", "--fail-on", "low"])
        self.assertEqual(rc, 0)

    def test_min_score_gate(self):
        out = tmpfile(".txt")
        rc = main([os.path.join(FIXTURES, "bad-chart"), "-o", out,
                   "--helm", "off", "--min-score", "80"])
        self.assertEqual(rc, 1)

    def test_min_score_fails_on_ungradeable(self):
        out = tmpfile(".txt")
        empty = tempfile.mkdtemp()
        rc = main([empty, "-o", out, "--helm", "off", "--min-score", "1"])
        self.assertEqual(rc, 1)

    def test_not_a_directory(self):
        self.assertEqual(main(["/definitely/not/a/dir"]), 2)

    def test_json_output(self):
        out, jout = tmpfile(".txt"), tmpfile(".json")
        rc = main([os.path.join(FIXTURES, "bad-chart"), "-o", out,
                   "--helm", "off", "--json", jout])
        self.assertEqual(rc, 0)
        with open(jout) as f:
            payload = json.load(f)
        self.assertTrue(payload["graded"])
        self.assertLess(payload["score"], 60)
        self.assertTrue(any(f["rule"] == "HP050" for f in payload["findings"]))
        self.assertTrue(all("severity" in f and "fix" in f
                            for f in payload["findings"]))
        self.assertTrue(payload["coverage"])


if __name__ == "__main__":
    unittest.main()

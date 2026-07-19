"""Guided preflight + external cross-check."""

import os
import tempfile
import unittest
from unittest import mock

import hpaanalyzer.external as ext
from hpaanalyzer.__main__ import main
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
    def test_all_absent_reports_install_hints(self):
        # sandbox genuinely has none of these -> honest 'not installed'
        with mock.patch.object(ext, "find_helm", return_value=None), \
             mock.patch.object(ext, "_which", return_value=None):
            res = ext.run_cross_check("/some/chart")
        names = {e.name for e in res}
        self.assertEqual(names, {"helm lint", "kubeconform", "kube-score",
                                 "polaris"})
        for e in res:
            self.assertFalse(e.installed)
            self.assertFalse(e.ran)
            self.assertTrue(e.manual_cmd)
        # render-needing tools carry an install hint
        self.assertTrue(any(e.name == "kubeconform" and e.install_hint
                            for e in res))

    def test_present_tools_run_and_report_pass_fail(self):
        def fake_which(b):
            return "/usr/bin/" + b if b in ("kubeconform",) else None

        def fake_run(cmd, **kw):
            if "lint" in cmd:
                return (0, "1 chart(s) linted, 0 failed", "")
            if "kubeconform" in cmd[0]:
                return (1, "Summary: 0 valid, 1 invalid", "")
            return (None, "", "err")

        with mock.patch.object(ext, "find_helm", return_value="/usr/bin/helm"), \
             mock.patch.object(ext, "_which", side_effect=fake_which), \
             mock.patch.object(ext, "render_chart",
                               return_value=("kind: Service\n", None)), \
             mock.patch.object(ext, "_run", side_effect=fake_run):
            res = {e.name: e for e in ext.run_cross_check("/some/chart")}
        self.assertTrue(res["helm lint"].ran and res["helm lint"].ok)
        self.assertTrue(res["kubeconform"].ran and res["kubeconform"].ok is False)
        self.assertFalse(res["kube-score"].installed)

    def test_render_needing_tool_skipped_without_helm(self):
        # kubeconform present but no helm to render -> skipped with reason
        def fake_which(b):
            return "/usr/bin/kubeconform" if b == "kubeconform" else None
        with mock.patch.object(ext, "find_helm", return_value=None), \
             mock.patch.object(ext, "_which", side_effect=fake_which):
            res = {e.name: e for e in ext.run_cross_check("/some/chart")}
        kc = res["kubeconform"]
        self.assertTrue(kc.installed)
        self.assertFalse(kc.ran)
        self.assertIn("helm", kc.summary)


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

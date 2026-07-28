"""The output READERS in external.py, and run_cross_check's skip paths.

Literal-blob policy, stated once for the whole file: kube-score and polaris
are not installed in this environment, so their READERS are fed pinned
literals here. That is the pattern test_indeterminacy_never_upgrades_a_real_
failure established and justified: a literal is acceptable when it is a
statement about THIS module's arithmetic over a format that is pinned by a
real-binary test elsewhere. The marker vocabulary these literals use -
"[CRITICAL]"/"[WARNING]"/checkmark/collision for kube-score, "Danger"/
"Warning"/"Success"/"Final score:"/"Controllers:" for polaris, the parse-error
lines for both - is exactly the vocabulary the real-binary tests in
test_preflight_external.py assert appears in real output (they skip here, but
run wherever the binaries exist, e.g. the pinned image). Nothing in this file
executes a fake validator: the paths that would RUN a tool are exercised only
where the OS itself refuses to exec a nonexistent path, which is a real
observation, not a scripted stand-in.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

import hpaanalyzer.external as ext

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")

CONFIGMAP = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"


def _path_with(*binaries):
    """A real PATH directory containing only `binaries` (symlinked) - the
    established pattern from test_preflight_external.py, so even 'the tool is
    missing' is a real observation rather than a patched one."""
    d = tempfile.mkdtemp(prefix="hpa-path-")
    for b in binaries:
        real = shutil.which(b)
        if real:
            os.symlink(real, os.path.join(d, b))
    return d


class TestVerdictProperty(unittest.TestCase):
    def _res(self, **kw):
        base = dict(name="t", installed=True, ran=True, ok=None,
                    summary="", manual_cmd="t")
        base.update(kw)
        return ext.ExternalResult(**base)

    def test_indeterminate_overrides_a_recorded_failure(self):
        """The whole point of the indeterminacy machinery: once a result is
        marked indeterminate, the verdict must read UNKNOWN even though `ok`
        still records the raw non-zero exit. If `ok` won this race, every
        downgraded kubeconform network failure would print FAIL anyway and the
        R4 fix would be decorative."""
        r = self._res(ok=False, indeterminate=True,
                      indeterminate_why="schemas unreachable")
        self.assertEqual(r.verdict, "UNKNOWN")

    def test_ran_but_learned_nothing_is_unknown_not_pass(self):
        """ok=None after a run means the tool said nothing either way (e.g.
        polaris over zero controllers). Rounding that to PASS would report a
        clean bill of health from a checker that checked nothing; rounding to
        FAIL would blame the chart. UNKNOWN is the only honest word."""
        self.assertEqual(self._res(ok=None).verdict, "UNKNOWN")

    def test_not_run_is_its_own_state(self):
        """'not run' and UNKNOWN are different facts: one is about this
        machine's toolbox, the other about what a tool that DID run could
        conclude. Collapsing them would hide which installs would help."""
        self.assertEqual(self._res(ran=False).verdict, "not run")


class TestClean(unittest.TestCase):
    def test_scratch_path_and_its_directory_are_redacted(self):
        """polaris echoes its argv, temp path included, and that line was
        being shown to users as the verdict summary (see _clean's docstring).
        Both the file and its parent directory must be replaced, because the
        directory alone also appears in stderr lines."""
        d = tempfile.mkdtemp(prefix="hpa-xcheck-")
        p = os.path.join(d, "rendered.yaml")
        blob = f"audited {p}\nwrote junk under {d}\n\x1b[32mgreen\x1b[0m"
        out = ext._clean(blob, p)
        self.assertNotIn(p, out)
        self.assertNotIn(d, out)
        self.assertIn("<rendered manifests>", out)
        self.assertIn("<tmp>", out)
        # and ANSI escapes are gone in the same pass
        self.assertNotIn("\x1b[", out)
        self.assertIn("green", out)

    def test_bare_filename_has_no_directory_to_redact(self):
        """A rendered path with no directory component must not trigger the
        dirname replacement: replacing '' would corrupt the whole string
        (str.replace('', x) inserts x between every character)."""
        out = ext._clean("checked rendered.yaml fine", "rendered.yaml")
        self.assertEqual(out, "checked <rendered manifests> fine")


class TestReadKubeScore(unittest.TestCase):
    """_read_kube_score over literals in the marker vocabulary the real-binary
    tests pin (see module docstring)."""

    def test_parse_failure_is_indeterminate_and_blames_the_file(self):
        """kube-score exits 1 both for findings and for unreadable input; the
        reader must keep those apart. The `why` must say the failure is about
        the file handed over, not the chart - that exact sentence is what the
        report prints beside UNKNOWN."""
        # the error line sits below other output, as it does in a real run
        # where kube-score has already printed per-file progress: the reader
        # must find it wherever it is, not only on the first line.
        blob = ("junk.yaml\n"
                "Failed to score files: failed to parse files: "
                "invalid Kubernetes object in junk.yaml")
        r = ext._read_kube_score(blob)
        self.assertIsNone(r.ok)
        self.assertEqual(r.summary, "could not parse the manifests")
        self.assertIn("not about the chart", r.why)
        self.assertIn("failed to parse files", r.why)
        self.assertEqual(r.tally, {"parsed": False})
        self.assertIn("parse error", r.basis)

    def test_zero_objects_scored_is_unknown(self):
        """Empty output means kube-score said nothing about this chart; a
        PASS over zero objects would be a clean bill from an empty exam."""
        r = ext._read_kube_score("")
        self.assertIsNone(r.ok)
        self.assertEqual(r.summary, "scored 0 objects")
        self.assertIn("said nothing", r.why)
        self.assertEqual(r.tally["objects_scored"], 0)

    def test_critical_findings_fail_with_the_tally_shown(self):
        blob = ("apps/v1/Deployment web \U0001f4a5\n"
                "    [CRITICAL] Container Image Tag\n"
                "    [CRITICAL] Container Resources\n"
                "    [WARNING] Deployment Replicas\n"
                "v1/Service web ✅\n")
        r = ext._read_kube_score(blob)
        self.assertIs(r.ok, False)
        self.assertEqual(r.tally, {"objects_scored": 2, "objects_ok": 1,
                                   "objects_flagged": 1, "critical": 2,
                                   "warning": 1})
        self.assertEqual(r.summary, "2 object(s) scored: 2 critical, 1 warning")
        self.assertIn("not its exit code", r.basis)

    def test_warnings_alone_do_not_fail(self):
        """kube-score's own severity model: only CRITICAL is a failure. A
        reader that failed charts on warnings would be stricter than the tool
        it claims to be transcribing."""
        blob = ("apps/v1/Deployment web \U0001f4a5\n"
                "    [WARNING] Deployment Replicas\n")
        r = ext._read_kube_score(blob)
        self.assertIs(r.ok, True)
        self.assertEqual(r.tally["critical"], 0)
        self.assertEqual(r.tally["warning"], 1)


class TestReadPolaris(unittest.TestCase):
    """_read_polaris over literals in the format the real-binary tests pin
    (see module docstring). polaris's exit code is always 0 and is never
    consulted here - the reader works from the printed audit alone."""

    POLARIS_OK = ("Polaris audited Path <rendered manifests>\n"
                  "    Nodes: 0 | Namespaces: 0 | Controllers: 2\n"
                  "    Final score: 92\n\n"
                  "Deployment web\n"
                  "    \U0001f389 Success: Image tag is specified\n"
                  "    \U0001f62c Warning: CPU limits should be set\n")

    def test_danger_findings_fail_despite_exit_zero(self):
        blob = (self.POLARIS_OK +
                "    ❌ Danger: Container should not run as root\n")
        r = ext._read_polaris(blob)
        self.assertIs(r.ok, False)
        self.assertEqual(r.tally["danger"], 1)
        self.assertEqual(r.tally["controllers"], 2)
        self.assertEqual(r.tally["score"], 92)
        self.assertIn("exit code is always 0", r.basis)

    def test_no_danger_passes_with_score_in_summary(self):
        r = ext._read_polaris(self.POLARIS_OK)
        self.assertIs(r.ok, True)
        self.assertEqual(r.summary,
                         "score 92/100 over 2 controller(s): 0 danger, 1 warning")

    def test_missing_score_line_says_unreported_not_a_number(self):
        """If polaris stops printing 'Final score', the summary must admit it
        rather than invent one - a fabricated 0 or 100 would each mislead in
        a different direction."""
        blob = ("Controllers: 2\n"
                "    \U0001f389 Success: ok\n")
        r = ext._read_polaris(blob)
        self.assertIs(r.ok, True)
        self.assertTrue(r.summary.startswith("score unreported"))
        self.assertIsNone(r.tally["score"])

    def test_zero_controllers_is_unknown(self):
        """polaris prints 'Final score: 100' over 'Controllers: 0' for input
        it could not use. A perfect score over an empty set is not a fact
        about the chart, and must not become PASS."""
        blob = "Controllers: 0\nFinal score: 100\n"
        r = ext._read_polaris(blob)
        self.assertIsNone(r.ok)
        self.assertEqual(r.summary, "audited 0 controllers")
        self.assertIn("empty set", r.why)

    def test_missing_controllers_line_treated_like_zero(self):
        """No 'Controllers:' line at all leaves the denominator unknown - the
        reader must not assume anything was audited."""
        r = ext._read_polaris("Final score: 100\n")
        self.assertIsNone(r.ok)
        self.assertIsNone(r.tally["controllers"])

    def test_parse_error_beats_the_perfect_score(self):
        """The C2.2 case for polaris: a logged YAML parse error means the
        score covers only what survived parsing, so even 100/100 over a
        nonzero controller count is indeterminate."""
        blob = ('time=x level=error msg="Error parsing YAML: yaml: line 2: '
                'mapping values are not allowed"\n'
                "Controllers: 1\nFinal score: 100\n")
        r = ext._read_polaris(blob)
        self.assertIsNone(r.ok)
        self.assertEqual(r.summary, "could not parse the manifests")
        self.assertIn("perfect score", r.why)


class TestReadKubeconform(unittest.TestCase):
    """_read_kubeconform is a thin exposure of the R4 verdict logic; these pin
    the exposure. The literal's format is pinned against the real binary by
    test_kubeconform_summary_regex_matches_real_output."""

    SUMMARY = ("Summary: 9 resources found in 1 file - Valid: 4, Invalid: 2, "
               "Errors: 3, Skipped: 0")

    def test_real_invalids_stay_fail_and_relabel_errors_honestly(self):
        """Invalid > 0 with rc 1 is a FAIL (the asymmetry test elsewhere pins
        why); the summary must translate kubeconform's 'Errors' to 'not
        checkable' so a reader does not double-count them as failures."""
        r = ext._read_kubeconform(self.SUMMARY, 1)
        self.assertIs(r.ok, False)
        self.assertEqual(r.why, "")
        self.assertEqual(r.summary,
                         "4 valid, 2 invalid, 3 not checkable, 0 skipped")
        self.assertEqual(r.tally, {"valid": 4, "invalid": 2, "errors": 3,
                                   "skipped": 0})

    def test_exit_zero_passes(self):
        blob = self.SUMMARY.replace("Invalid: 2", "Invalid: 0").replace(
            "Errors: 3", "Errors: 0")
        r = ext._read_kubeconform(blob, 0)
        self.assertIs(r.ok, True)
        self.assertEqual(r.why, "")

    def test_no_exit_code_means_no_verdict(self):
        """rc=None is 'the process did not complete', which is not evidence
        in either direction."""
        r = ext._read_kubeconform(self.SUMMARY, None)
        self.assertIsNone(r.ok)

    def test_without_a_summary_line_the_exit_code_stands_alone(self):
        """When the tally regex finds nothing there is no basis to downgrade,
        so a non-zero exit reads FAIL and the summary falls back to the last
        output line - the only signal left. An empty blob must still produce
        a summary string, not a blank cell."""
        r = ext._read_kubeconform("something broke\nlast line here", 1)
        self.assertIs(r.ok, False)
        self.assertEqual(r.tally, {})
        self.assertEqual(r.summary, "last line here")
        self.assertEqual(r.why, "")
        self.assertEqual(ext._last_summary_line(""), "(no output)")


class TestIndeterminacyScope(unittest.TestCase):
    def test_helm_lint_is_never_downgraded(self):
        """_indeterminacy knows only kubeconform's tally. helm lint's exit
        code IS its documented verdict, so even an error-laden lint blob must
        not be excused to UNKNOWN."""
        self.assertEqual(
            ext._indeterminacy("helm lint", "Error: 3 chart(s) failed"), "")

    def test_no_tally_no_downgrade(self):
        """Downgrading FAIL to UNKNOWN requires positive evidence (the
        Invalid: 0 / Errors: >0 tally). Absent the summary line there is
        none, and the raw exit must stand."""
        self.assertEqual(
            ext._indeterminacy("kubeconform", "cryptic failure, no summary"),
            "")


class TestRunLaunchFailure(unittest.TestCase):
    def test_unlaunchable_command_returns_none_not_an_exit_code(self):
        """rc=None is the channel by which 'the process never ran' stays
        distinct from every real exit code; downstream it maps to 'not run'
        rather than FAIL. The path genuinely does not exist - the OS's
        refusal is the observation, nothing is faked."""
        rc, out, err = ext._run(["/nonexistent-hpa-test/validator"])
        self.assertIsNone(rc)
        self.assertEqual(out, "")
        self.assertIn("No such file or directory", err)


class TestCrossCheckSkipPaths(unittest.TestCase):
    """run_cross_check's own dispatch: which tools are skipped, and what
    reason the reader is given. No validator output is fabricated anywhere
    here - `_which` is patched only where presence/absence is the fact under
    test and the binary is never executed, the same license the existing
    test_cross_check_adds_json_block already takes; and the one test that
    reaches the exec step does so with a path the OS itself refuses."""

    @unittest.skipUnless(shutil.which("helm"), "helm not installed")
    def test_no_chart_dir_helm_present_says_so_without_running(self):
        """helm installed but nothing to point it at: the result must be
        'not run' with a reason about the input, not a lint of nothing and
        not install advice. The tools needing a render get the parallel
        'no rendered manifests' reason (nothing rendered, nothing failed) -
        which is distinct from both 'helm missing' and 'helm refused'."""
        with mock.patch.dict(os.environ, {"PATH": _path_with("helm")}), \
             mock.patch.object(ext, "_which",
                               return_value="/opt/validators/present"):
            res = {e.name: e for e in ext.run_cross_check(None)}
        lint = res["helm lint"]
        self.assertTrue(lint.installed)
        self.assertFalse(lint.ran)
        self.assertEqual(lint.summary, "no chart directory to lint")
        for name in ("kubeconform", "kube-score", "polaris"):
            e = res[name]
            self.assertTrue(e.installed, name)
            self.assertFalse(e.ran, name)
            self.assertEqual(e.summary, "no rendered manifests were available",
                             name)

    def test_tools_present_helm_absent_names_the_actual_gap(self):
        """The D2 distinction from the missing-helm side: when the validators
        are installed and helm is not, the skip reason must say helm is the
        missing piece - installing more validators cannot help."""
        with mock.patch.object(ext, "find_helm", return_value=None), \
             mock.patch.object(ext, "_which",
                               return_value="/opt/validators/present"):
            res = {e.name: e for e in ext.run_cross_check("/some/chart")}
        for name in ("kubeconform", "kube-score", "polaris"):
            e = res[name]
            self.assertTrue(e.installed, name)
            self.assertFalse(e.ran, name)
            self.assertIn("helm is not on PATH", e.summary)

    @unittest.skipUnless(shutil.which("helm"), "helm not installed")
    def test_refused_render_reason_reaches_every_dependent_tool(self):
        """helm present, chart refused (kubeVersion floor above any shipped
        default, the fixture pattern test_renderplan pins for both majors):
        the dependent tools must carry helm's refusal verbatim, not install
        advice - the D2 case, checked without needing kubeconform installed."""
        d = tempfile.mkdtemp(prefix="hpa-refuse-")
        os.makedirs(os.path.join(d, "templates"))
        with open(os.path.join(d, "Chart.yaml"), "w", encoding="utf-8") as f:
            f.write("apiVersion: v2\nname: refuse\nversion: 1.0.0\n"
                    'kubeVersion: ">=1.99.0-0"\n')
        with open(os.path.join(d, "templates", "cm.yaml"), "w",
                  encoding="utf-8") as f:
            f.write(CONFIGMAP)
        with mock.patch.dict(os.environ, {"PATH": _path_with("helm")}), \
             mock.patch.object(ext, "_which",
                               return_value="/opt/validators/present"):
            res = {e.name: e for e in ext.run_cross_check(d)}
        for name in ("kubeconform", "kube-score", "polaris"):
            e = res[name]
            self.assertFalse(e.ran, name)
            self.assertIn("chart could not be rendered:", e.summary)
            self.assertNotIn("not on PATH", e.summary)

    def test_tool_that_cannot_launch_is_not_run_not_fail(self):
        """A binary that resolves but cannot exec (deleted between which()
        and run, broken interpreter line...) must surface as 'failed to run',
        never as a verdict on the chart. The nonexistent path makes the OS
        produce the failure for real - no fake binary is scripted, and no
        validator output is invented."""
        with mock.patch.object(ext, "find_helm", return_value=None), \
             mock.patch.object(ext, "_which",
                               return_value="/nonexistent-hpa-test/validator"):
            res = {e.name: e for e in ext.run_cross_check(
                None, rendered_text=CONFIGMAP)}
        for name in ("kubeconform", "kube-score", "polaris"):
            e = res[name]
            self.assertTrue(e.installed, name)
            self.assertFalse(e.ran, name)
            self.assertTrue(e.summary.startswith("failed to run:"), e.summary)
            self.assertEqual(e.verdict, "not run")
            self.assertEqual(e.verdict_basis, "the tool did not run")

    @unittest.skipUnless(shutil.which("helm"), "helm not installed")
    def test_manual_cmd_without_kube_version_omits_the_flag(self):
        """manual_cmd promises to reproduce exactly what ran. When no
        kube_version was supplied, none may be smuggled into the command -
        helm's compiled-in default is then genuinely what both the run and
        the replay would use."""
        with mock.patch.dict(os.environ, {"PATH": _path_with("helm")}):
            res = {e.name: e for e in ext.run_cross_check(
                os.path.join(FIXTURES, "good-chart"))}
        lint = res["helm lint"]
        self.assertTrue(lint.ran)
        self.assertNotIn("--kube-version", lint.manual_cmd)
        self.assertEqual(lint.verdict_basis, "helm lint's exit code")


if __name__ == "__main__":
    unittest.main()

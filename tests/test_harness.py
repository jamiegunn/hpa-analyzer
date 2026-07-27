"""The shell wrapper (`bin/hpa-analyzer`) as a regression surface.

`proof/p10_harness.py` measures this wrapper against a real container. This
file exists for the part of it that has to survive routine maintenance: the
wrapper contains a **second argument parser**, written in bash, whose only job
is to work out which token is the positional directory and which tokens are
output paths. It has to agree with `argparse` to do that. Add a value-taking
flag to `__main__.py` without adding it to `VALUE_FLAGS` in the wrapper and the
next token gets read as the chart directory - `--new-flag foo ./svc` would
mount `foo` and analyze it. Nothing else in the suite would notice.

So every assertion here compares the shell's decision with the real parser's,
rather than with an author's reading of it.

Everything runs under `HPA_ANALYZER_DRY_RUN=1`, which prints the `docker run`
argv and executes nothing, so these tests need no daemon, no image and no
network. `HPA_ANALYZER_CONTAINER_CLI=true` points the existence check at
/bin/true so the absence of docker is not the absence of a test.
"""

import argparse
import os
import shutil
import subprocess
import tempfile
import unittest

import hpaanalyzer.__main__ as main_mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRAPPER = os.path.join(REPO, "bin", "hpa-analyzer")
FIXTURE = os.path.join(REPO, "fixtures", "bad-chart")
IMAGE = "hpa-analyzer-test:latest"


def _have_bash():
    return shutil.which("bash") is not None


# ---------------------------------------------------------------------------
# the authority: what argparse actually does with an argv
# ---------------------------------------------------------------------------


def argparse_says(argv):
    """Return the Namespace `python3 -m hpaanalyzer argv` would parse, or None
    if argparse rejects the argv. Nothing is analyzed: parse_args is replaced
    with a spy that records and exits before main() reaches any file."""
    captured = {}
    original = argparse.ArgumentParser.parse_args

    def spy(self, args=None, namespace=None):
        ns = original(self, args, namespace)
        captured["ns"] = ns
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = spy
    try:
        main_mod.main(list(argv))
    except SystemExit:
        pass
    finally:
        argparse.ArgumentParser.parse_args = original
    return captured.get("ns")


# ---------------------------------------------------------------------------
# the subject: what the wrapper decided to do
# ---------------------------------------------------------------------------


def dry_run(argv, env_extra=None, cwd=None):
    """Run the wrapper in dry-run mode and return its printed argv as tokens."""
    env = dict(os.environ)
    env.update({
        "HPA_ANALYZER_DRY_RUN": "1",
        "HPA_ANALYZER_CONTAINER_CLI": "true",
        "HPA_ANALYZER_IMAGE": IMAGE,
        "HPA_ANALYZER_NO_USER": "1",
    })
    env.pop("HPA_ANALYZER_OUTPUT_DIR", None)
    env.update(env_extra or {})
    p = subprocess.run(
        ["bash", WRAPPER] + list(argv),
        capture_output=True, text=True, env=env, cwd=cwd or REPO,
        # stdin is a pipe, so the wrapper must take its no-terminal path and
        # must not block. A hang here is a real failure, not a slow machine.
        stdin=subprocess.DEVNULL, timeout=30,
    )
    return p, p.stdout.split()


def mounts(tokens):
    """[(host_path, container_path, mode)] from a `docker run` token list."""
    out = []
    for i, t in enumerate(tokens):
        if t == "-v" and i + 1 < len(tokens):
            parts = tokens[i + 1].split(":")
            out.append((parts[0], parts[1], parts[2] if len(parts) > 2 else "rw"))
    return out


def tail_after_image(tokens):
    """The argv handed to the container, i.e. everything after the image."""
    return tokens[tokens.index(IMAGE) + 1:] if IMAGE in tokens else []


def fresh_env():
    """An XDG_CONFIG_HOME nobody has written to, plus a chosen output dir."""
    d = tempfile.mkdtemp(prefix="hpa-harness-")
    out = os.path.join(d, "out")
    os.makedirs(out, exist_ok=True)
    return d, {"XDG_CONFIG_HOME": os.path.join(d, "cfg"),
               "HPA_ANALYZER_OUTPUT_DIR": out}, out


@unittest.skipUnless(_have_bash(), "bash is not available")
@unittest.skipUnless(os.path.exists(WRAPPER), "bin/hpa-analyzer is not present")
class TestArgumentScan(unittest.TestCase):
    """The shell's idea of the chart directory must be argparse's idea of it."""

    # Rows chosen for where the two parsers can disagree: value flags whose
    # value looks like a path, `=`-joined forms, the short `-oVALUE` form, and
    # --html's optional argument.
    MATRIX = [
        [FIXTURE],
        [FIXTURE, "--summary"],
        ["--kube-version", "1.31.0", FIXTURE],
        ["--kube-version=1.31.0", FIXTURE],
        ["--helm", "off", FIXTURE],
        ["--assume-java", "21", FIXTURE],
        ["--measured", "rps=100", FIXTURE],
        ["--fail-on", "high", FIXTURE],
        ["--min-score", "80", FIXTURE],
        [FIXTURE, "--json", "/tmp/hpa-t/r.json"],
        [FIXTURE, "--json=/tmp/hpa-t/eq.json"],
        [FIXTURE, "--html"],
        [FIXTURE, "--html", "/tmp/hpa-t/r.html"],
        ["--html", "--summary", FIXTURE],
        ["--kube-version", "1.31.0", "--html", "--fail-on", "medium",
         FIXTURE, "--quiet"],
    ]

    def test_shell_and_argparse_agree_on_the_positional(self):
        _, env, _ = fresh_env()
        for argv in self.MATRIX:
            with self.subTest(argv=" ".join(argv)):
                ns = argparse_says(argv)
                self.assertIsNotNone(ns, "fixture argv should parse")
                want = os.path.realpath(ns.directory)
                p, tokens = dry_run(argv, env)
                self.assertEqual(p.returncode, 0, p.stderr)
                hosts = [os.path.realpath(m[0]) for m in mounts(tokens)]
                self.assertIn(want, hosts,
                              f"the chart argparse found is not mounted: {tokens}")

    def test_no_flag_value_is_ever_mounted(self):
        """`--kube-version 1.31.0 chart/` must not mount `1.31.0`."""
        _, env, _ = fresh_env()
        _, tokens = dry_run(["--kube-version", "1.31.0", FIXTURE], env)
        for host, _c, _m in mounts(tokens):
            self.assertNotIn("1.31.0", os.path.basename(host))

    def test_html_does_not_swallow_the_next_flag(self):
        """--html takes an OPTIONAL argument (nargs='?'). Consuming `--summary`
        here would leave the chart unmounted and the run analyzing $PWD."""
        _, env, _ = fresh_env()
        ns = argparse_says(["--html", "--summary", FIXTURE])
        self.assertEqual(os.path.realpath(ns.directory), os.path.realpath(FIXTURE))
        _, tokens = dry_run(["--html", "--summary", FIXTURE], env)
        hosts = [os.path.realpath(m[0]) for m in mounts(tokens)]
        self.assertIn(os.path.realpath(FIXTURE), hosts)

    def test_user_argv_survives_as_a_prefix(self):
        """The wrapper may append `-o <path>`; it may not rewrite or reorder
        anything the user typed."""
        _, env, _ = fresh_env()
        for argv in self.MATRIX:
            with self.subTest(argv=" ".join(argv)):
                _, tokens = dry_run(argv, env)
                passed = tail_after_image(tokens)
                self.assertEqual(passed[:len(argv)], list(argv))
                extra = passed[len(argv):]
                self.assertIn(len(extra), (0, 2), f"unexpected tail: {extra}")
                if extra:
                    self.assertEqual(extra[0], "-o")


@unittest.skipUnless(_have_bash(), "bash is not available")
@unittest.skipUnless(os.path.exists(WRAPPER), "bin/hpa-analyzer is not present")
class TestOutputDirectory(unittest.TestCase):

    def test_default_output_is_relocated(self):
        _, env, out = fresh_env()
        _, tokens = dry_run([FIXTURE], env)
        passed = tail_after_image(tokens)
        self.assertEqual(passed[-2], "-o")
        self.assertTrue(passed[-1].startswith(os.path.realpath(out)),
                        passed[-1])

    def test_explicit_output_is_never_touched(self):
        """This is the whole 'all the flags still work' promise. An -o the user
        typed must reach the tool unchanged, and no second -o may follow it."""
        _, env, _ = fresh_env()
        for argv in ([FIXTURE, "-o", "/tmp/hpa-t/explicit.txt"],
                     [FIXTURE, "-o/tmp/hpa-t/short.txt"],
                     [FIXTURE, "--output=/tmp/hpa-t/eq.txt"]):
            with self.subTest(argv=" ".join(argv)):
                _, tokens = dry_run(argv, env)
                self.assertEqual(tail_after_image(tokens), list(argv))

    def test_env_beats_config_file(self):
        d, env, _ = fresh_env()
        cfg_dir = os.path.join(env["XDG_CONFIG_HOME"], "hpa-analyzer")
        os.makedirs(cfg_dir, exist_ok=True)
        losing = os.path.join(d, "from-config")
        os.makedirs(losing, exist_ok=True)
        with open(os.path.join(cfg_dir, "config"), "w") as f:
            f.write('HPA_ANALYZER_OUTPUT_DIR="%s"\n' % losing)
        _, tokens = dry_run([FIXTURE], env)
        self.assertNotIn(losing, tail_after_image(tokens)[-1])

    def test_config_file_is_parsed_and_not_sourced(self):
        """A config file is a dotfile. Sourcing one promotes a typo into
        arbitrary code execution, so the wrapper reads it with sed."""
        d, env, _ = fresh_env()
        del env["HPA_ANALYZER_OUTPUT_DIR"]
        cfg_dir = os.path.join(env["XDG_CONFIG_HOME"], "hpa-analyzer")
        os.makedirs(cfg_dir, exist_ok=True)
        canary = os.path.join(d, "canary")
        chosen = os.path.join(d, "chosen")
        os.makedirs(chosen, exist_ok=True)
        with open(os.path.join(cfg_dir, "config"), "w") as f:
            f.write("touch %s\n" % canary)
            f.write('HPA_ANALYZER_OUTPUT_DIR="%s"\n' % chosen)
        _, tokens = dry_run([FIXTURE], env)
        self.assertFalse(os.path.exists(canary),
                         "the config file was executed, not parsed")
        self.assertIn(chosen, tail_after_image(tokens)[-1])

    def test_no_terminal_does_not_block(self):
        """CI has no /dev/tty. A wrapper that waits for an answer there breaks
        every gate this tool exists to provide. stdin is DEVNULL in dry_run(),
        and the 30s timeout is the assertion."""
        d, env, _ = fresh_env()
        del env["HPA_ANALYZER_OUTPUT_DIR"]
        p, tokens = dry_run([FIXTURE], env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("no terminal", p.stderr)
        cfg = os.path.join(env["XDG_CONFIG_HOME"], "hpa-analyzer", "config")
        self.assertFalse(os.path.exists(cfg),
                         "a non-interactive run saved a choice nobody made")


@unittest.skipUnless(_have_bash(), "bash is not available")
@unittest.skipUnless(os.path.exists(WRAPPER), "bin/hpa-analyzer is not present")
class TestMounts(unittest.TestCase):

    def test_host_paths_are_mounted_at_their_own_paths(self):
        """The report prints absolute paths. Mounting the chart at /work would
        make its own text wrong for anyone who pastes a path out of it."""
        _, env, _ = fresh_env()
        _, tokens = dry_run([FIXTURE], env)
        for host, container, _mode in mounts(tokens):
            self.assertEqual(host, container)

    def test_the_chart_is_read_only_and_the_output_dir_is_not(self):
        _, env, out = fresh_env()
        _, tokens = dry_run([FIXTURE], env)
        by_path = {os.path.realpath(h): m for h, _c, m in mounts(tokens)}
        self.assertEqual(by_path.get(os.path.realpath(FIXTURE)), "ro")
        self.assertEqual(by_path.get(os.path.realpath(out)), "rw")

    def test_mounts_are_deduplicated(self):
        """docker refuses two mounts at the same target, so a chart that IS the
        working directory must not be mounted twice."""
        _, env, _ = fresh_env()
        _, tokens = dry_run(["."], env, cwd=FIXTURE)
        targets = [c for _h, c, _m in mounts(tokens)]
        self.assertEqual(len(targets), len(set(targets)), targets)

    def test_help_and_version_mount_nothing(self):
        """Being asked where to save reports because you typed --version would
        be absurd; so would mounting a filesystem to print a version string."""
        _, env, _ = fresh_env()
        for argv in (["--help"], ["-h"], ["--version"], []):
            with self.subTest(argv=argv):
                p, tokens = dry_run(argv, env)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(mounts(tokens), [])
                self.assertNotIn("-o", tail_after_image(tokens))

    def test_no_arguments_is_not_turned_into_help(self):
        """`python3 -m hpaanalyzer` with an empty argv is a usage error that
        exits 2. A wrapper that answers it with help text and exit 0 has turned
        a red build green."""
        _, env, _ = fresh_env()
        _, tokens = dry_run([], env)
        self.assertEqual(tail_after_image(tokens), [])

    def test_a_bad_directory_is_passed_through_not_intercepted(self):
        """The analyzer reports this precisely and exits 2. A tidier message
        from the shell would report a different failure with a different code
        for the same input."""
        _, env, _ = fresh_env()
        p, tokens = dry_run(["/nonexistent-chart-dir-xyz"], env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(tail_after_image(tokens), ["/nonexistent-chart-dir-xyz"])


if __name__ == "__main__":
    unittest.main()

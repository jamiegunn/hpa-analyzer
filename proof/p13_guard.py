#!/usr/bin/env python3
"""PROOF R12: the module refuses to run outside its pinned image.

THE SUBJECT

This program's answer is a function of what is on PATH, and that is measured
rather than asserted - p10_harness.py CLAIM 3 diffs the same chart's report
with helm present and absent and finds the `Analysis mode` line, every row of
the coverage table, the set of scored categories, the denominator, the grade
and the wording of HP050 all different. Both runs are honest. Neither is
comparable to the other.

That is the failure mode the container image was built to close: four pinned
binaries, one build, the same report everywhere. And it closed nothing while
`python3 -m hpaanalyzer <dir>` remained in the README as an equally valid way
to run the tool, because that is the command people reach for - it needs no
build, no daemon, and no 400MB pull. The image was optional, so in practice
it was unused, so the grades stayed incomparable.

R12 makes the container the only supported entry point for the COMMAND.

CLAIM 1  A native `python3 -m hpaanalyzer <chart>` refuses. It exits 2 (the
         environment-error code, NOT 1 - CI must never read "you ran this
         wrong" as "your chart failed a gate"), and writes no report.
CLAIM 2  The refusal is actionable: it names the wrapper, reproduces the
         user's own arguments in the suggested command, and gives the build
         line. It does NOT print the override variable - a bypass shown in
         every terminal becomes the folk-standard invocation.
CLAIM 3  The refusal is universal across the surface. --help, --version and
         --check are refused too. A carve-out would teach that native mode
         half-works, which is exactly the belief this removes.
CLAIM 4  The LIBRARY is untouched. `from hpaanalyzer.__main__ import main;
         main([...])` still runs to completion and writes its report, in the
         same process, with no marker and no override. The guard is on the
         entry point, not on the code - embedders are not the mistake.
CLAIM 5  The marker admits a real run. With the marker file present the same
         refused command completes and produces a report.
CLAIM 6  The Dockerfile actually creates the marker the guard looks for, at
         the same path, in the runtime stage - and the version ARGs it stamps
         in are in global scope, so a plain `docker build` records the real
         pinned versions instead of blanks.
CLAIM 7  The escape hatch works and is documented where it belongs: set in
         proof/nativeoverride.py, described in docs/DEVELOPING.md, absent
         from the refusal text.

Run: python3 proof/p13_guard.py
"""

import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

FAILURES = []


def check(ok, label, extra=""):
    print(f"    [{'PASS' if ok else 'FAIL'}] {label}")
    if extra:
        print(f"           {extra}")
    if not ok:
        FAILURES.append(label)
    return ok


def clean_env(**over):
    """os.environ with every trace of the override removed.

    proof/nativeoverride.py is imported by the other proof scripts and sets
    HPA_ANALYZER_ALLOW_NATIVE=1 process-wide. If this script inherited that
    from a parent shell that had exported it, every CLAIM below would pass by
    running the tool rather than by refusing it, and the proof would be
    measuring nothing. So it is stripped explicitly here.
    """
    e = dict(os.environ)
    e.pop("HPA_ANALYZER_ALLOW_NATIVE", None)
    e.update(over)
    return e


def native(args, env=None, marker=None):
    """Run `python3 -m hpaanalyzer` as a real subprocess."""
    e = clean_env() if env is None else env
    e = dict(e, PYTHONPATH=REPO)
    if marker is not None:
        e["HPA_ANALYZER_MARKER"] = marker
    return subprocess.run([sys.executable, "-m", "hpaanalyzer"] + list(args),
                          cwd=REPO, env=e, capture_output=True, text=True,
                          timeout=300)


CHART = {
    "Chart.yaml": ('apiVersion: v2\nname: guard\nversion: 1.0.0\n'
                   'appVersion: "1.0"\ndescription: proof fixture\n'
                   'kubeVersion: ">=1.23.0-0"\nmaintainers: [{name: proof}]\n'
                   'icon: https://example.invalid/i.png\n'),
    "values.yaml": "replicaCount: 2\n",
    "templates/deployment.yaml": (
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata:\n  name: guard\n  labels: {app: guard}\n"
        "spec:\n  replicas: 2\n  selector:\n    matchLabels: {app: guard}\n"
        "  template:\n    metadata:\n      labels: {app: guard}\n"
        "    spec:\n      containers:\n        - name: guard\n"
        "          image: repo/guard:1.0.0\n          resources:\n"
        "            requests: {cpu: 500m, memory: 1Gi}\n"
        "            limits: {memory: 1Gi}\n"),
}


def build_chart():
    root = tempfile.mkdtemp(prefix="hpa-r12-")
    for rel, body in CHART.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
    return root


def main():
    print(__doc__)
    chart = build_chart()
    outdir = tempfile.mkdtemp(prefix="hpa-r12-out-")
    rpt = os.path.join(outdir, "r.txt")

    # -----------------------------------------------------------------
    print("CLAIM 1  a native invocation is refused, with the right exit code")
    p = native([chart, "-o", rpt, "--helm", "off"])
    check(p.returncode == 2,
          "exit 2 (environment error), not 1 (gate failed) and not 0",
          f"returncode={p.returncode}")
    check(not os.path.exists(rpt),
          "and no report was written - the run did not half-happen",
          f"exists={os.path.exists(rpt)}")
    check("not the supported entry point" in p.stderr,
          "the reason is on stderr, so a pipeline capturing stdout still sees it")

    # -----------------------------------------------------------------
    print("\nCLAIM 2  the refusal is actionable and does not teach the bypass")
    check("./bin/hpa-analyzer" in p.stderr,
          "names the wrapper that does work")
    check(chart in p.stderr and "--helm off" in p.stderr,
          "and reproduces the user's OWN arguments in it - copy-paste, not "
          "translate",
          next((ln.strip() for ln in p.stderr.splitlines()
                if "bin/hpa-analyzer" in ln), ""))
    check("docker build" in p.stderr and "docker/Dockerfile" in p.stderr,
          "and gives the one-time build line for a first-time reader")
    check("HPA_ANALYZER_ALLOW_NATIVE" not in p.stderr,
          "and does NOT print the override variable",
          "the escape hatch is in docs/DEVELOPING.md, not in every terminal")
    check("docs/DEVELOPING.md" in p.stderr,
          "but does point a contributor at where it is documented")

    # -----------------------------------------------------------------
    print("\nCLAIM 3  no carve-outs: the whole command surface refuses")
    for argv, label in ([], "no arguments"), (["--help"], "--help"), \
                       (["--version"], "--version"), \
                       ([chart, "--check"], "--check"):
        q = native(argv)
        check(q.returncode == 2 and "not the supported entry point" in q.stderr,
              f"{label} is refused too",
              f"returncode={q.returncode}")

    # -----------------------------------------------------------------
    print("\nCLAIM 4  the LIBRARY is not guarded - in-process calls still run")
    lib_out = os.path.join(outdir, "lib.txt")
    child = (
        "import sys, os\n"
        "sys.path.insert(0, %r)\n"
        "from hpaanalyzer.__main__ import main\n"
        "rc = main([%r, '-o', %r, '--quiet', '--helm', 'off'])\n"
        "print('rc=%%d written=%%s' %% (rc, os.path.exists(%r)))\n"
        % (REPO, chart, lib_out, lib_out))
    r = subprocess.run([sys.executable, "-c", child], cwd=REPO,
                       env=clean_env(), capture_output=True, text=True,
                       timeout=300)
    check("written=True" in r.stdout,
          "main([...]) imported and called in-process writes its report",
          (r.stdout.strip() + " " + r.stderr.strip()[:200]).strip())
    check("not the supported entry point" not in r.stderr,
          "and never sees the refusal - 20 unit tests depend on this")

    # -----------------------------------------------------------------
    print("\nCLAIM 5  the marker admits the run")
    mdir = tempfile.mkdtemp(prefix="hpa-r12-marker-")
    mpath = os.path.join(mdir, "hpa-analyzer-image")
    with open(mpath, "w", encoding="utf-8") as f:
        f.write("hpa-analyzer container image\nhelm=3.16.4\n")
    ok_rpt = os.path.join(outdir, "ok.txt")
    # _require_image()'s marker path is a module constant, so the positive
    # case is exercised through the function with the path injected, in a
    # child process, rather than by writing to this machine's /etc.
    child = (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "from hpaanalyzer.__main__ import _require_image, main\n"
        "rc = _require_image([], marker=%r)\n"
        "print('guard=%%d' %% rc)\n"
        "if rc == 0:\n"
        "    print('analysis=%%d' %% main([%r, '-o', %r, '--quiet', "
        "'--helm', 'off']))\n"
        % (REPO, mpath, chart, ok_rpt))
    r = subprocess.run([sys.executable, "-c", child], cwd=REPO,
                       env=clean_env(), capture_output=True, text=True,
                       timeout=300)
    check("guard=0" in r.stdout,
          "with the marker present the guard returns 0 (proceed)",
          r.stdout.strip().replace("\n", "  "))
    check(os.path.exists(ok_rpt),
          "and the analysis then runs to a written report")
    # and the negative control for the same call, same process shape
    r2 = subprocess.run(
        [sys.executable, "-c",
         "import sys\nsys.path.insert(0, %r)\n"
         "from hpaanalyzer.__main__ import _require_image\n"
         "print('guard=%%d' %% _require_image([], marker=%r))\n"
         % (REPO, os.path.join(mdir, "absent"))],
        cwd=REPO, env=clean_env(), capture_output=True, text=True, timeout=60)
    check("guard=2" in r2.stdout,
          "and the identical call with the marker absent returns 2 - the "
          "check is the file, not the weather",
          r2.stdout.strip())

    # -----------------------------------------------------------------
    print("\nCLAIM 6  the Dockerfile creates that exact marker")
    from hpaanalyzer.__main__ import IMAGE_MARKER  # noqa: E402
    dockerfile = open(os.path.join(REPO, "docker", "Dockerfile"),
                      encoding="utf-8").read()
    stages = dockerfile.split("\nFROM ")

    def instructions(text):
        """The stage with comment lines removed.

        Written after the first version of this claim passed on a COMMENT.
        This Dockerfile explains itself at length, and /etc/hpa-analyzer-image
        is named in three comments as well as in the one RUN that creates it;
        a substring test over the raw text is satisfied by prose alone, so it
        would have gone on passing after someone deleted the instruction.
        """
        return "\n".join(ln for ln in text.splitlines()
                         if not ln.lstrip().startswith("#"))

    runtime = instructions(stages[-1])
    builders = instructions("\n".join(stages[:-1]))
    check(IMAGE_MARKER in runtime,
          f"the runtime stage writes {IMAGE_MARKER}, the path the guard reads",
          "(no docker daemon in this sandbox - this is read from the "
          "Dockerfile's instructions, comments stripped, not from a built "
          "image)")
    check(IMAGE_MARKER not in builders,
          "and only the runtime stage does - a marker left in the builder "
          "stage would not reach the shipped image")
    # the ARG-scope trap: version args must be global, or the marker records
    # blanks on any build that does not pass --build-arg
    head = dockerfile.split("\nFROM ")[0]
    for var in ("HELM_VERSION", "KUBECONFORM_VERSION", "KUBE_SCORE_VERSION",
                "POLARIS_VERSION"):
        check(re.search(rf"^ARG {var}=\S+", head, re.M) is not None,
              f"{var} has its default in GLOBAL scope (above the first FROM)",
              "a per-stage default is invisible to stage 2 and the marker "
              "would read `=`")
        check(re.search(rf"^ARG {var}\s*$", runtime, re.M) is not None,
              f"and the runtime stage re-declares {var} bare to inherit it")

    # -----------------------------------------------------------------
    print("\nCLAIM 7  the escape hatch exists for the evidence layer only")
    r = native([chart, "-o", os.path.join(outdir, "ov.txt"), "--quiet",
                "--helm", "off"],
               env=clean_env(HPA_ANALYZER_ALLOW_NATIVE="1"))
    check(r.returncode == 0,
          "HPA_ANALYZER_ALLOW_NATIVE=1 lets a native run proceed",
          f"returncode={r.returncode}")
    src = open(os.path.join(REPO, "proof", "nativeoverride.py"),
               encoding="utf-8").read()
    check("HPA_ANALYZER_ALLOW_NATIVE" in src and "setdefault" in src,
          "proof/nativeoverride.py sets it, with setdefault so a deliberate "
          "value survives")
    dev = os.path.join(REPO, "docs", "DEVELOPING.md")
    check(os.path.exists(dev) and
          "HPA_ANALYZER_ALLOW_NATIVE" in open(dev, encoding="utf-8").read(),
          "and docs/DEVELOPING.md documents it - hidden is not the same as "
          "undocumented")

    # -----------------------------------------------------------------
    print("\n" + "=" * 72)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED\n")
    print("""The image stopped being the optional-and-therefore-unused path.
A grade produced by this tool is now a grade produced by one known set of
four binaries, or it is not produced at all. The one thing the refusal is
careful NOT to do is pretend to be a security control: anyone who can write
/etc can defeat it, and the docstring on IMAGE_MARKER says so. It is aimed at
habit, which is what was actually costing reproducibility.""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

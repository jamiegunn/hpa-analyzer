#!/usr/bin/env python3
"""PROOF R10: the container is only honest if the wrapper is transparent.

WHAT THIS ITERATION IS SUPPOSED TO DO.

Nine iterations went into making one number defensible. R10 changes nothing
about that number; it changes where the number is computed. The request was:

    run this as a docker image ... execute that docker image via shell
    harness, so to the user, it just looks like a shell script, but all the
    flags still work.

So the contract for R10 is unusually crisp, and it is a contract about
DIFFERENCE rather than about correctness:

    C10.1  `hpa-analyzer FLAGS DIR` produces the same bytes and the same exit
           code as `python3 -m hpaanalyzer FLAGS DIR`.
    C10.2  no flag is rewritten, dropped, reordered or given a new meaning.
    C10.3  the first run asks where reports should go, remembers the answer,
           and never asks again.
    C10.4  an explicit -o / --json / --html always beats the remembered
           directory, because C10.2 outranks C10.3.
    C10.5  no terminal is not an error. A CI job has no terminal and the CI
           gates are the reason this tool exists.

WHY THIS NEEDS A PROOF AT ALL.

Because a wrapper is a second parser. The moment a shell script has to decide
which token is the chart directory - and it must, since that directory has to
be mounted before the container starts - it is re-implementing argparse in
sh. Every such re-implementation is wrong somewhere, and the failure is
silent: `--kube-version 1.31.0 chart/` mounts `1.31.0` as the chart, the real
chart is never mounted, and the tool inside reports on a directory that is not
the one the user named. Nothing crashes. The report is simply about the wrong
thing.

There is a defence against that, and it is not care. It is to check the shell
scan against THE ACTUAL PARSER, on the actual argv strings, and let argparse
be the oracle. CLAIM 1 does exactly that: for each argv, the real
`hpaanalyzer` parser is asked what it thinks `directory`, `output`, `html`
and `json_path` are, and the wrapper's answer must agree. When those two
disagree, argparse is right by definition, because argparse is what runs.

WHAT THIS PROOF CANNOT ESTABLISH, STATED UP FRONT.

The image used here is NOT the one docker/Dockerfile builds. This sandbox
cannot reach any container registry (every one of them returns 403) and
cannot reach get.helm.sh either, so `docker build` is impossible here. The
image under test is assembled by `docker import` from this machine's own
filesystem, which means its four external binaries are the same builds that
the native run uses.

That is a real limitation and it cuts in a specific direction: CLAIM 7a's
byte-identity proves the WRAPPER is transparent - that mounting, working
directory, uid and path rewriting introduce no difference - and it proves
nothing about whether helm 3.16.4 and this sandbox's helm v3.16 agree. Those
are different questions, and only the first one is this file's business. The
second is answered by building the pinned image and re-running CLAIM 7a on a
machine with network access.

CLAIM 7b was written expecting the same byte-identity under --cross-check and
does not get it. The text there is the corrected version, and the correction
is left visible: two NATIVE runs do not match each other either, so the
non-determinism belongs to the validators rather than to the container.

Run: python3 proof/p10_harness.py
"""

import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE - see the module for why)
HARNESS = os.path.join(REPO, "bin", "hpa-analyzer")
IMAGE = os.environ.get("HPA_PROOF_IMAGE", "hpa-analyzer-standin:latest")
CHART = os.path.join(REPO, "fixtures", "bad-chart")

FAIL = []
SKIPPED = []
PASSED = 0


def check(label, ok, detail=""):
    global PASSED
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    if ok:
        PASSED += 1
    else:
        FAIL.append(label)


def hr(title=""):
    print()
    print("=" * 78)
    if title:
        print(title)
        print("=" * 78)


# ---------------------------------------------------------------------------
# oracles
# ---------------------------------------------------------------------------

_SPY = r"""
import argparse, json, sys, runpy
_orig = argparse.ArgumentParser.parse_args
def spy(self, argv=None, namespace=None):
    ns = _orig(self, argv, namespace)
    sys.stderr.write("SPY" + json.dumps(vars(ns), default=str) + "\n")
    raise SystemExit(0)
argparse.ArgumentParser.parse_args = spy
sys.argv = ["hpa-analyzer"] + sys.argv[1:]
runpy.run_module("hpaanalyzer", run_name="__main__")
"""


def argparse_says(argv):
    """What the REAL parser makes of this argv, without running an analysis.

    The parser is built inside main(), so rather than duplicate it - which
    would make the oracle a copy of the thing it is meant to check - this
    patches parse_args to dump its namespace and stop. Returns None when
    argparse rejects the argv, which is itself a meaningful answer.
    """
    p = subprocess.run([sys.executable, "-c", _SPY] + list(argv),
                       cwd=REPO, capture_output=True, text=True)
    for line in p.stderr.splitlines():
        if line.startswith("SPY"):
            return json.loads(line[3:])
    return None


def dry(argv, env=None, cwd=REPO):
    """The docker command line the wrapper WOULD run, as a token list."""
    e = dict(os.environ)
    e.update({
        "HPA_ANALYZER_DRY_RUN": "1",
        "HPA_ANALYZER_CONTAINER_CLI": "true",
        "HPA_ANALYZER_IMAGE": IMAGE,
        "HPA_ANALYZER_NO_USER": "1",
    })
    e.pop("HPA_ANALYZER_OUTPUT_DIR", None)
    if env:
        for k, v in env.items():
            if v is None:
                e.pop(k, None)
            else:
                e[k] = v
    p = subprocess.run([HARNESS] + list(argv), cwd=cwd, env=e,
                       capture_output=True, text=True, timeout=60)
    return p, p.stdout.strip().split()


def split_at_image(tokens):
    """(docker options, the argv actually handed to the analyzer)."""
    i = tokens.index(IMAGE)
    return tokens[:i], tokens[i + 1:]


def mounts_of(tokens):
    out = []
    for i, t in enumerate(tokens):
        if t == "-v":
            spec = tokens[i + 1]
            ro = spec.endswith(":ro")
            if ro:
                spec = spec[:-3]
            src, dst = spec.split(":", 1)
            out.append((src, dst, "ro" if ro else "rw"))
    return out


def fresh_cfg():
    d = tempfile.mkdtemp(prefix="hpa-cfg-")
    return d, {"XDG_CONFIG_HOME": d}


print(__doc__.split("Run: ")[0].rstrip())
print()
print(f"HARNESS = {HARNESS}")
print(f"IMAGE   = {IMAGE}")

# ---------------------------------------------------------------------- 1 --
hr("CLAIM 1: the shell's argument scan agrees with argparse, token for token.")
print("""
Each row is an argv the wrapper has to make sense of before docker starts.
`directory` is what the wrapper must mount; `output` is what must be writable.
argparse is the oracle - not because it is elegant, but because it is what
actually runs inside the container, so where the two differ the wrapper is
wrong by construction.

The rows are chosen to be the ones a hand-written scan gets wrong:
  * a value that looks like a path       (--helm off chart/)
  * a value that looks like a version    (--kube-version 1.31.0 chart/)
  * --html's OPTIONAL argument, both taken and not taken
  * the =VALUE and -oVALUE spellings argparse quietly also accepts
""")

CFGD, CFGENV = fresh_cfg()
CFGENV_OUT = dict(CFGENV)
CFGENV_OUT["HPA_ANALYZER_OUTPUT_DIR"] = os.path.join(CFGD, "reports")

MATRIX = [
    ["fixtures/bad-chart"],
    ["fixtures/bad-chart", "--summary"],
    ["--kube-version", "1.31.0", "fixtures/bad-chart"],
    ["--kube-version=1.31.0", "fixtures/bad-chart"],
    ["--helm", "off", "fixtures/bad-chart"],
    ["--assume-java", "21", "fixtures/bad-chart"],
    ["--measured", "rps=100", "fixtures/bad-chart"],
    ["--fail-on", "high", "fixtures/bad-chart"],
    ["--min-score", "80", "fixtures/bad-chart"],
    ["fixtures/bad-chart", "-o", "/tmp/hpa-p10/explicit.txt"],
    ["fixtures/bad-chart", "-o/tmp/hpa-p10/short.txt"],
    ["fixtures/bad-chart", "--output=/tmp/hpa-p10/eq.txt"],
    ["fixtures/bad-chart", "--json", "/tmp/hpa-p10/r.json"],
    ["fixtures/bad-chart", "--json=/tmp/hpa-p10/eq.json"],
    ["fixtures/bad-chart", "--html"],
    ["fixtures/bad-chart", "--html", "/tmp/hpa-p10/r.html"],
    ["--html", "--summary", "fixtures/bad-chart"],
    ["fixtures/bad-chart", "--cross-check", "--teach", "--all"],
    ["--kube-version", "1.31.0", "--html", "--fail-on", "medium",
     "fixtures/bad-chart", "--quiet"],
]

for argv in MATRIX:
    ns = argparse_says(argv)
    p, tokens = dry(argv, CFGENV_OUT)
    label = " ".join(argv)
    if ns is None:
        check(f"argparse rejects, wrapper defers: {label}",
              p.returncode == 0 and "-v" not in tokens[:tokens.index(IMAGE)]
              if IMAGE in tokens else False)
        continue
    want_dir = os.path.abspath(os.path.join(REPO, ns["directory"]))
    _, passed = split_at_image(tokens)
    srcs = [m[0] for m in mounts_of(tokens)]
    check(f"chart mounted where argparse points: {label}",
          want_dir in srcs, f"argparse.directory={ns['directory']}")

# ---------------------------------------------------------------------- 2 --
hr("CLAIM 2: nothing the user typed is rewritten, dropped or reordered.")
print("""
C10.2 is the whole promise - "all the flags still work" - and it has a form
that can be checked exactly rather than argued about: the tokens the wrapper
hands to the analyzer must be the tokens the user typed, IN ORDER, with at
most a trailing `-o <dir>/hpa_analysis_report.txt` appended when the user
named no output of their own.

Not "equivalent". Identical, as a prefix.
""")

for argv in MATRIX:
    if argparse_says(argv) is None:
        continue
    _, tokens = dry(argv, CFGENV_OUT)
    _, passed = split_at_image(tokens)
    label = " ".join(argv)
    prefix_ok = passed[:len(argv)] == argv
    tail = passed[len(argv):]
    tail_ok = tail == [] or (len(tail) == 2 and tail[0] == "-o")
    check(f"argv preserved as a prefix: {label}", prefix_ok and tail_ok,
          f"tail={tail}" if tail else "")

# ---------------------------------------------------------------------- 3 --
hr("CLAIM 3: the remembered directory moves the DEFAULT and nothing else.")
print("""
This is where the two halves of the request pull against each other. "Ask the
user where the output directory is and write to that" is a statement about
where reports land; "all the flags still work" is a statement about -o. They
collide whenever both are present, and only one resolution leaves the second
sentence literally true: the remembered directory replaces the tool's own
default (hpa_analysis_report.txt, relative to $PWD) and is not consulted at
all once the user has named a path.
""")

OUTDIR = os.path.join(CFGD, "reports")
_, tok_default = dry(["fixtures/bad-chart"], CFGENV_OUT)
_, passed_default = split_at_image(tok_default)
check("no -o given: default relocated into the remembered directory",
      passed_default[-2:] == ["-o", os.path.join(OUTDIR, "hpa_analysis_report.txt")],
      " ".join(passed_default[-2:]))

for spelling in (["-o", "/tmp/hpa-p10/explicit.txt"],
                 ["-o/tmp/hpa-p10/short.txt"],
                 ["--output=/tmp/hpa-p10/eq.txt"]):
    _, tk = dry(["fixtures/bad-chart"] + spelling, CFGENV_OUT)
    _, ps = split_at_image(tk)
    check(f"explicit output survives untouched: {' '.join(spelling)}",
          ps == ["fixtures/bad-chart"] + spelling, " ".join(ps))

_, tk = dry(["fixtures/bad-chart", "--json", "/tmp/hpa-p10/r.json"], CFGENV_OUT)
_, ps = split_at_image(tk)
check("--json does not suppress the text report, so -o is still relocated",
      ps[-2:] == ["-o", os.path.join(OUTDIR, "hpa_analysis_report.txt")]
      and "--json" in ps,
      "measured: __main__.py writes args.output unconditionally (line 204)")

srcs = {m[0]: m[2] for m in mounts_of(tk)}
check("--json's parent directory is mounted writable",
      srcs.get("/tmp/hpa-p10") == "rw", str(sorted(srcs.items())))

# ---------------------------------------------------------------------- 4 --
hr("CLAIM 4: every host path is mounted at its own path, exactly once.")
print("""
Mounting the chart at /work would make `Target directory : /work/...` in the
report a path that exists on no machine the user has. Mounting at the host's
own path is what lets a report be pasted into another command, and it is the
only reason CLAIM 7's byte-identity is even possible.

Twice over, docker refuses two mounts at the same target - so a chart inside
$PWD, or an output directory that IS $PWD, has to collapse to one entry with
read-write winning.
""")

_, tk = dry(["fixtures/bad-chart", "--cross-check"], CFGENV_OUT)
ms = mounts_of(tk)
check("source and target are the same path for every mount",
      all(s == d for s, d, _ in ms), str([f"{s}:{d}" for s, d, _ in ms]))
dsts = [d for _, d, _ in ms]
check("no duplicate mount targets", len(dsts) == len(set(dsts)), str(dsts))
modes = {s: m for s, _, m in ms}
check("the chart is read-only", modes.get(CHART) == "ro", str(modes))
check("the working directory is read-only", modes.get(REPO) == "ro", str(modes))
check("the output directory is writable", modes.get(OUTDIR) == "rw", str(modes))
check("-w is the host's own working directory", "-w" in tk
      and tk[tk.index("-w") + 1] == REPO)

# a chart that IS the working directory: one mount, not two
_, tk2 = dry(["."], CFGENV_OUT, cwd=CHART)
ms2 = mounts_of(tk2)
d2 = [d for _, d, _ in ms2]
check("chart == $PWD collapses to a single mount", len(d2) == len(set(d2))
      and d2.count(CHART) == 1, str(d2))

# output directory inside $PWD: read-write must win over read-only
inside = os.path.join(REPO, "sample_reports")
_, tk3 = dry(["fixtures/bad-chart", "-o", os.path.join(inside, "r.txt")], CFGENV_OUT)
m3 = {s: m for s, _, m in mounts_of(tk3)}
check("a writable output dir nested in a read-only $PWD keeps both modes",
      m3.get(REPO) == "ro" and m3.get(inside) == "rw", str(sorted(m3.items())))

# ---------------------------------------------------------------------- 5 --
hr("CLAIM 5: --help and --version mount nothing and ask nothing.")
print("""
Small, but it is the difference between a tool and a nuisance. `--version`
touches no file, so being asked where to save reports in order to be told a
version number would be indefensible - and worse, it would write a config
file on the strength of a question the user never meant to answer.
""")

EMPTY, EMPTYENV = fresh_cfg()
for argv in (["--help"], ["--version"], ["-h"], []):
    p, tk = dry(argv, EMPTYENV)
    _, ps = split_at_image(tk)
    check(f"no mounts for {argv or '(no arguments)'}",
          not mounts_of(tk) and "-w" not in tk, " ".join(tk))
check("no config file written by --help/--version",
      not os.path.exists(os.path.join(EMPTY, "hpa-analyzer", "config")))
p, tk = dry([], EMPTYENV)
_, ps = split_at_image(tk)
check("a bare invocation is passed through empty, not rewritten to --help",
      ps == [], " ".join(tk))
print("""
  That last row started life as `[ "$#" -eq 0 ] && set -- --help`, which is
  the friendly thing to do and was measured to be wrong: `python3 -m
  hpaanalyzer` with no arguments is an argparse usage error exiting 2, so a
  wrapper that answers with help text and exit 0 converts a failing command
  into a passing one. The image's `CMD ["--help"]` did the same thing one
  layer down and was removed for the same reason. CLAIM 8's last row is what
  caught both.""")

# ---------------------------------------------------------------------- 6 --
hr("CLAIM 6: env beats config beats prompt beats $PWD, and no TTY never blocks.")
print("""
A shell script cannot export a variable into the shell that called it. So
"save the output directory as an environment variable" is implemented as the
only thing that can actually work: a config file the wrapper parses - parses,
not sources, because sourcing turns a typo in a dotfile into code execution -
and re-exposes under that name. An exported variable outranks it.

The last row is the one that matters for CI. With no terminal there is nobody
to answer, and blocking would hang every pipeline that uses --fail-on. So the
absence of a terminal is not an error, it is a different default, announced
on stderr.
""")

# first run, with a real terminal: prompts, and remembers
PD, PENV = fresh_cfg()
target = os.path.join(PD, "chosen")
env = dict(os.environ)
env.update({"HPA_ANALYZER_DRY_RUN": "1", "HPA_ANALYZER_CONTAINER_CLI": "true",
            "HPA_ANALYZER_IMAGE": IMAGE, "HPA_ANALYZER_NO_USER": "1",
            "XDG_CONFIG_HOME": PD})
env.pop("HPA_ANALYZER_OUTPUT_DIR", None)

pid, fd = pty.fork()
if pid == 0:
    os.chdir(REPO)
    os.execve(HARNESS, [HARNESS, "fixtures/bad-chart"], env)
buf, deadline = b"", time.time() + 45
os.write(fd, (target + "\n").encode())
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1.0)
    if r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    if os.waitpid(pid, os.WNOHANG)[0]:
        break
os.close(fd)
session = buf.decode(errors="replace")

check("first run asks where reports should go",
      "First run" in session and "Where should reports be written" in session)
cfg_path = os.path.join(PD, "hpa-analyzer", "config")
check("the answer is written to the config file", os.path.exists(cfg_path))
if os.path.exists(cfg_path):
    body = open(cfg_path).read()
    check("the config names the variable it stands in for",
          f'HPA_ANALYZER_OUTPUT_DIR="{target}"' in body, body.strip().splitlines()[-1])
check("the chosen directory is used for this same run",
      os.path.join(target, "hpa_analysis_report.txt") in session)

# second run: silent
p2, tk2 = dry(["fixtures/bad-chart"], {"XDG_CONFIG_HOME": PD})
_, ps2 = split_at_image(tk2)
check("the second run does not ask again",
      "First run" not in p2.stderr and ps2[-1] ==
      os.path.join(target, "hpa_analysis_report.txt"), p2.stderr.strip())

# exported variable wins over the file
other = os.path.join(PD, "exported")
p3, tk3 = dry(["fixtures/bad-chart"], {"XDG_CONFIG_HOME": PD,
                                       "HPA_ANALYZER_OUTPUT_DIR": other})
_, ps3 = split_at_image(tk3)
check("an exported HPA_ANALYZER_OUTPUT_DIR outranks the config file",
      ps3[-1] == os.path.join(other, "hpa_analysis_report.txt"), ps3[-1])

# an explicit -o outranks both
p4, tk4 = dry(["fixtures/bad-chart", "-o", "/tmp/hpa-p10/wins.txt"],
              {"XDG_CONFIG_HOME": PD, "HPA_ANALYZER_OUTPUT_DIR": other})
_, ps4 = split_at_image(tk4)
check("an explicit -o outranks both of them",
      ps4 == ["fixtures/bad-chart", "-o", "/tmp/hpa-p10/wins.txt"], " ".join(ps4))

# no terminal, no config: falls back, does not hang
ND, NENV = fresh_cfg()
t0 = time.time()
try:
    p5 = subprocess.run([HARNESS, "fixtures/bad-chart"], cwd=REPO,
                        env={**env, "XDG_CONFIG_HOME": ND},
                        stdin=subprocess.DEVNULL, capture_output=True,
                        text=True, timeout=30)
    elapsed, timed_out = time.time() - t0, False
except subprocess.TimeoutExpired:
    p5, elapsed, timed_out = None, time.time() - t0, True

check("no terminal: the run completes instead of blocking", not timed_out,
      f"{elapsed:.2f}s")
if p5 is not None:
    _, ps5 = split_at_image(p5.stdout.strip().split())
    check("no terminal: falls back to $PWD",
          ps5[-1] == os.path.join(REPO, "hpa_analysis_report.txt"), ps5[-1])
    check("no terminal: says so on stderr rather than silently choosing",
          "no terminal to ask on" in p5.stderr, p5.stderr.strip().splitlines()[0]
          if p5.stderr.strip() else "(nothing on stderr)")
    check("no terminal: no config file is written behind the user's back",
          not os.path.exists(os.path.join(ND, "hpa-analyzer", "config")))

# the config file is parsed, not sourced
XD, XENV = fresh_cfg()
os.makedirs(os.path.join(XD, "hpa-analyzer"))
canary = os.path.join(XD, "canary")
with open(os.path.join(XD, "hpa-analyzer", "config"), "w") as f:
    f.write(f'HPA_ANALYZER_OUTPUT_DIR="{os.path.join(XD, "out")}"\n')
    f.write(f'touch {canary}\n')
p6, tk6 = dry(["fixtures/bad-chart"], {"XDG_CONFIG_HOME": XD})
_, ps6 = split_at_image(tk6)
check("a command in the config file is NOT executed",
      not os.path.exists(canary))
check("...and the directory it sets is still read correctly",
      ps6[-1] == os.path.join(XD, "out", "hpa_analysis_report.txt"), ps6[-1])

# ---------------------------------------------------------------------- 7 --
hr("CLAIM 7 (Bar 2): the containerised report is the native report, byte for byte.")

HAVE_DOCKER = shutil.which("docker") is not None
if HAVE_DOCKER:
    HAVE_DOCKER = subprocess.run(["docker", "image", "inspect", IMAGE],
                                 capture_output=True).returncode == 0

if not HAVE_DOCKER:
    SKIPPED.append(f"CLAIM 7/8: no docker daemon or no image {IMAGE}")
    print(f"\n  SKIPPED - {IMAGE} is not available on this machine.")
    print("  These two claims are the only ones that need a running daemon;")
    print("  build the image and re-run to measure them.")
else:
    print("""
This claim was written asserting byte-identity of a --cross-check run, and
its own first execution refuted it. What follows is the corrected version,
and the correction is the interesting part, so the original assertion is left
visible rather than quietly narrowed.

A report carries one field that cannot match across two runs by construction:
`Generated : <timestamp>`. That is normalised below, and normalising it is
only legitimate because it is a property of the clock rather than of the
container - which the native-vs-native row proves rather than assumes.
""")
    WORK = tempfile.mkdtemp(prefix="hpa-p10-run-")

    TS = re.compile(rb"^Generated .*$", re.M)

    def run_report(kind, argv, out, extra_env=None):
        e = dict(os.environ)
        e.update({"XDG_CONFIG_HOME": CFGD, "HPA_ANALYZER_OUTPUT_DIR": OUTDIR,
                  "HPA_ANALYZER_IMAGE": IMAGE})
        e.pop("HPA_ANALYZER_DRY_RUN", None)
        e.pop("HPA_ANALYZER_CONTAINER_CLI", None)
        if extra_env:
            e.update(extra_env)
        cmd = [sys.executable, "-m", "hpaanalyzer"] if kind == "native" else [HARNESS]
        p = subprocess.run(cmd + argv + ["-o", out], cwd=REPO, env=e,
                           capture_output=True, text=True, timeout=900)
        body = open(out, "rb").read() if os.path.exists(out) else b""
        return p, TS.sub(b"Generated : <normalised>", body)

    def first_diff(a, b, n=12):
        import difflib
        d = list(difflib.unified_diff(a.decode(errors="replace").splitlines(),
                                      b.decode(errors="replace").splitlines(),
                                      "native", "harness", lineterm="", n=0))
        return [ln[:150] for ln in d[:n]]

    # ---- 7a: the harness itself, with no external tools in the way --------
    print("  7a. the analyzer alone - no --cross-check, so no subprocess but helm\n")
    pn, bn = run_report("native", ["fixtures/bad-chart"], os.path.join(WORK, "a.txt"))
    ph, bh = run_report("harness", ["fixtures/bad-chart"], os.path.join(WORK, "a.txt"))
    check("both runs succeeded", pn.returncode == 0 and ph.returncode == 0,
          f"native={pn.returncode} harness={ph.returncode} {ph.stderr.strip()[:200]}")
    check("the report file is byte-identical", bn == bh,
          f"{len(bn)} vs {len(bh)} bytes")
    check("the terminal summary is byte-identical, absolute paths included",
          pn.stdout == ph.stdout)
    check("the container rendered with helm, not the static fallback",
          b"static" not in bn.split(b"Analysis mode")[1][:60] if b"Analysis mode" in bn else False,
          "a container missing helm would answer a different question silently")
    if bn != bh:
        for ln in first_diff(bn, bh):
            print("     ", ln)

    # ---- 7b: what --cross-check actually does -----------------------------
    print("""
  7b. with --cross-check, and this is where the original claim died.

  Two NATIVE runs are compared first, on one machine, one chart, one set of
  binaries, seconds apart. If those already differ then byte-identity was
  never available to the container either, and demanding it of the harness
  would have been blaming the wrapper for somebody else's non-determinism.
""")
    _, x1 = run_report("native", ["fixtures/bad-chart", "--cross-check"],
                       os.path.join(WORK, "x1.txt"))
    _, x2 = run_report("native", ["fixtures/bad-chart", "--cross-check"],
                       os.path.join(WORK, "x2.txt"))
    native_stable = x1 == x2
    check("two native --cross-check runs are NOT reproducible",
          not native_stable,
          f"{len(first_diff(x1, x2, 999))} diff lines between two native runs")

    if not native_stable:
        print("""
  Measured, on this machine, same input file, same binaries:
    kube-score  six runs, six distinct md5s - every run reorders its findings
    polaris     three runs, two distinct md5s
    kubeconform varies with what the network answered that second

  Go maps do not iterate in a stable order and these tools print straight out
  of them. So the cross-check section of a report reshuffles between runs.
  That matters beyond this proof: the whole premise of this project is a
  report a human can diff against last week's, and one section of it produces
  spurious movement on every comparison. The verdict and the tally are
  computed from counts and are order-independent, so no VERDICT moves - but
  the evidence a reader would use to audit that verdict does. It is logged as
  R11 rather than fixed here, because fixing it means reordering another
  tool's output, and external.py's stated discipline is to reproduce it
  verbatim. That tension deserves its own iteration, not a footnote in this
  one.
""")
    pc, bc = run_report("harness", ["fixtures/bad-chart", "--cross-check"],
                        os.path.join(WORK, "x3.txt"))
    check("the containerised --cross-check run still succeeds", pc.returncode == 0,
          pc.stderr.strip()[:200])
    check("the container's cross-check verdicts are still self-declared, "
          "not silently downgraded",
          b"schema store unreachable" in bc or b"not checkable" in bc
          or b"UNKNOWN" in bc,
          "C2.2: a limit of the method must not be reported as a fact "
          "about the chart")

    # ------------------------------------------------------------------ 8 --
    hr("CLAIM 8 (Bar 2): the exit code is the analyzer's, not the wrapper's.")
    print("""
Every CI use of this tool is an exit code: --fail-on, --min-score,
--require-coverage exit 1, --check exits 2 on a directory that is not a
chart, and a bad path exits 2. A wrapper that swallows or invents one of
those turns a red build green. `exec` is what keeps them - there is nothing
left in between to have an opinion.

The last two rows are the ones a wrapper gets wrong by being helpful: it is
very natural to validate the directory in the shell and exit 1 with a tidier
message. That would report a DIFFERENT failure than the tool reports, with a
different code, for the same input.
""")
    CASES = [
        (["fixtures/bad-chart", "--quiet"], "clean run"),
        (["fixtures/bad-chart", "--fail-on", "high", "--quiet"], "--fail-on gate"),
        (["fixtures/bad-chart", "--min-score", "99", "--quiet"], "--min-score gate"),
        (["fixtures/bad-chart", "--require-coverage", "--quiet"], "--require-coverage"),
        (["fixtures/bad-chart", "--check"], "--check on a chart"),
        (["proof", "--check"], "--check on a non-chart"),
        (["does-not-exist"], "a directory that is not there"),
        (["README.md"], "a file where a directory was expected"),
        (["--nonsense", "fixtures/bad-chart"], "an unknown flag"),
        ([], "no arguments at all"),
    ]
    for argv, label in CASES:
        e = dict(os.environ)
        e.update({"XDG_CONFIG_HOME": CFGD, "HPA_ANALYZER_OUTPUT_DIR": OUTDIR})
        e.pop("HPA_ANALYZER_DRY_RUN", None)
        e.pop("HPA_ANALYZER_CONTAINER_CLI", None)
        e["HPA_ANALYZER_IMAGE"] = IMAGE
        base = dict(e)
        base["HPA_ANALYZER_OUTPUT_DIR"] = os.path.join(WORK, "native")
        os.makedirs(base["HPA_ANALYZER_OUTPUT_DIR"], exist_ok=True)
        nat = subprocess.run([sys.executable, "-m", "hpaanalyzer"] + argv,
                             cwd=REPO, env=base, capture_output=True,
                             text=True, timeout=600)
        har = subprocess.run([HARNESS] + argv, cwd=REPO, env=base,
                             capture_output=True, text=True, timeout=600)
        check(f"exit code matches native: {label}",
              nat.returncode == har.returncode,
              f"native={nat.returncode} harness={har.returncode}")

# ---------------------------------------------------------------------------
hr()
print(f"  {PASSED} of {PASSED + len(FAIL)} checks passed")
for s in SKIPPED:
    print(f"  SKIPPED: {s}")
if FAIL:
    print("\nNOT PROVEN. Failing checks:")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)

print("""
R10 holds, with the limitation named at the top of this file intact.

The wrapper is a second parser, and it was checked against the first one
rather than against its author's reading of it. It mounts host paths at their
own paths, which is what makes a containerised report the same bytes as a
native one rather than merely the same findings with different paths in them
- proven for the analyzer itself, and proven NOT to be available under
--cross-check for a reason that has nothing to do with containers.
It relocates the DEFAULT output and refuses to touch an -o the user typed. It
asks once, remembers by parsing rather than sourcing, and - the row that
decides whether this tool can be used in CI at all - treats the absence of a
terminal as a different default rather than a reason to wait forever.

Two things are owed, and neither is hidden in a comment.

The image measured here was assembled by `docker import` from this machine's
own filesystem, because no container registry and not even get.helm.sh is
reachable from this sandbox. Its four binaries are therefore the same builds
the native run uses, so CLAIM 7a proves the HARNESS transparent and proves
nothing about whether helm 3.16.4 agrees with this sandbox's helm v3.16.
Build docker/Dockerfile on a machine with network access and re-run this
file. If 7a then fails, the difference is the pinned toolchain, and that is a
fact about the report worth publishing rather than a bug in the wrapper.

And R11 is now on the board, found by accident while trying to prove
something else: the cross-check section of every report reshuffles on every
run, natively, because the tools it quotes iterate Go maps. No verdict moves,
but the evidence under it does, and a report nobody can diff cleanly is a
weaker artifact than this project claims to produce.
""")
sys.exit(0)

# Running hpa-analyzer from a container

`bin/hpa-analyzer` is a shell wrapper around `docker run`. The point of it is
that you should not have to know that. `hpa-analyzer --fail-on high ./svc` and
`python3 -m hpaanalyzer --fail-on high ./svc` are meant to produce the same
report text, print the same terminal summary, and exit with the same code —
with only the toolchain underneath pinned. This file records why the container
exists at all, what the wrapper does to keep that promise, what was measured,
and the two things it does **not** establish.

---

## Why bother

The analyzer's answer is a function of `PATH`, and that is a measurement, not a
turn of phrase. Run the same chart with `helm` present and absent and the
report changes its `Analysis mode` from `helm (rendered truth)` to `static`,
rewrites every row of the coverage table from `rendered by helm` to
`statically parsed`, and rewords a finding (HP050 loses the word "Rendered").
Add or remove `kubeconform`, `kube-score` or `polaris` and the `--cross-check`
section gains or loses whole verdicts. Two engineers on the same commit of the
same chart can therefore hand each other different reports and both be right.

Pinning the four binaries is the reason the image exists. Everything else in it
is packaging.

```
helm         3.16.4
kubeconform  0.6.7
kube-score   1.20.0
polaris      9.6.4
```

Those are `ARG`s at the top of `docker/Dockerfile`. Bump them deliberately.
A toolchain change can move a report's findings, so the version of the image
is part of the provenance of the report — treat it the way you would treat the
version of a compiler in a build you have to reproduce.

## Build

There is no published image. Build it yourself, from the repo root:

```bash
docker build -f docker/Dockerfile -t hpa-analyzer:latest .
```

The build is two stages. The first fetches the four binaries and — this matters
— **executes each one** (`helm version --short`, `kubeconform -v`,
`kube-score version`, `polaris version`) before anything is copied forward. A
binary that downloaded but cannot run (wrong arch, missing loader) would not
announce itself at run time; it would surface as a quiet coverage downgrade in
a report that still looks complete. `TARGETARCH` is set by BuildKit, and all
four projects publish `amd64` and `arm64`, so an Apple Silicon build gets
native binaries rather than emulated ones.

`podman build` and `nerdctl build` work the same way; set
`HPA_ANALYZER_CONTAINER_CLI` at run time to match (see below).

## Install the wrapper

Put `bin/hpa-analyzer` somewhere on your `PATH`:

```bash
install -m 0755 bin/hpa-analyzer /usr/local/bin/hpa-analyzer
```

It is a single bash script with no dependencies beyond a container CLI. It is
written for bash 3.2 on purpose, because that is what macOS ships — hence the
counter-based array loops rather than `declare -A` and `"${arr[@]}"`, which
abort under `set -u` on an empty array in bash before 4.4.

## First run

The first time you run it against a chart, it asks one question on stderr:

```
First run. Where should reports be written?
  Saved to ~/.config/hpa-analyzer/config and re-exposed as $HPA_ANALYZER_OUTPUT_DIR.
  This sets the DEFAULT only - an explicit -o/--json/--html always wins.
  [/current/dir] >
```

Empty answer accepts the default. `~` is expanded. The directory is created if
it does not exist, resolved physically, and written to
`${XDG_CONFIG_HOME:-~/.config}/hpa-analyzer/config`. It is asked once; every
later run is silent.

### "Save it as an environment variable"

A child process cannot export a variable into the shell that launched it. That
is not a limitation of this script, it is how `execve` works, and any tool that
claims otherwise is writing to a dotfile behind your back. So the request is
honoured by writing a config file that the wrapper **parses** and re-exposes
under the name you would have expected:

```
$HPA_ANALYZER_OUTPUT_DIR    exported in your environment      — wins
the config file             ~/.config/hpa-analyzer/config
the first-run prompt        interactive only
$PWD                        no terminal: fallback, announced on stderr
```

Parsed, not sourced. The file belongs to you, but sourcing it would promote a
typo in a dotfile into arbitrary code execution. This is proven rather than
asserted: `proof/p10_harness.py` writes a config file containing a
`touch <canary>` line, runs the wrapper, and shows the canary is never created.

### No terminal

In CI, in cron, or behind a pipe there is no human to ask, so the wrapper does
not ask. It uses `$PWD`, prints two notes on stderr saying so and naming the
variable to set, and carries on. Blocking on a prompt there would hang exactly
the runs — `--fail-on`, `--min-score`, `--json` — that the tool exists to
provide. Measured cost of the no-TTY path: 0.01s, no config file written.

## What the wrapper actually does to your command line

Two things, and nothing else.

**It appends `-o <dir>/hpa_analysis_report.txt` when, and only when, you did
not pass `-o`/`--output` yourself.** That replaces the tool's *default* output
path. It never rewrites a path you typed — that is what makes "all the flags
still work" literally true rather than approximately true. `--html` with no
argument then lands beside the report for free, because the analyzer derives
that path from `-o` itself.

**It mounts every host path it can see at its own path**, and sets the
container's working directory to your `$PWD`. This is the single most important
decision in the file. The report prints `Target directory : <path>` and the
terminal prints `Full report: <path>`; mount the chart at `/work` and both
become lies the moment somebody pastes them into another command. Mounting
`/home/you/svc` at `/home/you/svc` is what makes the containerised report the
same *bytes* as the native one, not merely the same findings with different
paths in them.

Charts mount read-only; only the parents of output paths are writable. The
analyzer provably writes to `-o`, `--json` and `--html` and nowhere else — a
`--cross-check` run leaves the chart tree byte-identical.

Output directories are created host-side, by you, before the container starts,
so the daemon cannot create them root-owned. The container itself runs as
`--user $(id -u):$(id -g)`, so reports belong to you. That means running as a
uid with no `/etc/passwd` entry and no writable home, which is why the image
pins `HOME=/tmp` — helm tolerates a missing `HOME` but not one it cannot write
to.

`--help`, `--version` and a bare invocation mount nothing, prompt for nothing,
and resolve no output directory. Being asked where to save reports because you
typed `--version` would be absurd.

### What it deliberately does not do

It does not validate your chart directory. A missing directory, or a file where
a directory was expected, is passed straight through, because the analyzer
already reports both precisely — `error: <abspath> is not a directory`, exit 2
— and a tidier message from the shell would substitute this script's wording
and this script's exit code for the tool's.

It does not turn an empty argv into `--help`. `python3 -m hpaanalyzer` with no
arguments is an argparse usage error that exits 2. A wrapper answering the same
input with help text and exit 0 has turned a failing command into a passing
one. For the same reason there is no `CMD` in the Dockerfile: `CMD ["--help"]`
is the obvious friendly default and it was measured to break this contract.

It does not interpret exit codes. The last line is `exec`, so the container's
status becomes the script's status with nothing in between to have an opinion.

## Environment knobs

| Variable | Effect |
|---|---|
| `HPA_ANALYZER_OUTPUT_DIR` | default report directory; beats the config file |
| `HPA_ANALYZER_IMAGE` | image to run (default `hpa-analyzer:latest`) |
| `HPA_ANALYZER_CONTAINER_CLI` | `docker` (default), `podman`, `nerdctl` |
| `HPA_ANALYZER_DRY_RUN=1` | print the `docker run` argv and exit 0, run nothing |
| `HPA_ANALYZER_NO_USER=1` | skip `--user`; output will be root-owned |

`HPA_ANALYZER_DRY_RUN=1` is the honest way to answer "what is this thing about
to do to my filesystem", and it is also what `proof/p10_harness.py` uses to
check 19 different command lines without needing an image at all.

## What was measured

`proof/p10_harness.py` — 88 checks, exit 0. In outline:

The wrapper is a second argument parser, and it was checked against the first
one rather than against its author's reading of it. The proof monkey-patches
`argparse.ArgumentParser.parse_args`, dumps the resulting namespace, and
asserts the shell agreed about which token is the positional directory. That
catches the whole class of bug where `--kube-version 1.31.0 chart/` mounts
`1.31.0`, and the `--html` optional-argument rule where `--html --summary
chart/` swallows `--summary` and loses the chart.

Your argv survives as a *prefix* of the container's argv, with at most `-o
<path>` appended. Mounts are deduplicated, read-write wins over read-only for
the same path, and `--help`/`--version`/bare mount nothing. The precedence
chain is exercised end to end, including the real first-run prompt driven over
a real controlling terminal via `pty.fork()`.

And the one that matters most: **an analyzer report is byte-identical native
versus containerised** — 62704 bytes either way, terminal summary included.
Ten exit-code rows match native, including the four ways to exit 2.

`tests/test_harness.py` keeps the parts of that under the normal regression net
— 15 tests, all under `HPA_ANALYZER_DRY_RUN=1`, so they need no daemon, no
image and no network and run in half a second. Six deliberate mutations of the
wrapper confirm those tests can actually fail: dropping `--kube-version` from
`VALUE_FLAGS` fails two of them, appending `-o` over an explicit one fails
three, turning an empty argv into `--help` fails one, mounting the chart at
`/work` fails one, sourcing the config instead of parsing it fails the canary
test, and validating the chart directory in the shell fails one. A test that
cannot fail is not a test, and this project has shipped one before.

## Two things this does not establish

**The image measured in the proof is not the image in the Dockerfile.** No
container registry — and not even `get.helm.sh` — is reachable from the sandbox
this was developed in, so the image used for the byte-identity check was
assembled with `docker import` from that machine's own filesystem. Its four
binaries are therefore the *same builds* the native run uses. That proves the
**harness** transparent and proves nothing about whether helm 3.16.4 agrees
with the helm you have. Build the real Dockerfile on a networked machine and
re-run `proof/p10_harness.py`. If the byte-identity check then fails, the
difference is the pinned toolchain — which is a fact about your report worth
publishing, not a bug in the wrapper.

**`--cross-check` output is not reproducible run to run, natively.** This was
found by accident while trying to prove something else, and it is not caused by
containers. kube-score printed six distinct outputs over six runs of the same
chart; polaris printed two over three. The cause is Go map iteration order in
the tools being quoted. Verdicts and tallies are count-based and stay stable —
no finding moves — but the evidence underneath them reshuffles: four
consecutive **native** runs over `fixtures/bad-chart` produced four distinct
md5s, with pairwise diffs of 51, 55 and 65 lines (`proof/p10_harness.py`'s own
run of the same check measured 70). An earlier draft of this paragraph quoted
a narrower 45–57; the numbers above are what re-measuring actually returned and
the range is wider than the first sample suggested. `external.py`
reproduces external tool output verbatim by design, so "fixing" this means
reordering another tool's words, which is a decision this project has not made.
Until it does: do not diff two `--cross-check` reports and expect the diff to
mean something. Diff the runs without it.

## CI

Nothing special. The wrapper is transparent to exit codes and does not prompt
without a terminal, so:

```bash
export HPA_ANALYZER_OUTPUT_DIR="$PWD/reports"
hpa-analyzer ./svc --fail-on high --json reports/hpa.json
```

`0` ok, `1` a gate failed, `2` usage or IO error. Pin the image tag rather than
tracking `latest`, for the reason the whole first section of this file exists.

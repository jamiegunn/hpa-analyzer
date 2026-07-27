# Developing on hpa-analyzer

This page is for people changing the analyzer. If you only want to analyze a
chart, you want [the usage docs](usage.html) and the one command in the
README — nothing here applies to you.

## Why the command refuses to run natively

`python3 -m hpaanalyzer <dir>` exits 2 with a refusal, and so does the old
`python3 hpa-analyzer.py <dir>`. That is deliberate, and the reason is
measured rather than stylistic.

This tool's answer is a function of what is on `PATH`. With `helm` present and
absent, the same chart produces reports that differ in the `Analysis mode`
line, in every row of the coverage table, in which categories are scored at
all, in the denominator the score is averaged over, in the final grade, and in
the wording of at least one finding. Both runs are honest. Neither is
comparable to the other, and `proof/p10_harness.py` demonstrates the whole
list as a diff rather than asserting it.

The container image exists to close that: four pinned binaries — helm,
kubeconform, kube-score, polaris — one build, the same report on every
machine. While the native command remained equally documented, the image was
optional, so in practice it went unused, so the grades stayed incomparable. A
reproducibility mechanism nobody is required to use is decoration.

So the image is now the only supported entry point for the *command*. It is
not the only entry point for the *code*: see below.

## The library is not guarded

The refusal lives in the `if __name__ == "__main__":` block of
`hpaanalyzer/__main__.py`. Importing the package and calling `main()` in
process is untouched:

```python
from hpaanalyzer.__main__ import main
rc = main(["./my-chart", "-o", "report.txt", "--helm", "off"])
```

Twenty unit tests do exactly this, and so does anyone embedding the analyzer
in their own tooling. Guarding the library would break embedders in order to
prevent a mistake embedders are not making. `proof/p13_guard.py` CLAIM 4 pins
the distinction.

## The escape hatch

```
HPA_ANALYZER_ALLOW_NATIVE=1 python3 -m hpaanalyzer ./my-chart
```

This exists for one reason: the evidence layer. Every script under `proof/`
runs the CLI as a real subprocess — that is the entire point of the directory,
that its numbers are program output and not recollection — and it has to do so
on machines with no docker daemon. A guard that made the proofs unrunnable
would be protecting the tool by deleting the thing that shows the tool is
right.

You do not need to set it by hand. `proof/nativeoverride.py` sets it on
import, every proof script that shells out imports it, and the rationale lives
in that module's docstring. It uses `setdefault`, so if you have deliberately
exported a different value — to watch the refusal happen, for instance — yours
survives.

**The refusal message does not mention this variable, and that is on purpose.**
A bypass printed in every user's terminal becomes the folk-standard way to run
the tool inside a week, and then the guard has cost everyone a line of typing
and prevented nothing. Documented here, absent from there. If you find
yourself reaching for it outside `proof/`, the honest question is whether you
wanted `./bin/hpa-analyzer` instead.

One thing it costs, stated plainly: a proof script running under the override
measures the analyzer against whatever `helm` is on *your* host. That is why
the scripts whose measurements must not move pass `--helm off` explicitly on
the command line, pinning the mode from the arguments so the run is identical
on a machine with helm and one without. A script that does not pin the mode
has host-dependent numbers and says so in its own docstring.

## The marker

The guard looks for the file `/etc/hpa-analyzer-image`, which the runtime
stage of `docker/Dockerfile` writes. It records the pinned tool versions, so a
report that looks wrong can be traced to a toolchain:

```
docker run --rm --entrypoint cat hpa-analyzer:local /etc/hpa-analyzer-image
```

Nothing parses that content — the guard is an existence check — so the format
is for humans and may change.

It is a file rather than an environment variable on purpose. An env marker is
inherited by every child process, so one `export` in a shell profile turns the
guard off for a whole machine and nobody notices. A file has to be created
deliberately.

**It is not a security boundary.** Anyone who can write to `/etc` defeats it in
one command, and `IMAGE_MARKER`'s docstring says so. It is not defending a
machine from its operator; it is stopping a reproducible-by-construction tool
from being run irreproducibly out of habit, which is what was actually
happening.

## Running the tests and the proofs

```
python3 -m unittest discover -s tests -t .
python3 proof/p13_guard.py
```

Each `proof/p*.py` is standalone, prints its own claims, and exits non-zero
with the list of failed checks. They import `nativeoverride` themselves; you
do not need to set anything in your shell.

The image itself cannot be built or run in every environment — a sandbox with
no docker daemon, or no route to a registry, cannot do it — so the claims that
would need a live container are read from the Dockerfile instead, and say so
in their own output rather than quietly passing.

## Adding a check

Two things are load-bearing and easy to get wrong.

**Pick the `Basis` honestly.** `OBSERVED` means the finding was read directly
out of the user's files. `DERIVED` means arithmetic with a stated model.
`ASSUMED` means a fallback was used, and carries a mandatory `Assumes:` clause
and a cap of HIGH on what would otherwise be CRITICAL. R11 exists because a
check stamped an accusation of absence as `OBSERVED` when it had not opened
the file the answer lived in.

**Do not score what you did not look at.** `scoring.py`'s docstring is the
rule: there is no honest number for "not looked at", so an unassessable
category leaves both the numerator and the denominator, and every place that
prints the score prints what it was computed over. Scoring an unassessed
category 100, 0, or at the mean are all fabrication. The opposite mistake has
its own precedent — R8 removed a gate that dropped a probe finding whenever
the Dockerfile was absent while leaving the category in the denominator, which
moved the score for no reason in the world. If anything in a category is
legible, the category stays.

"""CLI entry point.

    hpa-analyzer <directory> [options]

The supported way to run this command is the container, through the
`hpa-analyzer` wrapper in bin/. Running the module directly against whatever
happens to be on the host's PATH is refused - see _require_image() below for
why, and docs/DEVELOPING.md for the escape hatch this repo's own evidence
layer uses.

Exit codes (CI-gateable):
    0  analysis ran; no gate violated
    1  a gate was violated (--fail-on threshold hit, or score < --min-score,
       or --require-coverage with an unassessed category, or the input was
       ungradeable while a gate was requested)
    2  usage / IO / environment error (includes the refusal above)
"""

import argparse
import json
import os
import sys

# F8: PyYAML is the one hard third-party dependency. A missing-dep traceback
# exits 1 - the SAME code as a failed quality gate - so CI cannot tell "tool
# broken" from "chart failed". Fail fast with a clear message and exit 2 (usage
# / environment error) before the engine import chain touches yaml.
#
# Seeing this at all means something is off: the image installs PyYAML at build
# time, so a user running `hpa-analyzer` cannot reach it. It is reachable only
# by an embedder importing the package, or by a contributor with the native
# override set - so the message points at both of those, not at a pip line the
# supported path never needed.
try:
    import yaml  # noqa: F401
except ImportError:
    print("error: PyYAML is required but not installed.\n"
          "    the supported command is `./bin/hpa-analyzer <dir>`, which "
          "carries its own\n"
          "    dependencies - see docs/DEVELOPING.md if you are running the "
          "package directly.",
          file=sys.stderr)
    raise SystemExit(2)

from . import __version__
from .clusterprobes import build_probes as _cluster_probes
from .engine import analyze
from .models import Severity
from .report import render
from .scoring import coverage, grade, overall_grade, overall_score

_SEV_ORDER = ["none", "low", "medium", "high", "critical"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="hpa-analyzer",
        description="Quality analysis of a Helm chart + values + Dockerfile "
                    "directory: HPA correctness, requests/limits, and JVM "
                    "container fitness, with an educational math-backed "
                    "plain-text report. Uses `helm template` when helm is on "
                    "PATH; falls back to static analysis with explicit "
                    "coverage reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("directory", help="directory containing the chart/values/Dockerfile")

    g_out = ap.add_argument_group("output & verbosity")
    g_out.add_argument("-o", "--output", default="hpa_analysis_report.txt",
                       help="text report path (default: %(default)s)")
    g_out.add_argument("--html", metavar="PATH", nargs="?", const="__auto__",
                       help="also write a browsable HTML report (filter, "
                            "collapsible sections, TOC). PATH optional - "
                            "defaults to the -o path with a .html extension")
    verb = g_out.add_mutually_exclusive_group()
    verb.add_argument("--summary", action="store_true",
                      help="short report: score, scorecard and the top "
                           "CRITICAL/HIGH findings only")
    verb.add_argument("--full", action="store_true",
                      help="everything: expands LOW/INFO and includes the "
                           "education appendix (implies --all --teach)")
    g_out.add_argument("--all", action="store_true",
                       help="expand LOW/INFO findings to full detail "
                            "(default collapses them to one line each)")
    g_out.add_argument("--teach", action="store_true",
                       help="include the education appendix (HPA/JVM primer); "
                            "omitted from the default report")
    g_out.add_argument("--stdout", action="store_true",
                       help="also print the full text report to stdout")
    g_out.add_argument("--quiet", action="store_true",
                       help="terminal: print only the one-line result "
                            "(suppress the banner and the fix-first summary)")

    g_an = ap.add_argument_group("analysis")
    g_an.add_argument("--helm", choices=("auto", "on", "off"), default="auto",
                      help="render via the helm binary: auto (default, if on "
                           "PATH), on (require it), off (static only)")
    g_an.add_argument("--kube-version", metavar="VER", dest="kube_version",
                      help="Kubernetes version to render the chart FOR, e.g. "
                           "1.31.0. Passed to `helm template --kube-version`. "
                           "Without it the tool derives one from the chart's "
                           "own kubeVersion; without THAT, helm falls back to "
                           "its compiled-in v1.20.0, which is EOL and will "
                           "refuse most modern charts.")
    g_an.add_argument("--assume-java", metavar="VER",
                      help="Java version to assume when the base image tag "
                           "hides it (e.g. 8, 8u151, 11.0.16, 17)")
    g_an.add_argument("--measured", metavar="K=V[,K=V]", action="append",
                      help="replace an estimated JVM memory component with a "
                           "number you measured, e.g. "
                           "--measured metaspace=210Mi,threads=180. Keys: "
                           "metaspace, codecache, threads, direct, gc, xss. "
                           "Sizes take Ki/Mi/Gi or k/M/G; threads is a plain "
                           "count. A measured component becomes OBSERVED, "
                           "drops out of the budget's range, and stops being "
                           "able to make the fit UNDETERMINED.")
    g_an.add_argument("--check", action="store_true",
                      help="input check ONLY: report what was discovered and "
                           "what looks misplaced, then exit without analyzing "
                           "(exit 2 if it is not a chart directory)")

    g_ci = ap.add_argument_group("CI gates & machine output")
    g_ci.add_argument("--fail-on", choices=_SEV_ORDER, default="none",
                      help="exit 1 if any finding at or above this severity "
                           "exists")
    g_ci.add_argument("--min-score", type=float, metavar="N",
                      help="exit 1 if the score is below N (ungradeable also "
                           "fails). NOTE: the score is a weighted mean over "
                           "the categories that could be assessed, so a run "
                           "that loses an input (e.g. the Dockerfile) is "
                           "compared on a different scale - see "
                           "--require-coverage")
    g_ci.add_argument("--require-coverage", action="store_true",
                      help="exit 1 if any scoring category could not be "
                           "assessed. Use with --min-score in CI: without it, "
                           "deleting an input silently changes the scale the "
                           "threshold is compared against")
    g_ci.add_argument("--json", metavar="PATH", dest="json_path",
                      help="also write machine-readable findings to PATH")

    g_eco = ap.add_argument_group("ecosystem")
    g_eco.add_argument("--cross-check", action="store_true",
                       help="also run helm lint / kubeconform / kube-score / "
                            "polaris (if on PATH) and fold their verbatim "
                            "output into the report")

    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.epilog = ("first time?  run  `hpa-analyzer <dir> --check`  to confirm the "
                 "tool found your chart/values/Dockerfile before analyzing.\n"
                 "quick look?  add --summary.   want to click around?  add "
                 "--html.   CI gate?  --fail-on high --json out.json.")
    args = ap.parse_args(argv)

    target = os.path.abspath(args.directory)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2

    # F7: an unparseable --assume-java is a USAGE error (exit 2), not a finding
    # buried in the report at exit 0 where CI never sees it.
    if args.assume_java:
        from .discovery import parse_assumed_java
        if parse_assumed_java(args.assume_java) is None:
            print(f"error: --assume-java '{args.assume_java}' not understood "
                  f"(expected forms: 8, 8u151, 11.0.16, 17)", file=sys.stderr)
            return 2

    # An unparseable --kube-version is a usage error, not a silent fallback:
    # falling back would render for a cluster the user did not ask for and
    # then call the result "rendered truth".
    if args.kube_version:
        from .kubeversion import parse_version
        if parse_version(args.kube_version) is None:
            print(f"error: --kube-version '{args.kube_version}' is not a "
                  f"version (expected forms: 1.31, 1.31.0, v1.31.0)",
                  file=sys.stderr)
            return 2

    # Same rule as --assume-java: a value the tool cannot parse is a USAGE
    # error at exit 2, not a silent fallback to the estimate it was meant to
    # replace. Silently ignoring it would print "est." next to a number the
    # user believes they measured.
    from .proofs import parse_measured
    try:
        measured = parse_measured(args.measured)
    except ValueError as e:
        print(f"error: --measured {e}", file=sys.stderr)
        return 2

    result = analyze(target, helm_mode=args.helm, assume_java=args.assume_java,
                     kube_version=args.kube_version, measured=measured)
    ctx = result.context

    # --- guided input check (always computed; --check exits here) ---------
    from .preflight import build_preflight, render_preflight
    pf = build_preflight(ctx)
    if args.check:
        print(render_preflight(pf, target, full=True))
        return 0 if pf.is_chart else 2
    if not args.quiet:
        print(render_preflight(pf, target, full=False))
        print()

    if args.helm == "on" and ctx.render_mode != "helm":
        print(f"error: --helm on but rendering failed: "
              f"{ctx.helm_error or ctx.render_mode}", file=sys.stderr)
        return 2

    # --- optional: run the ecosystem validators --------------------------
    external = None
    if args.cross_check:
        from .external import run_cross_check
        external = run_cross_check(ctx.chart_dir_abs,
                                   kube_version=ctx.render_kube_version)

    level = "summary" if args.summary else "full" if args.full else "default"
    text = render(result, target, external=external, level=level,
                  teach=args.teach, show_all=args.all)
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        print(f"error: cannot write report: {e}", file=sys.stderr)
        return 2

    html_path = None
    if args.html is not None:
        html_path = (os.path.splitext(args.output)[0] + ".html"
                     if args.html == "__auto__" else args.html)
        from .html_report import render_html
        try:
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(render_html(result, target, external=external))
        except OSError as e:
            print(f"error: cannot write html: {e}", file=sys.stderr)
            return 2

    score = overall_score(result)
    # R14. "grade" is the capped grade, because it is what the reports print
    # and what a CI gate will branch on - a consumer that gated on an uncapped
    # B+ while the human report said C would be the same lie in a new place.
    # The raw band and the reason are both emitted so nothing is hidden.
    _grade_capped, _grade_cap_why = overall_grade(result, score)
    _cov = coverage(result)
    if args.json_path:
        payload = {
            "target": target,
            "mode": ctx.render_mode,
            "score": round(score, 1) if score is not None else None,
            "grade": _grade_capped if score is not None else None,
            "grade_uncapped": grade(score) if score is not None else None,
            "grade_cap_reason": _grade_cap_why,
            "graded": score is not None,
            # A consumer that reads "score" without reading this cannot tell
            # a 51.8 over 7 categories from a 51.8 over 10.
            "score_coverage": {
                "assessed": [c.name for c in _cov.assessed],
                "unassessed": [{"category": c.name, "reason": r}
                               for c, r in _cov.unassessed],
                # R16. A separate key, not a widening of "unassessed": a
                # consumer parsing this JSON has already written code that
                # treats every entry of that list as a blind spot to chase,
                # and a category the tool answered completely does not belong
                # in it. `complete` keeps its meaning (no blind spots) for the
                # same reason; `all_scored` is the new, narrower claim that
                # the mean ran over all ten categories.
                "not_applicable": [{"category": c.name, "reason": r}
                                   for c, r in _cov.not_applicable],
                "weight_assessed": _cov.weight_assessed,
                "weight_total": _cov.weight_total,
                "complete": _cov.complete,
                "all_scored": _cov.all_scored,
                "note": _cov.one_line(),
            },
            "counts": {s.label.lower(): sum(1 for f in result.findings
                                            if f.severity is s)
                       for s in Severity},
            "findings": [{
                "rule": f.rule_id, "severity": f.severity.label,
                "basis": f.basis.label, "assumes": f.assumes,
                "category": f.category.value, "title": f.title,
                "file": f.file, "line": f.line, "detail": f.detail,
                "why": f.why, "fix": f.fix, "math": f.math,
            } for f in result.findings],
            "coverage": [list(c) for c in ctx.coverage],
            "cluster_probes": [{
                "key": p.key, "title": p.title, "gap": p.gap,
                "commands": p.commands, "read": p.read,
                "triggered_by": p.triggered_by,
            } for p in _cluster_probes(result)],
            "preflight": [{"status": i.status, "label": i.label, "hint": i.hint}
                          for i in pf.items],
            # `ok` alone is not enough for a consumer to audit a verdict, and
            # a consumer that cannot audit it will treat it as this project's
            # opinion rather than the other tool's. `verdict_basis` names the
            # signal the verdict came from and `tally` gives the counts it was
            # computed from, so a machine reader can recompute it or disagree.
            "cross_check": ([{"tool": e.name, "installed": e.installed,
                              "ran": e.ran, "ok": e.ok, "summary": e.summary,
                              "verdict": e.verdict,
                              "verdict_basis": e.verdict_basis,
                              "tally": e.tally,
                              "indeterminate": e.indeterminate,
                              "indeterminate_why": e.indeterminate_why,
                              "manual_cmd": e.manual_cmd,
                              "install_hint": e.install_hint}
                             for e in external] if external else []),
        }
        try:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except OSError as e:
            print(f"error: cannot write json: {e}", file=sys.stderr)
            return 2

    # terminal-first: the answer (grade + top fixes) prints HERE, so an SRE
    # never has to open a file to know what to do. --quiet drops to one line.
    if args.quiet:
        # Even one line carries the denominator: `score 51.8/100` alone is
        # the exact string a reader would diff against another run, and two
        # runs over different category sets are not comparable (scoring.py).
        cov = coverage(result)
        over = ("" if cov.all_scored
                else f" over {cov.n_assessed}/{cov.n_total} categories")
        # The capped grade, and marked as capped. One line is exactly where a
        # silent cap would do the most damage: it is the line that gets pasted
        # into a ticket with nothing else around it.
        capped = "" if not _grade_cap_why else " CAPPED"
        score_str = (f"score {score:.1f}/100 (grade {_grade_capped}{capped})"
                     f"{over}"
                     if score is not None else "NOT GRADED")
        print(f"hpa-analyzer [{ctx.render_mode}]: {score_str}, "
              f"{len(result.findings)} finding(s) -> {os.path.abspath(args.output)}")
    else:
        from .report import stdout_summary
        print(stdout_summary(result, os.path.abspath(args.output),
                             os.path.abspath(html_path) if html_path else None))
        print(f"  ({len(result.findings)} findings, {len(result.proofs)} proof "
              f"tables, mode: {ctx.render_mode})")
    if args.stdout:
        print()
        print(text)

    # ---- CI gates ----------------------------------------------------------
    failed = False
    if args.fail_on != "none":
        threshold = _SEV_ORDER.index(args.fail_on)
        worst = max((_SEV_ORDER.index(f.severity.label.lower())
                     for f in result.findings
                     if f.severity is not Severity.INFO), default=0)
        if worst >= threshold:
            print(f"gate: findings at or above --fail-on={args.fail_on} exist",
                  file=sys.stderr)
            failed = True
    if args.min_score is not None:
        if score is None:
            print(f"gate: input ungradeable, --min-score={args.min_score} "
                  f"cannot be met", file=sys.stderr)
            failed = True
        elif score < args.min_score:
            print(f"gate: score {score:.1f} < --min-score={args.min_score}",
                  file=sys.stderr)
            failed = True
        # R5: a threshold is a comparison, and a comparison needs a scale. The
        # score is a weighted mean over the categories that could be assessed,
        # so a run that loses an input is measured on a different scale than
        # the run before it - and CI reads the exit code, not the report, so
        # the coverage block added to the report cannot help here. Measured on
        # this project's own fixture: bad-chart scores 45.5, and deleting its
        # Dockerfile - with every Kubernetes manifest byte-identical - scores
        # 49.9. Any threshold in that band is a red build that turns green
        # for deleting a file. (The band was 45.5 -> 51.8 when this was
        # written and the example read `--min-score 50`; R8 recovered a HIGH
        # that the missing file had been hiding, so the gap narrowed and a
        # literal 50 stopped sitting inside it. proof/p5b_bar2.py now derives
        # its threshold from the measured pair for exactly that reason - a
        # number written into prose is a number that goes stale silently,
        # which is the same disease as the one this block exists to treat.)
        # The note below puts that in the CI
        # log on every run, pass or fail; --require-coverage turns it into an
        # actual gate, because a log line does not stop a deploy.
        if not _cov.all_scored:
            advice = (" - pass --require-coverage to gate on this."
                      if not _cov.complete else
                      " - and --require-coverage will NOT fail on this, "
                      "deliberately: there is no input anyone could add.")
            print(f"gate: {_cov.one_line()} A threshold compared against a "
                  f"score over a different set of categories is not the same "
                  f"comparison{advice}", file=sys.stderr)
    if args.require_coverage and not _cov.complete:
        print(f"gate: --require-coverage: {_cov.one_line()}", file=sys.stderr)
        failed = True
    return 1 if failed else 0


IMAGE_MARKER = "/etc/hpa-analyzer-image"
"""File the Dockerfile writes into the runtime stage. Its presence is what
`python3 -m hpaanalyzer` treats as "I am inside the pinned image".

Deliberately a file at an absolute path outside the package, not an
environment variable. An env marker is inherited by every child process, so a
single `export` in a shell profile silently turns the guard off for that
machine forever and nobody notices; a file has to be created on purpose.

What this does NOT do, stated plainly so nobody builds on it: it is not a
security boundary. Anyone who can write /etc can defeat it in one command,
and that is fine - it is not defending the machine from its operator, it is
stopping a reproducible-by-construction tool from being run irreproducibly by
habit. See _require_image().
"""

NATIVE_OVERRIDE = "HPA_ANALYZER_ALLOW_NATIVE"
"""Escape hatch for this repository's own tests and proof scripts.

It exists because the evidence layer has to run the CLI as a real subprocess
on a machine that has no docker daemon, and a proof that cannot run is worth
less than the guard it was protecting.

It is documented in docs/DEVELOPING.md and NOT printed in the refusal message.
That is a deliberate asymmetry, not an oversight: a bypass printed in every
user's terminal becomes the folk-standard way to run the tool within a week,
and then the guard has cost everyone a line of typing and prevented nothing.
"""


def _require_image(argv=None, env=None, marker=IMAGE_MARKER) -> int:
    """Return 0 if this process may proceed, or 2 after printing a refusal.

    WHY THE COMMAND IS GUARDED AT ALL
    ---------------------------------
    This tool's answer is a function of what is on PATH, and that is measured,
    not asserted: with helm absent the same chart's report changes its
    `Analysis mode`, rewrites every row of the coverage table, drops whole
    categories out of the score denominator, and rewords findings. Two people
    running `python3 -m hpaanalyzer` on the same chart on two laptops get two
    different grades and neither of them is wrong. The image pins helm,
    kubeconform, kube-score and polaris precisely so that stops happening;
    running the module natively opts out of the only thing that makes the
    number comparable.

    WHY IT GUARDS THE COMMAND AND NOT THE LIBRARY
    ---------------------------------------------
    This lives in the `__main__` block, so `main([...])` called in-process is
    untouched. 20 tests do exactly that, and so does anyone embedding the
    analyzer. The refusal is about the unsupported *entry point*, not about
    the code; making the library refuse would break embedding to prevent a
    mistake embedders are not making.
    """
    env = os.environ if env is None else env
    if os.path.exists(marker):
        return 0
    if env.get(NATIVE_OVERRIDE) == "1":
        return 0
    argv = sys.argv[1:] if argv is None else argv
    where = " ".join(argv) if argv else "<chart-directory>"
    print(
        "error: this module is not the supported entry point.\n"
        "\n"
        "    `python3 -m hpaanalyzer` analyzes your chart with whatever helm,\n"
        "    kubeconform, kube-score and polaris happen to be on this host's\n"
        "    PATH - or with none of them. That changes the analysis mode, the\n"
        "    coverage table, which categories are scored at all, and the final\n"
        "    grade. The same chart scores differently on two machines and\n"
        "    neither run is wrong, which makes the number useless for review\n"
        "    or for a CI gate. The image exists to pin that toolchain.\n"
        "\n"
        "run it through the wrapper instead - every flag is identical:\n"
        f"    ./bin/hpa-analyzer {where}\n"
        "\n"
        "first time (builds the pinned image, once):\n"
        "    docker build -t hpa-analyzer:local -f docker/Dockerfile .\n"
        "\n"
        "working on the analyzer itself?  see docs/DEVELOPING.md",
        file=sys.stderr)
    return 2


if __name__ == "__main__":
    _refused = _require_image()
    raise SystemExit(_refused or main())

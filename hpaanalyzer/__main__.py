"""CLI entry point.

    python3 -m hpaanalyzer <directory> [options]

Exit codes (CI-gateable):
    0  analysis ran; no gate violated
    1  a gate was violated (--fail-on threshold hit, or score < --min-score,
       or the input was ungradeable while a gate was requested)
    2  usage / IO error
"""

import argparse
import json
import os
import sys

# F8: PyYAML is the one hard third-party dependency. A missing-dep traceback
# exits 1 - the SAME code as a failed quality gate - so CI cannot tell "tool
# broken" from "chart failed". Fail fast with a clear message and exit 2 (usage
# / environment error) before the engine import chain touches yaml.
try:
    import yaml  # noqa: F401
except ImportError:
    print("error: PyYAML is required but not installed.\n"
          "    pip install -r requirements.txt   (or: pip install PyYAML)",
          file=sys.stderr)
    raise SystemExit(2)

from . import __version__
from .clusterprobes import build_probes as _cluster_probes
from .engine import analyze
from .models import Severity
from .report import render
from .scoring import grade, overall_score

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
    g_an.add_argument("--assume-java", metavar="VER",
                      help="Java version to assume when the base image tag "
                           "hides it (e.g. 8, 8u151, 11.0.16, 17)")
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
                           "fails)")
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

    result = analyze(target, helm_mode=args.helm, assume_java=args.assume_java)
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
        external = run_cross_check(ctx.chart_dir_abs)

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
    if args.json_path:
        payload = {
            "target": target,
            "mode": ctx.render_mode,
            "score": round(score, 1) if score is not None else None,
            "grade": grade(score) if score is not None else None,
            "graded": score is not None,
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
            "cross_check": ([{"tool": e.name, "installed": e.installed,
                              "ran": e.ran, "ok": e.ok, "summary": e.summary,
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
        score_str = (f"score {score:.1f}/100 (grade {grade(score)})"
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
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

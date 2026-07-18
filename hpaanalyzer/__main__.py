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
                    "coverage reporting.")
    ap.add_argument("directory", help="directory containing the chart/values/Dockerfile")
    ap.add_argument("-o", "--output", default="hpa_analysis_report.txt",
                    help="output report path (default: %(default)s)")
    ap.add_argument("--stdout", action="store_true",
                    help="also print the report to stdout")
    ap.add_argument("--helm", choices=("auto", "on", "off"), default="auto",
                    help="use the helm binary to render templates: auto = if "
                         "found on PATH (default), on = require it, off = "
                         "static analysis only")
    ap.add_argument("--assume-java", metavar="VER",
                    help="Java version to assume when the base image does not "
                         "reveal it (e.g. 8, 8u151, 11.0.16, 17) - essential "
                         "for internal corporate base images")
    ap.add_argument("--fail-on", choices=_SEV_ORDER, default="none",
                    help="exit 1 if any finding at or above this severity "
                         "exists (for CI gates)")
    ap.add_argument("--min-score", type=float, metavar="N",
                    help="exit 1 if the overall score is below N (an "
                         "ungradeable input also fails this gate)")
    ap.add_argument("--json", metavar="PATH", dest="json_path",
                    help="additionally write machine-readable findings to PATH")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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

    if args.helm == "on" and ctx.render_mode != "helm":
        print(f"error: --helm on but rendering failed: "
              f"{ctx.helm_error or ctx.render_mode}", file=sys.stderr)
        return 2

    text = render(result, target)
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        print(f"error: cannot write report: {e}", file=sys.stderr)
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
        }
        try:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except OSError as e:
            print(f"error: cannot write json: {e}", file=sys.stderr)
            return 2

    score_str = (f"score {score:.1f}/100 (grade {grade(score)})"
                 if score is not None else "NOT GRADED (no analyzable input)")
    print(f"hpa-analyzer [{ctx.render_mode}]: {score_str}, "
          f"{len(result.findings)} finding(s), {len(result.proofs)} proof "
          f"table(s)")
    print(f"report written to {os.path.abspath(args.output)}")
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

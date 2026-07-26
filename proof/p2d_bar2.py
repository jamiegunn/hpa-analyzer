#!/usr/bin/env python3
"""PROOF R2, Bar 2: did the pod-scope answer reach the terminal?

Bar 1 asks whether the arithmetic matches upstream. proof/p2_sidecar.py
answers that. This asks the question the user actually asked - "not just
correct, but does it do what it is supposed to do" - and it is a different
question with a different answer.

The subject is fixtures/initheavy-chart, built for this iteration and correct
at every per-container check the tool has: the app container is Guaranteed
(request == limit on cpu and memory), has readiness, liveness and startup
probes, runs non-root with a read-only root filesystem and all capabilities
dropped, and has a preStop hook. Nothing about it is wrong in isolation.

At pod scope it is a capacity accident:

    metrics-agent   native sidecar (restartPolicy: Always), NO resources
    db-migrate      one-shot init, 2 CPU / 6 GiB
    ledger          app container, 500m / 1 GiB

Steady state is 500m / 1 GiB. The init peak is 2 cores / 6 GiB, and per
aggregateContainerResourcesByFn the pod's request is max(steady, init peak) -
so every replica reserves 6 GiB for its entire life, of which it uses 1 GiB
after the first few seconds. At replicaCount: 4 that is 20 GiB of cluster
memory held open for nothing, and it will not fit two-to-a-node on an 8 GiB
node when the author's mental model says four.

BEFORE is the committed pre-fix tree, extracted with `git archive <baseline>`
(pinned in proof/baseline.py, NOT HEAD) and run in a subprocess - not a description of it. Run: python3 proof/p2d_bar2.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline import BASELINE, resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)

FIXTURE = os.path.join(REPO, "fixtures", "initheavy-chart")

_CHILD = r"""
import json, sys, tempfile, os
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary
r = analyze(sys.argv[2], helm_mode="off")
out = os.path.join(tempfile.mkdtemp(), "report.txt")
print("---JSON---")
print(json.dumps({"summary": stdout_summary(r, out),
                  "rules": sorted(f.rule_id for f in r.findings)}))
"""


def run_head():
    tmp = tempfile.mkdtemp(prefix="hpa-before-")
    tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                         capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
    subprocess.run(["cp", "-r", FIXTURE, os.path.join(tmp, "chart")],
                   check=True)
    out = subprocess.run(
        [sys.executable, "-c", _CHILD, tmp, os.path.join(tmp, "chart")],
        capture_output=True, text=True, check=True).stdout
    return json.loads(out.split("---JSON---", 1)[1])


def run_now():
    import tempfile as tf
    from hpaanalyzer.engine import analyze
    from hpaanalyzer.report import stdout_summary
    r = analyze(FIXTURE, helm_mode="off")
    out = os.path.join(tf.mkdtemp(), "report.txt")
    return {"summary": stdout_summary(r, out),
            "rules": sorted(f.rule_id for f in r.findings)}


def _fixfirst(summary):
    """The lines an SRE actually reads before deciding what to do today."""
    keep, on = [], False
    for line in summary.splitlines():
        if "GRADE" in line or "Fix first" in line:
            on = True
        if on and line.strip():
            keep.append(line.rstrip())
        if on and "Full report" in line:
            break
    return "\n".join(keep)


def main():
    print(__doc__)
    b, a = run_head(), run_now()

    print("=" * 74)
    print(f"BEFORE  (git archive {BASELINE}, run in a subprocess)")
    print("=" * 74)
    print(_fixfirst(b["summary"]))
    print()
    print("=" * 74)
    print("AFTER   (working tree)")
    print("=" * 74)
    print(_fixfirst(a["summary"]))

    def grade(s):
        m = re.search(r"GRADE\s+(\S+)\s+\(([\d.]+)/100\)", s)
        return (m.group(1), float(m.group(2))) if m else (None, None)

    gb, sb = grade(b["summary"])
    ga, sa = grade(a["summary"])

    print()
    print("=" * 74)
    print("CLAIM 1: the pre-fix tool graded this chart at the top of the")
    print("         scale and told the user there was nothing urgent to do.")
    print(f"         grade before: {gb} ({sb}/100); the fix-first list "
          f"{'is empty' if 'Fix first' not in b['summary'] else 'exists'}, "
          f"and the words 'No critical or high findings' "
          f"{'appear' if 'No critical or high' in b['summary'] else 'do not appear'}.")
    quiet = "No critical or high" in b["summary"] or "Fix first" not in b["summary"]

    print()
    print("CLAIM 2: neither the 6 GiB reservation nor the unsized sidecar was")
    print("         mentioned anywhere in that summary.")
    for token in ("6 GiB", "metrics-agent", "init peak", "sidecar"):
        print(f"         '{token}' in the before-summary: "
              f"{token in b['summary']}")
    silent = not any(t in b["summary"]
                     for t in ("6 GiB", "metrics-agent", "init peak"))

    print()
    print("CLAIM 3: it now reaches the terminal, at the top, with numbers.")
    print(f"         grade after: {ga} ({sa}/100)")
    reaches = ("RS017" in a["summary"] and "RS016" in a["summary"]
               and ga != gb)
    for line in a["summary"].splitlines():
        if re.match(r"\s+\d+\.\s+\[RS01[67]\]", line):
            print(f"         {line.strip()}")

    print()
    print("CLAIM 4: new rules, not re-labelled old ones.")
    new = sorted(set(a["rules"]) - set(b["rules"]))
    gone = sorted(set(b["rules"]) - set(a["rules"]))
    print(f"         rules added : {new}")
    print(f"         rules lost  : {gone or 'none'}")
    honest = not gone

    print()
    print("=" * 74)
    ok = quiet and silent and reaches and honest
    if ok:
        print("Bar 2 MET for R2. The defect that only exists at pod scope is")
        print("now the first thing the terminal says, and the chart that is")
        print("correct at pod scope (fixtures/sidecar-chart) does not gain a")
        print("single new finding - see tests/test_fitness_podresources.py.")
        print()
        print(f"Read honestly: the grade fell from {gb} to {ga} on a chart "
              f"nobody")
        print("changed. That is the tool correcting itself, not the chart")
        print("getting worse, and it is the whole argument for Bar 2 - the")
        print("A was the bug.")
        return 0
    print("NOT PROVEN:", dict(quiet=quiet, silent=silent, reaches=reaches,
                              honest=honest))
    return 1


if __name__ == "__main__":
    sys.exit(main())

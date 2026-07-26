#!/usr/bin/env python3
"""R2, third defect: the pod total's own label was wrapped across two cells.

This is the smallest defect in iteration 2 and the easiest to wave away, so
it is worth being precise about what was broken. Contract C1.5 says any total
the tool prints must say which containers are in it. Iteration 2 built that
table. The row carrying the answer was labelled

    Deployment/payments  => POD REQUEST

and the renderer printed it as

    | Deployment/payments  => POD     | ... |
    | REQUEST                         |     |

A reader scanning the left column for the pod total does not find it, because
it is not there - "=> POD" is there, and "REQUEST" is on the next physical
line under a container-shaped cell. Grep does not find it either, which is how
the Bar 2 test caught it: assertIn("=> POD REQUEST", text) failed on a report
that contained every character of that string.

Cause, measured rather than guessed: report.WIDTH is 100. A 5-column table
spends 3*5+1 = 16 characters on borders and padding, leaving 84 for content.
The natural widths were 33/9/30/7/7 = 86, so _table shrank the widest column
twice, to 31. The label is 33 characters (35 on this fixture). It did not fit,
so textwrap split it.

Fix: merge "Role" into "How it counts". That is not cosmetic tidying - the
role IS how it counts, a native sidecar is summed *because* it is a sidecar,
so the two columns were carrying one fact twice. Four columns leave 87 for
content against naturals of 35/30/7/7 = 79, and every label fits whole.

Run: python3 proof/p2c_label.py     (exit 0; prints the before and after)
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from hpaanalyzer.report import _table, WIDTH, render     # noqa: E402
from hpaanalyzer.engine import analyze                   # noqa: E402

FIXTURE = os.path.join(REPO, "fixtures", "sidecar-chart")

# The exact pre-fix layout: same renderer, same data, one extra column.
BEFORE_HEADERS = ["Container", "Role", "How it counts", "req CPU", "req Mem"]
BEFORE_ROWS = [
    ["Deployment/payments:payments", "container", "summed (runs always)",
     "1 core", "2 GiB"],
    ["Deployment/payments:istio-proxy", "container", "summed (runs always)",
     "100m", "128 MiB"],
    ["Deployment/payments:wait-for-db", "init", "peak only (max)",
     "0 cores", "0 B"],
    ["Deployment/payments:log-shipper", "sidecar", "summed (runs always)",
     "50m", "128 MiB"],
    ["Deployment/payments  steady state", "-", "sum of the above",
     "1150m", "2.2 GiB"],
    ["Deployment/payments  init peak", "-", "max(init + sidecars before it)",
     "50m", "128 MiB"],
    ["Deployment/payments  => POD REQUEST", "-", "max(steady, init peak)",
     "1150m", "2.2 GiB"],
]

LABELS = ["Deployment/payments  => POD REQUEST",
          "Deployment/payments  steady state",
          "Deployment/payments  init peak",
          "Deployment/payments:payments",
          "Deployment/payments:istio-proxy",
          "Deployment/payments:wait-for-db",
          "Deployment/payments:log-shipper"]


def broken(text):
    """Labels that do not survive on one physical line."""
    lines = text.splitlines()
    return [lbl for lbl in LABELS if not any(lbl in ln for ln in lines)]


def main():
    before = _table(BEFORE_HEADERS, BEFORE_ROWS)
    after = render(analyze(FIXTURE, helm_mode="off"), "sidecar-chart",
                   level="deep")

    print(__doc__.split("Run:")[0].rstrip())
    print("=" * 78)
    print(f"report.WIDTH = {WIDTH}; a 5-column table leaves "
          f"{WIDTH - (3 * 5 + 1)} chars of content, a 4-column one "
          f"{WIDTH - (3 * 4 + 1)}.")
    print()
    print("BEFORE (5 columns, real renderer, real numbers):")
    print(before)
    b = broken(before)
    print(f"\n  labels split across lines: {len(b)} -> {b}")

    print("\nAFTER (shipped report, 4 columns):")
    lines = after.splitlines()
    start = next(i for i, l in enumerate(lines) if "scheduling footprint" in l)
    tbl = [l for l in lines[start:start + 34]]
    print("\n".join(tbl))
    a = broken(after)
    print(f"\n  labels split across lines: {len(a)} -> {a}")

    print()
    print("CLAIM 1: the pre-fix report did not contain the string it was "
          "asked to print.")
    print(f"         '=> POD REQUEST' findable by scanning or grep, before: "
          f"{'Deployment/payments  => POD REQUEST' not in b}")
    print(f"         ... after: "
          f"{'Deployment/payments  => POD REQUEST' not in a}")
    print("CLAIM 2: no other label regressed to buy that back.")
    print(f"         broken labels before={len(b)}  after={len(a)}")
    print("CLAIM 3: the numbers are untouched - this was a layout defect, "
          "and the fix is a layout fix. The pod request is still")
    print("         1150m / 2.2 GiB, derived by "
          "component-helpers/resource/helpers.go, as in proof/p2_sidecar.py.")

    return 0 if (b and not a) else 1


if __name__ == "__main__":
    sys.exit(main())

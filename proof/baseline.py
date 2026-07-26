"""The commit every BEFORE column in proof/ is measured against.

The before/after scripts extract the pre-fix tree with `git archive` and run
it in a subprocess, so the BEFORE numbers are real program output rather than
a recollection of what the old code did. That only holds if the revision is
FIXED. They originally said `HEAD`, which was correct exactly as long as
nothing had been committed - and the first commit of this iteration series
would have silently re-pointed every proof at its own fix, turning
"here is what changed" into "nothing changed".

So the revision is pinned to a literal SHA: the last commit before iteration 1
started. If that commit is not present (a shallow clone, a fresh archive), the
scripts say so and exit rather than quietly falling back to HEAD.
"""

import subprocess

BASELINE = "ea95681"
"""hpa-analyzer: static analyzer for Helm + JVM container fitness + HPA
correctness - the state of the tool when the Torvalds critique was written."""

R8_TREE = "f806890"
"""R1-R8 as committed.

A second pin, and it needs a reason, because "add another baseline whenever
the first one is inconvenient" is how a proof suite stops proving anything.

The reason is that R9's subject - the JVM memory budget - was NOT REACHED on
several fixtures at `BASELINE`. The pre-R8 gate skipped the whole budget on
any chart without a Dockerfile, so `git archive ea95681` produces a report
for `fixtures/initheavy-chart` with no budget table in it at all. A BEFORE
column drawn there would not show R9's defect looking better or worse; it
would show a blank where the defect lives, and R9 would appear to have
invented the subject.

So R9's before/after is measured against R8_TREE, and the price of the second
pin is paid in p9_estimates.py CLAIM 0: the arithmetic under test - the five
constants, the sum, and the branch that turns the sum into a verdict - is
proved BYTE-IDENTICAL between BASELINE and R8_TREE before any measurement is
taken. The defect being measured is therefore the original one, not one the
intervening eight iterations introduced.
"""


class BaselineMissing(RuntimeError):
    pass


def resolve(repo: str, rev: str = BASELINE) -> str:
    """Return the full SHA of a pinned commit, or raise."""
    r = subprocess.run(["git", "rev-parse", "--verify", f"{rev}^{{commit}}"],
                       cwd=repo, capture_output=True, text=True)
    if r.returncode != 0:
        raise BaselineMissing(
            f"pinned commit {rev} is not in this repository, so the "
            f"BEFORE column cannot be produced. Fetch the full history "
            f"(git fetch --unshallow) and re-run.")
    return r.stdout.strip()

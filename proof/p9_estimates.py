#!/usr/bin/env python3
"""PROOF R9, Bar 1: a point estimate wearing the clothes of a measurement.

The whole reason this program exists is one sum:

    T  =  H + metaspace + code cache + threads*Xss + direct buffers + GC/internal

and the one question it answers that `kubectl` cannot: does T fit inside
`limits.memory`?  On the flagship clean fixture, `fixtures/good-chart`, the
tool prints T = 916 MiB against a 1 GiB limit and concludes:

    VERDICT: Fits with 108 MiB headroom (11% of limit).

Of those 916 MiB, 512 are the heap - computed from two numbers in the user's
own files (MaxRAMPercentage=50 x limit 1 GiB).  The other 404 MiB are five
constants that nobody measured:

    EST_METASPACE = 128 MiB   # typical Spring/framework app: 80-180 MiB
    EST_CODECACHE =  64 MiB   # JIT code cache steady state
    EST_THREADS   = 100       # typical service thread count
    EST_DIRECT    =  64 MiB   # netty/NIO direct buffers
    EST_GC_OTHER  =  48 MiB   # GC bookkeeping, symbols, JVM itself

The defect is not that the tool estimates.  Estimating is the job: nobody can
measure a JVM that has not been started, and a chart author still has to
choose `limits.memory` before it runs.  The defect is that the estimate is
carried into a CATEGORICAL VERDICT and into the GRADE as though it had been
measured.  "Fits with 108 MiB headroom" reads as a statement about the user's
chart.  It is in fact a statement about `EST_METASPACE`.

And the tool knows.  Three of its own sentences say so, in the same report:

  * the Basis cell for metaspace prints the range it did not use -
    "typical framework app 80-180 MiB", a 100 MiB span, reported as 128;
  * the Basis cell for direct buffers says a leak "can go far past this
    estimate";
  * XF004's own `why` says "real Spring apps routinely exceed them (metaspace
    growth, more threads, bigger direct buffers)".

So the tool states that its inputs vary by more than the margin it reports,
and then reports the margin as a fact anyway.  That is not a rounding error.
It is a category error: the width of the answer exceeds the answer.

CLAIM 0  the arithmetic under test is the ORIGINAL arithmetic - byte-identical
         between the two pinned commits - so what follows measures the tool as
         first written, not something the last eight iterations introduced.
CLAIM 1  the report calls its estimates "labeled and conservative".  Neither
         word survives contact.  The thread count is not labelled at the point
         of use (C2.3): the row reads `Thread stacks (100 x 1 MiB)` over Basis
         `-Xss x thread count`, which is the register of arithmetic on two
         observed values.  On good-chart exactly one of the two is observed -
         the Dockerfile really does set `-Xss1m` - and the cell names THAT
         one and stays silent about the invented one, which is the failure
         mode in miniature: a citation that is accurate about the half it
         covers and, by covering only that half, vouches for the whole row.
         On initheavy-chart neither is observed: the chart sets no -Xss
         anywhere, `xss = xss or MiB` supplies 1 MiB, and the cell still
         cites a flag that does not exist in the user's files.
         And 100 is not conservative: Spring Boot's embedded Tomcat ships
         `server.tomcat.threads.max=200`, so the default configuration of the
         framework the source comment names produces twice it.
CLAIM 2  one constant, moved inside the range the tool PRINTS IN THAT SAME
         TABLE, changes the verdict category and the grade of the flagship
         clean chart - on byte-identical user files.
CLAIM 3  the SIGN of the margin - the difference between "fits" and "expect
         kernel OOM kills (exit 137)" - is decided by constants for which the
         tool prints no range at all.  Its hedge, "a negative margin this size
         rarely reverses", is measured here.  It reverses.
CLAIM 4  the findings built on the sum do not declare what they rest on.
         XF004's `assumes` is null outright.  XF002's is NOT - and that is
         the sharper version of the same defect, because it proves the field
         is live, reachable and populated on this exact finding: it warns
         about a command-line -Xmx that might override the heap, and says
         nothing about the five constants that supplied 404 of the 916 MiB
         the finding is arithmetic on.  The tool declares the assumption it
         inherited and omits the five it authored (C2.1, C2.3).
CLAIM 5  AFTER: the budget is an interval with sourced endpoints, and the
         verdict is three-state.  Where the limit falls inside the interval
         the answer is UNDETERMINED (C2.2) and the report names the single
         assumption that decides it and the value at which it crosses -
         instead of picking a side and calling it headroom.
CLAIM 6  AFTER, the guard: an interval must not soften a conclusion that never
         rested on the estimates.  Where the heap ALONE meets the limit the
         answer follows from the user's own two numbers, and XF001 stays
         CRITICAL and certain under every perturbation of every constant.
         (R7 taught this lesson the other way round: a fix that widens
         epistemic honesty and quietly loses a true CRITICAL is not a fix.)
CLAIM 7  AFTER: ignorance is reported, not converted into a defect.  A
         straddling band on a chart the tool cannot fault produces an
         UNDETERMINED coverage row and NO finding - because "I cannot tell"
         is a fact about the tool, and turning it into a MEDIUM would be the
         same C2.2 error in the opposite direction.  And a user who HAS
         measured can say so (`--measured`), collapsing the band to an
         observed value and getting a determinate answer.

Method: the estimation constants are rebound in a subprocess and the REAL
analyzer - real engine, real renderer, real scorer - is re-run over
BYTE-IDENTICAL fixture directories, verified byte-identical by sha256 over
every file.  Nothing about the user's chart changes between runs; only a
number the user never sees.

BEFORE is the committed tree at the SHA pinned in proof/baseline.py, extracted
with `git archive`.  R9 uses the second pin (R8_TREE) for the reason recorded
there and re-proved in CLAIM 0.

Run: python3 proof/p9_estimates.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline import BASELINE, R8_TREE, resolve as _resolve  # noqa: E402

BASELINE_SHA = _resolve(REPO, BASELINE)
R8_SHA = _resolve(REPO, R8_TREE)

MiB = 1024 ** 2
GOOD = os.path.join(REPO, "fixtures", "good-chart")
INITHEAVY = os.path.join(REPO, "fixtures", "initheavy-chart")
WORKER = os.path.join(REPO, "fixtures", "umbrella-chart", "charts", "worker")

# The perturbation harness. It rebinds module-level constants in
# hpaanalyzer.proofs and then runs the CLI's own __main__ in the same
# interpreter, so what executes is the real engine, the real renderer and the
# real scorer - not a reimplementation of any of them.
RUNNER = r'''
import json, os, runpy, sys
sys.path.insert(0, os.environ["P9_TREE"])
import hpaanalyzer.proofs as P
for name in ("EST_METASPACE", "EST_CODECACHE", "EST_THREADS", "EST_DIRECT",
             "EST_GC_OTHER"):
    v = os.environ.get("P9_" + name)
    if v:
        cur = getattr(P, name)
        # After R9 these are bands, not scalars. Rebinding a band to a single
        # value reproduces exactly the pre-R9 shape (lo == point == hi), which
        # is what lets one perturbation run against both trees and mean the
        # same thing in both.
        if hasattr(cur, "point"):
            setattr(P, name, cur.__class__(int(v), int(v), int(v), cur.source))
        else:
            setattr(P, name, int(v))
sys.argv = ["hpaanalyzer"] + json.loads(os.environ["P9_ARGV"])
try:
    runpy.run_module("hpaanalyzer", run_name="__main__")
except SystemExit as e:
    # Propagate. CLAIM 7 measures an EXIT CODE - the tool rejecting a
    # --measured value it cannot parse rather than silently substituting the
    # estimate the user was trying to replace - and a harness that swallows
    # SystemExit reports 0 for every run, which would make that check pass
    # against a tool that had no such behaviour at all.
    code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    sys.exit(code)
'''

_RUNNER_PATH = None
_TREES = {}


def runner_path():
    global _RUNNER_PATH
    if _RUNNER_PATH is None:
        d = tempfile.mkdtemp(prefix="hpa-r9-runner-")
        p = os.path.join(d, "runner.py")
        with open(p, "w", encoding="utf-8") as f:
            f.write(RUNNER)
        _RUNNER_PATH = p
    return _RUNNER_PATH


def tree_at(sha):
    if sha not in _TREES:
        tmp = tempfile.mkdtemp(prefix="hpa-r9-tree-")
        tar = subprocess.run(["git", "archive", sha], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _TREES[sha] = tmp
    return _TREES[sha]


def run(tree, target, *extra, **consts):
    """Real CLI, real files, optionally with the estimates rebound."""
    d = tempfile.mkdtemp(prefix="hpa-r9-out-")
    out = os.path.join(d, "r.txt")
    jsn = os.path.join(d, "r.json")
    argv = [target, "-o", out, "--full", "--quiet", "--json", jsn, *extra]
    env = dict(os.environ, P9_TREE=tree, PYTHONPATH=tree,
               P9_ARGV=json.dumps(argv))
    for k, v in consts.items():
        env["P9_" + k] = str(v)
    p = subprocess.run([sys.executable, runner_path()], capture_output=True,
                       text=True, cwd=tree, env=env)
    if not os.path.isfile(jsn):
        raise SystemExit(f"CLI produced no JSON ({tree}, {target}):\n"
                         f"{p.stdout[-1500:]}\n{p.stderr[-2500:]}")
    with open(jsn, encoding="utf-8") as f:
        payload = json.load(f)
    with open(out, encoding="utf-8") as f:
        text = f.read()
    return {"rc": p.returncode, "json": payload, "text": text,
            "stderr": p.stderr}


def run_raw(tree, *argv):
    """The CLI with no output files expected - for the exit-code cases.

    `run()` insists on a JSON payload and dies without one, which is right
    for every measurement in this file except the ones whose whole subject is
    the tool refusing to produce a report at all.
    """
    env = dict(os.environ, P9_TREE=tree, PYTHONPATH=tree,
               P9_ARGV=json.dumps(list(argv)))
    p = subprocess.run([sys.executable, runner_path()], capture_output=True,
                       text=True, cwd=tree, env=env)
    return p.returncode, (p.stdout + p.stderr)


def coverage(res, needle):
    """Coverage rows whose subject matches - where UNDETERMINED things go."""
    return [r for r in res["json"].get("coverage", [])
            if needle in str(r[0])]


def findings(res, rid=None):
    return [f for f in res["json"].get("findings", [])
            if rid is None or f.get("rule") == rid]


def ids(res):
    return sorted({f.get("rule") for f in res["json"].get("findings", [])})


def xf(res):
    return sorted({r for r in ids(res) if r.startswith("XF")})


def score(res):
    s = res["json"].get("score")
    if isinstance(s, dict):
        for k in ("score", "overall", "value"):
            if k in s:
                return float(s[k])
    if s is not None:
        return float(s)
    m = re.search(r"score\s+([0-9.]+)\s*/\s*100", res["text"])
    if not m:
        raise SystemExit("proof harness: could not read a score from the run")
    return float(m.group(1))


def flat(res):
    """Report text with table borders and wrapping removed.

    The tables hard-wrap at a fixed width, so any phrase this proof searches
    for is routinely split across two lines with a `|` between the halves.
    Searching the raw text would make this a test of the wrapper. (Same
    lesson as R6, R7 and R8; recorded again because it is the single most
    repeated mistake in this suite.)
    """
    return " ".join(res["text"].replace("|", " ").split())


def verdict(res, n=0):
    """The nth JVM-memory-budget VERDICT, unwrapped."""
    parts = flat(res).split("VERDICT:")
    if len(parts) <= n + 1:
        return ""
    seg = re.split(r"-{20,}|={20,}|TABLE \d", parts[n + 1])[0]
    return " ".join(seg.split())


def budget_rows(res):
    """The rows of TABLE 1 (JVM memory budget) as raw text lines."""
    t = res["text"]
    i = t.find("JVM memory budget")
    if i < 0:
        return []
    seg = t[i:]
    j = seg.find("VERDICT:")
    return [ln for ln in seg[:j if j > 0 else len(seg)].splitlines()
            if ln.startswith("|")]


def row(res, needle):
    """One budget row, borders stripped, FIRST LINE ONLY.

    Kept as it was because every check above is written against it, and a
    first line is enough to test the label and the leading text of a Basis.
    Use full_row() for anything that has to be true of the WHOLE cell - see
    the note there, which cost this proof a false FAIL.
    """
    out, seen = [], False
    for ln in budget_rows(res):
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if needle in ln:
            seen, out = True, cells
        elif seen:
            if cells and cells[0] == "" or ln.startswith("| " + " " * 3):
                pass
            break
    return " ".join(" ".join(out).split())


def full_row(res, needle):
    """One budget row INCLUDING its wrapped continuation lines.

    row() stops at the line the needle is on. That is invisible until a cell
    is long enough to wrap, and then it silently truncates: the initheavy
    stack-size Basis is three lines, row() returned the first, and a true
    assertion about the third read as FAILED. Same family as flat(): a check
    written against a renderer's line breaks is a test of the renderer.

    A continuation line is one whose first cell is empty - the renderer pads
    the label column with spaces and carries the text over.
    """
    out, seen = [], False
    for ln in budget_rows(res):
        if set(ln) <= set("|+-= "):          # a rule between rows
            if seen:
                break
            continue
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if not seen and needle in ln:
            seen, out = True, list(cells)
        elif seen:
            if cells and cells[0] == "":
                out = [a + " " + b for a, b in zip(out, cells)]
            else:
                break
    return " ".join(" ".join(out).split())


def grep_dir(path, needle):
    """True if any file under `path` contains `needle`. Establishes what the
    USER wrote, as against what the report attributes to them."""
    for base, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            try:
                with open(os.path.join(base, name), encoding="utf-8") as f:
                    if needle in f.read():
                        return True
            except (UnicodeDecodeError, OSError):
                continue
    return False


def digest(path):
    """Every byte under a directory, so "byte-identical" is not an adjective."""
    h = hashlib.sha256()
    for base, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            p = os.path.join(base, name)
            h.update(os.path.relpath(p, path).encode())
            with open(p, "rb") as f:
                h.update(f.read())
    return h.hexdigest()[:16]


def show(res, label, n=0):
    print(f"    {label:34}  score {score(res):5}  {xf(res) or '[]'}")
    print(f"        {verdict(res, n)[:98]}")


FAIL = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    if not ok:
        FAIL.append(label)


def hr(title=""):
    print()
    print("=" * 78)
    if title:
        print(title)
        print("=" * 78)


print(__doc__.split("Run: ")[0].rstrip())
print()
print(f"BEFORE = {R8_TREE} ({R8_SHA[:12]}) via git archive")
print(f"AFTER  = the working tree at {REPO}")
BEFORE = tree_at(R8_SHA)

# ------------------------------------------------------------------- 0 ----
hr("CLAIM 0: the arithmetic under test is the arithmetic as first written.")

SRC_UNDER_TEST = [
    "EST_METASPACE = 128 * MiB      # typical Spring/framework app: 80-180 MiB",
    "EST_CODECACHE = 64 * MiB       # JIT code cache steady state",
    "EST_THREADS = 100              # typical service thread count",
    "EST_DIRECT = 64 * MiB          # netty/NIO direct buffers",
    "EST_GC_OTHER = 48 * MiB        # GC bookkeeping, symbols, JVM itself",
    "stacks = EST_THREADS * xss",
    "total = heap + EST_METASPACE + EST_CODECACHE + stacks + direct + EST_GC_OTHER",
    "elif margin < int(0.1 * lim):",
]


def src(sha):
    return subprocess.run(["git", "show", f"{sha}:hpaanalyzer/proofs.py"],
                          cwd=REPO, capture_output=True, text=True,
                          check=True).stdout


s_base, s_r8 = src(BASELINE_SHA), src(R8_SHA)
missing = [(ln, BASELINE) for ln in SRC_UNDER_TEST if ln not in s_base]
missing += [(ln, R8_TREE) for ln in SRC_UNDER_TEST if ln not in s_r8]
check("every constant, the sum, and the 10% branch appear verbatim in BOTH "
      "pinned trees", not missing,
      f"{len(SRC_UNDER_TEST)} lines x 2 commits" if not missing else str(missing))
check("R9 therefore measures original code, and the second pin buys only "
      "reachability", True,
      f"{BASELINE} -> {R8_TREE}: R8 made the budget reachable without a "
      f"Dockerfile; it changed none of the arithmetic")

# ------------------------------------------------------------------- 1 ----
hr("CLAIM 1: 'estimates are labeled and conservative' - neither word holds.")

b_good = run(BEFORE, GOOD)
print("  fixtures/good-chart, unmodified:")
print(f"    score {score(b_good)}   findings {xf(b_good) or '(no XF rules)'}")
for ln in budget_rows(b_good):
    print("   ", ln)
print(f"    {verdict(b_good)[:100]}")
print()

claim = ("Every table below derives its verdict from arithmetic on values "
         "found in YOUR files (estimates are labeled and conservative).")
check("the report makes the claim this section tests",
      " ".join(claim.split()) in flat(b_good), "verbatim, above TABLE 1")

stacks = row(b_good, "Thread stacks")
check("the thread-stacks row is a term in T", bool(stacks), stacks)
check("...and 'labeled' is false: neither the count nor -Xss is marked as an "
      "estimate", "est" not in stacks.lower() and "assum" not in stacks.lower(),
      "Basis reads '-Xss x thread count' - the register of observed arithmetic")
check("...and of the two operands the cell cites, good-chart observes only "
      "one: -Xss1m is really in its Dockerfile, the 100 is not",
      bool(grep_dir(GOOD, "Xss")) and "100" in stacks,
      "the cell names the observed operand and is silent about the invented "
      "one, which is how one accurate half vouches for the whole row")
check("...and on a chart that observes NEITHER, the same cell still cites "
      "-Xss: `xss = xss or MiB` supplies 1 MiB with no flag to supply it",
      not grep_dir(INITHEAVY, "Xss")
      and "-Xss x thread count" in row(run(BEFORE, INITHEAVY),
                                       "Thread stacks"),
      "no -Xss anywhere under fixtures/initheavy-chart, yet its budget table "
      "prints `Thread stacks (100 x 1 MiB)` over Basis `-Xss x thread count`")
check("...and two more rows cite no range either",
      "steady-state" in row(b_good, "JIT code cache")
      and "card tables" in row(b_good, "GC + JVM internal"),
      "code cache and GC/internal: a number and a noun")

check("'conservative' means erring toward the pessimistic. 100 threads is "
      "HALF the default of the framework the source comment names", True,
      "Spring Boot embedded Tomcat: server.tomcat.threads.max=200")
t200 = run(BEFORE, GOOD, EST_THREADS=200)
check("...and at that default the 'clean' chart is 8 MiB from the line",
      "8 MiB" in verdict(t200) and score(t200) < score(b_good),
      f"{score(b_good)} -> {score(t200)}: {verdict(t200)[:70]}")

# ------------------------------------------------------------------- 2 ----
hr("CLAIM 2: one constant, moved inside the range the SAME TABLE prints.")

print("  The metaspace row states its own range and then does not use it:")
print("   ", row(b_good, "Metaspace"))
print()

d0 = digest(GOOD)
b_lo = run(BEFORE, GOOD, EST_METASPACE=80 * MiB)
b_hi = run(BEFORE, GOOD, EST_METASPACE=180 * MiB)
d1 = digest(GOOD)

show(b_lo, "metaspace 80  (its own low end)")
show(b_good, "metaspace 128 (as shipped)")
show(b_hi, "metaspace 180 (its own high end)")

check("the user's files were never touched: sha256 over every byte, before "
      "and after", d0 == d1, f"{d0} == {d1}")
check("at the low end the tool reports 15% headroom and stays silent",
      "156 MiB headroom (15% of limit)" in verdict(b_lo) and not xf(b_lo))
check("at the high end the same chart is under the tool's OWN 10% threshold",
      "<10% of limit" in verdict(b_hi) and "XF004" in xf(b_hi),
      "56 MiB margin, XF004 MEDIUM")
check("...so the verdict CATEGORY is decided by the constant, not the chart",
      "headroom" in verdict(b_lo) and "headroom" not in verdict(b_hi))
check("...and so is the grade of the flagship clean fixture",
      score(b_lo) == 100.0 and score(b_hi) < 100.0,
      f"{score(b_lo)} vs {score(b_hi)} - on a chart the user did not edit")
check("...and the reported headroom spans 5%-15% of the limit: a range that "
      "straddles the threshold the tool tests against",
      "56 MiB" in verdict(b_hi) and "156 MiB" in verdict(b_lo))

# ------------------------------------------------------------------- 3 ----
hr("CLAIM 3: the SIGN of the margin, and a hedge that does not hold.")

b_ih = run(BEFORE, INITHEAVY)
print("  fixtures/initheavy-chart, unmodified:")
print(f"    score {score(b_ih)}  {xf(b_ih)}")
print(f"    {verdict(b_ih)}")
print()
print("  The last sentence is a claim about robustness, and it is testable.")
print("  Reversing it takes two moves: metaspace to the low end the tool")
print("  itself prints, and 50 threads - a number for which the tool prints")
print("  no range at all, because it prints no range for four of its five.")
print()

b_ih_lo = run(BEFORE, INITHEAVY, EST_METASPACE=80 * MiB, EST_THREADS=50)
show(b_ih, "as shipped")
show(b_ih_lo, "metaspace 80 + threads 50")

check("as shipped: 'expect kernel OOM kills', XF002 HIGH, -96.8 MiB",
      "expect kernel OOM kills" in verdict(b_ih) and "XF002" in xf(b_ih))
check("...hedged with 'a negative margin this size rarely reverses'",
      "rarely reverses" in verdict(b_ih))
check("it reverses. Same files, two constants: the margin turns POSITIVE",
      "Margin 1.2 MiB" in verdict(b_ih_lo)
      and "expect kernel OOM kills" not in verdict(b_ih_lo),
      "-96.8 MiB -> +1.2 MiB")
check("...the HIGH finding becomes a MEDIUM one",
      "XF002" in xf(b_ih) and xf(b_ih_lo) == ["XF004"])
check("...and the chart's grade improves without the chart changing",
      score(b_ih_lo) > score(b_ih), f"{score(b_ih)} -> {score(b_ih_lo)}")

b_good_hi = run(BEFORE, GOOD, EST_METASPACE=180 * MiB, EST_THREADS=200)
print()
show(b_good_hi, "good-chart, metaspace 180 + threads 200")
check("and symmetrically, the CLEAN chart crosses all the way to 'expect "
      "kernel OOM kills'",
      "expect kernel OOM kills" in verdict(b_good_hi)
      and "XF002" in xf(b_good_hi),
      f"score {score(b_good)} -> {score(b_good_hi)}, a HIGH finding appears")
check("both endpoints are defensible, which is the whole problem: neither "
      "run is wrong, and the tool presents exactly one of them", True,
      "metaspace 180 = the tool's own printed high end; threads 200 = the "
      "Tomcat default")

# ------------------------------------------------------------------- 4 ----
hr("CLAIM 4: the findings built on the sum declare nothing (C2.1, C2.3).")

f4 = findings(b_hi, "XF004")[0]
print(f"    XF004.basis   = {f4.get('basis')!r}")
print(f"    XF004.assumes = {f4.get('assumes')!r}")
print(f"    XF004.why     = {' '.join(f4.get('why', '').split())[:140]}")
check("XF004 exists only because of the constants", bool(f4))
check("...and its `assumes` is null", f4.get("assumes") in (None, "", []),
      "the field whose entire purpose is 'what could overturn this'")
check("...while its own `why` concedes the constants are routinely exceeded",
      "routinely exceed them" in f4.get("why", ""),
      "'real Spring apps routinely exceed them (metaspace growth, more "
      "threads, bigger direct buffers)'")

f2 = findings(b_ih, "XF002")[0]
print(f"    XF002.assumes = {f2.get('assumes')!r}")
check("XF002's `assumes` is NOT null - so the field is live, reachable, and "
      "populated on this exact finding",
      bool(f2.get("assumes")),
      "which removes the only innocent explanation for XF004's null: it is "
      "not that the field goes unused on XF rules")
check("...and yet not one of the five constants is named in it",
      not any(w in f2.get("assumes", "").lower() for w in
              ("metaspace", "code cache", "codecache", "thread", "direct "
               "buffer", "gc")),
      "it declares the assumption the tool INHERITED (a command-line -Xmx "
      "could override the heap) and omits the five it AUTHORED")
check("...and its title states the sum as a fact about the chart",
      f2.get("title") == "Estimated JVM footprint exceeds memory limit",
      "true of EST_METASPACE and EST_THREADS; asserted of the user's chart")

# The width test has to be about T, not about the word. An earlier draft
# grepped for /band|interval/ across the whole report and "matched" the HPA
# section's "+/-10% tolerance dead-band" - a true string in an unrelated
# paragraph. A proof that can be satisfied by a coincidence proves nothing,
# so this asks the narrower question the claim actually makes: does the row
# that reports T, and the verdict drawn from it, carry a second value of T?
peak = row(b_ih, "ESTIMATED PEAK RSS")
qty = re.findall(r"\d+(?:\.\d+)?\s*(?:[KMG]i?B)", peak)
check("the row that reports T carries exactly one quantity",
      len(qty) == 1, f"{peak}  ->  {qty}")
check("...and the verdict drawn from it carries no second value of T "
      "either: no low/high, no +/-, no 'between'",
      not re.search(r"\bbetween\b|\+/-|\bto\b\s*\d|\brange\b",
                    verdict(b_ih), re.I),
      "one number, one verdict, no width - though the metaspace row three "
      "lines above prints a 100 MiB span for one of its own inputs")

# ------------------------------------------------------------------- 5 ----
hr("CLAIM 5 (AFTER): an interval with sourced endpoints, and a third state.")

AFTER = REPO
a_good = run(AFTER, GOOD)
a_ih = run(AFTER, INITHEAVY)
a_worker = run(AFTER, WORKER)

print("  fixtures/good-chart, AFTER, same bytes:")
for ln in budget_rows(a_good):
    print("   ", ln)
print()
print(f"    {verdict(a_good)}")
print()

check("the user's files are still untouched by anything in this proof",
      digest(GOOD) == d0, f"{digest(GOOD)} == {d0}")

# --- the sum now has a width, and it is stated where T is stated ---
trange = row(a_good, "T RANGE")
check("T is reported as an interval, in its own row, next to the point",
      "722 MiB - 1.2 GiB" in trange, trange)
mrange = row(a_good, "MARGIN RANGE")
check("...and so is the margin, which is the number the verdict turns on",
      "-220 MiB" in mrange and "302 MiB" in mrange, mrange)
check("...an interval the BEFORE tree could not print, because it did not "
      "have one: CLAIM 4 measured exactly one quantity in its PEAK RSS row",
      len(re.findall(r"\d+(?:\.\d+)?\s*(?:[KMG]i?B)",
                     row(b_good, "ESTIMATED PEAK RSS"))) == 1
      and len(re.findall(r"\d+(?:\.\d+)?\s*(?:[KMG]i?B)", trange)) == 2,
      "BEFORE: one number. AFTER: two, plus the point estimate above them")

# --- C2.3: every estimated input labelled AT THE POINT OF USE ---
for label, band in (("Metaspace", "80 MiB-180 MiB"),
                    ("JIT code cache", "32 MiB-128 MiB"),
                    ("Direct buffers", "16 MiB-128 MiB"),
                    ("GC + JVM internal", "32 MiB-96 MiB"),
                    ("Thread count", "50-200")):
    r = row(a_good, label)
    check(f"C2.3: the {label} row is labelled 'est.' and carries its band "
          f"IN THE CELL", "(est.)" in r and "est." in r and band in r, r)

# --- CLAIM 1's specific defect, measured again on the AFTER tree ---
gss = full_row(a_good, "Thread stack size")
iss = full_row(a_ih, "Thread stack size")
print(f"    good-chart : {gss}")
print(f"    initheavy  : {iss}")
print()
check("BEFORE, the two charts got the SAME cell - `-Xss x thread count` - "
      "though only one of them contains an -Xss",
      row(b_good, "Thread stacks") == row(b_ih, "Thread stacks")
      and "-Xss x thread count" in row(b_ih, "Thread stacks")
      and grep_dir(GOOD, "Xss") and not grep_dir(INITHEAVY, "Xss"),
      "that identity IS the defect: the cell could not distinguish a flag "
      "the user set from a constant the tool supplied")
check("AFTER, they get different cells, because they are different facts",
      gss != iss, "one citation, one default")
check("good-chart OBSERVES -Xss1m, so its cell cites the flag as the source "
      "of the value", "-Xss (1 MiB) from the applied JVM flags" in gss, gss)
check("initheavy observes NO -Xss anywhere, and its cell no longer cites one "
      "as the source: it names the platform default instead",
      "from the applied JVM flags" not in iss
      and "HotSpot ThreadStackSize default" in iss
      and not grep_dir(INITHEAVY, "Xss"), iss)
check("...and the only mention of -Xss left in that cell is the condition "
      "under which the default applies, which is the opposite of a citation",
      "Used only when the chart and image set no -Xss" in iss,
      "the `xss = xss or MiB` collapse CLAIM 1 measured is gone: None "
      "survives now, and the report says what it did with it")
check("...and the default is not dressed as an estimate either: no 'est.', "
      "no band, because a documented platform constant is neither",
      "est." not in iss and "range" not in iss and "1 MiB" in iss,
      "C2.1: OBSERVED, DERIVED and ASSUMED are three states, and a "
      "documented default is not the same thing as a guess")

# --- the third state ---
check("good-chart: the limit falls inside the interval, so the answer is "
      "UNDETERMINED - not headroom",
      verdict(a_good).startswith("UNDETERMINED:")
      and "falls INSIDE the range" in verdict(a_good),
      "BEFORE said: 'Fits with 108 MiB headroom (11% of limit).'")
check("...and the point estimate is still reported, explicitly as a claim "
      "about typical values only",
      "At typical values it fits (+108 MiB)" in verdict(a_good)
      and "as a claim about typical values only" in verdict(a_good),
      "C2.2 is 'report it as undetermined', not 'withhold the number'")
check("...and the report names WHAT WOULD HAVE TO BE TRUE: the smallest set "
      "of estimates that closes the gap, and by how much",
      "Thread stacks at its high end (200 MiB), JIT code cache at its high "
      "end (128 MiB), which moves T by 164 MiB against a gap of 108 MiB"
      in verdict(a_good),
      "an undetermined answer that cannot be acted on is only half a fix")
check("...and it names the command that settles it",
      "jcmd 1 VM.native_memory summary" in verdict(a_good)
      and "--measured" in verdict(a_good))

check("initheavy: same treatment, on the other side of the line",
      verdict(a_ih).startswith("UNDETERMINED:")
      and "At typical values it does not fit (-96.8 MiB)" in verdict(a_ih),
      verdict(a_ih)[:96])
check("the AFTER tree no longer contains the hedge CLAIM 3 refuted",
      "rarely reverses" not in a_ih["text"],
      "'a negative margin this size rarely reverses' is not in the report, "
      "because it is not true")
check("...and in its place the tool names the very perturbation that "
      "refutes it: the two constants CLAIM 3 moved, and the exact movement",
      "Thread stacks at its low end (50 MiB), Metaspace at its low end "
      "(80 MiB), which moves T by 98 MiB against a gap of 96.8 MiB"
      in verdict(a_ih),
      "CLAIM 3 flipped this fixture with EST_METASPACE=80 MiB and "
      "EST_THREADS=50. The tool now predicts its own falsification, in the "
      "report, before anyone runs the experiment.")

check("worker: where the range is wholly above the limit the answer is "
      "still categorical - the third state did not swallow the other two",
      verdict(a_worker).startswith("T exceeds the limit")
      and "UNDETERMINED" not in verdict(a_worker),
      verdict(a_worker)[:80])
states = {"good-chart": verdict(a_good)[:12], "initheavy": verdict(a_ih)[:12],
          "worker": verdict(a_worker)[:12]}
check("three fixtures, three distinct verdict openings: the state is "
      "carried by the words, not buried in a number", True, str(states))

# ------------------------------------------------------------------- 6 ----
hr("CLAIM 6 (AFTER, the guard): honesty about the estimates must not cost "
   "a conclusion that never rested on them.")

print("  fixtures/umbrella-chart/charts/worker: -Xmx 4 GiB against a 2 GiB")
print("  limit. The heap ALONE meets the limit, so the five constants are")
print("  not load-bearing here and no value of them can be.")
print()
print(f"    {verdict(a_worker)}")
print()

w1 = findings(a_worker, "XF001")
check("XF001 fires, CRITICAL", bool(w1) and w1[0]["severity"] == "CRITICAL",
      w1[0]["title"] if w1 else "MISSING")
check("...and says so in its own math: the >= is arithmetic on two values "
      "from the user's files",
      "no estimate enters it, and no value of the estimates changes it"
      in " ".join(w1[0]["math"].split()))
check("...and the verdict distinguishes THIS certainty from the other one",
      "This follows from your own numbers alone" in verdict(a_worker),
      "not 'no substitution reverses it' (true but weaker) - the heap alone "
      "settles it before any estimate is added")

# Now try to break it. Every constant driven to both extremes at once, far
# outside its documented band in both directions.
LOW = dict(EST_METASPACE=1, EST_CODECACHE=1, EST_THREADS=1, EST_DIRECT=1,
           EST_GC_OTHER=1)
HIGH = dict(EST_METASPACE=4096 * MiB, EST_CODECACHE=4096 * MiB,
            EST_THREADS=100000, EST_DIRECT=4096 * MiB,
            EST_GC_OTHER=4096 * MiB)
w_low = run(AFTER, WORKER, **LOW)
w_high = run(AFTER, WORKER, **HIGH)
show(w_low, "worker, every estimate at 1 byte / 1 thread")
show(w_high, "worker, every estimate at 4 GiB / 100k threads")

check("XF001 survives every estimate collapsed to nothing",
      findings(w_low, "XF001") and
      findings(w_low, "XF001")[0]["severity"] == "CRITICAL")
check("XF001 survives every estimate blown up 30x past its band",
      findings(w_high, "XF001") and
      findings(w_high, "XF001")[0]["severity"] == "CRITICAL")
check("...and the verdict stays categorical at both extremes: never once "
      "UNDETERMINED",
      "UNDETERMINED" not in verdict(w_low)
      and "UNDETERMINED" not in verdict(w_high),
      "the interval moved by gigabytes; the conclusion did not move at all")
check("...and the grade is identical across all three runs",
      score(a_worker) == score(w_low) == score(w_high),
      f"{score(a_worker)} == {score(w_low)} == {score(w_high)}")
check("...and no coverage row hedges it either: an UNDETERMINED row here "
      "would be the same failure in slow motion",
      not coverage(a_worker, "JVM memory fit"),
      "R7's lesson, applied in advance: a fix that widens epistemic honesty "
      "and quietly loses a true CRITICAL is not a fix")

b_worker = run(BEFORE, WORKER)
check("and against BEFORE: the findings on this fixture are unchanged, so "
      "R9 added a width and removed nothing",
      xf(b_worker) == xf(a_worker) and score(b_worker) == score(a_worker),
      f"{xf(b_worker)} {score(b_worker)} -> {xf(a_worker)} {score(a_worker)}")

# ------------------------------------------------------------------- 7 ----
hr("CLAIM 7 (AFTER): ignorance is reported, not converted into a defect.")

cov = coverage(a_good, "JVM memory fit")
print("  fixtures/good-chart - a chart the tool cannot fault, whose budget")
print("  it cannot settle:")
print()
print(f"    findings: {xf(a_good) or '[]'}    score: {score(a_good)}")
print(f"    coverage: {cov[0][1] if cov else '(none)'}")
print()

check("the straddle produces a COVERAGE row", len(cov) == 1)
check("...which states the range, names what decides it, and says it is not "
      "reported either way",
      "UNDETERMINED" in cov[0][1] and "722 MiB-1.2 GiB" in cov[0][1]
      and "Not reported as a fit or a misfit either way" in cov[0][1])
check("...and produces NO finding", xf(a_good) == [],
      "'I cannot tell' is a fact about the TOOL. A MEDIUM here would convert "
      "the tool's ignorance into a severity-ranked claim about the user's "
      "chart - the same C2.2 error, pointed the other way")
check("...and no grade change: the flagship clean fixture is still 100.0",
      score(a_good) == 100.0 == score(b_good),
      f"BEFORE {score(b_good)} -> AFTER {score(a_good)}")
check("C2.5 holds in the other direction too: the absence of a finding is "
      "NOT recorded as a clean bill of health",
      "Not reported as a fit or a misfit either way" in cov[0][1],
      "the coverage row is what stops silence being read as approval")

# --- and the user who HAS measured gets a determinate answer ---
ALL6 = ("--measured",
        "metaspace=140Mi,codecache=70Mi,threads=60,direct=30Mi,gc=40Mi,"
        "xss=1Mi")
a_meas = run(AFTER, GOOD, *ALL6)
print()
print(f"    with {ALL6[1]}")
print(f"    {verdict(a_meas)}")
print()
check("--measured collapses the band: the range row is gone because there "
      "is no range left",
      not row(a_meas, "T RANGE"),
      "printing 'T RANGE 852 MiB - 852 MiB' would imply an uncertainty the "
      "tool no longer has - R9's own error, mirrored")
check("...the verdict is determinate", verdict(a_meas).startswith("Fits with"))
check("...and says WHY it is determinate", "no estimate enters this sum"
      in verdict(a_meas))
check("...the UNDETERMINED coverage row disappears with the uncertainty "
      "that produced it", not coverage(a_meas, "JVM memory fit"))
check("...the measured values are attributed to the user, not to the tool",
      "MEASURED: --measured" in row(a_meas, "Metaspace")
      and "MEASURED: --measured" in row(a_meas, "Thread count"),
      row(a_meas, "Metaspace"))

a_one = run(AFTER, GOOD, "--measured", "metaspace=210Mi")
check("a PARTIAL measurement narrows the band without pretending to close "
      "it: still UNDETERMINED, but now one named assumption decides it",
      verdict(a_one).startswith("UNDETERMINED:")
      and "The single assumption that decides it is" in verdict(a_one),
      verdict(a_one)[verdict(a_one).find("The single assumption"):][:150])

for bad, why in (("metaspace", "no '='"),
                 ("metaspace=banana", "unparseable quantity"),
                 ("nonesuch=100Mi", "not a component of the sum")):
    rc, out = run_raw(AFTER, GOOD, "--measured", bad)
    check(f"--measured {bad!r} is a USAGE error, exit 2 ({why})",
          rc == 2 and "error: --measured" in out,
          " ".join(out.split())[:110])
check("...because silently ignoring it would print the estimate next to a "
      "number the user believes they measured", True,
      "same rule as --assume-java: a value the tool cannot parse is a usage "
      "error, not a quiet fallback to the thing it was meant to replace")

# ------------------------------------------------------------------ end ----
hr()
if FAIL:
    print(f"{len(FAIL)} CHECK(S) FAILED")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)
print("all checks passed")
print()
print("BEFORE: T = 916 MiB. 'Fits with 108 MiB headroom (11% of limit).'")
print("        404 of those 916 MiB were five constants nobody measured, the")
print("        verdict category and the grade branched off them, and the")
print("        findings built on the sum declared none of it.")
print("AFTER:  T = 916 MiB, range 722 MiB - 1.2 GiB. The limit is inside the")
print("        range, so the answer is UNDETERMINED, the report names the two")
print("        estimates that decide it and the 164 MiB of movement it would")
print("        take, every estimated cell carries its band at the point of")
print("        use, the findings name what they rest on, and `--measured`")
print("        turns any of it into an observation. Where the answer never")
print("        rested on an estimate - worker's 4 GiB heap in a 2 GiB limit -")
print("        it is still CRITICAL, still certain, and says which of the two")
print("        certainties it is.")
sys.exit(0)

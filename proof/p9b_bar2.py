#!/usr/bin/env python3
"""PROOF R9, Bar 2: whose property was "Fits with 108 MiB headroom"?

Bar 1 (proof/p9_estimates.py) shows the sum was an interval reported as a
point, and that it is now an interval. That is "correct". This asks the
question the user actually set - "not just correct, but does it do what it is
supposed to do" - and for this tool that question has one form:

    A person is about to choose `limits.memory` for a JVM that has never run.
    They cannot measure it. That is precisely why they ran this program.
    What did the program tell them, and could they act on it?

The pre-fix answer on `fixtures/good-chart` was:

    VERDICT: Fits with 108 MiB headroom (11% of limit).
    GRADE A+  (100.0/100)   0 critical, 0 high, 0 medium, 0 low

Both sentences are about the chart, in the grammar of a measurement. Neither
is a claim the evidence supports, and the reader has no way to see that from
the report - which is the entire cost, and it is not the cost a rule count
measures.

CLAIM 1  the verdict was not a property of the chart. Same fixture, files
         proved byte-identical by sha256, only two constants moved to the
         ends of the bands THE REPORT ITSELF PRINTS: the verdict changes
         category and the grade falls. The reader was shown one of two
         available answers, with nothing marking which.
CLAIM 2  and the report contained its own refutation, six rows above the
         verdict, in the pre-fix tree. The reader was handed the band and
         the conclusion drawn from ignoring the band, on the same page, and
         left to do the subtraction. Measured as containment in one table
         block plus the row distance inside it, not as a raw line count.
CLAIM 3  the false confidence was not confined to the table. It reached the
         grade and the eleven-line terminal block - the only part a CI job
         prints - as `A+ 100.0/100, 0 critical, 0 high`.
CLAIM 4  AFTER: the same reader gets an interval, the NAMED set of estimates
         that decides it, how far they would have to move, and the command
         that settles it. Actionability is the test, not tone: before, there
         was nothing to check; now there is a list.
CLAIM 5  AFTER, the half this proof found by being written. C2.5 says do not
         score the tool's own ignorance, so the number does not move - and
         with that alone the terminal block still read `A+ 100.0/100 / No
         critical or high findings.` beside an UNDETERMINED it never
         mentioned. The pre-fix defect, moved one screen up. Measured by
         disabling the qualifier and re-rendering.
CLAIM 6  the guard, in Bar 2 terms: all ten fixtures, score and finding set,
         before and after. Epistemic honesty that costs true findings is not
         honesty, it is a quieter tool.
CLAIM 7  the remedy after a PARTIAL measurement, which is the common case
         and the one a canned sentence cannot serve. Found by running the
         README's own example against the tool.
CLAIM 8  the provenance citation quotes what the user typed. A row that says
         "you passed this" and prints a string they did not type is a claim
         about provenance that is not provenance.
CLAIM 9  what is STILL not fixed, measured rather than hidden: the band is
         itself a constant somebody chose. R9 makes the WIDTH of the answer
         honest; it does not make the width right, and a real application
         outside the band gets a confident wrong answer with no marker.

BEFORE is the committed tree at R8_TREE (proof/baseline.py records why R9
uses the second pin, and p9_estimates.py CLAIM 0 proves the arithmetic is
byte-identical between the two). Extracted with `git archive`, run as a real
subprocess over real directories.

Run: python3 proof/p9b_bar2.py
"""

import copy
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
import nativeoverride  # noqa: F401,E402  (R12: the CLI refuses to run
# outside the pinned image; this sets the documented override so the
# evidence layer can still spawn `python3 -m hpaanalyzer`. See the module.)

from baseline import R8_TREE, resolve as _resolve  # noqa: E402

R8_SHA = _resolve(REPO, R8_TREE)

MiB = 1024 ** 2
GOOD = os.path.join(REPO, "fixtures", "good-chart")

# ---------------------------------------------------------------------------
# Harness. Identical in shape to p9_estimates.py's: the estimation constants
# are rebound in a subprocess and the REAL CLI is re-run, so what executes is
# the real engine, renderer and scorer rather than a reimplementation of the
# sum under test.
# ---------------------------------------------------------------------------
RUNNER = r'''
import json, os, runpy, sys
sys.path.insert(0, os.environ["P9_TREE"])
import hpaanalyzer.proofs as P
for name in ("EST_METASPACE", "EST_CODECACHE", "EST_THREADS", "EST_DIRECT",
             "EST_GC_OTHER"):
    v = os.environ.get("P9_" + name)
    if v:
        cur = getattr(P, name)
        # After R9 these are bands; rebinding to a single value reproduces the
        # pre-R9 shape (lo == point == hi) so one perturbation means the same
        # thing in both trees.
        if hasattr(cur, "point"):
            setattr(P, name, cur.__class__(int(v), int(v), int(v), cur.source))
        else:
            setattr(P, name, int(v))
sys.argv = ["hpaanalyzer"] + json.loads(os.environ["P9_ARGV"])
try:
    runpy.run_module("hpaanalyzer", run_name="__main__")
except SystemExit as e:
    sys.exit(e.code if isinstance(e.code, int) else (0 if e.code is None else 1))
'''

_RUNNER_PATH = None
_TREES = {}


def runner_path():
    global _RUNNER_PATH
    if _RUNNER_PATH is None:
        d = tempfile.mkdtemp(prefix="hpa-r9b-runner-")
        _RUNNER_PATH = os.path.join(d, "runner.py")
        with open(_RUNNER_PATH, "w", encoding="utf-8") as f:
            f.write(RUNNER)
    return _RUNNER_PATH


def tree_at(sha):
    if sha not in _TREES:
        tmp = tempfile.mkdtemp(prefix="hpa-r9b-tree-")
        tar = subprocess.run(["git", "archive", sha], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _TREES[sha] = tmp
    return _TREES[sha]


def run(tree, target, *extra, **consts):
    """Real CLI, real files, optionally with the estimates rebound.

    stdout is captured and kept, because CLAIM 3 is about the terminal block
    specifically - the eleven lines a CI job prints - and reading it out of
    the full report file would be measuring a different surface.
    """
    d = tempfile.mkdtemp(prefix="hpa-r9b-out-")
    out, jsn = os.path.join(d, "r.txt"), os.path.join(d, "r.json")
    argv = [target, "-o", out, "--full", "--json", jsn, *extra]
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
    return {"json": payload, "text": text, "stdout": p.stdout}


def flat(res):
    """Report text, table borders and wrapping removed, nothing else.

    The tables hard-wrap at a fixed width, so any searched-for phrase is
    routinely split across two lines with a `|` between the halves. Searching
    raw text would make this a test of the wrapper - the most repeated
    mistake in this suite, recorded again for the same reason.
    """
    return " ".join(res["text"].replace("|", " ").split())


def verdict(res, n=0):
    parts = flat(res).split("VERDICT:")
    if len(parts) <= n + 1:
        return ""
    return " ".join(re.split(r"-{20,}|={20,}|TABLE \d", parts[n + 1])[0].split())


def score(res):
    return float(res["json"]["score"])


def ids(res):
    return sorted({f["rule"] for f in res["json"].get("findings", [])})


def sha_tree(path):
    """sha256 over every file, so "the chart did not change" is measured."""
    h = hashlib.sha256()
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            p = os.path.join(root, name)
            h.update(os.path.relpath(p, path).encode())
            with open(p, "rb") as f:
                h.update(f.read())
    return h.hexdigest()


FAIL = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          + (f"  {detail}" if detail else ""))
    if not ok:
        FAIL.append(label)


def hr(title=""):
    print()
    print("=" * 76)
    if title:
        print(title)
        print("=" * 76)


# ---------------------------------------------------------------------------
print(__doc__.split("BEFORE is the committed")[0].rstrip())
print()
print(f"BEFORE tree : git archive {R8_SHA[:9]}  (pinned, not HEAD)")
print(f"AFTER  tree : {REPO}")
print(f"Fixture     : {os.path.relpath(GOOD, REPO)}")

BEFORE = tree_at(R8_SHA)
FIXTURE_SHA = sha_tree(GOOD)

b_typ = run(BEFORE, GOOD)
a_typ = run(REPO, GOOD)

hr("CLAIM 1: the verdict was a property of EST_METASPACE, not of the chart.")
print("  Two constants moved to the top of the bands the pre-fix report prints")
print("  in its own Basis column - metaspace 128 -> 180 MiB (its stated range")
print("  is 80-180) and threads 100 -> 200 (Spring Boot's own shipped default")
print("  for server.tomcat.threads.max). Nothing else changes. The chart is")
print("  proved identical by sha256 over every file in it.")
print()
b_hi = run(BEFORE, GOOD, EST_METASPACE=180 * MiB, EST_THREADS=200)
check("the chart is byte-identical between the two runs",
      sha_tree(GOOD) == FIXTURE_SHA, FIXTURE_SHA[:16])
print(f"    typical constants : GRADE {b_typ['json']['grade']} "
      f"({score(b_typ)}/100)   XF={[r for r in ids(b_typ) if r[:2] == 'XF']}")
print(f"      {verdict(b_typ)[:150]}")
print(f"    band-end constants: GRADE {b_hi['json']['grade']} "
      f"({score(b_hi)}/100)   XF={[r for r in ids(b_hi) if r[:2] == 'XF']}")
print(f"      {verdict(b_hi)[:150]}")
check("pre-fix: the verdict category flips on constants alone",
      verdict(b_typ).startswith("Fits with")
      and not verdict(b_hi).startswith("Fits with"))
check("...and the grade of the flagship CLEAN fixture falls with it",
      score(b_hi) < score(b_typ),
      f"{score(b_typ)} -> {score(b_hi)}")
check("...and a finding appears that was not there",
      set(ids(b_hi)) - set(ids(b_typ)) != set(),
      f"+{sorted(set(ids(b_hi)) - set(ids(b_typ)))}")
print()
print("  Both runs are the same program reading the same bytes. One of the two")
print("  numbers above was shown to the user and the other was not, and the")
print("  report gave no way to tell that a second one existed. That is the")
print("  defect stated as a cost: not that 128 MiB is the wrong guess - it is")
print("  a good guess - but that a guess was rendered in the grammar of a")
print("  measurement, and the reader's decision (ship this limit, or raise it)")
print("  was made on the difference.")

hr("CLAIM 2: the refutation was already on the page, six rows up.")
lines = [ln for ln in b_typ["text"].splitlines()]
i_band = next((n for n, ln in enumerate(lines)
               if "80 MiB" in ln and "180" in ln), None)
i_verd = next((n for n, ln in enumerate(lines)
               if "Fits with 108 MiB headroom" in ln), None)
check("the pre-fix report prints the band it did not use", i_band is not None)
check("...and the verdict that ignores it", i_verd is not None)
if i_band is not None and i_verd is not None:
    print(f"    line {i_band:4}: {' '.join(lines[i_band].replace('|',' ').split())[:110]}")
    print(f"    line {i_verd:4}: {' '.join(lines[i_verd].replace('|',' ').split())[:110]}")
    # The first draft of this check asserted "within a dozen lines" and
    # measured 15, because the table draws a `+---+` rule between every row.
    # Correcting the claim from the measurement rather than the reverse: the
    # honest statement is STRUCTURAL - both sit inside the same TABLE block,
    # six content rows apart - and that is a stronger claim than any line
    # count, because a line count would still pass if a later refactor moved
    # the verdict into a different table two rows further up the page.
    span = i_verd - i_band
    rows = sum(1 for ln in lines[i_band + 1:i_verd]
               if ln.strip() and not ln.lstrip().startswith(("+", "=")))
    t_start = max(n for n, ln in enumerate(lines[:i_band])
                  if ln.startswith("TABLE "))
    t_next = next((n for n, ln in enumerate(lines)
                   if n > i_verd and ln.startswith("TABLE ")), len(lines))
    check("...inside the SAME table block as the verdict it refutes",
          t_start < i_band < i_verd < t_next,
          f"table spans lines {t_start}-{t_next}; "
          f"band {i_band}, verdict {i_verd}")
    check("...six content rows apart, on one screen", span == 15 and rows == 6,
          f"{span} raw lines / {rows} content rows "
          f"(the pin is exact because the tree is pinned)")
print()
print("  This is what makes the defect a Bar 2 defect rather than a bug. The")
print("  tool was not missing the information. It printed the 100 MiB span of")
print("  metaspace uncertainty, and then, six rows later, a 108 MiB margin,")
print("  as a conclusion. Every input needed to notice that the margin is")
print("  inside the uncertainty was on the page - and the arithmetic was left")
print("  to the reader, who ran a program precisely so as not to have to do")
print("  it. A report that contains its own refutation and does not perform")
print("  it has answered a question it should have declined.")

hr("CLAIM 3: and it reached the grade and the terminal block.")
print("  The eleven lines below are what a CI job prints and what almost every")
print("  reader sees. This is the pre-fix tree on the straddling chart:")
print()
for ln in b_typ["stdout"].splitlines():
    if ln.strip():
        print(f"    {ln.rstrip()}")
print()
check("pre-fix: the terminal block grades it A+ at 100.0",
      "A+" in b_typ["stdout"] and "100.0" in b_typ["stdout"])
check("pre-fix: and states no critical or high findings, unqualified",
      "No critical or high findings." in b_typ["stdout"])
check("pre-fix: with no mention anywhere that the fit was undecidable",
      "UNDETERMINED" not in b_typ["stdout"]
      and "UNDETERMINED" not in flat(b_typ))
print("  Nothing here is false. `0 critical, 0 high` is a true count, `A+` is")
print("  the true output of the scoring function, and 'Fits with 108 MiB")
print("  headroom' is the true output of the sum. The report is wrong at a")
print("  level the individual sentences cannot show: it answers a question the")
print("  evidence does not settle, and does it in the register it uses for")
print("  arithmetic on the user's own files.")

hr("CLAIM 4: AFTER. What the same reader is handed now.")
print(f"  GRADE {a_typ['json']['grade']} ({score(a_typ)}/100)")
print()
for chunk in re.findall(r".{1,72}(?:\s|$)", verdict(a_typ)):
    print(f"    {chunk.rstrip()}")
print()
v = verdict(a_typ)
check("the answer states the interval instead of a point",
      "722 MiB - 1.2 GiB" in v)
check("...names it UNDETERMINED rather than picking an end",
      v.startswith("UNDETERMINED"))
check("...still reports the point estimate, labelled as one",
      "916 MiB" in flat(a_typ) and "typical values only" in v)
check("...names WHICH estimates decide it",
      "Thread stacks at its high end" in v and "JIT code cache at its high end" in v)
check("...and how far they have to move against how big a gap",
      "164 MiB" in v and "108 MiB" in v)
check("...and the command that settles it", "jcmd" in v and "--measured" in v)
print()
print("  The test of a Bar 2 fix is not that the tone got humbler. It is")
print("  whether the reader can now DO something they could not do before.")
print("  Before: 'Fits with 108 MiB headroom' - nothing to check, nothing to")
print("  measure, no way to discover the sentence was fragile. After: two")
print("  named quantities, the amount of movement that flips the answer, and")
print("  the one command that replaces both with observations. The tool went")
print("  from answering the wrong question confidently to answering the right")
print("  question - 'what would I have to know?' - exactly.")

# The escape hatch has to actually work, or the advice above is decoration.
a_meas = run(REPO, GOOD, "--measured",
             "metaspace=210Mi,codecache=70Mi,threads=180,direct=90Mi,gc=60Mi")
print()
print(f"  Following that advice with real NMT numbers:")
for chunk in re.findall(r".{1,72}(?:\s|$)", verdict(a_meas)):
    print(f"    {chunk.rstrip()}")
check("measuring produces a determinate answer",
      not verdict(a_meas).startswith("UNDETERMINED"))
check("...and the tool stops claiming a range it no longer has",
      "T RANGE" not in flat(a_meas)
      and "every estimate at its high end" not in verdict(a_meas))
# The first draft looked for "no estimate enters this sum" and FAILED here:
# that is the fits-branch wording, and these NMT numbers exceed the limit, so
# the run takes the other branch, which says the same thing in different
# words. The check was branch-specific where the property is not. Replaced by
# the property itself, measured on BOTH branches - and the two branches are
# proved to be different branches first, so the pair cannot be one case twice.
a_meas_fits = run(REPO, GOOD, "--measured",
                  "metaspace=100Mi,codecache=40Mi,threads=60,direct=20Mi,gc=40Mi")
BASIS = ("so this is arithmetic on observed values only",
         "no estimate enters this sum")
check("the two measured runs land on opposite verdicts, not one twice",
      verdict(a_meas).startswith("T exceeds")
      and verdict(a_meas_fits).startswith("Fits with"),
      f"{verdict(a_meas)[:40]!r} / {verdict(a_meas_fits)[:40]!r}")
for _label, _res in (("over-limit", a_meas), ("fits", a_meas_fits)):
    check(f"...and the {_label} branch SAYS the basis is observed, "
          f"rather than leaving the reader to notice the range vanished",
          any(b in verdict(_res) for b in BASIS), verdict(_res)[:130])

hr("CLAIM 5: the half this proof found. C2.5 was right and not enough.")
print("  An UNDETERMINED fit must not move the score: deducting for it would")
print("  convert the TOOL's ignorance into the USER's defect, which is the")
print("  same C2.2 error R9 exists to remove, pointed the other way. So the")
print("  number stays at 100.0 - correctly.")
print()
print("  With that alone, here is what the reader saw. Produced by disabling")
print("  the summary qualifier in the CURRENT tree and re-rendering, so it is")
print("  the real counterfactual and not a recollection:")
print()
from unittest import mock                                  # noqa: E402
from hpaanalyzer import report as R                        # noqa: E402
from hpaanalyzer.engine import analyze                     # noqa: E402

live = analyze(GOOD, helm_mode="auto")
with mock.patch.object(R, "undetermined_fit_lines", lambda _r: []):
    without = R.stdout_summary(live, "/tmp/r.txt")
with_it = R.stdout_summary(live, "/tmp/r.txt")
for ln in without.splitlines():
    print(f"    {ln.rstrip()}")
check("the score-only fix leaves the terminal block claiming A+ and no "
      "findings", "A+" in without and "No critical or high findings." in without)
check("...with no mention of the undetermined fit anywhere in it",
      "UNDETERMINED" not in without)
print()
print("  Both lines true; together, the pre-fix defect one screen up. R8 spent")
print("  thirteen sites learning that a reader does not experience modules,")
print("  and R9 rediscovered it: fixing the table and leaving the summary is")
print("  fixing a module. What ships instead:")
print()
for ln in with_it.splitlines():
    print(f"    {ln.rstrip()}")
check("the qualifier reaches the terminal block",
      "JVM fit UNDETERMINED" in with_it)
check("...carries the range, so the doubt is sized not just named",
      "model range 722 MiB-1.2 GiB" in with_it)
check("...and says explicitly that it is not a pass",
      "NOT a pass" in with_it)
check("...and the clean-bill line no longer reads as one",
      "No critical or high findings - but see the UNDETERMINED item above."
      in with_it)
check("...while the score is still untouched, as C2.5 requires",
      score(a_typ) == 100.0, f"{score(a_typ)}/100")

from hpaanalyzer.html_report import render_html             # noqa: E402
surfaces = {
    "terminal block": "JVM fit UNDETERMINED" in with_it,
    "full report exec summary":
        "UNDETERMINED, which is not the same as a pass"
        in " ".join(R.render(live, GOOD, level="full").split()),
    "coverage table": "UNDETERMINED" in flat(a_typ),
    "budget verdict": verdict(a_typ).startswith("UNDETERMINED"),
    "HTML summary": "JVM fit UNDETERMINED" in render_html(live, GOOD),
    "JSON coverage": any("UNDETERMINED" in str(r)
                         for r in a_typ["json"].get("coverage", [])),
}
print()
for k, ok in surfaces.items():
    print(f"    {k:28} {ok}")
check("every surface that states the verdict also states the doubt",
      all(surfaces.values()),
      "silent: " + ", ".join(k for k, ok in surfaces.items() if not ok))

hr("CLAIM 6: the guard. Honesty that costs true findings is not honesty.")
print("  All ten fixtures, both trees. If R9 had bought its epistemic caution")
print("  by softening conclusions the tool could always support, the columns")
print("  below would differ - and R7 is the recorded case of exactly that")
print("  trade being made by accident.")
print()
FIX = os.path.join(REPO, "fixtures")
targets = sorted(os.path.join(FIX, n) for n in os.listdir(FIX)
                 if os.path.isdir(os.path.join(FIX, n)))
targets.append(os.path.join(FIX, "umbrella-chart", "charts", "worker"))
print(f"  {'fixture':22}{'BEFORE':>18}{'AFTER':>18}   XF findings")
same = True
for t in targets:
    b, a = run(BEFORE, t), run(REPO, t)
    xa = [r for r in ids(a) if r.startswith("XF")]
    ok = (score(b) == score(a) and ids(b) == ids(a))
    same = same and ok
    bcell = f"{score(b)} {b['json'].get('grade')}"
    acell = f"{score(a)} {a['json'].get('grade')}"
    flag = "" if ok else "   <-- CHANGED"
    print(f"  {os.path.basename(t):22}{bcell:>18}{acell:>18}   {xa}{flag}")
check("every fixture keeps its exact score and its exact finding set", same)
print()
print("  Zero movement across ten charts is the claim: R9 added a state the")
print("  tool did not have, and did not take a single finding, severity or")
print("  point away from the cases it could already decide. The straddling")
print("  chart gained an UNDETERMINED coverage row and no finding, which is")
print("  the C2.5 requirement and the reason the scores hold.")

hr("CLAIM 7: the remedy after a PARTIAL measurement.")
print("  C2.8(e) requires the verdict to name the observation that settles it")
print("  and the flag that accepts it. R9's first implementation satisfied")
print("  that with ONE hand-written sentence, identical on every run. Then the")
print("  README printed this as its example invocation - and running the")
print("  tool's own documented command is what found the defect:")
print()
print("    python3 hpa-analyzer.py ./svc --measured metaspace=210Mi,threads=180")
print()
# The BEFORE is produced by COUNTERFACTUAL, not quoted from memory: the
# superseded implementation ended every undetermined verdict with one fixed
# component list, so restoring that behaviour is a one-line rebinding of the
# function that now derives the list. CLAIM 5 uses the same technique for the
# same reason - a remembered string is not a measurement, and this proof has
# already had four of its own claims corrected by their own runs.
CANNED = "metaspace=...,threads=...,direct=..."
part = run(REPO, GOOD, "--measured", "metaspace=210Mi,threads=180")
full_run = run(REPO, GOOD)


def _flags_raw(text):
    """The `a=...,b=...` blob out of `--measured a=...,b=...`, or None."""
    m = re.search(r"--measured ([a-z]+=\.\.\.(?:,[a-z]+=\.\.\.)*)", text)
    return None if m is None else m.group(1)


def _flags(text):
    """Just the component names from that blob, in order, or None."""
    blob = _flags_raw(text)
    return None if blob is None else [q.split("=")[0] for q in blob.split(",")]


# Rebinding the function that now derives the list to a constant restores the
# superseded behaviour exactly, so the BEFORE line below is rendered by the
# tool rather than typed by me.
from unittest import mock                                          # noqa: E402
from hpaanalyzer import proofs as _P                                # noqa: E402
from hpaanalyzer.engine import analyze as _an0                      # noqa: E402

with mock.patch.object(_P, "_settle_flags", lambda _c: CANNED):
    _before_part = _an0(GOOD, helm_mode="auto",
                        measured={"metaspace": 210 * MiB, "threads": 180})
_bv = [t for t in _before_part.proofs
       if "memory budget" in t.title][0].conclusion
print(f"    BEFORE, same partial run                   : "
      f"--measured {_flags_raw(_bv)}")
print(f"    AFTER, nothing measured                    : "
      f"--measured {','.join(k + '=...' for k in _flags(verdict(full_run)))}")
print(f"    AFTER, metaspace and threads measured      : "
      f"--measured {','.join(k + '=...' for k in _flags(verdict(part)))}")
print()
print("  The BEFORE line named two components the reader had JUST supplied and")
print("  omitted two of the three still deciding the answer. It is not a")
print("  wording bug: WHICH observation settles the question is a property of")
print("  the run, so no fixed sentence can be right for every run.")
print()
_canned = _flags(_bv)
check("the canned sentence named components the user had already supplied",
      _canned is not None and "metaspace" in _canned and "threads" in _canned,
      f"rendered by the tool with the derivation disabled: {_canned}")
check("...and omitted components that were still deciding the answer",
      set(_flags(verdict(part))) - set(_canned) == {"codecache", "gc"},
      f"still-deciding: {_flags(verdict(part))}, canned: {_canned}")
check("AFTER: with nothing measured, every component is named",
      _flags(verdict(full_run))
      == ["metaspace", "codecache", "threads", "direct", "gc"],
      str(_flags(verdict(full_run))))
check("AFTER: after the partial run, only what is left is named",
      _flags(verdict(part)) == ["codecache", "direct", "gc"],
      str(_flags(verdict(part))))
print("  A reader handed a different list than the one they passed has to be")
print("  told why it changed, or the tool reads as having ignored them:")
print()
_credit = re.search(r"You have already measured[^.]*\.", verdict(part))
print(f"    {_credit.group(0) if _credit else '(absent)'}")
print()
check("...and the verdict credits the measurement rather than silently "
      "re-listing", _credit is not None
      and "metaspace, threads" in _credit.group(0)
      and "codecache, direct, gc" in _credit.group(0),
      _credit.group(0) if _credit else "no credit sentence")
check("...which is a report of what happened, not decoration: it is absent "
      "when nothing was measured",
      "already measured" not in verdict(full_run))
print("  All three surfaces a reader can reach it from, from the real CLI run,")
print("  because R8's lesson was that fixing one and leaving the others is not")
print("  fixing the tool:")
print()
_cov = [c for c in part["json"].get("coverage", [])
        if "JVM memory fit" in str(c)]
_surfaces = {
    "budget verdict": verdict(part),
    "coverage row": json.dumps(_cov),
    "terminal block": part["stdout"],
}
for _name, _text in _surfaces.items():
    print(f"    {_name:16}: --measured "
          f"{','.join(k + '=...' for k in (_flags(_text) or ['(none)']))}")
    check(f"...{_name} names exactly what is still missing",
          _flags(_text) == ["codecache", "direct", "gc"],
          _text[-160:])
print()

hr("CLAIM 8: the citation quotes what was typed, not what it parsed to.")
print("  `MEASURED: --measured metaspace=...` is a claim about PROVENANCE: it")
print("  says this number is here BECAUSE YOU PASSED THAT. Rendering the value")
print("  back from the parsed integer broke that claim quietly - the row cited")
print("  a string the user never typed and would have to do arithmetic to")
print("  recognise as their own. Both rows, from the real CLI:")
print()
_ROW = r"Metaspace\s+(\S+(?: \S+)?)\s+MEASURED: (--measured \S+)"
_after = run(REPO, GOOD, "--measured", "metaspace=256M")
_ms = re.search(_ROW, flat(_after))

# The BEFORE is measured, not remembered. A first draft of this block typed
# `metaspace=268435456` into the print by hand and it was WRONG - `256M` is
# 256 * 10^6 in Kubernetes quantity notation, not 2^28 - which is the exact
# failure mode this proof exists to prevent, committed inside the proof
# itself. Produced now by rebinding the citation to the superseded form and
# re-rendering in-process, so the string below is the tool's output rather
# than mine.
from hpaanalyzer.models import MeasuredValues as _MV               # noqa: E402
from hpaanalyzer.proofs import parse_measured as _pm               # noqa: E402
from hpaanalyzer import report as _R                               # noqa: E402
from hpaanalyzer.engine import analyze as _an                      # noqa: E402

with mock.patch.object(_MV, "cite", lambda self, k: f"{k}={self[k]}"):
    _before_r = _an(GOOD, helm_mode="auto",
                    measured=_pm(["metaspace=256M"]))
_bt = [t for t in _before_r.proofs if "memory budget" in t.title][0]
_brow = [r for r in _bt.rows if r[0].startswith("Metaspace")][0]
print(f"    BEFORE : Metaspace | {_brow[1]} | {_brow[2]}")
print(f"    AFTER  : Metaspace | {_ms.group(1) if _ms else '?'} | "
      f"MEASURED: {_ms.group(2) if _ms else '?'}")
print()
check("the BEFORE line is a counterfactual, not a recollection: the same "
      "value, cited as the integer nobody typed",
      _brow[1] == (_ms.group(1) if _ms else None)
      and _brow[2] == "MEASURED: --measured metaspace=256000000",
      f"{_brow[1]!r} / {_brow[2]!r}")
print("  `256M` is chosen deliberately: it is the case where the two differ.")
print("  Re-rendering the integer through the tool's own formatter would only")
print("  move the defect - it would print `244.1Mi`, a different string the")
print("  user did not type, and one that reads as the tool disagreeing with")
print("  them. The VALUE cell shows the tool's reading and the SOURCE cell")
print("  shows the user's words, which is what lets the reader catch a")
print("  misunderstanding instead of only the tool catching it.")
print()
check("the source cell quotes the literal the user typed",
      _ms is not None and _ms.group(2) == "--measured metaspace=256M",
      _ms.group(2) if _ms else "no metaspace row matched")
check("...while the value cell still shows the tool's own reading of it",
      _ms is not None and _ms.group(1) == "244.1 MiB",
      _ms.group(1) if _ms else "?")
check("...so a reader can see both, and neither is silently substituted",
      _ms is not None and "268435456" not in flat(
          run(REPO, GOOD, "--measured", "metaspace=256M")),
      "the parsed integer appears nowhere in the report")
print()

hr("CLAIM 9: what is STILL not fixed. The band is also a guess.")
print("  R9 makes the WIDTH of the answer honest. It does not make the width")
print("  right, and that distinction is the remaining defect.")
print()
print("  `EST_METASPACE = 80-180 MiB` is sourced to 'typical Spring/framework")
print("  app'. A service with a large dependency graph, an ORM generating")
print("  proxies, or any bytecode-weaving agent, sits outside it. For that")
print("  application the tool is confidently wrong in exactly the pre-R9 way -")
print("  it just states a range instead of a point while being wrong:")
print()
real = run(REPO, GOOD, "--measured", "metaspace=400Mi")
print(f"    default bands   : {verdict(a_typ)[:110]}")
print(f"    metaspace 400Mi : {verdict(real)[:110]}")
check("a value outside the band changes the answer",
      verdict(real)[:40] != verdict(a_typ)[:40])
# A first draft tested `"400 MiB" not in flat(a_typ)` and FAILED - not because
# the report suggests 400 MiB of metaspace, but because the education section
# advises "~250-400 MiB of absolute non-heap headroom" for the WHOLE non-heap
# total. The string was searching the whole document for a number whose
# meaning is scoped to one row. Corrected by scoping the measurement to the
# metaspace row itself and asserting the real claim: every metaspace quantity
# the tool prints lies inside 80-180 MiB, so a reader working only from this
# report has no reason to try a value twice the top of that band.
_seg = re.search(r"Metaspace \(est\.\)(.*?)JIT code cache", flat(a_typ))
_mib = [float(m.group(1)) for m in re.finditer(r"([\d.]+) MiB", _seg.group(1))] \
    if _seg else []
print(f"    metaspace row, every quantity it prints: {_mib} MiB")
check("...and nothing in the default output would lead a reader there",
      bool(_mib) and max(_mib) == 180.0 and 400.0 not in _mib,
      f"the metaspace row tops out at {max(_mib) if _mib else '?'} MiB; the "
      f"400 MiB that changes the answer is off the scale it prints")
check("...the only 400 MiB the report contains is about a different quantity",
      "250-400 MiB of absolute non-heap headroom" in flat(a_typ),
      "measured, not assumed: that string is why the crude search misfired")
print()
print("  And the escape hatch has a precondition the tool's main use case")
print("  cannot meet. `--measured` needs numbers from `jcmd VM.native_memory`,")
print("  which needs a RUNNING POD - and the person choosing `limits.memory`")
print("  for the first deploy does not have one. For them the band IS the")
print("  answer, and its endpoints are two more numbers nobody measured.")
print()
print("  What R9 can claim: the reader is now told the answer depends on")
print("  named assumptions, is shown their documented ranges at the point of")
print("  use, and is given the command that removes them. What it cannot")
print("  claim: that the ranges are right. A confidence axis on the bands")
print("  themselves - narrow where the chart supplies evidence, wide where it")
print("  does not - is the next iteration's subject, and it is recorded here")
print("  rather than in a footnote because an admitted limit is a coverage")
print("  row and an unadmitted one is the defect this whole iteration was")
print("  about.")

hr("VERDICT")
print("  Bar 1 asked whether the sum was right. It was arithmetic on five")
print("  constants presented as arithmetic on the user's files, and it is now")
print("  an interval with sourced endpoints and a three-state conclusion.")
print()
print("  Bar 2 asked what that cost the person choosing a memory limit. They")
print("  were given one of two answers their own chart supports, in the")
print("  grammar of a measurement, with the refutation printed six rows")
print("  above it and left undone; and the same confidence was carried into")
print("  the grade and into the eleven lines a CI job prints. They now get")
print("  the interval, the named assumptions that decide it, the movement")
print("  required, the command that settles it - and, when it is undecided,")
print("  a terminal block that says so beside the grade instead of a clean")
print("  bill of health.")
print()
print("  What is not claimed: that the tool now knows how much memory a JVM")
print("  needs. It does not, it cannot before the JVM runs, and CLAIM 9")
print("  measures the case where its bands are simply wrong. The change is")
print("  that the report's confidence and the evidence's confidence are now")
print("  the same size.")
print()
if FAIL:
    print(f"  {len(FAIL)} CHECK(S) FAILED:")
    for f in FAIL:
        print(f"    - {f}")
    sys.exit(1)
print("  ALL CHECKS PASSED")

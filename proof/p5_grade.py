#!/usr/bin/env python3
"""PROOF R5, Bar 1: the grade moved when the INPUTS changed, not the chart -
and said nothing about it.

THE DEFECT
----------
`overall_score()` is a weighted mean over the categories that could be
assessed. A category that cannot be assessed - JAVA and DOCKERFILE with no
Dockerfile, CROSS with no Dockerfile or no workloads - is dropped from the
mean: out of the numerator AND out of the denominator. The remaining
categories are then renormalised over a smaller weight.

The consequence is arithmetic, not opinion: deleting a file moves the score,
in whichever direction the dropped categories sat relative to the ones that
stayed. Up, if the chart was scoring badly on exactly the categories that
left. And the pre-fix report printed the resulting number in a format
byte-identical to a score computed over all ten - no count, no list, no
warning. Its scorecard footer went further and told the reader the exclusion
was harmless: "N/A categories are excluded, not free points". True in the
narrow sense that no points were gifted, and it leaves the reader believing
the number is stable under a missing input. It is not.

WHAT IS MEASURED HERE
---------------------
Each fixture is copied to a temp directory and the Dockerfile deleted. Every
other byte - Chart.yaml, values, every template - is asserted identical
first, so any score movement is attributable to the missing Dockerfile and
nothing else. Both columns run the same fixture bytes; only the TOOL varies,
BEFORE being the committed pre-fix tree extracted with `git archive` at the
SHA pinned in proof/baseline.py (not HEAD).

CLAIM 0  the two directories differ by exactly one file
CLAIM 1  the pre-fix score MOVES, and moves UP on at least one chart
CLAIM 2  the pre-fix output never says the two runs were computed over
         different category sets - the numbers are directly comparable to
         the eye and must not be
CLAIM 3  R5 imputed nothing: the score is still exactly the weighted mean
         over the assessed categories (recomputed here from the tool's own
         category table), the number of categories entering the mean equals
         the number the report claims, the movement's DIRECTION survives -
         and the denominator, the dropped categories and the reason for each
         are now printed. Not asserted: that the before/after deltas match
         numerically. An earlier draft did assert that, and the run refuted
         it on sidecar-chart (-4.0 vs -5.0), because R1-R4 added rules that
         change that chart's per-category scores. The assertion was wrong,
         not the code.
CLAIM 4  every surface that prints the score prints the denominator:
         terminal summary, full text report, HTML badge, --quiet one-liner,
         --json
CLAIM 5  no finding was lost, and the complete-coverage case is unchanged -
         a chart with all ten categories assessed reads exactly as before
         apart from the added "all 10 categories" line

Run: python3 proof/p5_grade.py
"""

import filecmp
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline import BASELINE, resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)

# Charts that ship a Dockerfile, so "delete it" is a meaningful operation.
FIXTURES = ["good-chart", "sidecar-chart", "bad-chart"]

_CHILD = r"""
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary, render
from hpaanalyzer.scoring import overall_score, grade, category_scores

r = analyze(sys.argv[2], helm_mode="off")
out = os.path.join(tempfile.mkdtemp(), "report.txt")
s = overall_score(r)
try:
    from hpaanalyzer.scoring import coverage
    c = coverage(r)
    cov = {"complete": c.complete, "n_assessed": c.n_assessed,
           "n_total": c.n_total, "weight_assessed": c.weight_assessed,
           "unassessed": [[k.name, v] for k, v in c.unassessed]}
except ImportError:
    # The pre-fix scoring module has no coverage() at all - which is the
    # defect, stated as an import error.
    cov = None
print("---JSON---")
print(json.dumps({
    "score": s,
    "grade": grade(s) if s is not None else None,
    "summary": stdout_summary(r, out),
    "full": render(r, sys.argv[2], show_all=True, level="full"),
    "rules": sorted({f.rule_id for f in r.findings}),
    "cats": [[c[0].name, c[1]] for c in category_scores(r)],
    "coverage": cov,
}))
"""


def _payload(tree, chart):
    p = subprocess.run([sys.executable, "-c", _CHILD, tree, chart],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"child failed on {chart}:\n{p.stderr[-2000:]}")
    return json.loads(p.stdout.split("---JSON---", 1)[1])


_BEFORE_TREE = None


def before_tree():
    global _BEFORE_TREE
    if _BEFORE_TREE is None:
        tmp = tempfile.mkdtemp(prefix="hpa-before-")
        tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _BEFORE_TREE = tmp
    return _BEFORE_TREE


def chart_dir(name):
    """The fixture, asserted to exist.

    Same guard as p4_render.py, kept because its absence there produced a
    proof that measured an empty directory and reported success. A missing
    input must be a stop, not a data point.
    """
    p = os.path.join(REPO, "fixtures", name)
    if not os.path.isfile(os.path.join(p, "Chart.yaml")):
        raise SystemExit(f"proof harness: {p}/Chart.yaml does not exist")
    if not os.path.isfile(os.path.join(p, "Dockerfile")):
        raise SystemExit(f"proof harness: {p}/Dockerfile does not exist; "
                         f"'delete the Dockerfile' would measure nothing")
    return p


_STRIPPED = {}


def stripped(name):
    """A real copy of the fixture with ONLY the Dockerfile removed."""
    if name not in _STRIPPED:
        d = tempfile.mkdtemp(prefix="hpa-nodocker-")
        dst = os.path.join(d, name)
        shutil.copytree(chart_dir(name), dst)
        os.remove(os.path.join(dst, "Dockerfile"))
        _STRIPPED[name] = dst
    return _STRIPPED[name]


def diff_files(a, b):
    """Relative paths that differ, exist only in a, or only in b."""
    out = []

    def walk(root):
        seen = set()
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                seen.add(os.path.relpath(os.path.join(dirpath, fn), root))
        return seen

    ra, rb = walk(a), walk(b)
    for rel in sorted(ra - rb):
        out.append(("only-in-original", rel))
    for rel in sorted(rb - ra):
        out.append(("only-in-copy", rel))
    for rel in sorted(ra & rb):
        if not filecmp.cmp(os.path.join(a, rel), os.path.join(b, rel),
                           shallow=False):
            out.append(("differs", rel))
    return out


def hr(title=""):
    print()
    print("=" * 76)
    if title:
        print(title)
        print("=" * 76)


def fmt(p):
    if p["score"] is None:
        return "NOT GRADED"
    return f"{p['score']:5.1f} {p['grade']:<2}"


FAIL = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    if not ok:
        FAIL.append(label)


# ---------------------------------------------------------------------------
print(__doc__.split("Run:")[0].rstrip())
print()
print(f"BEFORE tree : git archive {BASELINE_SHA[:9]}  (pinned, not HEAD)")
print(f"AFTER  tree : {REPO}")

hr("CLAIM 0: the with/without pairs differ by exactly one file.\n"
   "         Without this, any score movement below proves nothing.")
for n in FIXTURES:
    d = diff_files(chart_dir(n), stripped(n))
    ok = d == [("only-in-original", "Dockerfile")]
    check(f"{n:<16} diff = {d}", ok)

hr("CLAIM 1: the PRE-FIX score moves when the Dockerfile is deleted,\n"
   "         with every Kubernetes manifest byte-identical.")
B_with = {n: _payload(before_tree(), chart_dir(n)) for n in FIXTURES}
B_less = {n: _payload(before_tree(), stripped(n)) for n in FIXTURES}
print(f"  {'fixture':<16} {'with Dockerfile':<16} {'without':<16} delta")
deltas = {}
for n in FIXTURES:
    d = B_less[n]["score"] - B_with[n]["score"]
    deltas[n] = d
    print(f"  {n:<16} {fmt(B_with[n]):<16} {fmt(B_less[n]):<16} {d:+.1f}")
print()
check("at least one chart MOVES", any(abs(d) > 0.05 for d in deltas.values()),
      f"moved: {[n for n in FIXTURES if abs(deltas[n]) > 0.05]}")
up = [n for n in FIXTURES if deltas[n] > 0.05]
check("at least one chart moves UP - deleting a file IMPROVES the grade",
      bool(up), f"up: {up}")
print()
print("  Why: the dropped categories and their pre-fix scores.")
for n in FIXTURES:
    w = dict(B_with[n]["cats"])
    l_ = dict(B_less[n]["cats"])
    gone = [k for k in w if w[k] is not None and l_.get(k) is None]
    kept = [w[k] for k in w if w[k] is not None and l_.get(k) is not None]
    gone_v = [w[k] for k in gone]
    print(f"    {n:<16} dropped {','.join(gone) or 'none':<28} "
          f"scoring {['%.1f' % v for v in gone_v]}")
    if gone_v and kept:
        print(f"    {'':<16} vs unweighted mean of what stayed: "
              f"{sum(kept)/len(kept):.1f}  -> score moves "
              f"{'UP' if sum(gone_v)/len(gone_v) < sum(kept)/len(kept) else 'DOWN'}")

hr("CLAIM 2: the PRE-FIX output never says the two runs were computed\n"
   "         over different category sets.")
for n in FIXTURES:
    s_with = B_with[n]["summary"]
    s_less = B_less[n]["summary"]
    grade_lines = [l for l in s_less.splitlines() if "GRADE" in l or "NOT GRADED" in l]
    said = any(("categor" in l.lower()) for l in s_less.splitlines())
    check(f"{n:<16} pre-fix summary mentions no denominator", not said,
          f"grade line: {grade_lines[0].strip() if grade_lines else '(none)'}")
# and in the long report: the footer actively reassures the reader
foot = "not free points"
present = [n for n in FIXTURES if foot in B_less[n]["full"]]
check(f"pre-fix full report contains the reassurance {foot!r}",
      present == FIXTURES, f"in: {present}")
print()
print("  So a reader diffing two pre-fix runs of the SAME chart sees only:")
for n in FIXTURES:
    a = [l.strip() for l in B_with[n]["summary"].splitlines() if "GRADE" in l]
    b = [l.strip() for l in B_less[n]["summary"].splitlines() if "GRADE" in l]
    if a and b and a[0] != b[0]:
        print(f"    {n}:")
        print(f"      with    {a[0]}")
        print(f"      without {b[0]}")

hr("CLAIM 3: R5 changed no arithmetic - it imputes nothing and hides\n"
   "         nothing - and now prints what the number was computed over.")
A_with = {n: _payload(REPO, chart_dir(n)) for n in FIXTURES}
A_less = {n: _payload(REPO, stripped(n)) for n in FIXTURES}

# An earlier draft of this proof asserted the BEFORE and AFTER deltas would be
# numerically identical. The run said sidecar-chart moved -4.0 before and -5.0
# after, and it was the ASSERTION that was wrong: iterations R1-R4 added rules
# (RS015, RS016, RS017, TP013, ...) that change sidecar-chart's per-category
# scores, so its delta is not expected to survive four iterations of new
# findings unchanged. Asserting sameness across tool versions was measuring the
# wrong thing. What R5 must actually preserve is the RULE: the overall score is
# still exactly the weighted mean over the assessed categories, with no value
# imputed for the unassessed ones. That is checked against the tool's own
# category table below, and the direction of the movement is checked separately.
from hpaanalyzer.scoring import WEIGHTS as _W, Category as _C  # noqa: E402


def _weighted_mean(cats):
    num = den = 0.0
    for name, sc in cats:
        if sc is None:
            continue
        w = _W[_C[name]]
        num += w * sc
        den += w
    return num / den if den else None


print("  The score still equals the weighted mean over ASSESSED categories,")
print("  recomputed here from the tool's own printed category table:")
for n in FIXTURES:
    for tag, p in (("with", A_with[n]), ("without", A_less[n])):
        recomputed = _weighted_mean(p["cats"])
        ok = recomputed is not None and abs(recomputed - p["score"]) < 1e-9
        check(f"{n:<16} {tag:<8} score == weighted mean of assessed cats", ok,
              f"reported {p['score']:.4f} vs recomputed "
              f"{recomputed if recomputed is None else round(recomputed, 4)}")
print()
print("  And no unassessed category was quietly given a value: the count of")
print("  categories entering the mean equals the count the report claims.")
for n in FIXTURES:
    p = A_less[n]
    entering = sum(1 for _name, sc in p["cats"] if sc is not None)
    check(f"{n:<16} categories in the mean == coverage.n_assessed",
          entering == p["coverage"]["n_assessed"],
          f"{entering} vs {p['coverage']['n_assessed']}")
print()
print(f"  {'fixture':<16} {'before delta':<14} {'after delta':<14} same sign?")
for n in FIXTURES:
    da = A_less[n]["score"] - A_with[n]["score"]
    sign_ok = (abs(da) <= 0.05 and abs(deltas[n]) <= 0.05) or (da * deltas[n] > 0)
    print(f"  {n:<16} {deltas[n]:+13.1f} {da:+13.1f}  "
          f"{'yes' if sign_ok else 'NO'}")
    check(f"{n:<16} movement direction preserved", sign_ok)
print("  (magnitudes differ where R1-R4 added findings to that chart; the")
print("   defect being demonstrated is the movement, which survives.)")
print()
print("  No value was imputed for the unassessed categories. Scoring them 100")
print("  would invent a clean bill of health for something never looked at;")
print("  scoring them 0 would invent findings; scoring them at the mean would")
print("  assert the unseen resembles the seen. There is no honest number for")
print("  'not looked at', so the fix is to stop hiding the denominator.")
print()
for n in FIXTURES:
    c = A_less[n]["coverage"]
    check(f"{n:<16} coverage object present and incomplete",
          c is not None and not c["complete"],
          f"{c['n_assessed']}/{c['n_total']} cats, "
          f"{c['weight_assessed']}/100 weight" if c else "coverage() missing")
    if c:
        for cat, reason in c["unassessed"]:
            print(f"      {cat:<12} {reason}")
        check(f"{n:<16} every drop carries a reason naming the input",
              all("Dockerfile" in r for _c, r in c["unassessed"]))
print()
check("pre-fix scoring module had no coverage() to call",
      B_less[FIXTURES[0]]["coverage"] is None)

hr("CLAIM 4: every surface that prints the score prints the denominator.")
N = "bad-chart"
sm = A_less[N]["summary"]
full = A_less[N]["full"]
check("terminal summary carries the count", "7 of 10 categories" in sm)
check("terminal summary names what was dropped", "NOT assessed" in sm)
check("full report carries the count", "7 of 10 categories" in full)
check("full report gives the reason", "no Dockerfile was found" in full)
check("full report warns about comparability", "NOT comparable" in full)
check("full report says what the number is",
      "not an estimate of risk" in full)
check("the old reassurance is gone", "not free points" not in full)

# the CLI surfaces, run as real processes
env = dict(os.environ, PYTHONPATH=REPO)
tmpd = tempfile.mkdtemp()
rpt = os.path.join(tmpd, "r.txt")
jsn = os.path.join(tmpd, "r.json")
html = os.path.join(tmpd, "r.html")
q = subprocess.run([sys.executable, "-m", "hpaanalyzer", stripped(N),
                    "-o", rpt, "--quiet", "--helm", "off"],
                   capture_output=True, text=True, env=env, cwd=REPO)
check("--quiet one-liner carries the count",
      "over 7/10 categories" in q.stdout, q.stdout.strip())
subprocess.run([sys.executable, "-m", "hpaanalyzer", stripped(N), "-o", rpt,
                "--json", jsn, "--html", html, "--helm", "off"],
               capture_output=True, text=True, env=env, cwd=REPO, check=True)
with open(jsn) as fh:
    payload = json.load(fh)
jc = payload.get("score_coverage")
check("--json carries score_coverage", jc is not None)
if jc:
    check("--json lists the dropped categories with reasons",
          {u["category"] for u in jc["unassessed"]} == {"JAVA", "DOCKERFILE",
                                                        "CROSS"}
          and all(u["reason"] for u in jc["unassessed"]),
          jc["note"])
with open(html) as fh:
    h = fh.read()
check("HTML badge itself carries the count", "7/10 cats" in h)
check("HTML lists the dropped categories", "Not assessed, and why" in h)

hr("CLAIM 5: nothing was lost, and the complete-coverage case still reads\n"
   "         as a score over all ten categories.")
for n in FIXTURES:
    lost = sorted(set(B_less[n]["rules"]) - set(A_less[n]["rules"]))
    check(f"{n:<16} no rule lost", not lost, f"lost={lost or 'none'}")
for n in FIXTURES:
    c = A_with[n]["coverage"]
    check(f"{n:<16} with Dockerfile: coverage complete",
          c is not None and c["complete"])
    check(f"{n:<16} with Dockerfile: says 'all 10 categories'",
          "all 10 categories" in A_with[n]["full"])
    check(f"{n:<16} with Dockerfile: no comparability warning",
          "NOT comparable" not in A_with[n]["full"])

hr("VERDICT")
print(f"  The pre-fix tool moved bad-chart's score by {deltas['bad-chart']:+.1f} points for")
print("  deleting a file, printed the result in the same format as a score")
print("  over all ten categories, and told the reader in its own scorecard")
print("  footer that the exclusion was 'not free points'.")
print()
print("  The arithmetic is unchanged - it was the only honest arithmetic")
print("  available. What changed is that the denominator is now printed on")
print("  every surface that prints the number, with the reason each category")
print("  was dropped, and the reader is told plainly that two scores over")
print("  different category sets are not comparable.")
print()
if FAIL:
    print(f"  {len(FAIL)} CHECK(S) FAILED:")
    for f in FAIL:
        print(f"    - {f}")
    raise SystemExit(1)
print("  ALL CHECKS PASSED")

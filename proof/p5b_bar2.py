#!/usr/bin/env python3
"""PROOF R5, Bar 2: a number you cannot compare is not a grade.

Bar 1 (proof/p5_grade.py) shows the machinery is right: the score moves when
an input disappears, that movement is honest arithmetic, and the denominator
is now printed on every surface that prints the number. That is "correct".

This asks the user's harder question - "not just correct, but does it do what
it is supposed to do". What is a grade FOR? Nobody reads 51.8 and stops. They
do one of three things with it:

    (a) compare two charts        - "is the payments chart worse than orders?"
    (b) compare one chart to itself over time - "did this PR make it worse?"
    (c) gate a deploy on it       - `--min-score 50` in CI

The pre-fix tool served (a) and (b) badly and (c) DANGEROUSLY, and printing a
coverage block in the report fixes only (a) and (b), because CI reads the
exit code, not the report. That gap is the content of this proof, and the
reason R5 needed a second change after the report was already honest.

CLAIM 1  (c) is an outage, not a nit: deleting the Dockerfile turns a RED
         build GREEN, exit 1 -> exit 0, with every Kubernetes manifest
         byte-identical and no message of any kind on the pre-fix tool
CLAIM 2  the report fix alone does NOT close it - a green build stays green
CLAIM 3  the CI surface now carries the scale on every run, pass or fail,
         and --require-coverage turns it into a real gate
CLAIM 4  (a) is served: two charts scored over different category sets can no
         longer be put side by side without the difference being visible
CLAIM 5  what is STILL not fixed, stated rather than hidden - the denominator
         is necessary for comparability, not sufficient. Three ways two
         10-of-10 scores still fail to mean the same thing, each measured.

BEFORE is the committed pre-fix tree, extracted with `git archive` at the SHA
pinned in proof/baseline.py (NOT HEAD), run as a real subprocess over real
directories. Run: python3 proof/p5b_bar2.py
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE - see the module for why)

from baseline import resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)
N = "bad-chart"

# THRESHOLD is calibrated at run time - see calibrate() below. It was the
# literal 50.0 until an unrelated fix moved a measured score across it and
# broke this proof; a proof whose premise is a hardcoded number is a proof
# with a half-life.
THRESHOLD = None

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
    """The fixture, asserted to exist - the guard from p4_render.py, kept
    because its absence there produced a proof that measured an empty
    directory and reported success."""
    p = os.path.join(REPO, "fixtures", name)
    if not os.path.isfile(os.path.join(p, "Chart.yaml")):
        raise SystemExit(f"proof harness: {p}/Chart.yaml does not exist")
    return p


_STRIPPED = {}


def stripped(name):
    if name not in _STRIPPED:
        d = tempfile.mkdtemp(prefix="hpa-nodocker-")
        dst = os.path.join(d, name)
        shutil.copytree(chart_dir(name), dst)
        df = os.path.join(dst, "Dockerfile")
        if not os.path.isfile(df):
            raise SystemExit(f"proof harness: {name} ships no Dockerfile; "
                             f"'delete the Dockerfile' would measure nothing")
        os.remove(df)
        _STRIPPED[name] = dst
    return _STRIPPED[name]


def cli(tree, target, *flags):
    """Run the CLI as CI would: a real process, exit code and stderr kept."""
    out = os.path.join(tempfile.mkdtemp(), "r.txt")
    p = subprocess.run(
        [sys.executable, "-m", "hpaanalyzer", target, "-o", out, "--quiet",
         "--helm", "off", *flags],
        capture_output=True, text=True, cwd=tree,
        env=dict(os.environ, PYTHONPATH=tree))
    return {"rc": p.returncode, "out": p.stdout.strip(),
            "err": p.stderr.strip(), "report": out}


def score_of(tree, target):
    """The score the tool prints, from a real run with no gate involved."""
    line = cli(tree, target)["out"]
    m = re.search(r"score\s+([\d.]+)/100", line)
    if not m:
        raise SystemExit(f"proof harness: no score in summary line: {line!r}")
    return float(m.group(1))


def calibrate():
    """Derive the CI threshold from the scores this proof will encounter.

    A CI author picks a threshold that fails the chart they consider unsafe.
    This proof then shows that deleting a file walks that same chart back
    across it. The number itself is arbitrary - what has to be true is that
    it sits between the with-Dockerfile score and the without-Dockerfile
    score, in BOTH trees, so that "the gate flips" is the only thing the
    deletion changed.

    It was written as the literal 50.0, chosen when those scores were 45.5
    and 51.8. Then removing a `ctx.dockerfiles` gate on PB004 (R8, site 6)
    recovered a HIGH that the missing file had been hiding, the stripped
    score fell 51.8 -> 49.9, and CLAIM 2 failed - not because its argument
    had stopped being true, but because 50.0 had stopped being between the
    two numbers. The claim was correct and the constant was stale, so the
    constant is now measured instead of asserted. Fixing this by lowering
    50.0 to 49.0 would have been the same bug with a longer fuse.
    """
    fails = {"pre-fix, intact": score_of(before_tree(), chart_dir(N)),
             "post-fix, intact": score_of(REPO, chart_dir(N))}
    passes = {"pre-fix, stripped": score_of(before_tree(), stripped(N)),
              "post-fix, stripped": score_of(REPO, stripped(N))}
    lo, hi = max(fails.values()), min(passes.values())
    print("  calibrating the gate from measured scores, not a constant:")
    for k, v in list(fails.items()) + list(passes.items()):
        print(f"    {k:<22} {v:>6.1f}")
    if not hi > lo:
        raise SystemExit(
            f"proof harness: no threshold can separate these runs "
            f"(intact {lo}, stripped {hi}). Deleting the Dockerfile no "
            f"longer raises the score past any gate - if that is a real "
            f"fix, this proof has been made obsolete by it and should be "
            f"rewritten, not adjusted.")
    t = round((lo + hi) / 2, 1)
    if not lo < t <= hi:
        raise SystemExit(f"proof harness: midpoint {t} is not inside "
                         f"({lo}, {hi}]")
    print(f"    -> --min-score {t}: above every intact run, at or below "
          f"every stripped run")
    return t


def hr(title=""):
    print()
    print("=" * 76)
    if title:
        print(title)
        print("=" * 76)


FAIL = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    if not ok:
        FAIL.append(label)


# ---------------------------------------------------------------------------
print(__doc__.split("BEFORE is the committed")[0].rstrip())
print()
print(f"BEFORE tree : git archive {BASELINE_SHA[:9]}  (pinned, not HEAD)")
print(f"AFTER  tree : {REPO}")
print(f"Gate under test: fixtures/{N}, --min-score calibrated below")
print()
THRESHOLD = calibrate()

hr("CLAIM 1: the pre-fix CI gate is turned GREEN by deleting a file.")
b_with = cli(before_tree(), chart_dir(N), "--min-score", str(THRESHOLD))
b_less = cli(before_tree(), stripped(N), "--min-score", str(THRESHOLD))
print(f"  with Dockerfile     exit={b_with['rc']}   {b_with['out']}")
print(f"                      stderr: {b_with['err'] or '(silent)'}")
print(f"  without Dockerfile  exit={b_less['rc']}   {b_less['out']}")
print(f"                      stderr: {b_less['err'] or '(silent)'}")
check("pre-fix: with the Dockerfile the build FAILS", b_with["rc"] == 1)
check("pre-fix: without it the build PASSES", b_less["rc"] == 0)
check("pre-fix: and says nothing at all about why the scale moved",
      b_less["err"] == "")
print()
print("  Every Kubernetes manifest is byte-identical between those two runs")
print("  (asserted file-by-file in proof/p5_grade.py, CLAIM 0). Nothing was")
print(f"  fixed. The chart that was too dangerous to ship at "
      f"{score_of(before_tree(), chart_dir(N))} shipped at")
print(f"  {score_of(before_tree(), stripped(N))} because JAVA, DOCKERFILE "
      f"and CROSS - the three categories it")
print("  was failing hardest - left the mean along with the file.")

hr("CLAIM 2: the report fix alone does NOT close it.\n"
   "         A coverage block in a text file cannot stop a deploy.")
print("  The R5 report change makes the denominator visible in the terminal")
print("  summary, the full report, the HTML badge and the JSON. CI reads the")
print("  EXIT CODE. So the honest test of the report-only fix is: does the")
print("  build still go green? It does - which is why R5 needed a second")
print("  change, and why this proof exists as more than a formality.")
report_only = cli(REPO, stripped(N), "--min-score", str(THRESHOLD))
check("with the report fix, the gate still returns 0",
      report_only["rc"] == 0,
      "the number in the report is honest; the exit code is what ships")

hr("CLAIM 3: the CI surface now carries the scale on every run,\n"
   "         and --require-coverage makes it a gate.")
print(f"  --min-score {THRESHOLD} alone:")
print(f"    exit={report_only['rc']}")
for line in report_only["err"].splitlines():
    print(f"    stderr: {line}")
check("the pass is no longer silent - stderr names the reduced scale",
      "7 of 10 categories" in report_only["err"])
check("stderr names WHICH categories left",
      all(k in report_only["err"] for k in ("DOCKERFILE", "JAVA", "CROSS")))
check("stderr points at the lever rather than just complaining",
      "--require-coverage" in report_only["err"])

gated = cli(REPO, stripped(N), "--min-score", str(THRESHOLD),
            "--require-coverage")
print(f"\n  --min-score {THRESHOLD} --require-coverage:")
print(f"    exit={gated['rc']}")
for line in gated["err"].splitlines():
    print(f"    stderr: {line}")
check("the build that deleted its Dockerfile now FAILS", gated["rc"] == 1)

full_cov = cli(REPO, chart_dir(N), "--require-coverage")
check("--require-coverage does NOT punish a fully-assessed chart",
      full_cov["rc"] == 0, f"exit={full_cov['rc']} on the intact fixture")
print()
print("  This adds a flag, and 'flag sprawl' is on this project's own defect")
print("  list. It was judged worth one more: a stderr line in a green build's")
print("  log is read by nobody, and there was no other way for a CI author to")
print("  gate on the scale their threshold is compared against. The default")
print("  is unchanged - a chart-only repo that never had a Dockerfile still")
print("  passes, because for that repo the scale never moves.")

hr("CLAIM 4: two charts scored over different sets can no longer be put\n"
   "         side by side without the difference being visible.")
_CHILD = r"""
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary
r = analyze(sys.argv[2], helm_mode="off")
print("---JSON---")
print(json.dumps({"summary": stdout_summary(
    r, os.path.join(tempfile.mkdtemp(), "r.txt"))}))
"""


def summary(tree, target):
    p = subprocess.run([sys.executable, "-c", _CHILD, tree, target],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(p.stderr[-2000:])
    return json.loads(p.stdout.split("---JSON---", 1)[1])["summary"]


print("  Pre-fix, the two grade lines an SRE would compare:")
for tag, t in (("intact ", chart_dir(N)), ("stripped", stripped(N))):
    line = [l.strip() for l in summary(before_tree(), t).splitlines()
            if "GRADE" in l]
    print(f"    {tag}  {line[0] if line else '(none)'}")
print("  Nothing distinguishes them but the number, and the number is the")
print("  thing being compared. Post-fix:")
for tag, t in (("intact ", chart_dir(N)), ("stripped", stripped(N))):
    print(f"    {tag}")
    for l in summary(REPO, t).splitlines():
        if "GRADE" in l or "categor" in l.lower() or "NOT assessed" in l:
            print(f"        {l.strip()}")
a = summary(REPO, chart_dir(N))
b = summary(REPO, stripped(N))
check("the intact run declares nothing (it is the full scale)",
      "categor" not in a.lower())
check("the reduced run declares its scale", "7 of 10 categories" in b)

hr("CLAIM 5: what is STILL not fixed. The denominator is necessary for\n"
   "         comparability, not sufficient - three measured cases.")
sys.path.insert(0, REPO)
from hpaanalyzer.engine import analyze          # noqa: E402
from hpaanalyzer.scoring import category_scores, overall_score, coverage  # noqa: E402

print("  (1) The per-category score floors at 0, so badness SATURATES.")
print()
print("      The first draft of this claim probed bad-chart for categories")
print("      already sitting at 0.0 and printed 'none' - the claim was")
print("      asserted, the measurement refuted it, and the text is corrected")
print("      from the measurement rather than the assertion softened. What")
print("      follows is the experiment that does show saturation: copy the")
print("      fixture and duplicate its Deployment template N times, so every")
print("      finding in it is found N+1 times over. Real directories on disk,")
print("      real engine runs.")
print()


def _duplicated(n):
    """bad-chart with its Deployment template copied n extra times.

    The copies are byte-identical under different filenames; the loader
    treats each template file as its own workload, which the workload count
    below verifies rather than assumes. (An earlier draft of this helper
    rewrote a hardcoded `name:` in each copy to force distinctness - the
    fixture's name is a `{{ .Release.Name }}` template, so that substitution
    matched nothing and the guard around it aborted the run. The duplication
    never needed it.)
    """
    d = tempfile.mkdtemp(prefix=f"hpa-dup{n}-")
    dst = os.path.join(d, N)
    shutil.copytree(chart_dir(N), dst)
    with open(os.path.join(dst, "templates", "deployment.yaml")) as fh:
        body = fh.read()
    for i in range(n):
        with open(os.path.join(dst, "templates", f"dep{i}.yaml"), "w") as fh:
            fh.write(body)
    return d, dst


_sat = {}
for _n in (0, 3, 20, 40):
    _tmp, _dst = _duplicated(_n)
    _r = analyze(_dst, helm_mode="off")
    _cs = {c.name: (s, len(f)) for c, s, f in category_scores(_r)}
    _sat[_n] = {
        "score": overall_score(_r),
        "findings": sum(v[1] for v in _cs.values()),
        "floored": sorted(k for k, v in _cs.items() if v[0] == 0.0),
        "security": _cs["SECURITY"],
        "resources": _cs["RESOURCES"],
        "workloads": len(_r.context.workloads),
    }
    shutil.rmtree(_tmp)

if [_sat[k]["workloads"] for k in (0, 3, 20, 40)] != [1, 4, 21, 41]:
    raise SystemExit("proof harness: template duplication did not produce "
                     "n+1 workloads (" +
                     ", ".join(f"x{k}={_sat[k]['workloads']}"
                               for k in (0, 3, 20, 40)) +
                     ") - the saturation experiment would measure nothing")

print(f"      {'copies':<8}{'workloads':>10}{'score':>8}{'findings':>10}"
      f"{'floored':>9}")
for _n in (0, 3, 20, 40):
    _s = _sat[_n]
    print(f"      x{_n:<7}{_s['workloads']:>10}{_s['score']:>8.2f}"
          f"{_s['findings']:>10}{len(_s['floored']):>9}")
print()
print(f"      x20 and x40 score IDENTICALLY ({_sat[20]['score']:.2f} both) "
      f"while x40")
print(f"      carries {_sat[40]['findings'] - _sat[20]['findings']} more "
      f"findings - SECURITY {_sat[20]['security'][1]} -> "
      f"{_sat[40]['security'][1]}, RESOURCES "
      f"{_sat[20]['resources'][1]} -> {_sat[40]['resources'][1]},")
print("      every one of them at 0.0 in both runs. Once a category floors,")
print("      further findings in it are free. The score stops ordering charts")
print("      exactly where ordering them would matter most.")
print()
print("      Note what the measurement also shows: saturation is PER-CATEGORY.")
print(f"      x3 ({_sat[3]['score']:.2f}) and x20 ({_sat[20]['score']:.2f}) "
      f"still differ, because at x3 only")
print(f"      {len(_sat[3]['floored'])} categories had floored and the rest "
      f"still had headroom. The overall")
print("      number keeps moving until the last category bottoms out, and")
print("      then it is frozen. That is the honest shape of the defect.")
check("two charts differing by hundreds of findings score identically",
      _sat[20]["score"] == _sat[40]["score"]
      and _sat[40]["findings"] > _sat[20]["findings"],
      f"x20 {_sat[20]['score']:.2f}/{_sat[20]['findings']}f == "
      f"x40 {_sat[40]['score']:.2f}/{_sat[40]['findings']}f")
check("the floored categories are the same set in both",
      _sat[20]["floored"] == _sat[40]["floored"],
      ", ".join(_sat[20]["floored"]))

print()
print("  (2) Evidence basis. The coverage denominator does NOT encode it.")
print()
print("      The first draft compared helm-rendered vs static scores on")
print("      bad-chart expecting them to differ. Measured, they are equal to")
print("      the decimal - so that comparison proves nothing and is replaced")
print("      by the pair of fixtures where the evidence basis changes the")
print("      answer categorically.")
helm_ok = shutil.which("helm") is not None
if helm_ok:
    _same = analyze(chart_dir(N), helm_mode="auto"), \
        analyze(chart_dir(N), helm_mode="off")
    print()
    print(f"      {N}:  helm {overall_score(_same[0]):.1f}   "
          f"static {overall_score(_same[1]):.1f}   (identical)")
    _evid = {}
    for _name in ("capability-chart", "apiversion-chart"):
        _evid[_name] = {}
        for _mode in ("auto", "off"):
            _r = analyze(chart_dir(_name), helm_mode=_mode)
            _evid[_name][_mode] = (
                overall_score(_r), coverage(_r).n_assessed,
                _r.context.render_mode)
        _a, _o = _evid[_name]["auto"], _evid[_name]["off"]
        print(f"      {_name}:  helm {_a[0]:.1f} over {_a[1]}/10   "
              f"static NOT GRADED over {_o[1]}/10")
    print()
    print("      Same chart, same coverage line - 7 of 10 categories, the")
    print("      identical string in both runs - and one mode produces a B+")
    print("      while the other refuses to produce a number at all. The")
    print("      denominator R5 added is necessary for comparability and")
    print("      demonstrably not sufficient: it does not distinguish these")
    print("      two runs. What distinguishes them is the render mode, which")
    print("      R4 made a first-class report line and R5 attaches to the")
    print("      score line - but the NUMBER still does not carry it, so two")
    print("      /100 values diffed across modes are not the same comparison.")
    check("static and helm disagree about whether a chart is gradeable at all",
          all(_evid[k]["auto"][0] is not None and _evid[k]["off"][0] is None
              for k in _evid),
          "capability-chart, apiversion-chart: graded under helm, "
          "NOT GRADED static")
    check("and the coverage denominator is identical in both modes",
          all(_evid[k]["auto"][1] == _evid[k]["off"][1] for k in _evid),
          "7/10 either way - coverage cannot tell the reader which happened")
else:
    print("      (helm absent; skipped rather than asserted)")
    check("helm present for the evidence-basis measurement", False,
          "this proof will not fake a helm run")

print()
print("  (3) The weights are a judgement, not a measurement. RESOURCES 15 and")
print("      CHART 4 encode somebody's opinion that requests/limits matter")
print("      ~4x chart hygiene. No evidence in this repo supports that ratio.")
print("      It is documented as an opinion in scoring.py and README, and it")
print("      is the reason the number is called a weighted finding count")
print("      rather than a risk score.")
check("the tool describes the score as what it is, not as risk",
      "not an estimate of risk" in open(
          os.path.join(REPO, "hpaanalyzer", "report.py")).read())

hr("VERDICT")
print("  Bar 1 asked whether the arithmetic was honest. It was, and it now")
print("  shows its denominator.")
print()
print("  Bar 2 asked whether the grade does its job. It found that the job")
print("  includes gating a deploy, that the pre-fix gate could be turned")
print("  green by deleting a file, and that an honest REPORT does not fix a")
print("  dishonest EXIT CODE. That needed a second change, which is the only")
print("  reason this iteration touched __main__.py at all.")
print()
print("  What is not claimed: that the score is now comparable across runs in")
print("  general. It is not. Floored categories cannot order two bad charts,")
print("  helm-rendered and static scores are printed in the same units, and")
print("  the weights are an opinion. Those are stated in CLAIM 5, in the")
print("  report itself, and in the README - not fixed, and not hidden.")
print()
if FAIL:
    print(f"  {len(FAIL)} CHECK(S) FAILED:")
    for f in FAIL:
        print(f"    - {f}")
    raise SystemExit(1)
print("  ALL CHECKS PASSED")

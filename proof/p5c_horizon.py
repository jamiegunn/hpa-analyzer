"""R5, second defect: the analyzer reported the edge of its own sampling as a
property of the world.

THE CLAIM UNDER TEST
    kubeVersion: ">=1.61.0-0" parses, and is satisfiable - by 1.61 and up.
    The analyzer enumerates minors 1.0 .. 1.DOMAIN_MAX_MINOR, so its minor set
    came back empty, and the empty set fell into CH013, whose text reads "no
    Kubernetes 1.x release satisfies it" and whose stated usual cause is "a
    reversed or overlapping pair of bounds".

    Both halves are false about this chart. Nothing is reversed, and the tool
    had not established that nothing satisfies the range - it had stopped
    looking at 1.60. That is contract C2.2 (do not report a limit of the
    method as a finding about the target) violated by the tool that exists to
    catch C2.2 violations in other people's charts.

    It is not cosmetic. CH013 sends the reader hunting a bound conflict that
    does not exist. The actual bug in ">=1.61.0-0" is one transposed digit.

A NOTE ON THE BEFORE COLUMN - READ THIS BEFORE TRUSTING THE TABLE
    Every other proof in this directory extracts its BEFORE tree with
    `git archive` at the pinned baseline SHA, so the old numbers are real
    output from real old code. That is impossible here and the difference is
    not a technicality:

      * The baseline commit predates iteration 3. CH013 does not exist in it
        at all, so extracting it would print "no finding" and prove nothing
        about the defect.
      * The defective revision - R3's CH013 with no horizon concept - was
        never committed. There is no object to archive.

    So the BEFORE column here is RECONSTRUCTED: the child process runs the
    CURRENT tree with one thing disabled, `DeclaredRange.above_domain` forced
    to False, which is precisely the state of the field before R5 added it
    (it did not exist, so no branch could test it). Everything else - the
    loader, the engine, CH013's own branch - is the real code path.

    This is weaker evidence than an archived tree and is labelled as such in
    the output. What it cannot rule out: that R5 changed CH013's own wording
    at the same time (it did - the detail now adds "and probed above that
    horizon too"). CLAIM 2 therefore asserts only on the part of CH013's text
    that R3 wrote and R5 did not touch.
"""

import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

FAILURES = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


CHART = """apiVersion: v2
name: horizon
version: 1.0.0
appVersion: "1.0.0"
description: kubeVersion horizon fixture
kubeVersion: "{kv}"
"""

DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: horizon
  labels: {app.kubernetes.io/name: horizon}
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3
"""

_CHILD = r'''
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
KV, DISABLE = sys.argv[2], sys.argv[3] == "disable"

from hpaanalyzer import kubeversion as kv_mod

if DISABLE:
    # Reconstruct the pre-R5 field: `above_domain` did not exist, so no
    # branch could consult it. Forcing it False is the faithful equivalent
    # and is the ONLY thing this child changes.
    import dataclasses
    _real = kv_mod.declared_range
    def _patched(raw):
        dr = _real(raw)
        return dataclasses.replace(dr, above_domain=False)
    kv_mod.declared_range = _patched
    import hpaanalyzer.checks_chart as cc
    cc.declared_range = _patched
    import hpaanalyzer.renderplan as rp
    rp.declared_range = _patched

from hpaanalyzer.engine import analyze
from hpaanalyzer.renderplan import plan as render_plan

d = tempfile.mkdtemp(prefix="hpa-horizon-")
open(os.path.join(d, "Chart.yaml"), "w").write(sys.stdin.read().replace("@KV@", KV))
open(os.path.join(d, "values.yaml"), "w").write("replicaCount: 2\n")
os.makedirs(os.path.join(d, "templates"))
open(os.path.join(d, "templates", "objects.yaml"), "w").write(
    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: horizon\n"
    "  labels: {app.kubernetes.io/name: horizon}\nspec:\n  template:\n"
    "    spec:\n      containers:\n        - name: app\n"
    "          image: nginx:1.25.3\n")

r = analyze(d, helm_mode="off")
hits = {f.rule_id: {"sev": f.severity.name, "detail": f.detail, "fix": f.fix}
        for f in r.findings if f.rule_id in ("CH013", "CH014", "CH017")}
dr = kv_mod.declared_range(KV)
plan = render_plan(KV)
print("---JSON---" + json.dumps({
    "hits": hits,
    "parsed": dr.parsed,
    "minors": len(dr.minors),
    "above_domain": bool(dr.above_domain),
    "describe": dr.describe(),
    "plan_source": plan.source,
}))
'''


def run(kv, disable):
    p = subprocess.run(
        [sys.executable, "-c", _CHILD, REPO, kv, "disable" if disable else "keep"],
        input=CHART.replace("{kv}", "@KV@"), capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"child failed for {kv!r} (disable={disable}):\n"
                         f"{p.stderr[-3000:]}")
    return json.loads(p.stdout.split("---JSON---", 1)[1])


HORIZON = ">=1.61.0-0"
TYPO = ">=1.99.0-0"
MAJOR = ">=2.0.0-0"
REVERSED = ">=1.30.0-0 <1.20.0-0"
CEILING = "<1.0.0-0"
FINE = ">=1.29.0-0"

print(__doc__)
print("=" * 78)
print("BEFORE  = current tree, DeclaredRange.above_domain forced False")
print("          (RECONSTRUCTED, not `git archive` - see the docstring)")
print("AFTER   = current tree, unmodified")
print("=" * 78)

DOMAIN_MAX = __import__("hpaanalyzer.kubeversion", fromlist=["x"]).DOMAIN_MAX_MINOR
print(f"\nDOMAIN_MAX_MINOR = {DOMAIN_MAX}  (the analyzer enumerates 1.0 .. 1.{DOMAIN_MAX})")

# ---------------------------------------------------------------- CLAIM 1
print("\n\nCLAIM 1: the constraint really is satisfiable - the tool just could "
      "not see it")
print("-" * 78)
a = run(HORIZON, disable=False)
print(f"  kubeVersion            : {HORIZON!r}")
print(f"  parsed                 : {a['parsed']}")
print(f"  minors enumerated      : {a['minors']}   <- inside 1.0 .. 1.{DOMAIN_MAX}")
print(f"  admits something above : {a['above_domain']}")
print(f"  describe()             : {a['describe']!r}")
check("it parses (so 'unparseable' was never the right answer)", a["parsed"])
check("no in-domain minor satisfies it", a["minors"] == 0)
check("but versions above the horizon do", a["above_domain"] is True)

# ---------------------------------------------------------------- CLAIM 2
print("\n\nCLAIM 2: BEFORE, that gap was reported as a contradiction")
print("-" * 78)
b = run(HORIZON, disable=True)
print(f"  BEFORE rules fired     : {sorted(b['hits']) or 'none'}")
if "CH013" in b["hits"]:
    print(f"  BEFORE CH013 severity  : {b['hits']['CH013']['sev']}")
    print(f"  BEFORE CH013 detail    : {b['hits']['CH013']['detail'][:200]}")
    print("  NOTE: that detail is CURRENT wording run through a reconstructed")
    print("        BEFORE, so its 'probed above that horizon too' clause is an")
    print("        artifact - R3's text did not contain it, and here it is")
    print("        false besides (CLAIM 1 shows the probe does find versions).")
    print("        The clause makes the BEFORE read WORSE than R3 actually was;")
    print("        the checks below therefore ignore it and assert only on the")
    print("        sentence R3 wrote and R5 left alone.")
check("BEFORE: CH013 fires", "CH013" in b["hits"])
check("BEFORE: at CRITICAL", b["hits"].get("CH013", {}).get("sev") == "CRITICAL")
# Assert only on R3-authored wording that R5 did not edit, per the docstring.
_r3_text = "no Kubernetes 1.x release satisfies it"
check(f"BEFORE: it states {_r3_text!r} - a claim about Kubernetes, not "
      f"about how far we sampled",
      _r3_text in b["hits"].get("CH013", {}).get("detail", ""))
check("BEFORE: no CH017 exists to say otherwise", "CH017" not in b["hits"])
print(f"  BEFORE render plan     : source={b['plan_source']!r}")
check("BEFORE: the render plan calls it unparseable, which CLAIM 1 refutes",
      b["plan_source"] == "unparseable")

# ---------------------------------------------------------------- CLAIM 3
print("\n\nCLAIM 3: AFTER, the two causes are told apart")
print("-" * 78)
rows = []
for kv, tag in ((HORIZON, "floor above horizon (minor axis)"),
                (TYPO, "floor above horizon (placeholder typo)"),
                (MAJOR, "floor above horizon (MAJOR axis)"),
                (REVERSED, "reversed bounds"),
                (CEILING, "ceiling below every release"),
                (FINE, "correct")):
    r = run(kv, disable=False)
    rows.append((kv, tag, sorted(r["hits"]), r["plan_source"], r["above_domain"]))
w = max(len(r[0]) for r in rows)
print(f"  {'kubeVersion'.ljust(w)}  {'what it is':38}  {'fires':10}  "
      f"{'plan source':14}  above")
for kv, tag, hits, src, ad in rows:
    print(f"  {kv.ljust(w)}  {tag:38}  {(','.join(hits) or '-'):10}  "
          f"{src:14}  {ad}")

_by = {r[0]: r for r in rows}
check("CH017 (not CH013) for the above-horizon floor",
      _by[HORIZON][2] == ["CH017"], f"got {_by[HORIZON][2]}")
check("CH017 (not CH013) for the placeholder typo",
      _by[TYPO][2] == ["CH017"], f"got {_by[TYPO][2]}")
check("CH013 (not CH017) still owns reversed bounds",
      _by[REVERSED][2] == ["CH013"], f"got {_by[REVERSED][2]}")
check("CH013 (not CH017) owns a ceiling below every release - the probe "
      "above the horizon must come back false here",
      _by[CEILING][2] == ["CH013"], f"got {_by[CEILING][2]}")
check("a correct constraint fires neither", _by[FINE][2] == [],
      f"got {_by[FINE][2]}")
check("the render plan names the case instead of blaming the author",
      _by[HORIZON][3] == "above-horizon", f"got {_by[HORIZON][3]!r}")

# ---------------------------------------------------------------- CLAIM 3b
print("\n\nCLAIM 3b: the SECOND edge - a defect this proof's first draft "
      "missed entirely")
print("-" * 78)
print("  `declared_range(majors=(1,))` samples one major, so '>=2.0.0-0' also")
print("  produced an empty minor set. The first cut of R5's fix probed minors")
print("  ONLY, and left that case in CH013 with a render plan of")
print("  'unparseable'. It survived review because CH013's headline is TRUE")
print("  for it - no 2.x has shipped - which is the most dangerous kind of")
print("  wrong: accidentally right in the summary, wrong in the diagnosis")
print("  ('reversed bounds'), and flatly false in the subsidiary claim")
print("  ('unparseable' about a string that parses).")
m = run(MAJOR, disable=False)
mf = m["hits"].get("CH017", {})
print(f"\n  AFTER, {MAJOR!r}:")
print(f"    fires       : {sorted(m['hits'])}")
print(f"    plan source : {m['plan_source']}")
print(f"    describe()  : {m['describe']!r}")
print(f"    detail      : {mf.get('detail', '(none)')}")
print(f"    fix         : {mf.get('fix', '(none)')}")
check("CH017, not CH013, for a 2.x floor", sorted(m["hits"]) == ["CH017"],
      f"got {sorted(m['hits'])}")
check("the plan stops calling a parseable constraint 'unparseable'",
      m["plan_source"] == "above-horizon", f"got {m['plan_source']!r}")
check("it says 2.0 rather than the minor horizon - the wrong number would "
      "read as precision",
      "2.0" in mf.get("detail", "")
      and f"only by versions above 1.{DOMAIN_MAX}" not in mf.get("detail", ""))
check("the ADVICE differs too (a 2 is a typo for a 1.x minor, not a digit "
      "to re-check)",
      "2.0" in mf.get("fix", "") and "digit-by-digit" not in mf.get("fix", ""))

# ---------------------------------------------------------------- CLAIM 4
print("\n\nCLAIM 4: the replacement says what it does not know (C2.2)")
print("-" * 78)
f = run(HORIZON, disable=False)["hits"]["CH017"]
print(f"  detail: {f['detail']}")
print(f"  fix   : {f['fix']}")
check("names the horizon as this analyzer's limit, in the detail",
      f"1.{DOMAIN_MAX}" in f["detail"])
check("names it again in the fix, where the reader acts",
      f"1.{DOMAIN_MAX}" in f["fix"])
check("disowns the contradiction reading by rule id",
      "CH013" in f["detail"])
check("quotes what the author actually wrote", "1.61.0-0" in f["detail"])
check("severity is still CRITICAL - the chart installs nowhere either way",
      f["sev"] == "CRITICAL")

# ---------------------------------------------------------------- CLAIM 5
print("\n\nCLAIM 5: what this fix does NOT do")
print("-" * 78)
print("  The horizon is still 1.%d. A chart pinned '>=1.61.0-0' is still not"
      % DOMAIN_MAX)
print("  reasoned about beyond that point: CH017 reports the floor and stops.")
print("  If Kubernetes ships 1.61, this analyzer will call a correct chart")
print("  CRITICAL until DOMAIN_MAX_MINOR is raised. That is a known, bounded,")
print("  DOCUMENTED wrong answer, which is a different thing from the")
print("  undocumented one R5 removed - but it is not no wrong answer.")
above = run(HORIZON, disable=False)
check("the tool still refuses to pick a render version above the horizon "
      "rather than guessing one", above["plan_source"] == "above-horizon")

print("\n" + "=" * 78)
if FAILURES:
    print(f"{len(FAILURES)} CHECK(S) FAILED:")
    for x in FAILURES:
        print(f"  - {x}")
    sys.exit(1)
print("all checks passed")

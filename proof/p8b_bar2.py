#!/usr/bin/env python3
"""PROOF R8, Bar 2: a JVM check that fires on a filename is not a JVM check.

Bar 1 (proof/p8_jvm_gate.py) shows the gate was wrong in both directions and
that both directions are now closed. That is "correct". This asks the harder
question the user set - "not just correct, but does it do what it is supposed
to do" - and the way to ask it is not "did the rule fire" but "what happened
to the person who read the report".

Two people read this tool's output about a JVM, and the pre-fix tool failed
each of them in a different way:

    the operator of a Java service   was told the chart was fine (A-, and not
                                     one finding about memory at any severity)
                                     while its pod spec asked for a 4 GiB heap
                                     inside a 2 GiB limit. They deploy. The
                                     kernel kills it.

    the operator of an nginx service was told, at HIGH, to set
                                     -XX:MaxRAMPercentage on a container with
                                     no JVM in it. They either do something
                                     inert, or they learn that this tool
                                     invents findings - and that lesson is
                                     applied to the true findings printed
                                     beside it.

The second cost is the one a rules-and-counts view misses entirely. A false
finding is not a neutral entry in a list; it spends the reader's trust, and
the trust is the only thing that makes the true findings act.

CLAIM 1  FACE A cost: the pre-fix report on a chart with a guaranteed OOMKill
         carries no finding about memory at any severity, and grades it A-.
CLAIM 2  and the grade could not have saved them either. The SAME gate that
         hid the finding also removed the category it lands in from the
         score's denominator - so even a tool that FOUND the CRITICAL would
         have printed the identical number. Measured by re-scoring the fixed
         tool's findings over the pre-fix denominator: 0.0 points of movement.
CLAIM 3  FACE B cost: what the nginx operator was actually told to do, and
         the true findings whose credibility it was spent on.
CLAIM 4  AFTER: both closed - and FACE B is not closed by going quiet, which
         would be indistinguishable from a pass. The report says the JVM
         checks did not apply, and says what would make them apply.
CLAIM 5  the defect was ONE wrong question asked in THIRTEEN places, so fixing
         the checks was not fixing the tool. Every reader-visible surface is
         enumerated and measured on both charts - because a reader does not
         experience modules, they experience one page that has to agree with
         itself.
CLAIM 6  what is STILL not fixed, measured rather than hidden: the evidence
         is a heuristic over names and env vars, and an opaque corporate
         image with no flags remains invisible to it. The tool now says so
         instead of guessing.

BEFORE is the committed pre-fix tree, extracted with `git archive` at the SHA
pinned in proof/baseline.py (NOT HEAD), run as a real subprocess over real
directories. Run: python3 proof/p8b_bar2.py
"""

import copy
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE - see the module for why)

from baseline import resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)

WORKER = os.path.join(REPO, "fixtures", "umbrella-chart", "charts", "worker")
NOJVM = os.path.join(REPO, "fixtures", "nojvm-chart")

_BEFORE_TREE = None


def before_tree():
    global _BEFORE_TREE
    if _BEFORE_TREE is None:
        tmp = tempfile.mkdtemp(prefix="hpa-before-r8b-")
        tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _BEFORE_TREE = tmp
    return _BEFORE_TREE


def cli(tree, target):
    """Run the CLI the way a user does: a real process, real files on disk."""
    d = tempfile.mkdtemp(prefix="hpa-r8b-out-")
    out, jsn = os.path.join(d, "r.txt"), os.path.join(d, "r.json")
    p = subprocess.run(
        [sys.executable, "-m", "hpaanalyzer", target, "-o", out, "--full",
         "--quiet", "--json", jsn],
        capture_output=True, text=True, cwd=tree,
        env=dict(os.environ, PYTHONPATH=tree))
    if not os.path.isfile(jsn):
        raise SystemExit(f"CLI produced no JSON ({tree}):\n{p.stderr[-2000:]}")
    with open(jsn, encoding="utf-8") as f:
        payload = json.load(f)
    with open(out, encoding="utf-8") as f:
        text = f.read()
    return {"json": payload, "text": text}


def flat(res):
    """Report text with wrapping and table borders removed, nothing else.

    The tables hard-wrap at a fixed width, so a searched-for phrase is
    routinely split across two lines with a `|` between the halves. Searching
    raw text would make this a test of the wrapper - the single most repeated
    mistake in this suite, recorded here again for the same reason.
    """
    return " ".join(res["text"].replace("|", " ").split())


def sev(res, *levels):
    """Findings at these severities, case-normalised.

    The JSON emits `"severity": "HIGH"`; the Python enum's value is lowercase.
    Written as a bare `in ("critical", "high")` this helper returned [] on
    every chart, and CLAIM 1 - "not one finding at CRITICAL" - passed on every
    input including the ones that are full of them. A proof that cannot fail
    proves nothing, so the comparison is normalised at the one place it is
    made rather than spelled correctly at each call site.
    """
    want = {l.upper() for l in levels}
    return [f for f in res["json"]["findings"]
            if str(f["severity"]).upper() in want]


FAIL = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
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
print(f"BEFORE tree : git archive {BASELINE_SHA[:9]}  (pinned, not HEAD)")
print(f"AFTER  tree : {REPO}")
print(f"FACE A chart: {os.path.relpath(WORKER, REPO)}")
print(f"FACE B chart: {os.path.relpath(NOJVM, REPO)}")

b_worker = cli(before_tree(), WORKER)
a_worker = cli(REPO, WORKER)
b_nojvm = cli(before_tree(), NOJVM)
a_nojvm = cli(REPO, NOJVM)

hr("CLAIM 1: FACE A. What the Java operator was told.")
bj = b_worker["json"]
crit = sev(b_worker, "critical")
high = sev(b_worker, "high")
print(f"  pre-fix verdict on a chart whose pod spec sets -Xmx4g under a 2Gi")
print(f"  limit:  GRADE {bj['grade']}  ({bj['score']}/100), "
      f"{len(bj['findings'])} findings")
print(f"    critical : {len(crit)}")
print(f"    high     : {len(high)}")
print(f"    rules    : {', '.join(sorted({f['rule'] for f in bj['findings']}))}")
print(f"    the 2 HIGHs are : "
      + "; ".join(f"{f['rule']} {f['title']} [{f.get('category')}]"
                  for f in high))
mem = [f for f in bj["findings"]
       if f["rule"].startswith(("JV", "XF", "RS"))
       or any(w in str(f.get("category", "")).lower()
              for w in ("memory", "resource"))
       or any(w in f["title"].lower() for w in ("heap", "memory", "oom"))]
check("pre-fix: not one finding at CRITICAL", not crit)
check("pre-fix: nothing at ANY severity about memory, heap or the limit",
      not mem, f"{[f['rule'] for f in mem]}" if mem else "")
check("pre-fix: and the heap is never compared to the limit",
      "XF001" not in {f["rule"] for f in bj["findings"]})
print()
print("  The first draft of this claim asserted 'no finding above MEDIUM',")
print("  and the run above refutes it: there are two HIGHs. They are a")
print("  missing readinessProbe and a possibly-root container - both real,")
print("  both in other categories, and neither one anything a reader chasing")
print("  a memory question would follow. The claim is therefore made on the")
print("  axis the measurement supports, which is also the sharper one: on a")
print("  chart whose pod spec asks for a 4 GiB heap inside a 2 GiB limit,")
print("  the pre-fix tool produced ZERO findings about memory at any")
print("  severity. Not a hedge, not a LOW, not an INFO - nothing.")
print()
print("  That is worse than a miss, because the report is not ambiguous. The")
print("  one sum this program exists to compute (heap + metaspace + code")
print("  cache + threads*Xss + direct vs limits.memory) was never attempted,")
print("  and nothing in the output marks the gap, so the reader cannot even")
print("  know to look elsewhere. C2.2 exists for exactly this: a limit of the")
print("  method was printed as a finding about the target.")

hr("CLAIM 2: and the GRADE could not have saved them either.\n"
   "         Two gates, arranged so that finding it would not have mattered.")
from hpaanalyzer.engine import analyze            # noqa: E402
from hpaanalyzer.scoring import category_scores, WEIGHTS  # noqa: E402

live = analyze(WORKER, helm_mode="off")


def weighted(result, excluded):
    num = den = 0.0
    for c, s, _ in category_scores(result):
        if s is None or c.name in excluded:
            continue
        w = WEIGHTS[c]
        num += s * w
        den += w
    return round(num / den, 1)


def dropping(result, rule_id):
    r2 = copy.deepcopy(result)
    r2.findings = [f for f in r2.findings if f.rule_id != rule_id]
    return r2


# The pre-fix denominator for this chart: no Dockerfile, so DOCKERFILE, JAVA
# and CROSS were all declared unassessable by the same `ctx.dockerfiles` test.
PRE_DEN = {"DOCKERFILE", "JAVA", "CROSS"}
NOW_DEN = {"DOCKERFILE"}
pre_with = weighted(live, PRE_DEN)
pre_without = weighted(dropping(live, "XF001"), PRE_DEN)
now_with = weighted(live, NOW_DEN)
now_without = weighted(dropping(live, "XF001"), NOW_DEN)
print("  Take the FIXED tool's findings - including the CRITICAL - and score")
print("  them over the PRE-FIX denominator. Then delete the CRITICAL and")
print("  score again. The difference is what that finding was worth to a")
print("  reader who gates on the number:")
print()
print(f"      pre-fix denominator (7 categories)   with XF001 {pre_with}"
      f"   without {pre_without}   delta {abs(pre_with - pre_without):.1f}")
print(f"      fixed  denominator (9 categories)    with XF001 {now_with}"
      f"   without {now_without}   delta {abs(now_with - now_without):.1f}")
check("the CRITICAL was worth exactly 0.0 points under the pre-fix scale",
      pre_with == pre_without,
      f"{pre_with} either way")
check("under the fixed scale the same finding moves the grade",
      abs(now_with - now_without) > 1.0,
      f"{now_without} -> {now_with}, {abs(now_with - now_without):.1f} points")
print()
print("  That zero is the whole point of this claim, and it is not a")
print("  coincidence - it is the same line of code twice. `ctx.dockerfiles`")
print("  decided whether the check ran, AND `scoring.unassessed_reason` used")
print("  the identical test to decide whether the category counted. So on a")
print("  chart with no Dockerfile the CROSS category was removed from the")
print("  denominator by the same condition that stopped anything being put")
print("  into it. Fixing only the check would have produced a tool that")
print("  found a guaranteed OOMKill and still printed 90.9 - which is why R8")
print("  had to be one change across thirteen sites and not a patch at one.")

hr("CLAIM 3: FACE B. What the nginx operator was told to do,\n"
   "         and whose credibility it was spent.")
inv = [f for f in b_nojvm["json"]["findings"] if f["rule"].startswith(("JV", "DF"))]
for f in sorted(inv, key=lambda f: f["rule"]):
    print(f"    {f['severity'].upper():8} {f['rule']}  {f['title']}")
    print(f"             file={f.get('file')}  basis={f.get('basis')}")
    if f.get("fix"):
        print(f"             fix: {' '.join(str(f['fix']).split())[:150]}")
jv = [f for f in b_nojvm["json"]["findings"] if f["rule"] == "JV021"]
check("pre-fix: a JVM heap finding on a chart with no JVM", bool(jv))
check("...at HIGH", bool(jv) and jv[0]["severity"].upper() == "HIGH")
check("...on OBSERVED basis - asserted as read, not inferred",
      bool(jv) and jv[0].get("basis") == "observed")
check("...and the score carries a Java category row",
      "Java" in flat(b_nojvm) and "76.0" in flat(b_nojvm))
print()
print("  Now the part a rule count cannot see. Those findings did not print")
print("  alone - they printed in the same list as these, which are TRUE of")
print("  this chart and worth acting on:")
true_ones = [f for f in b_nojvm["json"]["findings"]
             if f["rule"] in ("PB004", "PB005", "SC001", "SC002", "AV003")]
for f in sorted(true_ones, key=lambda f: f["rule"])[:5]:
    print(f"    {f['severity'].upper():8} {f['rule']}  {f['title']}")
print()
print("  An operator who checks the JVM claim first - it is the loudest, and")
print("  it is trivially checkable by reading their own Dockerfile - finds it")
print("  is nonsense about software they do not run. Every finding above")
print("  inherits that. This is the asymmetry that makes invention cost more")
print("  than silence: silence loses one finding, invention discounts the")
print("  whole page.")

hr("CLAIM 4: AFTER. Both closed - and the silence is not silence.")
aj_w, aj_n = a_worker["json"], a_nojvm["json"]
xf = [f for f in aj_w["findings"] if f["rule"] == "XF001"]
print(f"  FACE A chart: GRADE {aj_w['grade']} ({aj_w['score']}/100), "
      f"was {bj['grade']} ({bj['score']}/100)")
check("the OOMKill is now reported", bool(xf))
check("...at CRITICAL", bool(xf) and xf[0]["severity"].upper() == "CRITICAL")
check("...on OBSERVED basis, because both numbers were read from the chart",
      bool(xf) and xf[0].get("basis") == "observed")
if xf:
    print(f"    {' '.join(str(xf[0].get('detail', '')).split())[:180]}")
check("and the arithmetic is shown, not just the verdict",
      "4 GiB" in flat(a_worker) and "2 GiB" in flat(a_worker))

print()
print(f"  FACE B chart: GRADE {aj_n['grade']} ({aj_n['score']}/100), "
      f"was {b_nojvm['json']['grade']} ({b_nojvm['json']['score']}/100)")
after_jv = [f for f in aj_n["findings"] if f["rule"].startswith("JV")]
check("no JVM findings on the nginx chart", not after_jv,
      f"{[f['rule'] for f in after_jv]}" if after_jv else "")
check("the JAVA category is not scored", "JAVA" in flat(a_nojvm))
check("...and says it was NOT ASSESSED rather than vanishing",
      "not assessed" in flat(a_nojvm).lower())
print()
print("  C2.6, and the reason this claim is not just `assertNotIn`: an")
print("  unrun check and a passed check look identical in a report that only")
print("  prints failures. Deleting the JV021 line would have replaced a false")
print("  HIGH with a false clean bill of health. So the coverage row states")
print("  the gap AND what would close it:")
for line in a_nojvm["text"].splitlines():
    if "wrong place" in line or "JAVA_TOOL_OPTIONS in the pod spec" in line:
        print(f"    {' '.join(line.replace('|', ' ').split())}")
check("the remedy names the input, not the rule",
      "JAVA_TOOL_OPTIONS" in flat(a_nojvm))

hr("CLAIM 5: one wrong question, thirteen places. Every reader-visible\n"
   "         surface, measured on both charts.")
print("  R8 began as four sites in the check layer. Fixing those four left")
print("  the tool still printing `Dockerfile [Java version unknown]` on the")
print("  FIRST line of the nginx report, still titling a probe finding after")
print("  a JVM, still demanding `--assume-java` in the preflight block, and")
print("  still withholding the cgroup probe from the chart with -Xmx in its")
print("  pod spec. The checks were right and the page still lied, because a")
print("  reader does not experience modules.")
print()
print("  The last three were found by THIS proof rather than by reading the")
print("  code, and they are the smallest: two security findings whose")
print("  rationale prose explained itself in terms of a JVM without gating")
print("  on one, an appendix that printed a JVM primer on every chart, and")
print("  a file inventory that - being a list of FILES - said nothing about")
print("  a JVM on the chart whose JVM is declared in its pod spec. None of")
print("  them is a rule. All of them are the page telling the reader")
print("  something about a runtime, which is why they are in the table.")
print()
from hpaanalyzer.preflight import build_preflight     # noqa: E402
from hpaanalyzer.clusterprobes import build_probes    # noqa: E402
from hpaanalyzer.kube import jvm_evidence             # noqa: E402
from hpaanalyzer.scoring import coverage              # noqa: E402

live_nojvm = analyze(NOJVM, helm_mode="off")


def asserts_jvm(text, ev):
    """Does this surface tell the reader a JVM is present?

    Two ways it can, and both count. It can reproduce the evidence sentence
    the analysis actually used (`ev` = jvm_evidence(ctx) for this chart) - the
    honest form, since the reader can then check the claim against their own
    pod spec. Or it can assert a JVM in its own words, which is the form R8
    was about: `Java version unknown`, `Re-run with --assume-java`.

    Written first as `"JVM detected" in pf`, which matched inside the string
    `no JVM detected` and reported the pure-nginx chart as asserting a JVM -
    the exact inversion this claim exists to rule out, reproduced inside the
    instrument that was supposed to detect it. Negations are stripped before
    the affirmative search, and they are listed literally rather than matched
    by regex so that adding one is a deliberate act.
    """
    t = " ".join(text.lower().split())
    for negated in ("no jvm detected", "no jvm in it", "no jvm evidence",
                    "nothing in this file indicates a jvm",
                    "nothing in this chart indicates a jvm",
                    "nothing indicates a jvm",
                    "none detected (checked pod-spec env"):
        t = t.replace(negated, "")
    if any(" ".join(e.lower().split())[:50] in t for e in ev):
        return True
    return any(k in t for k in ("jvm evidenced", "jvm detected", "--assume-java",
                                "java version unknown", "java 8", "java 11",
                                "java 17", "java 21"))


def surfaces(result, res):
    """The six places a reader meets the JVM question, as booleans.

    `txt` is the CHART-SPECIFIC part of the report. Section 6 is a reference
    manual whose JVM chapters print for every chart by design (report.py
    `_education`), and it is excluded here on that basis - not to make the
    table come out even. The exclusion is checked, not asserted: the two
    reports' section 6 are compared below, and the claim only stands if the
    part being excluded is identical between a JVM chart and an nginx one
    apart from the detection note that now heads 6.2.
    """
    pf = " ".join(f"{i.label} {i.hint}"
                  for i in build_preflight(result.context).items)
    txt = flat(res).split("6.1 THE HPA CONTROL LOOP")[0]
    head = txt.split("EXECUTIVE SUMMARY")[0]
    cov = coverage(result)
    ev = jvm_evidence(result.context)
    return {
        "preflight asserts a JVM": asserts_jvm(pf, ev),
        "file inventory asserts a JVM": asserts_jvm(head, ev),
        "a JV/XF finding is raised":
            any(f["rule"].startswith(("JV", "XF"))
                for f in res["json"]["findings"]),
        "JAVA category is scored":
            any(c.name == "JAVA" for c in cov.assessed),
        "cgroup probe is offered":
            "jvm-sees-limit" in {p.key for p in build_probes(result)},
        "prose claims JVM startup behaviour":
            "class loading" in txt.lower() or "JIT" in txt,
    }


s_java = surfaces(live, a_worker)
s_nginx = surfaces(live_nojvm, a_nojvm)
print(f"  {'surface':38}{'JVM in pod spec':>17}{'pure nginx':>13}")
for k in s_java:
    print(f"  {k:38}{str(s_java[k]):>17}{str(s_nginx[k]):>13}")
check("every surface agrees a JVM is present on the JVM chart",
      all(s_java.values()),
      "disagreeing: " + ", ".join(k for k, v in s_java.items() if not v))
check("every surface agrees there is none on the nginx chart",
      not any(s_nginx.values()),
      "disagreeing: " + ", ".join(k for k, v in s_nginx.items() if v))

# The excluded region, checked rather than asserted. Section 6 is a manual:
# if it differed between the two charts it would be reporting, not reference,
# and excluding it from the table above would be hiding a surface.
def section6(res):
    return flat(res).split("6.1 THE HPA CONTROL LOOP")[-1]


def without_note(s6):
    """Section 6 minus the one bracketed line that states the detection."""
    return re.sub(r"\[(?:applies to this chart|reference only)[^\]]*\]", "", s6)


s6_java, s6_nginx = section6(a_worker), section6(a_nojvm)
note_java = "[applies to this chart -" in s6_java
note_nginx = "[reference only - nothing in this chart indicates a JVM" in s6_nginx
check("both primers carry a note saying whether they apply to THIS chart",
      note_java and note_nginx)
check("and apart from that note section 6 is identical between the two charts",
      without_note(s6_java) == without_note(s6_nginx),
      "so it is reference material, not a claim about the target")
print("  Section 6 (the primer) is excluded from the table and the line above")
print("  is why that is legitimate: it is byte-identical between the two")
print("  charts apart from a note that STATES the detection result. Its JVM")
print("  chapters are kept even for a chart with no JVM evidence, on purpose")
print("  - CLAIM 6's opaque image is a real Java service this tool cannot")
print("  detect, and withholding the heap arithmetic from precisely that")
print("  reader would turn an admitted blind spot into a withheld answer.")
print("  So it is labelled instead of deleted: reference, not finding.")
print()
print("  The JVM chart ships NO Dockerfile and the nginx chart ships one, so")
print("  a column of six agreeing `True` beside a column of six agreeing")
print("  `False` is the whole of R8 in one table: the answer now tracks the")
print("  JVM and not the filename, on every surface, in both directions.")

hr("CLAIM 6: what is STILL not fixed. The evidence is a heuristic.")
DEP = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
      - name: api
        image: corp.registry/payments-api:4.2
        resources:
          requests: {cpu: 500m, memory: 1Gi}
          limits: {cpu: "1", memory: 2Gi}
"""
d = tempfile.mkdtemp(prefix="hpa-opaque-")
os.makedirs(os.path.join(d, "templates"))
for path, body in (("Chart.yaml", "apiVersion: v2\nname: opaque\nversion: 1.0.0\n"),
                   ("values.yaml", "{}\n"),
                   ("templates/deployment.yaml", DEP)):
    with open(os.path.join(d, path), "w", encoding="utf-8") as f:
        f.write(body)
opaque = analyze(d, helm_mode="off")
cov = coverage(opaque)
reason = next((r for c, r in cov.unassessed if c.name == "JAVA"), "")
print("  A Spring Boot service whose image is `corp.registry/payments-api:4.2`,")
print("  built by a pipeline this run cannot see, with its JVM flags baked")
print("  into the image rather than the pod spec, is a JVM this tool cannot")
print("  detect. It is the single most common real-world shape, and R8 does")
print("  not solve it - R8 stops the tool GUESSING about it.")
print()
print(f"    JAVA assessed: {any(c.name == 'JAVA' for c in cov.assessed)}")
print(f"    reason given : {' '.join(reason.split())[:300]}")
check("the tool does not invent a JVM for an opaque image",
      not any(c.name == "JAVA" for c in cov.assessed))
check("...and does not invent its ABSENCE either - it names the gap",
      "nothing in this chart indicates" in reason.lower())
check("...and lists exactly what it looked at, so the reader can supply it",
      "JAVA_TOOL_OPTIONS" in reason and "FROM" in reason)
print()
print("  This is C2.2 doing its job rather than being violated: 'I could not")
print("  determine this' is reported as a limit of the method, in the place")
print("  the answer would have gone, with the inputs it examined listed so")
print("  the reader can close the gap by adding one. The pre-fix tool had no")
print("  vocabulary for this state at all - it had a filename, and a filename")
print("  is always either there or not.")

hr("VERDICT")
print("  Bar 1 asked whether the gate tested the right thing. It did not,")
print("  and now it does.")
print()
print("  Bar 2 asked what the wrong gate cost the reader, and the answer was")
print("  worse in both directions than a rule count shows. The Java operator")
print("  got a confident A- over a guaranteed OOMKill - and CLAIM 2 shows")
print("  the number could not have warned them even if the finding had been")
print("  made, because the same condition removed the category from the")
print("  denominator. The nginx operator got a HIGH instructing them to")
print("  configure a runtime they do not run, printed beside real findings")
print("  it discredited.")
print()
print("  What is not claimed: that this tool can now tell whether an")
print("  arbitrary image runs a JVM. It cannot, and CLAIM 6 measures the")
print("  case where it fails. The change is that it says so - in the")
print("  coverage table, in the preflight block, and in the category row -")
print("  instead of answering a question about a runtime by looking at a")
print("  directory listing.")
print()
if FAIL:
    print(f"  {len(FAIL)} CHECK(S) FAILED:")
    for f in FAIL:
        print(f"    - {f}")
    sys.exit(1)
print("  ALL CHECKS PASSED")

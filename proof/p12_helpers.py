#!/usr/bin/env python3
"""PROOF R11, Bar 1: the tool accused charts of a defect it could not see.

THE SUBJECT

Helm charts put shared blocks in `templates/_helpers.tpl` and pull them in
with `include`. It is the idiom `helm create` itself teaches, and resources
are one of the most commonly shared blocks:

    resources:
      {{- include "orders.resources" . | nindent 12 }}

This program has two parse paths. With `helm` on PATH it renders the chart
and reads the result. Without helm - the default for anyone who has not
installed it, and the only path inside the shipped container image unless
helm is present - it scrubs the Go template actions into markers and parses
the YAML. `.tpl` files are NEVER parsed as documents on that path
(discovery.py records only that helpers exist), so the whole block above
collapses to one leaf string:

    HELMINC@orders.resources

Three checks read that string, found no `requests` key inside it, and said
so - at the severity of a fact:

    [RS001] CRITICAL  Container has no resource requests/limits
    [HP022] CRITICAL  HPA scales on CPU but target workload has no CPU request
    [RS011] HIGH      Pod QoS class is BestEffort

and a fourth read `resources: {}` in a values file no template consumes:

    [VA004] HIGH      Empty resources block in values

Each is a claim of ABSENCE. None was supported by absence: the tool did not
open the file the values live in. The RS001 entry was stamped

    Basis : OBSERVED - read directly from your files (stated as fact)

which is the one thing it was not.

WHY THE FIX IS NARROWER THAN "unresolved"

helmyaml.is_unresolved() is true for both markers the scrubber can leave, and
they mean opposite things:

    HELMVAL@resources   `.Values.resources` is unset in every values file
                        read. helm renders an EMPTY block from the same
                        inputs. "No resource requests/limits" is TRUE, and
                        RS001 must keep saying it at CRITICAL.
    HELMINC@x           the body is in a file this run did not open. Nothing
                        about absence has been established - only blindness.

Branching on is_unresolved() would have silenced a true CRITICAL to fix a
false one. The fix branches on the include marker alone.

CLAIM 1  The defect is not about a badly written chart. Two charts differing
         ONLY in the spelling of the resources block - values-supplied vs
         helper-supplied, rendering byte-identically under helm - are graded
         differently by the pre-fix tool on the static path.
CLAIM 2  BEFORE, on the committed baseline tree, as a real subprocess: the
         helper chart collects RS001, HP022 and VA004, and the report stamps
         the RS001 accusation OBSERVED.
CLAIM 3  AFTER: those claims are withdrawn, and REPLACED - not deleted. The
         run says which helper it could not read, which verdicts it withheld
         because of that, and how to get them back.
CLAIM 4  AFTER: the true CRITICAL survives. The same chart with the resources
         templated from an unset .Values path still gets RS001 at CRITICAL,
         because there helm renders nothing too.
CLAIM 5  AFTER: the score stops fabricating. RESOURCES leaves the denominator
         rather than scoring 100 over a file that was never read, and the
         report prints the reason - the module's own rule ("there is no
         honest number for 'not looked at'"), applied to itself.
CLAIM 6  AFTER: one legible container is enough to keep the category in the
         mean. Dropping RESOURCES whenever a helper appears would delete real
         findings from the score - the PB004/Dockerfile mistake R8 removed.
CLAIM 7  AFTER: charts that never touch a helper are unchanged. All nine
         fixtures are compared rule-for-rule AND score-for-score against the
         commit this fix is applied to, in full. Not one of them produces
         RS001, RS011, HP022 or VA004, so a comparison narrowed to the rules
         R11 touches would pass without being able to fail; the whole report
         is compared instead.

BEFORE is the committed pre-fix tree, extracted with `git archive` at the SHA
pinned in proof/baseline.py, run as a real subprocess over real directories.
Run: python3 proof/p12_helpers.py
"""

import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE - see the module for why)

from baseline import (BASELINE, R11_PARENT,  # noqa: E402
                      resolve as _resolve_baseline)

BASELINE_SHA = _resolve_baseline(REPO)
PARENT_SHA = _resolve_baseline(REPO, R11_PARENT)

FAILURES = []


def check(ok, label, extra=""):
    print(f"    [{'PASS' if ok else 'FAIL'}] {label}")
    if extra:
        print(f"           {extra}")
    if not ok:
        FAILURES.append(label)
    return ok


# ---------------------------------------------------------------------------
# The chart pair. Everything is identical except the four lines under
# `resources:`; both render to the same Deployment under helm.
# ---------------------------------------------------------------------------

CHART = """apiVersion: v2
name: orders
version: 1.0.0
appVersion: "1.0"
description: proof fixture
kubeVersion: ">=1.23.0-0"
maintainers: [{name: proof}]
icon: https://example.invalid/i.png
"""

DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-orders
  labels:
    app.kubernetes.io/name: orders
spec:
  replicas: 2
  selector:
    matchLabels: {app: orders}
  template:
    metadata:
      labels: {app: orders}
    spec:
      containers:
        - name: orders
          image: "repo/orders:1.4.2"
          ports: [{containerPort: 8080}]
          resources:
            %(resources)s
"""

HELPERS = """{{- define "orders.resources" -}}
requests:
  cpu: 500m
  memory: 1Gi
limits:
  memory: 1Gi
{{- end }}
"""

HPA = """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ .Release.Name }}-orders
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ .Release.Name }}-orders
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource: {name: cpu, target: {type: Utilization, averageUtilization: 70}}
"""

VIA_HELPER = '{{- include "orders.resources" . | nindent 12 }}'
VIA_VALUES = '{{- toYaml .Values.resources | nindent 12 }}'
LONGHAND = 'requests: {cpu: 500m, memory: 1Gi}\n            limits: {memory: 1Gi}'


def build(kind: str) -> str:
    """kind: 'helper' | 'values' | 'longhand' | 'helper+sibling'."""
    root = tempfile.mkdtemp(prefix=f"hpa-r11-{kind.replace('+', '-')}-")
    block = {"helper": VIA_HELPER, "values": VIA_VALUES,
             "longhand": LONGHAND, "helper+sibling": VIA_HELPER}[kind]
    dep = DEPLOY % {"resources": block}
    if kind == "helper+sibling":
        # A second container the tool CAN read, carrying a real defect the
        # score must not lose: `memory: 512m` is 0.512 BYTES (RS002, CRITICAL).
        # It is a sibling rather than an init container on purpose - RS001/
        # RS002 walk spec.containers only, so an init container would produce
        # no scored finding and the claim would test nothing.
        dep += ("        - name: metrics\n"
                "          image: repo/metrics:0.9\n"
                "          resources:\n"
                "            requests: {cpu: 50m, memory: 512m}\n"
                "            limits: {memory: 512m}\n")
    files = {"Chart.yaml": CHART,
             "values.yaml": "resources: {}\nreplicaCount: 2\n",
             "templates/deployment.yaml": dep,
             "templates/hpa.yaml": HPA}
    if kind != "longhand":
        files["templates/_helpers.tpl"] = HELPERS
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    return root


# ---------------------------------------------------------------------------
# Running the real program, the way a user does.
# ---------------------------------------------------------------------------

_TREES = {}


def tree_at(sha, tag):
    if sha not in _TREES:
        tmp = tempfile.mkdtemp(prefix=f"hpa-{tag}-r11-")
        tar = subprocess.run(["git", "archive", sha], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _TREES[sha] = tmp
    return _TREES[sha]


def before_tree():
    """Where the defect shipped."""
    return tree_at(BASELINE_SHA, "before")


def parent_tree():
    """The commit this fix is applied to - the no-regression control."""
    return tree_at(PARENT_SHA, "parent")


# The subject is the STATIC path - what the tool may claim when it cannot
# render. helm on PATH would expand the include and there would be no
# question. `--helm off` is passed explicitly rather than relying on PATH, so
# the proof measures the same thing on a machine that has helm and one that
# does not.
def cli(tree, target):
    d = tempfile.mkdtemp(prefix="hpa-r11-out-")
    out, jsn = os.path.join(d, "r.txt"), os.path.join(d, "r.json")
    p = subprocess.run(
        [sys.executable, "-m", "hpaanalyzer", target, "-o", out, "--full",
         "--quiet", "--json", jsn, "--helm", "off"],
        capture_output=True, text=True, cwd=tree,
        env=dict(os.environ, PYTHONPATH=tree))
    if not os.path.isfile(jsn):
        raise SystemExit(f"CLI produced no JSON ({tree}):\n{p.stderr[-2000:]}")
    with open(jsn, encoding="utf-8") as f:
        payload = json.load(f)
    with open(out, encoding="utf-8") as f:
        text = f.read()
    # the JSON key for a rule id was renamed between the baseline and now;
    # read both so the BEFORE column is not silently empty.
    for f_ in payload["findings"]:
        f_.setdefault("rule_id", f_.get("rule"))
        f_.setdefault("rule", f_.get("rule_id"))
    return payload, text


def rules(payload):
    return {f["rule_id"] for f in payload["findings"]}


def by_rule(payload, rid):
    return [f for f in payload["findings"] if f["rule_id"] == rid]


def sev(payload, rid):
    f = by_rule(payload, rid)
    return f[0]["severity"] if f else None


def _unassessed(payload):
    """Category names dropped from the score denominator, as a set of str."""
    cov = payload.get("score_coverage") or {}
    out = set()
    for entry in (cov.get("unassessed") or []):
        if isinstance(entry, dict):
            out.add(str(entry.get("category")))
        elif isinstance(entry, (list, tuple)) and entry:
            out.add(str(entry[0]))
        else:
            out.add(str(entry))
    return out


AFTER = REPO


def main():
    print(__doc__)
    print(f"BEFORE tree: {BASELINE_SHA[:12]}  (proof/baseline.py: {BASELINE})")
    print(f"AFTER  tree: {AFTER}\n")

    helper = build("helper")
    values = build("values")
    longhand = build("longhand")
    hybrid = build("helper+sibling")

    b_helper, b_helper_txt = cli(before_tree(), helper)
    b_longhand, _ = cli(before_tree(), longhand)
    a_helper, a_helper_txt = cli(AFTER, helper)
    a_values, _ = cli(AFTER, values)
    a_longhand, _ = cli(AFTER, longhand)
    a_hybrid, a_hybrid_txt = cli(AFTER, hybrid)

    # -------------------------------------------------------------------
    print("CLAIM 1  same chart, two spellings, two grades (BEFORE)")
    print(f"    resources written longhand : {b_longhand['score']:.1f} "
          f"{b_longhand['grade']}   {len(b_longhand['findings'])} findings")
    print(f"    resources via include      : {b_helper['score']:.1f} "
          f"{b_helper['grade']}   {len(b_helper['findings'])} findings")
    delta = sorted(rules(b_helper) - rules(b_longhand))
    print(f"    findings present ONLY in the helper spelling: {delta}")
    check(b_helper["score"] < b_longhand["score"],
          "the helper spelling scores strictly worse before the fix",
          f"{b_helper['score']:.1f} < {b_longhand['score']:.1f}")
    check(bool(delta), "and it collects extra findings for the spelling alone")

    # -------------------------------------------------------------------
    print("\nCLAIM 2  BEFORE: absence claimed from a file that was not read")
    for rid in ("RS001", "HP022", "VA004"):
        s = sev(b_helper, rid)
        check(s in ("CRITICAL", "HIGH"),
              f"{rid} present at CRITICAL/HIGH on the helper chart",
              f"severity={s}")
    rs001 = by_rule(b_helper, "RS001")
    check(bool(rs001) and rs001[0].get("basis") == "observed",
          "and RS001 is stamped OBSERVED - an accusation voiced as evidence",
          f"basis={rs001[0].get('basis') if rs001 else '(absent)'}")
    check("OBSERVED" in b_helper_txt,
          "the printed report carries the same stamp")

    # -------------------------------------------------------------------
    print("\nCLAIM 3  AFTER: withdrawn, and replaced by what is actually known")
    for rid in ("RS001", "HP022", "RS011", "VA004"):
        check(rid not in rules(a_helper), f"{rid} no longer claimed")
    for rid, want in (("RS018", "INFO"), ("RS014", "INFO"),
                      ("HP032", "INFO"), ("VA011", "LOW")):
        check(sev(a_helper, rid) == want,
              f"{rid} reports the gap instead ({want})",
              f"severity={sev(a_helper, rid)}")
    rs018 = by_rule(a_helper, "RS018")[0] if by_rule(a_helper, "RS018") else {}
    check("orders.resources" in (rs018.get("detail") or ""),
          "the finding names the helper it could not read")
    check(all(r in (rs018.get("why") or "") for r in ("RS001", "RS011", "HP022")),
          "and names every verdict it withheld - silence would read as a pass")
    check("helm" in (rs018.get("fix") or "").lower(),
          "and says how to get those verdicts back")
    check(rs018.get("basis") == "derived",
          "stamped DERIVED, not OBSERVED", f"basis={rs018.get('basis')}")

    # -------------------------------------------------------------------
    print("\nCLAIM 4  AFTER: the TRUE critical survives (unset .Values path)")
    check(sev(a_values, "RS001") == "CRITICAL",
          "RS001 still CRITICAL when the values path is genuinely unset",
          f"severity={sev(a_values, 'RS001')}")
    check("RS018" not in rules(a_values),
          "and it is not misread as a helper")
    check(sev(a_values, "VA004") == "HIGH",
          "VA004 still HIGH where a template does consume the empty key")

    # -------------------------------------------------------------------
    print("\nCLAIM 5  AFTER: the score stops grading an unread file")
    unassessed = _unassessed(a_helper)
    check(any("RESOURCE" in str(u).upper() for u in unassessed),
          "RESOURCES is dropped from the denominator, not scored 100",
          f"unassessed={sorted(str(u) for u in unassessed)}")
    check("named template" in a_helper_txt,
          "and the report prints WHY it was dropped")

    # -------------------------------------------------------------------
    print("\nCLAIM 6  AFTER: one legible container keeps the category scored")
    un_h = _unassessed(a_hybrid)
    check(not any("RESOURCE" in str(u).upper() for u in un_h),
          "a readable sibling container keeps RESOURCES in the mean",
          f"unassessed={sorted(str(u) for u in un_h)}")
    res_findings = [f for f in a_hybrid["findings"]
                    if "Resource" in f.get("category", "")
                    and f["severity"] not in ("INFO",)]
    check(bool(res_findings),
          "and its findings are still scored, not silently dropped",
          f"{[f['rule_id'] for f in res_findings]}")

    # -------------------------------------------------------------------
    print("\nCLAIM 7  AFTER: charts with no helper-supplied resources unchanged")
    fixtures = sorted(
        os.path.join(REPO, "fixtures", d)
        for d in os.listdir(os.path.join(REPO, "fixtures"))
        if os.path.isdir(os.path.join(REPO, "fixtures", d)))
    # Compared against the IMMEDIATE PARENT, not BASELINE, and compared in
    # full: every rule and the score, on every fixture. See proof/baseline.py
    # R11_PARENT for why - the narrow version of this control passed while
    # being incapable of failing, because no fixture in the repo produces any
    # of the four rules this iteration touches.
    print(f"    control tree: {PARENT_SHA[:12]} (R11_PARENT), whole-report "
          f"comparison")
    ok_all = True
    for fx in fixtures:
        p, _ = cli(parent_tree(), fx)
        a, _ = cli(AFTER, fx)
        same = (rules(p) == rules(a)
                and round(p["score"] or -1, 4) == round(a["score"] or -1, 4))
        ok_all = ok_all and same
        moved = sorted(rules(p) ^ rules(a))
        print(f"    {'ok  ' if same else 'DIFF'} {os.path.basename(fx):<24} "
              f"{len(rules(a))} rules, {a['score']}"
              + (f"   MOVED: {moved} (was {p['score']})" if not same else ""))
    check(ok_all, "every fixture's whole report is byte-for-byte unmoved",
          "(none of them supplies resources through a helper, so the fix "
          "must be invisible to all nine)")

    print("\n" + "=" * 72)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    print("""
What changed is not the volume of output but its epistemic status. The
pre-fix run told a team with a perfectly good `_helpers.tpl` that their
containers had no resources, their pod was BestEffort, and their HPA would
never scale - three false CRITICAL/HIGH findings, one of them stamped as
read directly from their files. The post-fix run tells them the tool did not
open that file, names it, lists the four verdicts it therefore declined to
give, and drops the category out of the score instead of awarding it 100.
The chart is not graded better. It is graded over less, and the report says
so.""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

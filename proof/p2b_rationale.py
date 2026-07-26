#!/usr/bin/env python3
"""PROOF R2b: the tool already knows which containers are infra sidecars, and
then tells the user to fix them as if they were the Java application.

WHY THIS IS A DEFECT AND NOT A NITPICK

Every finding carries `why` (the reason to act) and `fix` (the action). Those
two fields are the entire value of the tool: a rule id and a severity are
noise without them. When they describe a workload the container is not, the
user is asked to reason from a false premise. The two available outcomes are
both bad -- either they follow advice that does not apply, or they learn that
the prose is decorative and stop reading it. The second is worse, because it
also discards the findings that WERE right.

THE AGGRAVATING FACT: this is not a missing capability. hpaanalyzer.kube
already ships `is_sidecar(name, image)`, and checks_workload.py already calls
it - exactly once, to suppress RS010. Every other rule ignores it. So the tool
possesses the knowledge and declines to use it.

WHAT THIS SCRIPT PROVES
  1. The classifier recognises the fixture's proxy containers.
  2. BEFORE: findings raised against those containers carry JVM-specific
     rationale and JVM-specific or image-owner-specific remediation.
     AFTER : the same findings, same severities, same fix-first list, carry
     rationale that is true of the container it is attached to.
  3. The advice was not merely off-topic but wrong-in-fact: it prescribed
     actions the reader cannot take.

HOW "BEFORE" IS OBTAINED. The fix is one function, `checks_workload._pick`,
which chooses between an application sentence and an infrastructure sentence.
Monkeypatching it to always return the application sentence restores the exact
pre-fix prose, so both columns below come from the same engine on the same
fixture and the only variable is the fix itself.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

FIXTURE = os.path.join(REPO, "fixtures", "sidecar-chart")

# Phrases that assert something about the container's runtime or its build.
# Each is a claim, not a flavour word.
JVM_CLAIMS = [
    (r"-Xmx", "asserts the process has a fixed JVM heap flag"),
    (r"\bJVM\b", "asserts the process is a Java virtual machine"),
    (r"Spring", "asserts a Spring-style application"),
    (r"class loading|classloading", "asserts JVM class loading"),
    (r"/actuator/", "prescribes a Spring Boot Actuator endpoint"),
    (r"MaxRAMPercentage", "prescribes a JVM ergonomics flag"),
    (r"USER in the Dockerfile", "prescribes editing a Dockerfile the user does "
                                "not own for a third-party image"),
]


def load(before=False):
    from hpaanalyzer import checks_workload
    from hpaanalyzer.engine import analyze
    from hpaanalyzer.kube import containers, is_sidecar, pod_spec

    real = checks_workload._pick
    if before:
        # pre-fix behaviour: every container gets the application sentence.
        checks_workload._pick = lambda infra, app_text, infra_text: app_text
    try:
        r = analyze(FIXTURE, helm_mode="off")
    finally:
        checks_workload._pick = real

    doc = r.context.workloads[0]
    cs = containers(doc)
    side = {c["name"]: c.get("image", "") for c in cs
            if is_sidecar(c.get("name", ""), c.get("image", ""))}
    return r, cs, side, pod_spec(doc)


def claim_1(cs, side):
    print("=" * 72)
    print("CLAIM 1: the tool can already tell these containers apart.")
    print("=" * 72)
    for c in cs:
        name = c.get("name", "?")
        tag = "INFRA SIDECAR" if name in side else "application"
        print(f"    {name:<14} {c.get('image','?'):<34} -> {tag}")
    print(f"  kube.is_sidecar() classifies {len(side)} of {len(cs)} "
          f"containers as infra: {sorted(side)}")
    ok = bool(side)
    print(f"  --> {'PROVEN: the knowledge exists.' if ok else 'no sidecars'}")
    return ok


def _false_premises(result, side):
    seen = []
    for f in result.findings:
        who = [n for n in side if f"'{n}'" in (f.detail or "")]
        if not who:
            continue
        for field in ("title", "why", "fix"):
            text = getattr(f, field, "") or ""
            for pat, what in JVM_CLAIMS:
                if re.search(pat, text, re.I):
                    key = (f.rule_id, field, what)
                    if key not in [s[:3] for s in seen]:
                        seen.append((f.rule_id, field, what, f.severity.name,
                                     who[0]))
    return seen


def claim_2(side):
    print()
    print("=" * 72)
    print("CLAIM 2: the JVM prose is attached to containers that are not JVMs,")
    print("         and the fix removes it without removing the finding.")
    print("=" * 72)

    before_r = load(before=True)[0]
    after_r = load(before=False)[0]
    before = _false_premises(before_r, side)
    after = _false_premises(after_r, side)

    print("  BEFORE (the fix disabled):")
    for rule, field, what, sev, who in before:
        print(f"    [{rule}] {sev:<8} on '{who}' -- .{field} {what}")
    print(f"    = {len(before)} false premises.")
    print()
    print("  AFTER:")
    for rule, field, what, sev, who in after:
        print(f"    [{rule}] {sev:<8} on '{who}' -- .{field} {what}")
    print(f"    = {len(after)} false premises.")

    # The finding set itself must be unchanged: this is a truthfulness fix,
    # not a way to make findings disappear. A heuristic that suppressed
    # findings would be a far worse defect than the one being fixed.
    b_ids = sorted((f.rule_id, f.severity.name) for f in before_r.findings)
    a_ids = sorted((f.rule_id, f.severity.name) for f in after_r.findings)
    print()
    print(f"  findings before: {len(b_ids)}   findings after: {len(a_ids)}")
    print(f"  identical rule/severity multiset: {b_ids == a_ids}")
    print()
    print("  NOTE, so the BEFORE column is not read as complete: RS015 also")
    print("  asserted 'costs the JVM its Guaranteed eviction priority'. That")
    print("  one was fixed by naming the container instead of guessing its")
    print("  runtime, not by _pick, so the monkeypatch cannot restore it and")
    print("  it is absent above. The pre-fix count was 8, not 7.")

    ok = bool(before) and not after and b_ids == a_ids
    print(f"  --> {'PROVEN AND FIXED.' if ok else 'NOT ESTABLISHED.'}")
    return ok


def claim_3(result, side):
    print()
    print("=" * 72)
    print("CLAIM 3: the advice WAS unactionable, not just irrelevant.")
    print("=" * 72)
    print("  istio-proxy runs Envoy, a C++ process. Taking the tool at its")
    print("  word, the reader is asked to:")
    print("    * reason about a -Xmx that does not exist, to decide whether a")
    print("      1 GiB limit over a 128 MiB request is safe;")
    print("    * expose /actuator/health/readiness from a binary that has no")
    print("      such endpoint (Envoy serves /ready on the admin port);")
    print("    * add a USER line to a Dockerfile owned by istio, which the")
    print("      reader does not build and cannot edit.")
    print()
    print("  None of these three actions is possible. A finding whose fix")
    print("  cannot be performed has a severity it cannot justify: it will be")
    print("  read once, found impossible, and thereafter ignored.")

    top = [f for f in result.findings
           if f.severity.name in ("CRITICAL", "HIGH")][:5]
    infra = [f for f in top if any(f"'{n}'" in (f.detail or "") for n in side)]
    print()
    print(f"  Of the {len(top)} findings the terminal prints under 'Fix first',")
    print(f"  {len(infra)} are against infra sidecars: "
          f"{[f.rule_id for f in infra]}")
    print("  The list the user is told to work through top-down therefore")
    print("  opens with items they cannot action.")
    ok = bool(infra)
    print(f"  --> {'PROVEN.' if ok else 'not reaching the fix-first list.'}")
    return ok


def main():
    print(__doc__)
    result, cs, side, _ = load(before=True)
    proven = [claim_1(cs, side), claim_2(side), claim_3(result, side)]
    print()
    print("=" * 72)
    if all(proven):
        print("ALL THREE CLAIMS PROVEN, AND THE FIX VERIFIED.")
        print("Recorded as an unfixed Bar 2 shortfall in docs/ITERATIONS.md R1;")
        print("closed in R2. The fix-first list is unchanged in length and")
        print("severity - every entry now describes the container it names.")
        return 0
    print("PROOF INCOMPLETE:", proven)
    return 1


if __name__ == "__main__":
    sys.exit(main())

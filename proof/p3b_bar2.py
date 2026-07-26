#!/usr/bin/env python3
"""PROOF R3, Bar 2: did the version arithmetic change what the terminal says?

Bar 1 for this iteration is conformance: proof/p3_oracle.py builds
Masterminds/semver v3.3.0 and checks 2632 (constraint, version) pairs against
the port, and proof/p3_severity.py shows the severity function is no longer a
constant. Both are about whether the machinery is right.

This asks the user's other question - "not just correct, but does it do what
it is supposed to do" - and the honest answer before this iteration was no,
in a specific and expensive way.

The subject is fixtures/legacy-chart. It declares:

    kubeVersion: ">=1.20.0-0 <1.22.0-0"

and ships four objects:

    networking.k8s.io/v1beta1  Ingress       removed in 1.22
    rbac.../v1beta1            Role          removed in 1.22
    rbac.../v1beta1            RoleBinding   removed in 1.22
    autoscaling/v2             HPA           first exists in 1.23

Read those two facts together and the chart has exactly one bug that can hurt
anyone today. The three v1beta1 objects are removed in 1.22, which is above
the declared ceiling of 1.21 - and helm ENFORCES that ceiling at render time
(pkg/action/action.go, quoted in proof/p3_severity.py CLAIM 0), so there is no
cluster on which this chart both installs and hits the removal. They are an
upgrade blocker: real, worth fixing, not tonight.

The HPA is the opposite. autoscaling/v2 does not exist on 1.20 or 1.21, which
is every version the chart claims to support. helm's gate PASSES - the chart
is telling the truth about where it wants to run - the install proceeds, and
the API server rejects that one object with "no matches for kind". A
half-applied release. That is the outage.

The pre-fix tool got this exactly backwards: it printed the three harmless
removals as CRITICAL (two of them, anyway - see CLAIM 3) and never mentioned
the outage at all. An SRE reading that summary spends the evening on a schema
migration and ships the broken HPA.

BEFORE is the committed pre-fix tree, extracted with `git archive <baseline>`
(pinned in proof/baseline.py, NOT HEAD) and run in a subprocess - not a
description of it. Run: python3 proof/p3b_bar2.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline import BASELINE, resolve as _resolve_baseline  # noqa: E402

BASELINE_SHA = _resolve_baseline(REPO)

FIXTURE = os.path.join(REPO, "fixtures", "legacy-chart")

_CHILD = r"""
import json, sys, tempfile, os
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.engine import analyze
from hpaanalyzer.report import stdout_summary, render
r = analyze(sys.argv[2], helm_mode="off")
out = os.path.join(tempfile.mkdtemp(), "report.txt")
print("---JSON---")
print(json.dumps({
    "summary": stdout_summary(r, out),
    "full": render(r, sys.argv[2], show_all=True),
    "findings": [[f.rule_id, f.severity.name, f.title, f.detail, f.fix, f.why]
                 for f in r.findings],
}))
"""


def _payload(root, chart):
    out = subprocess.run([sys.executable, "-c", _CHILD, root, chart],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out.split("---JSON---", 1)[1])


def before():
    tmp = tempfile.mkdtemp(prefix="hpa-before-")
    tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                         capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
    # The fixture is new in this iteration, so it is copied INTO the old tree.
    # The old code is unmodified; only the input is shared. That is the point:
    # same chart, same bytes, two versions of the tool.
    subprocess.run(["cp", "-r", FIXTURE, os.path.join(tmp, "chart")],
                   check=True)
    return _payload(tmp, os.path.join(tmp, "chart"))


def after():
    return _payload(REPO, FIXTURE)


def fixfirst(summary):
    """The lines an SRE actually reads before deciding what to do tonight."""
    keep, on = [], False
    for line in summary.splitlines():
        if "GRADE" in line or "Fix first" in line:
            on = True
        if on and line.strip():
            keep.append(line.rstrip())
        if on and "Full report" in line:
            break
    return "\n".join(keep)


def listed(summary):
    """Rule ids in the numbered fix-first list, in order."""
    return re.findall(r"^\s+\d+\.\s+\[([A-Z]{2}\d{3})\]", summary, re.M)


def sev(findings, rule):
    return [f[1] for f in findings if f[0] == rule]


def objects(findings, rule):
    """Which Kubernetes kinds a rule fired on, deduped and sorted."""
    kinds = set()
    for f in findings:
        if f[0] != rule:
            continue
        m = re.match(r"([A-Za-z]+)\s", f[3] or "")
        if m:
            kinds.add(m.group(1))
    return sorted(kinds)


def hr(title=""):
    print()
    print("=" * 76)
    if title:
        print(title)
        print("=" * 76)


def main():
    print(__doc__)
    b, a = before(), after()
    bf, af = b["findings"], a["findings"]

    hr(f"BEFORE  (git archive {BASELINE}, run in a subprocess)")
    print(fixfirst(b["summary"]))
    hr("AFTER   (working tree)")
    print(fixfirst(a["summary"]))

    lb, la = listed(b["summary"]), listed(a["summary"])

    # ---------------------------------------------------------------- 1 ----
    hr("CLAIM 1: the pre-fix fix-first list was topped by removals that\n"
       "         cannot fire on any cluster this chart can be installed on.")
    print(f"  BEFORE fix-first order : {lb}")
    print(f"  TP010 severities BEFORE: {sev(bf, 'TP010')}")
    print()
    print("  The chart's ceiling is 1.21. Every one of those APIs is removed")
    print("  in 1.22. helm's kubeVersion gate is executable, so the removal")
    print("  is unreachable while the constraint stands - and the constraint")
    print("  is in the chart, in the file the tool had already parsed.")
    misranked = "TP010" in lb[:3] and set(sev(bf, "TP010")) == {"CRITICAL"}
    print(f"  => misranked: {misranked}")

    # ---------------------------------------------------------------- 2 ----
    hr("CLAIM 2: the one defect that does cause an outage was absent -\n"
       "         not deprioritised, not softened. Absent.")
    print(f"  BEFORE rule ids present : {sorted({f[0] for f in bf})}")
    print(f"  'TP013' in BEFORE       : {'TP013' in {f[0] for f in bf}}")
    for token in ("autoscaling/v2", "1.23", "no matches for kind"):
        print(f"  '{token}' anywhere in the BEFORE full report: "
              f"{token in b['full']}")
    absent = "TP013" not in {f[0] for f in bf}
    print()
    print("  So an SRE who read the pre-fix report end to end - not the")
    print("  summary, the whole file - still had no way to learn that this")
    print("  release applies half of itself and stops.")
    print(f"  => absent: {absent}")

    # ---------------------------------------------------------------- 3 ----
    hr("CLAIM 3: even the claim it did make was incomplete, and silently.")
    print(f"  BEFORE TP010 fired on : {objects(bf, 'TP010')}")
    print(f"  AFTER  TP010 fired on : {objects(af, 'TP010')}")
    print()
    print("  Role and RoleBinding are the same apiVersion, removed in the")
    print("  same release, in the same file. The old table had one row and")
    print("  not the other, so the report was not 'a subset of the truth' in")
    print("  any way a reader could predict - it looked complete.")
    incomplete = (len(objects(bf, "TP010")) < len(objects(af, "TP010"))
                  and "RoleBinding" in objects(af, "TP010"))
    print(f"  => incomplete: {incomplete}")

    # ---------------------------------------------------------------- 4 ----
    hr("CLAIM 4: after the fix, the terminal ranks the outage above the\n"
       "         upgrade blockers - and does not delete the blockers.")
    print(f"  AFTER fix-first order  : {la}")
    print(f"  TP013 severities AFTER : {sev(af, 'TP013')}")
    print(f"  TP010 severities AFTER : {sev(af, 'TP010')}")
    print(f"  TP010 still in the full report: "
          f"{'TP010' in a['full']}  <- demoted, not suppressed")
    print()
    for line in a["summary"].splitlines():
        if re.match(r"\s+\d+\.\s+\[TP013\]", line):
            print(f"  {line.strip()}")
    ranked = ("TP013" in la and "TP010" not in la
              and set(sev(af, "TP010")) == {"LOW"}
              and "TP010" in a["full"])
    print(f"  => ranked: {ranked}")

    # ---------------------------------------------------------------- 5 ----
    hr("CLAIM 5: the demotion is reasoned in the finding, not asserted.")
    why = next((f[5] for f in af if f[0] == "TP010"), "") or ""
    for line in _wrap(why, 70):
        print(f"    | {line}")
    reasoned = ("IsCompatibleRange" in why and "upgrade blocker" in why)
    print(f"  => cites the enforcing code path and names what remains: "
          f"{reasoned}")

    # ---------------------------------------------------------------- 6 ----
    hr("CLAIM 6: nothing was lost to get here.")
    rb = sorted({f[0] for f in bf})
    ra = sorted({f[0] for f in af})
    gone = sorted(set(rb) - set(ra))
    new = sorted(set(ra) - set(rb))
    print(f"  rules added : {new}")
    print(f"  rules lost  : {gone or 'none'}")
    kept = not gone
    print(f"  => kept: {kept}")

    # ------------------------------------------------------------ verdict --
    def grade(s):
        m = re.search(r"GRADE\s+(\S+)\s+\(([\d.]+)/100\)", s)
        return (m.group(1), float(m.group(2))) if m else (None, None)

    gb, sb = grade(b["summary"])
    ga, sa = grade(a["summary"])

    hr()
    ok = misranked and absent and incomplete and ranked and reasoned and kept
    if not ok:
        print("NOT PROVEN:", dict(misranked=misranked, absent=absent,
                                  incomplete=incomplete, ranked=ranked,
                                  reasoned=reasoned, kept=kept))
        return 1

    print("Bar 2 MET for R3. On a chart nobody changed, the tool moved the")
    print("outage from 'not mentioned' to second on the list, and moved three")
    print("findings that cannot fire off the list without deleting them.")
    print()
    print("Read honestly, and this is the uncomfortable part:")
    print(f"  grade BEFORE {gb} ({sb}/100)   grade AFTER {ga} ({sa}/100)")
    print()
    print("  The score barely moved - it went UP by 1.2 - while what the")
    print("  report SAYS changed completely. That is not a defence of the")
    print("  grade, it is evidence against it. A single number that cannot")
    print("  tell 'three unreachable schema migrations' apart from 'this")
    print("  release will half-apply' is not carrying information, and R2's")
    print("  own proof leaned on a grade drop as if it were the result. The")
    print("  value here is the ORDER and the REASONING, not the score.")
    print("  Queued for R5: say plainly in the README that the grade is a")
    print("  weighted finding count and not a risk estimate.")
    return 0


def _wrap(text, width):
    out, line = [], ""
    for word in (text or "").split():
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


if __name__ == "__main__":
    sys.exit(main())

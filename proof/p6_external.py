#!/usr/bin/env python3
"""PROOF R6, Bar 1: the cross-check vouched for tools it had never run.

WHAT THE TOOL IS SUPPOSED TO DO, for this iteration specifically.

From the module that implements `--cross-check`, unchanged since the baseline:

    Discipline: this tool did not write these validators and does not vouch
    for their results - it runs them and reports exit status + output
    verbatim, clearly attributed.
                                                        -- external.py

And from the project's own contract list:

    C2.2  A value the tool cannot determine must be reported as
          undetermined. Never report a limit of the method as a finding
          about the target.

R4 applied C2.2 to another program's output for the first time: kubeconform
exits 1 when it cannot REACH a schema, which is a statement about the network
and not about the chart, so the tool reads kubeconform's own Valid/Invalid/
Errors tally instead of its exit code. That fix was written for one tool and
generalised to none.

WHY IT DID NOT DO THAT.

Four validators are wired in. Two of them - `helm lint` and `kubeconform` -
are run by real-binary tests. The other two, `kube-score` and `polaris`, were
never executed by any test in this repository, in any iteration. Their exit
codes were assumed to mean what kubeconform's means, and their output was
summarised by a function that takes the LAST NON-EMPTY LINE of the blob.

Neither assumption survives contact with the binaries:

  * polaris ALWAYS exits 0. It exits 0 having found danger-severity
    failures, and it exits 0 on a file that is not YAML at all - printing
    "Final score: 100" over "Controllers: 0" while logging a parse error to
    stderr. Read as an exit code, that is a PASS for input nothing could
    read: the exact C2.2 conflation, in the strongest possible form.
  * kube-score exits 1 both when it dislikes your manifests and when it
    cannot parse them ("Failed to score files"). Read as an exit code, an
    unreadable file becomes "your chart is invalid".
  * polaris's last non-empty output line is an ADVERTISEMENT for a hosted
    product, containing the analyzer's own temp path. That string was
    printed to users as polaris's verdict summary.
  * kube-score's last non-empty line is whichever object it happened to
    print last - on good-chart, a line ending in a green tick, displayed
    next to the word FAIL.

The BEFORE column below is the real pre-fix tool: `git archive` at the SHA
pinned in proof/baseline.py, run in a subprocess, against the same fixture
bytes and the same installed binaries as the AFTER column. Nothing here is
reconstructed.

Run: python3 proof/p6_external.py
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

from baseline import resolve as _resolve_baseline  # noqa: E402
import hpaanalyzer.external as ext  # noqa: E402  (current tree, for CLAIM 6)

BASELINE_SHA = _resolve_baseline(REPO)

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Unparseable on purpose: an unclosed flow sequence. Both binaries reject it,
# and they reject it in opposite directions - which is the point.
GARBAGE = "this: [is, not\n  a: manifest\n"

# The control: BOTH trees are handed the SAME rendered bytes, produced once
# by the current helm at 1.32.0, via `rendered_text`. Re-rendering inside each
# tree would have made the baseline column measure R4's defect instead of
# R6's - at the baseline commit `helm template` runs at its compiled-in
# v1.20.0 and REFUSES every modern fixture, so kube-score and polaris would
# have shown "not run" in the BEFORE column and proven nothing about how their
# output is read. The variable under test here is the interpretation of
# validator output, so the validators must actually be fed.
_CHILD = r"""
import json, os, sys
sys.path.insert(0, sys.argv[1])
from hpaanalyzer.external import run_cross_check
text = open(sys.argv[2], encoding="utf-8").read()
res = run_cross_check(None, rendered_text=text)

def verdict(e):
    # `verdict` is an R4 property and does not exist on the baseline tree.
    # Rather than invent a BEFORE value, reproduce EXACTLY what the baseline
    # report.py printed in the Status column, copied from that revision:
    #
    #     if not e.installed:   status = "not installed"
    #     elif not e.ran:       status = "skipped"
    #     else:                 status = "PASS" if e.ok else "FAIL"
    #
    # so the BEFORE column is the string a user actually read, not a
    # reconstruction of what the dataclass might have meant.
    v = getattr(e, "verdict", None)
    if v is not None:
        return v
    if not e.installed:
        return "not installed"
    if not e.ran:
        return "skipped"
    return "PASS" if e.ok else "FAIL"

print("---JSON---")
print(json.dumps([{
    "name": e.name, "installed": e.installed, "ran": e.ran, "ok": e.ok,
    "verdict": verdict(e), "summary": e.summary,
    "indeterminate": getattr(e, "indeterminate", False),
    "why": getattr(e, "indeterminate_why", ""),
    "detail": e.detail,
    # New in R6; absent on the baseline tree, and the proof must not crash
    # when it is missing - that absence IS the before state.
    "basis": getattr(e, "verdict_basis", None),
    "tally": getattr(e, "tally", None),
} for e in res]))
"""


def _run_tree(root, manifest_path):
    p = subprocess.run([sys.executable, "-c", _CHILD, root, manifest_path],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"child failed ({manifest_path}):\n{p.stderr[-2000:]}")
    out = json.loads(p.stdout.split("---JSON---", 1)[1])
    return {e["name"]: e for e in out}


_RENDERED = {}


def rendered(name):
    """`helm template <fixture> --kube-version 1.32.0`, once, cached.

    Rendered by the CURRENT helm on the CURRENT fixture bytes and reused for
    both trees, so the only thing that differs between BEFORE and AFTER is
    hpaanalyzer's own code.
    """
    if name not in _RENDERED:
        d = tempfile.mkdtemp(prefix="hpa-p6-")
        p = os.path.join(d, "rendered.yaml")
        if name == "garbage":
            open(p, "w", encoding="utf-8").write(GARBAGE)
        else:
            r = subprocess.run([shutil.which("helm"), "template", "r",
                                _chart(name), "--kube-version", "1.32.0"],
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise SystemExit(f"helm refused {name}: {r.stderr[:300]}")
            open(p, "w", encoding="utf-8").write(r.stdout)
        _RENDERED[name] = p
    return _RENDERED[name]


_BEFORE_TREE = None


def before_tree():
    global _BEFORE_TREE
    if _BEFORE_TREE is None:
        tmp = tempfile.mkdtemp(prefix="hpa-before-r6-")
        tar = subprocess.run(["git", "archive", BASELINE_SHA], cwd=REPO,
                             capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=tar, check=True)
        _BEFORE_TREE = tmp
    return _BEFORE_TREE


def _chart(name):
    p = os.path.join(REPO, "fixtures", name)
    if not os.path.isfile(os.path.join(p, "Chart.yaml")):
        raise SystemExit(f"proof harness: {p} is not a chart; refusing to "
                         f"measure a directory that does not exist")
    return p


def hr(title=""):
    print()
    print("=" * 76)
    if title:
        print(title)
        print("=" * 76)


CHECKS = []


def check(label, cond):
    CHECKS.append((label, bool(cond)))
    print(f"  [{'OK ' if cond else 'FAIL'}] {label}")
    return bool(cond)


def one_line(s, n=96):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n] + "..."


def main():
    print(__doc__)

    missing = [b for b in ("helm", "kube-score", "polaris") if not shutil.which(b)]
    if missing:
        print(f"NOT RUN: this proof is about the real behaviour of "
              f"{', '.join(missing)} and refuses to simulate it.")
        print("Install the binaries and re-run; nothing below is asserted "
              "from memory.")
        return 1

    for b, argv in (("helm", ["helm", "version", "--short"]),
                    ("kube-score", ["kube-score", "version"]),
                    ("polaris", ["polaris", "version"])):
        v = subprocess.run(argv, capture_output=True, text=True)
        print(f"  {b:<12} {shutil.which(b):<28} "
              f"{one_line((v.stdout or v.stderr), 40)}")
    print("  (versions recorded because a parser pinned to output is pinned "
          "to a version)")

    # ---------------------------------------------------------------- 0 ----
    hr("CLAIM 0: polaris's exit code carries no verdict. Measured directly,\n"
       "         before any of this tool's code is involved.")
    rows = []
    for label, fixture in (("good-chart", "good-chart"),
                           ("bad-chart", "bad-chart"),
                           ("unparseable garbage", "garbage")):
        p = rendered(fixture)
        pol = subprocess.run([shutil.which("polaris"), "audit", "--audit-path",
                              p, "--format", "pretty"],
                             capture_output=True, text=True)
        blob = ANSI.sub("", (pol.stdout or "") + "\n" + (pol.stderr or ""))
        sc = re.search(r"Final score:\s*(\d+)", blob)
        ct = re.search(r"Controllers:\s*(\d+)", blob)
        rows.append((label, pol.returncode, sc.group(1) if sc else "-",
                     ct.group(1) if ct else "-", blob.count("❌ Danger")))
    print(f"  {'input':<22} {'exit':>4}  {'score':>5} {'controllers':>11} "
          f"{'dangers':>7}")
    print(f"  {'-'*22} {'-'*4}  {'-'*5} {'-'*11} {'-'*7}")
    for r in rows:
        print(f"  {r[0]:<22} {r[1]:>4}  {r[2]:>5} {r[3]:>11} {r[4]:>7}")
    all_zero = all(r[1] == 0 for r in rows)
    garbage_row = rows[-1]
    check("polaris exits 0 on all three inputs, including the unparseable one",
          all_zero)
    check("polaris scores unparseable input 100 over 0 controllers",
          garbage_row[2] == "100" and garbage_row[3] == "0")
    check("polaris exits 0 while reporting danger-severity failures",
          rows[0][4] > 0 and rows[0][1] == 0)

    # ---------------------------------------------------------------- 1 ----
    hr("CLAIM 1: the pre-fix cross-check turned that into a PASS.")
    b_good = _run_tree(before_tree(), rendered("good-chart"))
    b_bad = _run_tree(before_tree(), rendered("bad-chart"))
    b_junk = _run_tree(before_tree(), rendered("garbage"))
    a_good = _run_tree(REPO, rendered("good-chart"))
    a_bad = _run_tree(REPO, rendered("bad-chart"))
    a_junk = _run_tree(REPO, rendered("garbage"))

    print(f"  {'input':<22} {'tool':<12} {'BEFORE':<8} {'AFTER':<8} basis (after)")
    print(f"  {'-'*22} {'-'*12} {'-'*8} {'-'*8} {'-'*24}")
    for label, b, a in (("good-chart", b_good, a_good),
                        ("bad-chart", b_bad, a_bad),
                        ("unparseable garbage", b_junk, a_junk)):
        for tool in ("kube-score", "polaris"):
            print(f"  {label:<22} {tool:<12} {b[tool]['verdict']:<8} "
                  f"{a[tool]['verdict']:<8} {a[tool]['basis'] or '-'}")

    check("BEFORE: polaris PASSes a file that is not YAML",
          b_junk["polaris"]["verdict"] == "PASS")
    check("BEFORE: polaris PASSes bad-chart",
          b_bad["polaris"]["verdict"] == "PASS")
    check("AFTER: unreadable input is UNKNOWN for polaris, not PASS",
          a_junk["polaris"]["verdict"] == "UNKNOWN")
    check("AFTER: polaris's own danger findings are not hidden behind PASS",
          a_bad["polaris"]["verdict"] == "FAIL")
    # This check's first draft asserted the basis string does not contain the
    # word "exit", on the theory that a verdict no longer read from the exit
    # code should not mention one. The run refuted it, and the run was right:
    # the basis reads "polaris's own danger tally and controller count; its
    # exit code is always 0 and carries no verdict" - naming the signal it
    # REJECTED, which is more useful than hiding it. The check now asserts
    # what was actually meant.
    p_basis = (a_bad["polaris"]["basis"] or "").lower()
    print(f"  polaris verdict basis: {a_bad['polaris']['basis']!r}")
    check("AFTER: the polaris verdict names the tally it came from",
          "danger" in p_basis and "tally" in p_basis)
    check("AFTER: and says explicitly that the exit code was not used",
          "always 0" in p_basis or "carries no verdict" in p_basis)

    # ---------------------------------------------------------------- 2 ----
    hr("CLAIM 2: kube-score's exit code conflates 'I dislike this' with\n"
       "         'I could not read this'. Both were reported as FAIL.")
    print(f"  {'input':<22} {'BEFORE':<8} {'AFTER':<8} after summary")
    print(f"  {'-'*22} {'-'*8} {'-'*8} {'-'*36}")
    for label, b, a in (("bad-chart", b_bad, a_bad),
                        ("unparseable garbage", b_junk, a_junk)):
        print(f"  {label:<22} {b['kube-score']['verdict']:<8} "
              f"{a['kube-score']['verdict']:<8} "
              f"{one_line(a['kube-score']['summary'], 36)}")
    check("BEFORE: unreadable input was FAIL for kube-score",
          b_junk["kube-score"]["verdict"] == "FAIL")
    check("AFTER: unreadable input is UNKNOWN for kube-score",
          a_junk["kube-score"]["verdict"] == "UNKNOWN")
    check("AFTER: the reason names the parse failure",
          "pars" in (a_junk["kube-score"]["why"] or "").lower())
    check("AFTER: a real dislike is still FAIL (the fix cannot only soften)",
          a_bad["kube-score"]["verdict"] == "FAIL")

    # ---------------------------------------------------------------- 3 ----
    hr("CLAIM 3: the one-line summary a user reads was, for two of four\n"
       "         tools, not a summary of anything.")
    print("  BEFORE, verbatim:")
    for label, b in (("good-chart", b_good), ("bad-chart", b_bad)):
        for tool in ("kube-score", "polaris"):
            print(f"    {label:<11} {tool:<11} {b[tool]['verdict']:<5} | "
                  f"{one_line(b[tool]['summary'], 74)}")
    print("  AFTER, verbatim:")
    for label, a in (("good-chart", a_good), ("bad-chart", a_bad)):
        for tool in ("kube-score", "polaris"):
            print(f"    {label:<11} {tool:<11} {a[tool]['verdict']:<5} | "
                  f"{one_line(a[tool]['summary'], 74)}")

    b_ad = b_bad["polaris"]["summary"]
    check("BEFORE: the polaris summary was an advertisement",
          "upload-insights" in b_ad or "Insights" in b_ad)
    check("BEFORE: it leaked this analyzer's temp path to the user",
          "hpa-xcheck-" in b_ad or "/tmp/" in b_ad)
    check("BEFORE: kube-score's summary on good-chart ended in a green tick "
          "while the verdict said FAIL",
          "✅" in b_good["kube-score"]["summary"]
          and b_good["kube-score"]["verdict"] == "FAIL")
    for label, a in (("good-chart", a_good), ("bad-chart", a_bad),
                     ("garbage", a_junk)):
        for tool in ("kube-score", "polaris"):
            s = a[tool]["summary"]
            check(f"AFTER: {label}/{tool} summary carries no advertisement, "
                  f"no temp path, no bare tick",
                  "upload-insights" not in s and "/tmp/" not in s
                  and "hpa-xcheck-" not in s and s.strip() != "✅")

    # ---------------------------------------------------------------- 4 ----
    hr("CLAIM 4: the captured output was pasted into a text report with the\n"
       "         terminal colour codes still in it.")
    b_det = b_bad["polaris"]["detail"]
    a_det = a_bad["polaris"]["detail"]
    print(f"  BEFORE: {len(ANSI.findall(b_det))} ANSI escape sequence(s) in the "
          f"polaris detail block")
    print(f"  AFTER : {len(ANSI.findall(a_det))}")
    print(f"  BEFORE first line: {one_line(b_det.splitlines()[0] if b_det else '', 66)!r}")
    print(f"  AFTER  first line: {one_line(a_det.splitlines()[0] if a_det else '', 66)!r}")
    check("BEFORE: escapes were present", len(ANSI.findall(b_det)) > 0)
    check("AFTER: none survive into the report", len(ANSI.findall(a_det)) == 0)
    check("AFTER: the detail still contains polaris's real content",
          "Final score" in a_det)

    # ---------------------------------------------------------------- 6 ----
    # Found by the first test that ever compared a tally against the detail
    # block printed under it. Not part of the original R6 diagnosis - it only
    # became visible once the tally existed to disagree with the excerpt.
    hr("CLAIM 6: the excerpt under each verdict admits it is an excerpt.")
    print("  The tally is counted over a validator's whole output; the block")
    print("  printed under it is cut at 1500 bytes. Both numbers were right")
    print("  and the pairing still lied: the report invites the reader to")
    print("  audit the transcription, then shows them a fragment whose only")
    print("  marker was the bare word '(truncated)'. Counting what is on the")
    print("  page gives a smaller number than the summary, and the obvious")
    print("  conclusion is that the summary is wrong.")
    long_blob = "\n".join(f"line {i}: [CRITICAL] something" for i in range(200))
    before_trunc = (long_blob.strip()[:1500] + "\n... (truncated)")
    after_trunc = ext._trunc(long_blob)
    print(f"\n  full output          : {len(long_blob)} bytes, "
          f"{long_blob.count(chr(10)) + 1} lines, "
          f"{long_blob.count('[CRITICAL]')} [CRITICAL]")
    print(f"  BEFORE, last line    : {before_trunc.splitlines()[-1]!r}")
    print(f"  AFTER , last line    : {after_trunc.splitlines()[-1]!r}")
    print(f"  visible in excerpt   : {after_trunc.count('[CRITICAL]')} "
          f"[CRITICAL]  (summary would say "
          f"{long_blob.count('[CRITICAL]')})")
    check("BEFORE: the marker gave no quantity",
          before_trunc.splitlines()[-1] == "... (truncated)")
    check("AFTER: the excerpt states how many lines were dropped",
          "more line(s)" in after_trunc)
    check("AFTER: the excerpt states the tally covers the full output",
          "FULL output" in after_trunc)
    check("AFTER: the excerpt genuinely does undercount, which is the point",
          after_trunc.count("[CRITICAL]") < long_blob.count("[CRITICAL]"))

    # ---------------------------------------------------------------- 5 ----
    hr("CLAIM 5: what this fix does NOT do.")
    print("  * It does not make this analyzer agree with kube-score or")
    print("    polaris, and it must not. good-chart grades A+ here and is")
    print("    criticised by both; those tools check things this one does not")
    print(f"    (polaris score {rows[0][2]}/100, kube-score criticals on the same")
    print("    bytes). Reporting their verdicts faithfully is the whole job.")
    print("  * It does not vouch for their correctness. The verdict shown is")
    print("    now derived from each tool's OWN tally rather than from an exit")
    print("    code this project assumed the meaning of - which is a claim")
    print("    about honest transcription, not about whether they are right.")
    print("  * It pins two more parsers to two more output formats. Those")
    print("    formats can change, and when they do these tests fail loudly")
    print("    instead of the summary quietly degrading - which is the only")
    print("    property being bought here.")
    for tool in ("kube-score", "polaris"):
        t = a_good[tool]["tally"]
        print(f"  AFTER tally, good-chart, {tool}: {t}")
        check(f"AFTER: {tool} exposes the tally its verdict came from",
              isinstance(t, dict) and bool(t))

    # ------------------------------------------------------------ verdict --
    hr()
    failed = [lbl for lbl, ok in CHECKS if not ok]
    print(f"  {len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("\nNOT PROVEN. Failing checks:")
        for f in failed:
            print(f"  - {f}")
        return 1
    print("Bar 1 MET for R6. Two of the four validators this tool offers to")
    print("run for you had never been run by this tool's own test suite, and")
    print("both were misreported: an unreadable file passed, a readable one")
    print("that polaris itself flagged as dangerous passed, an unparseable one")
    print("failed for the wrong reason, and the summary line for the tool the")
    print("user is most likely to trust was a hosted-product advertisement")
    print("containing a temp path. The verdicts now come from each tool's own")
    print("tally, the reason is printed, and real binaries decide it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

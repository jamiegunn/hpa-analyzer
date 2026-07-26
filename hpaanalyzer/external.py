"""Run the complementary ecosystem tools and report their output verbatim.

hpa-analyzer covers a niche (HPA + resources + JVM-in-container). The
standard stack covers other ground: `helm lint` (chart mechanics),
`kubeconform` (API-schema validation), `kube-score` / `polaris` (generic
best practices). This module DETECTS which of them are installed and, when
`--cross-check` is given, RUNS them and folds a summary into the report.

Discipline: this tool did not write these validators and does not vouch for
their results - it runs them and reports exit status + output verbatim,
clearly attributed. Absent tools are listed with an install command, never
silently skipped. Tools that need rendered manifests are skipped with a
reason when `helm` is unavailable to render.

Nothing is run unless the caller opts in.
"""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from .helmrender import find_helm, render_chart


@dataclass
class ExternalResult:
    name: str
    installed: bool
    ran: bool
    ok: Optional[bool]            # None = did not run / indeterminate
    summary: str                  # one line
    manual_cmd: str               # how to run it yourself
    install_hint: str = ""
    detail: str = ""              # captured output (truncated)
    # R4: a non-zero exit is not automatically "your manifests are bad".
    # kubeconform exits 1 when it could not REACH a schema, which is a
    # statement about the network, not about the chart:
    #
    #   Summary: 5 resources found in 1 file - Valid: 2, Invalid: 0,
    #            Errors: 3, Skipped: 0
    #
    # Invalid: 0. Nothing failed validation; three things could not be
    # checked. Rendering that as FAIL beside helm lint's PASS tells the
    # reader their chart is broken when the truth is that the tool learned
    # nothing - the same conflation contract C2.2 forbids this analyzer from
    # making about its own inputs, applied to another program's output.
    indeterminate: bool = False
    indeterminate_why: str = ""
    # R6: the R4 fix above was written for kubeconform and generalised to
    # nothing. Two of the four validators were never run by any test in this
    # repository, and both were misread:
    #
    #   polaris    ALWAYS exits 0. It exits 0 having found danger-severity
    #              failures, and it exits 0 on a file that is not YAML,
    #              printing "Final score: 100" over "Controllers: 0". Read as
    #              an exit code that is a PASS for input nothing could read.
    #   kube-score exits 1 both for "I dislike these manifests" and for
    #              "Failed to score files: failed to parse files". Read as an
    #              exit code, an unreadable file becomes an invalid chart.
    #
    # So the verdict is now derived from each tool's OWN tally, and `basis`
    # records which signal was read. A reader who disagrees with the verdict
    # can see what produced it instead of guessing.
    tally: dict = field(default_factory=dict)
    verdict_basis: str = ""

    @property
    def verdict(self) -> str:
        """PASS / FAIL / UNKNOWN / (not run) - the three honest states."""
        if not self.ran:
            return "not run"
        if self.indeterminate:
            return "UNKNOWN"
        if self.ok is None:
            return "UNKNOWN"
        return "PASS" if self.ok else "FAIL"


_KUBECONFORM_SUMMARY = re.compile(
    r"Valid:\s*(\d+),\s*Invalid:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)")

# polaris colours its "pretty" output unconditionally, pipe or no pipe. Those
# bytes were being pasted into a plain-text report, where they are noise at
# best and a mangled line at worst once _trunc cuts one in half.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_POLARIS_SCORE = re.compile(r"Final score:\s*(\d+)")
_POLARIS_CONTROLLERS = re.compile(r"Controllers:\s*(\d+)")
_POLARIS_PARSE_ERR = re.compile(r'level=error msg="Error parsing YAML')
_KUBESCORE_PARSE_ERR = re.compile(r"(?i)failed to (?:score|parse) files")


def _clean(blob: str, rendered_path: Optional[str] = None) -> str:
    """Strip terminal escapes and this analyzer's own scratch path.

    The scratch path mattered: polaris echoes its full argv on the last line
    of a successful audit, and `_last_summary_line` handed that line to the
    report as polaris's verdict summary. Users were shown

        | polaris | PASS | > polaris audit --audit-path
        |         |      | /tmp/hpa-xcheck-2bb6gmmw/rendered.yaml --format
        |         |      | pretty --upload-insights --cluster-name=my-cluster

    - an advertisement for a hosted product, quoting a temp directory that no
    longer exists by the time anyone reads the report.
    """
    out = _ANSI.sub("", blob or "")
    if rendered_path:
        out = out.replace(rendered_path, "<rendered manifests>")
        d = os.path.dirname(rendered_path)
        if d:
            out = out.replace(d, "<tmp>")
    return out


@dataclass
class _Reading:
    """What a validator's own output says, independent of its exit code."""
    ok: Optional[bool]
    summary: str
    why: str                      # '' when determinate
    tally: dict = field(default_factory=dict)
    basis: str = ""


def _read_kube_score(blob: str) -> _Reading:
    """kube-score: count its own severity markers.

    Exit 1 means "at least one CRITICAL" - and also means "I could not parse
    your files", which is not a fact about the manifests at all.
    """
    if _KUBESCORE_PARSE_ERR.search(blob):
        detail = ""
        for ln in blob.splitlines():
            if _KUBESCORE_PARSE_ERR.search(ln):
                detail = ln.strip()
                break
        return _Reading(
            ok=None, summary="could not parse the manifests",
            why=(f"kube-score could not parse its input, so it scored nothing: "
                 f"{detail or 'failed to parse files'}. That is a statement "
                 f"about the file it was handed, not about the chart's "
                 f"quality"),
            tally={"parsed": False},
            basis="kube-score's own parse error on stderr")

    crit = blob.count("[CRITICAL]")
    warn = blob.count("[WARNING]")
    ok_objs = blob.count("✅")
    bad_objs = blob.count("💥")
    scored = ok_objs + bad_objs
    tally = {"objects_scored": scored, "objects_ok": ok_objs,
             "objects_flagged": bad_objs, "critical": crit, "warning": warn}
    if scored == 0 and crit == 0 and warn == 0:
        return _Reading(
            ok=None, summary="scored 0 objects",
            why=("kube-score ran but scored no objects, so it has said nothing "
                 "about this chart either way"),
            tally=tally, basis="kube-score scored 0 objects")
    return _Reading(
        ok=(crit == 0),
        summary=(f"{scored} object(s) scored: {crit} critical, {warn} warning"),
        why="", tally=tally,
        basis="kube-score's own [CRITICAL]/[WARNING] tally, not its exit code")


def _read_polaris(blob: str) -> _Reading:
    """polaris: read the score, the controller count and the danger tally.

    polaris exits 0 unconditionally in `audit` mode - on a clean chart, on a
    chart it rates 66/100 with three danger-severity failures, and on a file
    that is not YAML. Its exit code is therefore not evidence of anything, and
    the pre-R6 code read nothing else.
    """
    controllers = _POLARIS_CONTROLLERS.search(blob)
    score = _POLARIS_SCORE.search(blob)
    n_ctrl = int(controllers.group(1)) if controllers else None
    danger = blob.count("❌ Danger")
    warn = blob.count("😬 Warning")
    success = blob.count("🎉 Success")
    tally = {"controllers": n_ctrl, "score": int(score.group(1)) if score else None,
             "danger": danger, "warning": warn, "success": success}

    if _POLARIS_PARSE_ERR.search(blob):
        return _Reading(
            ok=None, summary="could not parse the manifests",
            why=("polaris logged a YAML parse error and audited what was left. "
                 "Its 'Final score' counts only the objects it managed to "
                 "read, so on unreadable input it reports a perfect score for "
                 "having checked nothing"),
            tally=tally, basis="polaris's own parse error on stderr")

    if not n_ctrl:
        return _Reading(
            ok=None, summary="audited 0 controllers",
            why=("polaris found no controllers to audit, so its score is over "
                 "an empty set. It still exits 0 and still prints a score - "
                 "neither of which is a statement about this chart"),
            tally=tally, basis="polaris audited 0 controllers")

    parts = [f"score {tally['score']}/100" if score else "score unreported",
             f"over {n_ctrl} controller(s)",
             f"{danger} danger, {warn} warning"]
    return _Reading(
        ok=(danger == 0), summary=f"{parts[0]} {parts[1]}: {parts[2]}",
        why="", tally=tally,
        basis=("polaris's own danger tally and controller count; its exit "
               "code is always 0 and carries no verdict"))


def _read_kubeconform(blob: str, rc: Optional[int]) -> _Reading:
    """kubeconform already separates the two outcomes itself; R4 read that
    tally and this only exposes it. The verdict logic is deliberately
    unchanged - it is covered by real-binary tests and this iteration is not
    the place to quietly alter a verified path."""
    m = _KUBECONFORM_SUMMARY.search(blob)
    tally = {}
    if m:
        tally = {"valid": int(m.group(1)), "invalid": int(m.group(2)),
                 "errors": int(m.group(3)), "skipped": int(m.group(4))}
    why = _indeterminacy("kubeconform", blob) if rc not in (0, None) else ""
    summary = _last_summary_line(blob)
    if m:
        summary = (f"{tally['valid']} valid, {tally['invalid']} invalid, "
                   f"{tally['errors']} not checkable, {tally['skipped']} skipped")
    return _Reading(ok=(rc == 0) if rc is not None else None,
                    summary=summary, why=why, tally=tally,
                    basis=("kubeconform's Valid/Invalid/Errors tally, with the "
                           "exit code as the PASS signal"))


_READERS = {"kube-score": _read_kube_score, "polaris": _read_polaris}

# The validators that need rendered manifests, as (name, argv-builder, manual
# command, install hint). Module level, not a local inside run_cross_check,
# so tests can run the EXACT argv this module runs. A test that rebuilds the
# command line from memory is one edit away from validating a command nobody
# executes - which is the same failure the mocked tests had, one layer down:
# `--format pretty` is what makes polaris print the "Danger" markers the
# verdict is counted from, and a test that omitted it got JSON and 0 danger.
NEEDS_RENDER = [
    ("kubeconform",
     lambda p: [_which("kubeconform"), "-strict", "-summary", p],
     "kubeconform -strict -summary <(helm template <chart>)",
     "go install github.com/yannh/kubeconform/cmd/kubeconform@latest"),
    ("kube-score",
     lambda p: [_which("kube-score"), "score", p],
     "kube-score score <(helm template <chart>)",
     "https://github.com/zegl/kube-score#installation"),
    ("polaris",
     lambda p: [_which("polaris"), "audit", "--audit-path", p,
                "--format", "pretty"],
     "polaris audit --audit-path <(helm template <chart>)",
     "https://polaris.docs.fairwinds.com/infrastructure-as-code/"),
]


def _indeterminacy(name: str, blob: str) -> str:
    """Why this non-zero exit is 'unknown' rather than 'invalid'. '' if none.

    This is NOT string-sniffing for scary words. kubeconform prints a
    machine-readable tally and separates the two outcomes itself:

        Summary: 5 resources found in 1 file - Valid: 2, Invalid: 0,
                 Errors: 3, Skipped: 0

    `Invalid` counts resources that failed validation. `Errors` counts
    resources it could not validate - unreachable schema store, unregistered
    CRD. Both make it exit 1. Reading the tally instead of the exit code
    keeps the distinction the tool already made.

    Asymmetric on purpose: this can only downgrade FAIL to UNKNOWN, never
    upgrade anything to PASS. Invalid > 0 stays FAIL even when Errors is also
    non-zero, because a real validation failure is present.
    """
    if name == "kubeconform":
        m = _KUBECONFORM_SUMMARY.search(blob)
        if m:
            invalid, errors = int(m.group(2)), int(m.group(3))
            if invalid == 0 and errors > 0:
                return (f"{errors} resource(s) could not be validated at all "
                        f"(no schema available - schema store unreachable, or "
                        f"CRDs not registered) and 0 failed validation; this "
                        f"is 'not checked', not 'invalid'")
    return ""


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _run(cmd: List[str], timeout: int = 90, stdin: Optional[str] = None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=stdin)
        return p.returncode, (p.stdout or ""), (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, "", str(e)


def _trunc(s: str, n: int = 1500) -> str:
    """Cut long tool output, and say precisely what was cut.

    Found by the first test that ever compared a tally against the detail
    block it is printed above: kube-score's summary said "12 critical" and the
    output below it contained five `[CRITICAL]` lines, because the tally is
    computed over the whole blob and this cut the blob at 1500 bytes. The
    numbers were both right. The report was still misleading, because it
    invites the reader to audit the transcription against the excerpt and then
    hands them an excerpt whose truncation marker said only "(truncated)" -
    no count, no indication that the missing part contained findings.

    A reader who counts what is in front of them and gets a smaller number
    than the summary concludes the summary is wrong. Stating the drop makes
    the excerpt auditable as an excerpt.
    """
    s = s.strip()
    if len(s) <= n:
        return s
    head = s[:n]
    kept = head.count("\n") + 1
    total = s.count("\n") + 1
    # Two short lines, not one long one: this block is printed verbatim into
    # a fixed-width report that does not re-wrap it, so a single sentence
    # here overflows the table it sits under.
    return (f"{head}\n"
            f"... ({total - kept} more line(s), {len(s) - n} more byte(s) "
            f"not shown)\n"
            f"... the tally and verdict above were computed over the FULL "
            f"output, not this excerpt.")


def run_cross_check(chart_dir: Optional[str],
                    rendered_text: Optional[str] = None,
                    kube_version: Optional[str] = None) -> List[ExternalResult]:
    """Detect and run the ecosystem validators. `rendered_text` is the
    `helm template` output if the main run already produced it; otherwise we
    render here when helm is available.

    `kube_version` MUST be the same one the main analysis rendered at.
    Cross-checking a different render than the one the report describes
    produces two sets of facts about two different clusters and presents them
    as one - and before R4 that is exactly what happened, because neither
    render passed --kube-version and both silently used helm's v1.20.0.
    """
    results: List[ExternalResult] = []
    helm = find_helm()

    # ensure we have rendered manifests for the tools that need them
    rendered_path = None
    tmpdir = None
    render_err = None
    if rendered_text is None and helm and chart_dir:
        out, render_err = render_chart(chart_dir, helm_bin=helm,
                                       kube_version=kube_version)
        rendered_text = out
    if rendered_text:
        tmpdir = tempfile.mkdtemp(prefix="hpa-xcheck-")
        rendered_path = os.path.join(tmpdir, "rendered.yaml")
        with open(rendered_path, "w", encoding="utf-8") as f:
            f.write(rendered_text)

    # --- helm lint (chart mechanics) -------------------------------------
    if not helm:
        results.append(ExternalResult(
            "helm lint", installed=False, ran=False, ok=None,
            summary="helm not on PATH",
            manual_cmd=f"helm lint {chart_dir or '<chart-dir>'}",
            install_hint="https://helm.sh/docs/intro/install/"))
    elif not chart_dir:
        results.append(ExternalResult(
            "helm lint", installed=True, ran=False, ok=None,
            summary="no chart directory to lint",
            manual_cmd="helm lint <chart-dir>"))
    else:
        cmd = [helm, "lint", chart_dir]
        if kube_version:
            cmd.extend(["--kube-version", kube_version])
        rc, out, err = _run(cmd)
        blob = _clean((out + "\n" + err).strip())
        why = _indeterminacy("helm lint", blob) if rc not in (0, None) else ""
        results.append(ExternalResult(
            "helm lint", installed=True, ran=rc is not None,
            ok=(rc == 0) if rc is not None else None,
            summary=(_last_summary_line(blob) if rc is not None
                     else f"failed to run: {err}"),
            manual_cmd=" ".join(cmd),
            detail=_trunc(blob),
            indeterminate=bool(why), indeterminate_why=why,
            # helm lint's exit code IS its verdict and says so in its own
            # docs; it is left alone, and labelled so the report does not
            # imply a tally was read where none was.
            verdict_basis="helm lint's exit code"))

    # --- schema + best-practice tools needing rendered manifests ---------
    for name, argv_fn, manual, install in NEEDS_RENDER:
        binp = _which(name)
        if not binp:
            results.append(ExternalResult(
                name, installed=False, ran=False, ok=None,
                summary="not installed",
                manual_cmd=manual, install_hint=install))
            continue
        if not rendered_path:
            # Distinguish "helm is missing" from "helm is here and refused
            # this chart" - before R4 both printed the same install advice,
            # and only one of them is actionable by installing anything.
            if not helm:
                why = ("needs rendered manifests and helm is not on PATH to "
                       "render them")
            elif render_err:
                why = f"chart could not be rendered: {render_err}"
            else:
                why = "no rendered manifests were available"
            results.append(ExternalResult(
                name, installed=True, ran=False, ok=None,
                summary=why, manual_cmd=manual))
            continue
        rc, out, err = _run(argv_fn(rendered_path))
        blob = _clean((out + "\n" + err).strip(), rendered_path)
        if rc is None:
            results.append(ExternalResult(
                name, installed=True, ran=False, ok=None,
                summary=f"failed to run: {_clean(err, rendered_path)}",
                manual_cmd=manual, detail=_trunc(blob),
                verdict_basis="the tool did not run"))
            continue
        if name == "kubeconform":
            r = _read_kubeconform(blob, rc)
        else:
            r = _READERS[name](blob)
        results.append(ExternalResult(
            name, installed=True, ran=True, ok=r.ok,
            summary=r.summary, manual_cmd=manual, detail=_trunc(blob),
            indeterminate=bool(r.why), indeterminate_why=r.why,
            tally=r.tally, verdict_basis=r.basis))

    return results


def _last_summary_line(blob: str) -> str:
    """Best-effort one-liner: the last non-empty line of output."""
    lines = [ln.strip() for ln in blob.splitlines() if ln.strip()]
    return lines[-1] if lines else "(no output)"

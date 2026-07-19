"""Plain-text report renderer: scorecard, findings, proof tables, education."""

import textwrap
from datetime import datetime
from typing import List

from . import __version__
from .models import AnalysisResult, Basis, Category, ProofTable, Severity
from .scoring import WEIGHTS, category_scores, grade, overall_score

WIDTH = 100


def _hr(char="=") -> str:
    return char * WIDTH


def _wrap(text: str, indent: int = 0, width: int = WIDTH) -> str:
    pad = " " * indent
    out_lines: List[str] = []
    for para in (text or "").split("\n"):
        if not para.strip():
            out_lines.append("")
            continue
        out_lines.extend(textwrap.wrap(
            para, width=width - indent, initial_indent=pad,
            subsequent_indent=pad, break_long_words=False,
            break_on_hyphens=False) or [pad])
    return "\n".join(out_lines)


_BASIS_PHRASE = {
    Basis.OBSERVED: "OBSERVED - read directly from your files (stated as fact).",
    Basis.DERIVED:  "DERIVED - arithmetic on your values using the stated model "
                    "and estimated constants; re-check with measured numbers.",
    Basis.ASSUMED:  "ASSUMED - the tool could not observe this directly and fell "
                    "back to a guess; verify before acting (see Assumes).",
}


def _basis_phrase(b: Basis) -> str:
    return _BASIS_PHRASE.get(b, b.label)


def _section(title: str, number: str = "") -> str:
    head = f"{number}  {title}" if number else title
    return f"\n\n{_hr('=')}\n{head.upper()}\n{_hr('=')}\n"

class _Sec:
    """Incrementing section numberer so sections can appear/disappear by
    verbosity level without hand-maintained numbers."""
    def __init__(self):
        self.n = 0

    def __call__(self, title: str) -> str:
        self.n += 1
        return _section(f"{self.n}. {title}")


# ---------------------------------------------------------------------------
# ASCII tables with cell wrapping
# ---------------------------------------------------------------------------

def _table(headers: List[str], rows: List[List[str]], width: int = WIDTH) -> str:
    cols = len(headers)
    rows = [[("" if c is None else str(c)) for c in r] + [""] * (cols - len(r))
            for r in rows]
    naturals = [max(len(headers[i]), *(len(r[i]) for r in rows)) if rows
                else len(headers[i]) for i in range(cols)]
    budget = width - (3 * cols + 1)
    widths = list(naturals)
    if sum(widths) > budget:
        # shrink widest columns first, floor of 8 chars
        while sum(widths) > budget and max(widths) > 8:
            j = widths.index(max(widths))
            widths[j] -= 1
    def fmt_row(cells: List[str], sep="|") -> List[str]:
        wrapped = [textwrap.wrap(c, widths[i], break_long_words=True,
                                 break_on_hyphens=False) or [""]
                   for i, c in enumerate(cells)]
        height = max(len(w) for w in wrapped)
        lines = []
        for h in range(height):
            parts = [(wrapped[i][h] if h < len(wrapped[i]) else "").ljust(widths[i])
                     for i in range(cols)]
            lines.append(f"{sep} " + f" {sep} ".join(parts) + f" {sep}")
        return lines
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out = [border]
    out.extend(fmt_row(headers))
    out.append(border.replace("-", "="))
    for r in rows:
        out.extend(fmt_row(r))
        out.append(border)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Report body
# ---------------------------------------------------------------------------

def stdout_summary(result: AnalysisResult, report_path: str,
                   html_path: str = None) -> str:
    """The terminal-first answer: grade, counts, the top fixes, and where the
    full report is - so an SRE never has to open a file to know what to do."""
    findings = sorted(
        result.findings,
        key=lambda f: (-f.severity.rank, -WEIGHTS[f.category], f.rule_id))
    score = overall_score(result)
    counts = {s: sum(1 for f in findings if f.severity is s) for s in Severity}
    L: List[str] = []
    if score is None:
        L.append("  RESULT: NOT GRADED (no analyzable chart input - see report)")
    else:
        L.append(f"  GRADE {grade(score)}  ({score:.1f}/100)   "
                 f"{counts[Severity.CRITICAL]} critical, "
                 f"{counts[Severity.HIGH]} high, "
                 f"{counts[Severity.MEDIUM]} medium, {counts[Severity.LOW]} low")
    top = [f for f in findings
           if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if top:
        L.append("  Fix first:")
        for i, f in enumerate(top[:5], 1):
            loc = f"  ({f.file})" if f.file else ""
            tag = "  [ASSUMED - verify]" if f.basis is Basis.ASSUMED else ""
            L.append(f"    {i}. [{f.rule_id}] {f.title}{loc}{tag}")
        if len(top) > 5:
            L.append(f"    ... +{len(top) - 5} more critical/high "
                     f"(see report)")
    elif score is not None:
        L.append("  No critical or high findings.")
    tail = f"  Full report: {report_path}"
    if html_path:
        tail += f"   |   HTML: {html_path}"
    L.append(tail)
    return "\n".join(L)


def render(result: AnalysisResult, target: str, external=None,
           level: str = "default", teach: bool = False,
           show_all: bool = False) -> str:
    ctx = result.context
    findings = sorted(
        result.findings,
        key=lambda f: (-f.severity.rank, -WEIGHTS[f.category], f.rule_id))
    score = overall_score(result)
    g = grade(score) if score is not None else "-"
    counts = {s: sum(1 for f in findings if f.severity is s) for s in Severity}

    L: List[str] = []
    L.append(_hr())
    L.append("HELM CHART / KUBERNETES / JVM QUALITY ANALYSIS".center(WIDTH))
    L.append(f"hpa-analyzer v{__version__}".center(WIDTH))
    L.append(_hr())
    L.append(f"Target directory : {target}")
    L.append(f"Generated        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    chart = ctx.chart if isinstance(ctx.chart, dict) else {}
    if not ctx.chart_yaml_path:
        L.append("Chart            : NOT FOUND")
    elif not isinstance(ctx.chart, dict):
        L.append(f"Chart            : (malformed Chart.yaml - "
                 f"{type(ctx.chart).__name__}, see findings)")
    else:
        L.append(f"Chart            : "
                 f"{chart.get('name', '(none)')} "
                 f"v{chart.get('version', '?')} "
                 f"(appVersion {chart.get('appVersion', '?')})")

    # inventory
    L.append("\nFiles analyzed:")
    inv = []
    if ctx.chart_yaml_path:
        inv.append(f"  chart      : {ctx.chart_yaml_path}")
    for p in ctx.values_files:
        inv.append(f"  values     : {p}")
    for p in ctx.template_files:
        inv.append(f"  template   : {p}")
    for d in ctx.dockerfiles:
        java = (f"Java {d.java_major}" + (f"u{d.java_update}" if d.java_update
                and d.java_major == 8 else
                (f".0.{d.java_update}" if d.java_update and d.java_major != 8 else ""))
                if d.java_major else "Java version unknown")
        inv.append(f"  dockerfile : {d.path}  [{java}"
                   f"{', ' + d.java_flavor if d.java_flavor else ''}]")
    L.extend(inv or ["  (nothing found)"])

    # verbosity: full implies the teaching appendix and expanded LOW/INFO
    if level == "full":
        teach = True
        show_all = True
    sec = _Sec()

    # ----- executive summary (all levels) ----------------------------------
    L.append(sec("Executive summary"))
    if score is None:
        L.append("  OVERALL QUALITY SCORE : NOT GRADED")
        if ctx.ungradeable_reason:
            L.append(_wrap(f"Reason: {ctx.ungradeable_reason}. The findings and "
                           f"coverage section below still apply.", indent=2))
        else:
            L.append(_wrap("No analyzable chart, values, templates or Dockerfile "
                           "were found under the target directory. A score here "
                           "would be a statement about nothing - see the findings "
                           "and the coverage section for what is missing.", indent=2))
    else:
        bar = int(round(score / 2))
        L.append(f"  OVERALL QUALITY SCORE : {score:5.1f} / 100   GRADE: {g}")
        L.append(f"  [{'#' * bar}{'.' * (50 - bar)}]")
    L.append(f"  Analysis mode         : {ctx.render_mode}")
    L.append("")
    L.append(f"  Findings: {counts[Severity.CRITICAL]} critical, "
             f"{counts[Severity.HIGH]} high, {counts[Severity.MEDIUM]} medium, "
             f"{counts[Severity.LOW]} low, {counts[Severity.INFO]} info")
    crits = [f for f in findings if f.severity is Severity.CRITICAL]
    if crits:
        L.append("\n  Fix these first (each is an outage or a dead feature, not a style issue):")
        for i, f in enumerate(crits[:5], 1):
            tags = []
            if f.basis is Basis.ASSUMED:
                tags.append("ASSUMED - verify before acting")
            elif f.basis is Basis.DERIVED:
                tags.append("derived from estimates")
            if "[with values overlay " in f.detail:
                ov = f.detail.split("[with values overlay ", 1)[1].split("]", 1)[0]
                tags.append(f"overlay {ov} only")
            tag = f"   [{'; '.join(tags)}]" if tags else ""
            L.append(_wrap(f"{i}. [{f.rule_id}] {f.title}"
                           + (f"  ({f.file})" if f.file else "") + tag, indent=4))
        if len(crits) > 5:
            L.append(_wrap(f"... and {len(crits) - 5} more critical finding(s) - "
                           f"see the Findings section below.", indent=4))
    elif counts[Severity.HIGH]:
        L.append("\n  No critical findings; start with the HIGH severity list below.")
    else:
        L.append("\n  No critical or high findings - solid baseline.")

    # ----- coverage (default / full) ---------------------------------------
    if level != "summary":
        L.append(sec("Analysis coverage - what was and was NOT checked"))
        L.append(_wrap(
            "Findings can only come from files that were successfully analyzed. "
            "Anything marked as failed, skipped or unknown below produced NO "
            "findings - treat that as missing coverage, never as a clean bill "
            "of health."))
        L.append("")
        if ctx.coverage:
            L.append(_table(["Input", "Coverage"],
                            [list(row) for row in ctx.coverage]))
        else:
            L.append("  (no coverage records - nothing was analyzable)")
        if ctx.render_mode == "helm":
            L.append(_wrap("\nMode: `helm template` rendered the chart with its "
                           "real template engine - manifests below are rendered "
                           "truth for the analyzed values. Objects marked "
                           "'conditional' exist in templates but do not render "
                           "with these values.", indent=0))
        else:
            L.append(_wrap(f"\nMode: {ctx.render_mode}. Static scrubbing "
                           f"approximates helm rendering: conditionals are "
                           f"analyzed as taken and complex template expressions "
                           f"may hide configuration from these checks. Install "
                           f"helm on PATH and re-run for rendered-truth analysis "
                           f"- it materially improves precision.", indent=0))

    # ----- scorecard (all levels) ------------------------------------------
    L.append(sec("Scorecard by category"))
    rows = []
    for cat, cscore, cfind in category_scores(result):
        n_by_sev = ", ".join(
            f"{sum(1 for f in cfind if f.severity is s)}{s.label[0]}"
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                      Severity.LOW) if any(f.severity is s for f in cfind)) or "-"
        rows.append([
            cat.value,
            "N/A" if cscore is None else f"{cscore:5.1f}",
            "N/A" if cscore is None else grade(cscore),
            str(WEIGHTS[cat]),
            n_by_sev,
        ])
    L.append(_table(["Category", "Score", "Grade", "Weight", "Findings (C/H/M/L)"], rows))
    L.append(_wrap("\nScoring model: each category starts at 100; deductions "
                   "are CRITICAL -25, HIGH -12, MEDIUM -6, LOW -3, INFO -0, "
                   "floored at 0. Overall = weighted mean over applicable "
                   "categories (N/A categories are excluded, not free points)."))

    if level == "summary":
        # ----- compact top findings, then pointer --------------------------
        L.append(sec("Top findings (CRITICAL & HIGH)"))
        top = [f for f in findings
               if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if not top:
            L.append("  None at CRITICAL/HIGH. See the full report for "
                     "MEDIUM/LOW items.")
        for f in top:
            loc = f" ({f.file})" if f.file else ""
            L.append(_wrap(f"[{f.severity.label[0]}] [{f.rule_id}] {f.title}"
                           f"{loc}  ->  {f.fix}", indent=2))
        L.append(_wrap("\nThis is the --summary view. Re-run without --summary "
                       "for coverage, full findings, proof tables and the "
                       "cluster-verify commands; add --full (or --teach) for the "
                       "education appendix.", indent=2))
    else:
        # ----- findings (LOW/INFO collapsed unless --all) ------------------
        L.append(sec("Findings and remediation"))
        if not findings:
            L.append("  No findings. Exceptional.")
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
        for sev in order:
            sel = [f for f in findings if f.severity is sev]
            if not sel:
                continue
            compact = (sev is Severity.INFO) or (sev is Severity.LOW and not show_all)
            L.append(f"\n{_hr('-')}")
            L.append(f"{sev.label}  ({len(sel)})")
            L.append(_hr("-"))
            if compact:
                if sev is Severity.INFO:
                    note = ("Housekeeping - zero score impact, one line each so "
                            "they stop competing with real problems:")
                else:
                    note = (f"Summarized (one line each) - run with --all for the "
                            f"full Why/Math/Fix on each:")
                L.append(_wrap(note, indent=2))
                for f in sel:
                    loc = f" ({f.file})" if f.file else ""
                    L.append(_wrap(f"[{f.rule_id}] {f.title}{loc} -> {f.fix}",
                                   indent=4))
                continue
            for f in sel:
                loc = f" | {f.file}" + (f":{f.line}" if f.line else "") if f.file else ""
                L.append(f"\n[{f.rule_id}] {f.title}")
                L.append(f"    Category: {f.category.value}{loc}")
                L.append(_wrap(f"Basis : {_basis_phrase(f.basis)}", indent=4))
                if f.basis is Basis.ASSUMED and f.assumes:
                    L.append(_wrap(f"Assumes: {f.assumes} - if that is wrong, this "
                                   f"finding does not apply.", indent=4))
                L.append(_wrap(f"Found : {f.detail}", indent=4))
                L.append(_wrap(f"Why   : {f.why}", indent=4))
                if f.math:
                    L.append(_wrap(f"Math  : {f.math}", indent=4))
                L.append(_wrap(f"Fix   : {f.fix}", indent=4))

        # ----- proof tables ------------------------------------------------
        L.append(sec("Mathematical proof tables"))
        L.append(_wrap("Every table below derives its verdict from arithmetic on "
                       "values found in YOUR files (estimates are labeled and "
                       "conservative). Re-check any number by hand."))
        if not result.proofs:
            L.append("\n  (No workload/JVM pairs found to compute tables for.)")
        for i, p in enumerate(result.proofs, 1):
            L.append(f"\n{_hr('-')}")
            L.append(f"TABLE {i}: {p.title}")
            L.append(_hr("-"))
            L.append(_wrap(p.intro))
            L.append("")
            L.append(_table(p.headers, p.rows))
            L.append("")
            L.append(_wrap("VERDICT: " + p.conclusion, indent=2))

        # ----- verify on your cluster --------------------------------------
        from .clusterprobes import build_probes
        probes = build_probes(result)
        if probes:
            L.append(sec("Verify on your cluster - close the gaps static "
                         "analysis can't"))
            L.append(_wrap(
                "This tool reads files, not a cluster. Each item below is a real "
                "Kubernetes behaviour it cannot see from the chart; run the "
                "command to close the gap, then read the result as described. "
                "Only the checks relevant to THIS chart are shown; names and "
                "selectors are filled in from your files where resolved "
                "(placeholders like <namespace> are yours to substitute)."))
            for p in probes:
                L.append(f"\n{_hr('-')}")
                L.append(f"[{p.key}] {p.title}")
                L.append(_hr("-"))
                L.append(_wrap(f"Gap  : {p.gap}", indent=4))
                L.append("    Run  :")
                for cmd in p.commands:
                    L.append(f"        $ {cmd}")
                L.append(_wrap(f"Read : {p.read}", indent=4))

        # ----- external validators -----------------------------------------
        if external:
            L.append(sec("External validators - independent cross-check"))
            L.append(_wrap(
                "hpa-analyzer did not write these tools and does not vouch for "
                "their output - it ran them and reports their exit status and "
                "output verbatim. Absent tools show an install command. Tools "
                "that need rendered manifests are skipped (with a reason) when "
                "helm is unavailable to render."))
            xrows = []
            for e in external:
                if not e.installed:
                    status = "not installed"
                elif not e.ran:
                    status = "skipped"
                else:
                    status = "PASS" if e.ok else "FAIL"
                xrows.append([e.name, status, e.summary])
            L.append("")
            L.append(_table(["Tool", "Status", "Result / reason"], xrows))
            for e in external:
                if e.detail and e.ran:
                    L.append(f"\n  --- {e.name} output " + "-" * 40)
                    for ln in e.detail.splitlines():
                        L.append("  " + ln)
                if not e.installed and e.install_hint:
                    L.append(_wrap(f"install {e.name}: {e.install_hint}", indent=2))
                L.append(_wrap(f"run it yourself: {e.manual_cmd}", indent=2))

        # ----- education (only when teaching) ------------------------------
        if teach:
            L.append(sec("Education appendix - why this math matters"))
            L.append(_education())

    # ----- methodology (all levels) ----------------------------------------
    L.append(sec("Methodology and limitations"))
    if ctx.render_mode == "helm":
        mode_para = (
            "Manifests were produced by `helm template` - the real template "
            "engine with the analyzed values - so conditional logic, loops "
            "and helpers are evaluated exactly as a deploy would. Templates "
            "that do not render with these values were additionally analyzed "
            "statically and are labeled 'conditional' wherever they appear. ")
    else:
        mode_para = (
            f"Analysis mode: {ctx.render_mode}. Templates were parsed with "
            "Go-template expressions scrubbed and, where possible, resolved "
            "from values.yaml, WITHOUT executing helm. Conditional blocks "
            "are analyzed as if taken; complex expressions (tpl, printf, "
            "required, subcharts) are beyond static resolution and files "
            "that failed to parse produced no findings at all - the "
            "coverage section lists every such gap. Installing helm and "
            "re-running upgrades this report to rendered-truth analysis. ")
    L.append(_wrap(
        mode_para +
        "Numeric estimates (metaspace, thread counts, node sizes, startup "
        "times, per-pod availability) are stated inline and should be "
        "replaced with your measured values for final sizing decisions; "
        "conclusions drawn from estimates say so. Complement this report "
        "with: helm lint && helm template | kubeconform, a policy engine "
        "(Polaris/Kyverno/OPA), and real load-test data with GC logs "
        "(-Xlog:gc* / -XX:+PrintGCDetails) and kubectl top / VPA "
        "recommendations."))
    L.append("\n" + _hr())
    L.append("END OF REPORT".center(WIDTH))
    L.append(_hr())
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# Static education content
# ---------------------------------------------------------------------------

def _education() -> str:
    E: List[str] = []

    E.append("\n6.1  THE HPA CONTROL LOOP\n")
    E.append(_wrap(
        "Every ~15s the HPA computes, per metric:  desired = "
        "ceil(currentReplicas x currentValue / targetValue), takes the MAX "
        "across metrics, applies a +/-10% tolerance dead-band, clamps to "
        "[minReplicas, maxReplicas], then applies behavior policies "
        "(default: scale-up immediately, scale-down after a 300s "
        "stabilization window). Two facts follow directly from the formula:", indent=2))
    E.append(_wrap("(a) CPU 'utilization' is usage divided by the pod's "
                   "REQUEST - not its limit, not node capacity. Wrong "
                   "requests make the HPA scale wrongly, in exact "
                   "proportion.", indent=6))
    E.append(_wrap("(b) Any metric that does not fall when replicas rise "
                   "breaks the loop: desired can never go below current. "
                   "JVM memory is the canonical example (heap high-water "
                   "mark).", indent=6))

    E.append("\n6.2  THE JVM MEMORY MODEL IN A CONTAINER\n")
    E.append("      container limit (cgroup memory.max)  <-- kernel kills here (exit 137)")
    E.append("      +--------------------------------------------------+")
    E.append("      |  heap (-Xmx / MaxRAMPercentage)                  |")
    E.append("      |  metaspace (classes; unbounded by default!)      |")
    E.append("      |  JIT code cache                                  |")
    E.append("      |  thread stacks (threads x -Xss, ~1 MiB each)     |")
    E.append("      |  direct/NIO buffers (default cap = Xmx!)         |")
    E.append("      |  GC bookkeeping, symbols, JVM itself             |")
    E.append("      +--------------------------------------------------+")
    E.append(_wrap(
        "The kernel enforces the SUM. A heap that fits is necessary but not "
        "sufficient - rule of thumb: heap <= 50-75% of the limit, and never "
        "less than ~250-400 MiB of absolute non-heap headroom for framework "
        "apps. The kernel OOM kill (exit 137) produces NO Java stack trace "
        "and NO heap dump: if you see 137/OOMKilled with no "
        "OutOfMemoryError in logs, it was the cgroup, not the heap.", indent=2))

    E.append("\n6.3  JAVA CONTAINER-AWARENESS TIMELINE\n")
    E.append(_table(
        ["JVM", "Sees cgroup v1 limits?", "Sees cgroup v2?", "Heap % flags"],
        [
            ["Java 8 < 8u131", "NO - uses host RAM/CPUs", "NO", "-Xmx only"],
            ["8u131 - 8u190", "memory only, with -XX:+UnlockExperimentalVMOptions "
             "-XX:+UseCGroupMemoryLimitForHeap", "NO", "-Xmx, MaxRAMFraction"],
            ["8u191 - 8u371", "YES (UseContainerSupport backport, default on)",
             "NO", "MaxRAMPercentage"],
            ["8u372+", "YES", "YES", "MaxRAMPercentage"],
            ["11.0.0 - 11.0.15", "YES", "NO", "MaxRAMPercentage"],
            ["11.0.16+, 15+, 17, 21", "YES", "YES", "MaxRAMPercentage"],
        ]))
    E.append(_wrap(
        "cgroup v2 is the default on modern node images (Ubuntu 22.04+, "
        "EKS AL2023, current GKE/AKS). A pre-v2 JVM on a v2 node silently "
        "falls back to HOST sizing - the worst failure mode returns even "
        "though your JDK 'is container aware'.", indent=2))

    E.append("\n6.4  A SANE BASELINE FOR A JVM SERVICE CHART\n")
    E.append(_table(
        ["Setting", "Baseline", "Reason"],
        [
            ["requests.memory = limits.memory", "e.g. 1Gi / 1Gi",
             "memory is incompressible; Guaranteed-style memory QoS"],
            ["requests.cpu", "250m-1000m ~ typical usage", "HPA denominator; "
             "scheduler packing"],
            ["limits.cpu", "unset (or >= 2x request)",
             "avoid CFS throttling of GC/JIT bursts"],
            ["-XX:MaxRAMPercentage", "50-75", "heap scales with the limit"],
            ["-XX:+ExitOnOutOfMemoryError", "always", "die visibly; let K8s heal"],
            ["-XX:ActiveProcessorCount", "set if no cpu limit",
             "stable thread-pool sizing"],
            ["startupProbe", "period 5s x threshold 24-60",
             "protects slow JVM starts from liveness"],
            ["readiness != liveness", "always", "shed traffic without restarts"],
            ["HPA", "autoscaling/v2, CPU 60-75%, min >= 2",
             "headroom for scale-up lag"],
            ["PDB", "maxUnavailable: 1", "survive drains/upgrades"],
            ["replicas", "omit when HPA enabled",
             "helm upgrade must not reset scale"],
            ["ENTRYPOINT", "exec form (java as PID 1)",
             "SIGTERM -> graceful shutdown"],
        ]))

    E.append("\n6.5  THE RELATIVITY TRAP - REQUESTS, NOT LIMITS, DRIVE SCALING\n")
    E.append(_wrap(
        "The HPA computes CPU 'utilization' as usage / REQUEST - never the "
        "limit, never node capacity. Set the request as a low placeholder and "
        "you lie to the controller. Example: request=100m, limit=2000m, actual "
        "usage=150m. The kernel sees a pod using 7.5% of its 2000m ceiling - "
        "nowhere near throttling. The HPA sees 150m/100m = 150% utilization "
        "and, against a 70% target, scales aggressively to maxReplicas while "
        "every pod sits nearly idle. Under-sized requests 'trick' the loop into "
        "believing the system is saturated when it is merely active. Right-size "
        "requests FIRST (a day of VPA in recommendation mode); accuracy in the "
        "denominator is the only route to stability in the output.", indent=2))

    E.append("\n6.6  COMPRESSIBLE VS INCOMPRESSIBLE RESOURCES\n")
    E.append(_table(
        ["", "CPU (compressible)", "Memory (incompressible)"],
        [
            ["Exhaustion", "CFS throttling (slows down)", "OOM kill - SIGKILL (dies)"],
            ["Kernel signal", "container_cpu_cfs_throttled_periods_total",
             "container_memory_working_set_bytes"],
            ["Tracks load?", "yes - roughly linear with work",
             "no - heap/baseline stays flat"],
            ["Good scale metric?", "yes for stateless services",
             "NO - prone to permanent scale-out"],
        ]))
    E.append(_wrap(
        "Because memory is incompressible and a JVM/Go runtime rarely returns "
        "it to the OS, memory 'utilization' does not fall when load falls: an "
        "HPA on memory ratchets to max and stays. Diagnostic: if "
        "container_cpu_cfs_throttled_periods_total climbs while the HPA sits "
        "idle, your CPU request is too small or you are scaling on the wrong "
        "metric.", indent=2))

    E.append("\n6.7  THE UNREADY-POD OUTAGE (dampening logic)\n")
    E.append(_wrap(
        "When new pods fail readiness (bad deploy, missing DB schema) the HPA "
        "can REFUSE to scale even at 100% CPU on the ready pods. Its four-step "
        "logic: (1) group pods Ready / Unready / Ignored; (2) first pass uses "
        "Ready pods only; (3) if that says scale-up, add the Unready pods back "
        "at 0% usage; (4) if the resulting ratio is within a +/-10% tolerance "
        "of target, do nothing. With maxSurge=100%, two hot pods plus two "
        "unready-at-0% average to (100+100+0+0)/4 = 50%, well inside the "
        "tolerance of a 70% target - so scaling STOPS exactly when you need it. "
        "Mitigation: keep maxSurge at 25-50% so the ready pods' signal survives "
        "the dampening.", indent=2))

    E.append("\n6.8  THRASHING, STABILIZATION, AND THE HPA+VPA DEATH SPIRAL\n")
    E.append(_wrap(
        "Thrashing: high metric -> scale up -> load per pod drops -> scale down "
        "-> load spikes -> repeat, churning pods and cold caches. Damp it with "
        "stabilizationWindowSeconds over a rolling history. The production "
        "pattern is ASYMMETRIC - react up fast, release down slowly:", indent=2))
    E.append(_wrap(
        "behavior:\n"
        "  scaleUp:   { stabilizationWindowSeconds: 0,   policies: [{type: Percent, value: 100, periodSeconds: 15}] }\n"
        "  scaleDown: { stabilizationWindowSeconds: 300, policies: [{type: Percent, value: 10,  periodSeconds: 60}] }",
        indent=4))
    E.append(_wrap(
        "HPA+VPA on the SAME resource is a death spiral: VPA lowers the request "
        "because usage is low; the HPA sees a smaller denominator, computes "
        "higher utilization, and scales out unnecessarily. Rule: never let both "
        "auto-update the same resource. Use VPA in recommendation/initial mode "
        "to right-size requests; use the HPA to handle traffic. Also beware "
        "I/O-bound services: waiting on a lock or a slow downstream shows LOW "
        "CPU, so a CPU HPA never scales even as p99 breaches the SLO - scale "
        "those on latency or queue depth.", indent=2))

    E.append("\n6.9  DEMAND METRICS - SCALE ON CAUSE, NOT SYMPTOM\n")
    E.append(_wrap(
        "CPU/memory are lagging symptoms. Demand metrics track the cause:",
        indent=2))
    E.append(_table(
        ["Signal", "Best for", "Target rule of thumb"],
        [
            ["Requests/sec (RPS)", "stateless HTTP", "linear proxy for demand"],
            ["Queue depth / lag", "workers (Kafka/RabbitMQ)", "~30s of work to process"],
            ["p99 latency", "SLO-sensitive APIs", "p95 = 50% of the SLO"],
            ["CPU utilization", "general compute", "50-75% (60-75% for JVMs)"],
        ]))
    E.append(_wrap(
        "Expose app metrics via the Prometheus Adapter, or drive scaling from "
        "external event sources with KEDA (queues, streams, cron). RPS scales "
        "linearly regardless of I/O wait, which is why it beats CPU for "
        "latency-bound services.", indent=2))

    E.append("\n6.10  PREDICTIVE SCALING AND THE SCALING-INVARIANT SIGNAL\n")
    E.append(_wrap(
        "Reactive scaling has a 'startup gap': the sync period (~15s) plus "
        "metrics-server scrape latency (30-60s) plus pod schedule + image pull "
        "+ JVM warmup means the system is blind to the first minute of a surge. "
        "Predictive scaling forecasts load (e.g. Holt's / triple-exponential "
        "smoothing) and provisions capacity BEFORE the peak. It must forecast "
        "on a CLUSTER-WIDE AGGREGATE (sum of per-pod metrics), not a per-pod "
        "average: adding replicas drops the average even as total load rises, "
        "so the average is not a stable time series. The aggregate is "
        "scaling-invariant - stable however load redistributes - which is what "
        "makes clean extrapolation possible. A typical pipeline: align "
        "irregular batches onto a uniform grid, impute missing pods by carrying "
        "forward, gradually weight in new pods (so a starting pod is not read "
        "as a load 'drop'), forecast to the init-timeout horizon, then solve "
        "for the replica count needed now so capacity is ready when the peak "
        "arrives.", indent=2))

    E.append("\n6.11  WORKLOAD -> SCALER DECISION FRAMEWORK\n")
    E.append(_table(
        ["Workload", "Signal", "Tool", "Target"],
        [
            ["Stateless HTTP", "RPS / CPU", "HPA", "50-60% CPU"],
            ["I/O-bound API", "p99 latency", "HPA + Prometheus", "p95 = 50% of SLO"],
            ["Message consumer", "queue depth / lag", "KEDA", "~30s of work"],
            ["Stateful / singleton", "historical usage", "VPA (recommend)", "n/a"],
        ]))
    E.append(_wrap(
        "Non-negotiables: minReplicas >= 2 (no single point of failure at "
        "scale-in); a PodDisruptionBudget so the HPA/drains cannot evict every "
        "pod at once; right-size requests before setting targets.", indent=2))

    E.append("\n6.12  HOW TO READ THE 'BASIS' LINE ON EACH FINDING\n")
    E.append(_wrap(
        "Every finding declares how the tool knows what it claims, so a guess "
        "never reads like a measurement: OBSERVED = read directly from your "
        "files (stated as fact); DERIVED = arithmetic on your values using the "
        "stated model and estimated non-heap constants (re-check with measured "
        "numbers); ASSUMED = the tool could NOT see the truth and fell back to "
        "a guess - it prints an 'Assumes:' line, is flagged in the fix-first "
        "list, and (if CRITICAL) is capped at HIGH's score weight so the tool's "
        "own uncertainty can never sink your grade. When in doubt, act on "
        "OBSERVED first and verify ASSUMED before touching anything.", indent=2))

    E.append("\n6.13  GOLDEN RULES\n")
    for rule in (
        "1. The HPA divides by requests: requests ARE your scaling policy.",
        "2. The kernel sums everything: budget the whole JVM, not the heap.",
        "3. Kubernetes restarts what dies: make the JVM die on OOM, cleanly on SIGTERM.",
        "4. Never scale a JVM on memory utilization.",
        "5. Anything mutable ('latest', unpinned bases, helm-managed replicas "
        "under an HPA) will eventually mutate mid-incident.",
        "6. Scale up fast, scale down slow; never run HPA and VPA on the same "
        "resource.",
    ):
        E.append(_wrap(rule, indent=2))
    return "\n".join(E)

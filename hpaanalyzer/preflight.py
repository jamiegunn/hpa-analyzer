"""Guided input check - "did I point this at the right place, are my files
where they should be?" - answered BEFORE (and independently of) analysis.

`--check` prints this and exits; every normal run prints a one-block summary
to stdout first, so you always see what the tool found and what looks off.
Nothing here executes anything or touches a cluster.
"""

from dataclasses import dataclass
from typing import List, Optional

from .models import ChartContext

OK, WARN, ERROR, INFO = "ok", "warn", "error", "info"
_MARK = {OK: "[ok]  ", WARN: "[warn]", ERROR: "[MISS]", INFO: "[info]"}


@dataclass
class PreflightItem:
    status: str      # ok | warn | error | info
    label: str       # what was (or wasn't) found
    hint: str = ""   # what to do about it, if anything


@dataclass
class Preflight:
    items: List[PreflightItem]

    @property
    def is_chart(self) -> bool:
        """False only when the directory is not a Helm chart at all."""
        return not any(i.status == ERROR for i in self.items)

    @property
    def has_warnings(self) -> bool:
        return any(i.status == WARN for i in self.items)


def build_preflight(ctx: ChartContext) -> Preflight:
    items: List[PreflightItem] = []

    # --- chart ------------------------------------------------------------
    if ctx.chart_yaml_path:
        items.append(PreflightItem(OK, f"Helm chart: {ctx.chart_yaml_path}"))
    else:
        items.append(PreflightItem(
            ERROR, "No Chart.yaml found anywhere under the target directory.",
            "This is not a Helm chart directory. Point the tool at the folder "
            "that contains Chart.yaml (the chart root), e.g. "
            "`python3 hpa-analyzer.py ./my-service`."))

    if ctx.foreign_charts:
        others = ", ".join(ctx.foreign_charts)
        items.append(PreflightItem(
            WARN, f"{len(ctx.foreign_charts)} other chart(s) present and NOT "
                  f"analyzed: {others}.",
            "Several charts are under this directory. The tool analyzed the "
            "outermost one only (never merging them). Point at a single "
            "chart to choose deliberately."))

    # --- values -----------------------------------------------------------
    base = [p for p in ctx.values_files
            if p.rsplit("/", 1)[-1].lower() in ("values.yaml", "values.yml")]
    overlays = ctx.overlay_values
    if base:
        extra = f" (+ {len(overlays)} overlay: {', '.join(overlays)})" if overlays else ""
        items.append(PreflightItem(OK, f"Values: {', '.join(base)}{extra}"))
    elif ctx.values_files:
        items.append(PreflightItem(
            WARN, f"Values files found but no base values.yaml: "
                  f"{', '.join(ctx.values_files)}.",
            "A base values.yaml is what template `.Values.*` resolve against. "
            "Without it, values are unresolved and results are less precise."))
    else:
        items.append(PreflightItem(
            WARN, "No values file found.",
            "Add a values.yaml so `.Values.*` references resolve; otherwise "
            "checks run against empty configuration."))

    # --- templates & workloads -------------------------------------------
    n_tpl = len([t for t in ctx.template_files
                 if not t.endswith((".tpl",)) and "NOTES" not in t])
    if getattr(ctx, "templates_present", bool(ctx.template_files)):
        items.append(PreflightItem(OK, f"Templates: {len(ctx.template_files)} "
                                       f"file(s) under templates/"))
    elif ctx.chart_yaml_path:
        items.append(PreflightItem(
            WARN, "No templates/ directory (or it is empty).",
            "A chart with no templates renders nothing to analyze. Ensure "
            "you pointed at the chart root, not a packaged .tgz or a parent."))

    n_workloads = len(ctx.workloads)
    if n_workloads:
        kinds = ", ".join(sorted({(w.kind or "?") for w in ctx.workloads}))
        items.append(PreflightItem(OK, f"Workloads: {n_workloads} ({kinds})"))
    elif getattr(ctx, "templates_present", False):
        items.append(PreflightItem(
            WARN, "Templates exist but ZERO workload objects were parsed.",
            "Likely a library chart (`{{ include }}` rendering no objects), an "
            "unresolved template, or a parse failure - the run is scored NOT "
            "GRADED. See the coverage section. Install helm for rendered "
            "analysis if you are in static mode."))

    # --- dockerfile / jvm -------------------------------------------------
    if ctx.dockerfiles:
        df = ctx.dockerfiles[0]
        many = f" (+{len(ctx.dockerfiles)-1} more)" if len(ctx.dockerfiles) > 1 else ""
        if df.java_major is not None and ctx.assumed_java:
            items.append(PreflightItem(
                OK, f"Dockerfile: {df.path} (Java {ctx.assumed_java}, "
                    f"ASSUMED via --assume-java){many}"))
        elif df.java_major is not None:
            v = f"Java {df.java_major}" + (f"u{df.java_update}"
                 if df.java_update is not None and df.java_major == 8 else "")
            items.append(PreflightItem(OK, f"Dockerfile: {df.path} ({v}){many}"))
        else:
            items.append(PreflightItem(
                WARN, f"Dockerfile: {df.path} - Java version undeterminable"
                      f"{many}.",
                "Common for internal base images. Re-run with "
                "`--assume-java <ver>` (e.g. 8u151, 17) so the JVM/cgroup "
                "checks can run; otherwise they are skipped."))
    else:
        items.append(PreflightItem(
            WARN, "No Dockerfile found.",
            "The Java/JVM and cross-file (heap-vs-limit) categories will be "
            "N/A. Include the service Dockerfile anywhere under the directory "
            "(any name matching Dockerfile* or *.dockerfile), or accept the "
            "reduced scope."))

    # --- mode & parse health ---------------------------------------------
    if ctx.render_mode == "helm":
        items.append(PreflightItem(INFO, "Render mode: helm (rendered truth)."))
    else:
        items.append(PreflightItem(
            INFO, f"Render mode: {ctx.render_mode}.",
            "Install `helm` and put it on PATH for rendered-truth analysis - "
            "it resolves conditionals/loops/helpers static parsing cannot."))

    if ctx.parse_errors:
        first = ctx.parse_errors[0]
        more = f" (+{len(ctx.parse_errors)-1} more)" if len(ctx.parse_errors) > 1 else ""
        items.append(PreflightItem(
            WARN, f"{len(ctx.parse_errors)} parse problem(s){more}.",
            f"First: {first}. Files that fail to parse produce NO findings - "
            f"see the coverage section."))

    return Preflight(items)


def render_preflight(pf: Preflight, target: str, full: bool = True) -> str:
    """full=True: the standalone `--check` view with hints.
    full=False: the compact always-on stdout banner (statuses only)."""
    lines = []
    if full:
        lines.append("INPUT CHECK - " + target)
        lines.append("-" * min(78, max(20, len("INPUT CHECK - " + target))))
    for it in pf.items:
        lines.append(f"  {_MARK[it.status]} {it.label}")
        if full and it.hint:
            for hl in _wrap(it.hint, 8):
                lines.append(hl)
    if full:
        if not pf.is_chart:
            lines.append("\n  => Not a chart directory. Fix the path above and "
                         "re-run.")
        elif pf.has_warnings:
            lines.append("\n  => Usable, with the warnings above. Analysis will "
                         "run; some categories may be reduced or N/A.")
        else:
            lines.append("\n  => Looks complete. Analysis will run at full "
                         "coverage.")
    return "\n".join(lines)


def _wrap(text: str, indent: int) -> List[str]:
    import textwrap
    pad = " " * indent
    return textwrap.wrap(text, width=94 - indent, initial_indent=pad,
                         subsequent_indent=pad) or [pad + text]

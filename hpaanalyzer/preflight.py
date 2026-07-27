"""Guided input check - "did I point this at the right place, are my files
where they should be?" - answered BEFORE (and independently of) analysis.

`--check` prints this and exits; every normal run prints a one-block summary
to stdout first, so you always see what the tool found and what looks off.
Nothing here executes anything or touches a cluster.
"""

from dataclasses import dataclass
from typing import List, Optional

from .kube import dockerfile_jvm_evidence, jvm_evidence
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
            "`./bin/hpa-analyzer ./my-service`."))

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
    #
    # R8, tenth site - and the one the user meets FIRST, since preflight
    # prints above the report on every run. Both branches asked "is there a
    # Dockerfile?" and answered as if they had asked "is this a JVM?":
    #
    #   nginx pod, `FROM nginx:alpine`     -> "Java version undeterminable.
    #                                         Re-run with --assume-java"
    #   pod spec sets -Xmx1g, no Dockerfile -> "The Java/JVM and cross-file
    #                                          categories will be N/A"
    #
    # The first invents a JVM and then asks the reader to name its version.
    # The second is now simply false: measured on that exact chart, JAVA
    # scores 94.0 and CROSS 100.0, because after R8 the heap analysis reads
    # the pod spec. Telling someone their heap-vs-limit check did not run,
    # when it ran and passed, is worse than saying nothing - they will go
    # looking for a Dockerfile to satisfy a tool that did not need one.
    chart_ev = jvm_evidence(ctx)
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
        elif dockerfile_jvm_evidence(df):
            # A JVM is evidenced but its version is not readable. This is the
            # case --assume-java exists for, and now the only one that asks
            # for it.
            items.append(PreflightItem(
                WARN, f"Dockerfile: {df.path} - JVM detected, version "
                      f"undeterminable{many}.",
                f"Evidence: {dockerfile_jvm_evidence(df)}. Common for "
                f"internal base images. Re-run with `--assume-java <ver>` "
                f"(e.g. 8u151, 17) so the version-dependent JVM/cgroup "
                f"checks can run; otherwise they are skipped."))
        elif chart_ev:
            # No JVM in the file, but the chart evidences one elsewhere - so
            # this Dockerfile probably is not the one that builds the
            # workload. Say that, rather than demanding a Java version for a
            # file that has nothing to do with Java.
            items.append(PreflightItem(
                OK, f"Dockerfile: {df.path} (no JVM in it){many}",
                f"A JVM is evidenced elsewhere in this chart ({chart_ev[0]}), "
                f"so the JVM checks run from that. If this file was meant to "
                f"be the service image, it is not the one being analyzed."))
        else:
            items.append(PreflightItem(
                OK, f"Dockerfile: {df.path} (no JVM detected){many}",
                "Nothing in this file indicates a JVM, so the Java/JVM "
                "checks are reported as not assessed rather than passed. If "
                "this IS a Java service, its JVM settings are somewhere this "
                "tool cannot see: set them in the pod spec "
                "(JAVA_TOOL_OPTIONS), or point the run at the directory "
                "holding the real Dockerfile."))
    elif chart_ev:
        items.append(PreflightItem(
            OK, "No Dockerfile found - JVM evidenced in the chart itself.",
            f"{chart_ev[0]}. The Java/JVM and cross-file (heap-vs-limit) "
            f"checks run from the pod spec; only the image-level DOCKERFILE "
            f"category is unassessable without the file."))
    else:
        items.append(PreflightItem(
            WARN, "No Dockerfile found.",
            "The Dockerfile category will be N/A, and so will Java/JVM and "
            "cross-file unless the pod spec carries the JVM settings (this "
            "one does not). Include the service Dockerfile anywhere under "
            "the directory (any name matching Dockerfile* or *.dockerfile), "
            "set JAVA_TOOL_OPTIONS in the pod spec, or accept the reduced "
            "scope."))

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

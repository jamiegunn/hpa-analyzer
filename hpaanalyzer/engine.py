"""Analysis orchestration: base run + one variant run per values overlay.

Overlay variants exist because values-prod.yaml is usually the file that
actually reaches production; analyzing only values.yaml and calling it a
day is how a prod-only regression (dropped limits, latest tag, disabled
probes) sails through review. Each overlay is deep-merged over the base
(helm mode: re-rendered with -f) and the resource/HPA/JVM checks re-run;
findings NEW relative to the base run are reported, labeled with the
overlay file.
"""

import copy
import os
from typing import List, Optional

from . import (checks_chart, checks_docker, checks_hpa, checks_workload,
               proofs)
from .discovery import discover, helm_parse_output, scrub_parse_templates
from .helmrender import render_chart
from .helmyaml import deep_merge
from .models import AnalysisResult, ChartContext, Finding


def analyze(target: str, helm_mode: str = "auto",
            assume_java: Optional[str] = None) -> AnalysisResult:
    ctx = discover(target, helm_mode=helm_mode, assume_java=assume_java)
    result = AnalysisResult(context=ctx)
    for module in (checks_chart, checks_workload, checks_hpa, checks_docker,
                   proofs):
        module.run(ctx, result)
    _overlay_variants(ctx, result)
    return result


def _variant_ctx(ctx: ChartContext, overlay: str) -> Optional[ChartContext]:
    overlay_vals = ctx.values_files.get(overlay)
    if not isinstance(overlay_vals, dict):
        return None
    vctx = copy.copy(ctx)
    vctx.parse_errors = []
    vctx.coverage = []
    vctx.values = deep_merge(ctx.values, overlay_vals)
    vctx.docs = []

    if ctx.render_mode == "helm" and ctx.chart_dir_abs:
        overlay_abs = os.path.join(ctx.root, overlay)
        output, err = render_chart(ctx.chart_dir_abs,
                                   extra_values=[overlay_abs])
        if output is not None:
            vctx.docs = helm_parse_output(vctx, output)
            return vctx
        # fall through to static merge on render failure
    vctx.docs = scrub_parse_templates(vctx, record_coverage=False,
                                      record_errors=False)
    return vctx


def _overlay_variants(ctx: ChartContext, result: AnalysisResult) -> None:
    if not ctx.overlay_values:
        return
    base_keys = frozenset((f.rule_id, f.file) for f in result.findings)
    for overlay in ctx.overlay_values:
        vctx = _variant_ctx(ctx, overlay)
        if vctx is None:
            continue
        vres = AnalysisResult(context=vctx)
        checks_workload.run(vctx, vres)
        checks_hpa.run(vctx, vres)
        proofs.run(vctx, vres)          # findings only; tables are discarded
        added = 0
        seen_here = set()               # dedupe within THIS overlay only -
        for f in vres.findings:         # two overlays may share a regression
            key = (f.rule_id, f.file)
            if key in base_keys or key in seen_here:
                continue
            seen_here.add(key)
            f.detail = f"[with values overlay {overlay}] {f.detail}"
            result.add(f)
            added += 1
        ctx.coverage.append(
            [overlay, f"variant analyzed - {added} additional finding(s) "
                      f"vs base values"])

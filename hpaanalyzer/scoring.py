"""Weighted category scoring."""

from typing import Dict, List, Optional, Tuple

from .models import AnalysisResult, Category, Finding

# Category weights (sum is irrelevant; normalized over applicable categories)
WEIGHTS: Dict[Category, int] = {
    Category.RESOURCES:  15,
    Category.HPA:        15,
    Category.JAVA:       14,
    Category.CROSS:      14,
    Category.PROBES:     10,
    Category.DOCKERFILE:  8,
    Category.AVAIL:       8,
    Category.SECURITY:    7,
    Category.TEMPLATES:   5,
    Category.CHART:       4,
}


def grade(score: float) -> str:
    if score >= 97: return "A+"
    if score >= 93: return "A"
    if score >= 90: return "A-"
    if score >= 87: return "B+"
    if score >= 83: return "B"
    if score >= 80: return "B-"
    if score >= 77: return "C+"
    if score >= 73: return "C"
    if score >= 70: return "C-"
    if score >= 60: return "D"
    return "F"


def category_scores(result: AnalysisResult) -> List[Tuple[Category, Optional[float], List[Finding]]]:
    ctx = result.context
    has_docker = bool(ctx.dockerfiles)
    has_docs = bool(ctx.docs)
    has_workloads = bool(ctx.workloads)
    any_input = bool(ctx.chart_yaml_path or ctx.values_files
                     or ctx.template_files or ctx.dockerfiles)
    out = []
    for cat in Category:
        applicable = True
        if cat in (Category.JAVA, Category.DOCKERFILE) and not has_docker:
            applicable = False
        elif cat is Category.CROSS and not (has_docker and has_workloads):
            applicable = False
        elif cat in (Category.TEMPLATES, Category.RESOURCES, Category.HPA,
                     Category.AVAIL, Category.PROBES) and not has_docs:
            applicable = False
        elif cat is Category.SECURITY and not (has_docs or has_docker):
            applicable = False
        elif cat is Category.CHART and not any_input:
            applicable = False
        findings = [f for f in result.findings if f.category is cat]
        if not applicable:
            out.append((cat, None, findings))
            continue
        score = 100.0
        for f in findings:
            score -= f.effective_deduction()
        out.append((cat, max(0.0, score), findings))
    return out


def overall_score(result: AnalysisResult) -> Optional[float]:
    """Weighted mean over applicable categories.

    Returns None when there was nothing gradeable (e.g. an empty or
    unrelated directory) - an absence of analyzable input must never be
    reported as a passing grade.
    """
    if result.context.ungradeable_reason:
        return None
    cats = category_scores(result)
    num = den = 0.0
    for cat, score, _ in cats:
        if score is None:
            continue
        w = WEIGHTS[cat]
        num += w * score
        den += w
    return num / den if den else None

"""Weighted category scoring, and the coverage denominator that makes it readable.

WHAT THE SCORE IS
-----------------
Each of the ten categories starts at 100 and loses points per finding
(CRITICAL -25, HIGH -12, MEDIUM -6, LOW -3, INFO -0, floored at 0). The
overall score is the WEIGHTED MEAN of the categories that were assessed.

So the number is a weighted count of what this tool found. It is NOT an
estimate of risk, and it is NOT a probability that the service will hold up
in production. A chart can score 100 and fall over, because the tool only
subtracts for the specific things it knows how to look for.

WHY THE DENOMINATOR IS PART OF THE ANSWER (R5)
----------------------------------------------
A category that cannot be assessed is dropped from the mean - both numerator
and denominator. That is the only honest arithmetic available (see below),
but it has a consequence that the pre-R5 report did not state, and that its
own scorecard footer actively denied by calling excluded categories "not free
points":

    Removing an input file changes the score, in EITHER direction, without
    any Kubernetes manifest changing at all.

Measured, by deleting the Dockerfile from three fixtures and re-running with
the Kubernetes templates byte-identical (re-measured at R8; see below):

    fixtures/good-chart      100.0 A+  ->  100.0 A+   ( +0.0)   7/10 assessed
    fixtures/sidecar-chart    88.7 B+  ->   87.7 B+   ( -1.0)   9/10 assessed
    fixtures/bad-chart        45.5 F   ->   49.9 F    ( +4.4)   7/10 assessed

bad-chart gains 4.4 points for deleting a file. Nothing was fixed. JAVA,
DOCKERFILE and CROSS - the three categories where that chart was scoring
worst - left the mean, and the remaining categories, which happened to
average higher, were renormalised over a smaller weight. The direction of
the move depends only on whether the dropped categories sat above or below
the mean of the ones that stayed. Which way a given chart moves is not
something a reader can predict, and before R5 nothing in the output told
them the two numbers were computed over different category sets at all.

R8 shrank the effect where it was an artefact rather than a fact, in both
rows that moved, and for two different reasons.

The sidecar-chart row read -5.0 when this was written and reads -1.0 now,
because deleting its Dockerfile no longer drops JAVA and CROSS: that chart's
pod spec sets JVM options itself, so the heap-vs-limit analysis still has
everything it needs and only the image-level DOCKERFILE category leaves the
mean.

The bad-chart row read +6.3 and reads +4.4 now, and the 1.9 points did not
come from the categories that leave - they come from a finding that used to
disappear with the file. PB004 (liveness with no startupProbe) was gated on
`ctx.dockerfiles`, so deleting the Dockerfile silently deleted a HIGH from a
category that stayed in the denominator. Removing that gate means the
without-Dockerfile run now scores the probe defect it always had, and the
gap narrows. That is worth stating precisely, because it is the difference
between the two halves of the residue: part of this move is honest (JAVA
and DOCKERFILE really cannot be assessed with no image evidence) and part
of it was fabricated (a probe finding vanishing for a reason that had
nothing to do with probes). R8 removed the fabricated part; what is left is
the honest part.

So bad-chart still moves +4.4, and THAT is not a defect to be fixed:
nothing outside its Dockerfile says a JVM is involved, so with the file gone
there genuinely is no JVM evidence left to grade. The residue is real, and
the fix for it stays the same - print the denominator, never impute a value.

WHY NOT IMPUTE A VALUE INSTEAD
------------------------------
The tempting fixes are all fabrications:

  - Score an unassessed category 100: invents a clean bill of health for
    something never looked at. This is exactly the failure C2.2 forbids.
  - Score it 0: invents findings that were never made, and punishes a chart
    that legitimately ships no Dockerfile.
  - Score it at the mean of the others: asserts the unseen resembles the
    seen, which is the assumption the whole tool exists to avoid.

There is no honest number for "not looked at". So the mean stays over the
assessed categories, and the FIX is to stop hiding the denominator: every
place that prints the score also prints what it was computed over. A reader
must not be able to put 45.5 next to 51.8 without seeing that the second was
a mean over seven categories and the first over ten.

C2.2, one level up: an unassessed category must not silently contribute
zero - and must not silently contribute nothing, either.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .kube import JVM_EVIDENCE_INPUTS, jvm_evidence
from .models import AnalysisResult, Category, Finding

# Category weights (sum is irrelevant; normalized over assessed categories)
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

WEIGHT_TOTAL = sum(WEIGHTS.values())


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


def unassessed_reason(cat: Category, ctx) -> Optional[str]:
    """Why this category cannot be scored, or None if it can.

    The reason is returned rather than a bare boolean because the reason is
    what the reader needs: "no score" is not actionable, "no Dockerfile was
    found under the target" tells them whether that is expected.
    """
    has_docker = bool(ctx.dockerfiles)
    has_docs = bool(ctx.docs)
    has_workloads = bool(ctx.workloads)
    has_jvm = bool(jvm_evidence(ctx))
    any_input = bool(ctx.chart_yaml_path or ctx.values_files
                     or ctx.template_files or ctx.dockerfiles)

    # R8: the denominator was the third place that answered "is this Java?"
    # with "is there a Dockerfile?", and it got both directions wrong.
    #
    #   A chart with no Dockerfile but JAVA_TOOL_OPTIONS=-Xmx4g under a 2 GiB
    #   limit had JAVA and CROSS dropped from the mean - so even once the
    #   checks were fixed to FIND the OOMKill, a CRITICAL finding moved the
    #   score by exactly zero.
    #
    #   A pure nginx chart that shipped a file named Dockerfile had JAVA
    #   assessed, found nothing to deduct, and scored it 100.0 A+ - which is
    #   the first fabrication this module's own docstring forbids: "invents a
    #   clean bill of health for something never looked at".
    #
    # DOCKERFILE really is a property of the file. JAVA and CROSS are
    # properties of the workload, and they now ask the one evidence function
    # the checks ask, so the score and the findings cannot drift apart again.
    if cat is Category.DOCKERFILE and not has_docker:
        return "no Dockerfile was found under the target"
    if cat is Category.JAVA and not has_jvm:
        return ("nothing in this chart indicates a JVM workload; examined "
                + JVM_EVIDENCE_INPUTS)
    if cat is Category.CROSS and not (has_jvm and has_workloads):
        if not has_jvm and not has_workloads:
            return ("needs a JVM workload and Kubernetes workload objects to "
                    "compare it against; neither was found")
        if not has_jvm:
            return ("nothing indicates a JVM workload, so there is no heap to "
                    "compare against the limits; examined "
                    + JVM_EVIDENCE_INPUTS)
        return ("no workload objects (Deployment/StatefulSet/...) to compare "
                "the JVM configuration against")
    if cat in (Category.TEMPLATES, Category.RESOURCES, Category.HPA,
               Category.AVAIL, Category.PROBES) and not has_docs:
        return "no Kubernetes objects were parsed from the templates"
    if cat is Category.SECURITY and not (has_docs or has_docker):
        return "neither Kubernetes objects nor a Dockerfile were available"
    if cat is Category.CHART and not any_input:
        return "no chart, values, template or Dockerfile input was found"
    return None


def category_scores(result: AnalysisResult) -> List[Tuple[Category, Optional[float], List[Finding]]]:
    """(category, score or None if unassessed, findings) for every category."""
    ctx = result.context
    out = []
    for cat in Category:
        findings = [f for f in result.findings if f.category is cat]
        if unassessed_reason(cat, ctx) is not None:
            out.append((cat, None, findings))
            continue
        score = 100.0
        for f in findings:
            score -= f.effective_deduction()
        out.append((cat, max(0.0, score), findings))
    return out


@dataclass(frozen=True)
class Coverage:
    """What the overall score was computed over.

    Carried alongside the score everywhere it is printed. `complete` is the
    only case in which two scores from different runs are directly
    comparable, and even then only if the render mode matched.
    """
    assessed: List[Category]
    unassessed: List[Tuple[Category, str]]
    weight_assessed: int

    @property
    def weight_total(self) -> int:
        return WEIGHT_TOTAL

    @property
    def complete(self) -> bool:
        return not self.unassessed

    @property
    def n_assessed(self) -> int:
        return len(self.assessed)

    @property
    def n_total(self) -> int:
        return len(self.assessed) + len(self.unassessed)

    def one_line(self) -> str:
        """The short form, for the terminal summary and the JSON note."""
        if self.complete:
            return (f"Scored over all {self.n_total} categories "
                    f"({self.weight_total} of {self.weight_total} weight).")
        names = ", ".join(c.name for c, _ in self.unassessed)
        return (f"Scored over {self.n_assessed} of {self.n_total} categories "
                f"({self.weight_assessed} of {self.weight_total} weight); "
                f"NOT assessed: {names}.")


def coverage(result: AnalysisResult) -> Coverage:
    """The denominator behind overall_score()."""
    ctx = result.context
    assessed: List[Category] = []
    unassessed: List[Tuple[Category, str]] = []
    weight = 0
    for cat in Category:
        reason = unassessed_reason(cat, ctx)
        if reason is None:
            assessed.append(cat)
            weight += WEIGHTS[cat]
        else:
            unassessed.append((cat, reason))
    return Coverage(assessed=assessed, unassessed=unassessed,
                    weight_assessed=weight)


def overall_score(result: AnalysisResult) -> Optional[float]:
    """Weighted mean over assessed categories.

    Returns None when there was nothing gradeable (e.g. an empty or
    unrelated directory) - an absence of analyzable input must never be
    reported as a passing grade.

    The value is only interpretable next to coverage(result); see the module
    docstring for why no value is imputed for the unassessed categories, and
    why the caller is required to print the denominator.
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

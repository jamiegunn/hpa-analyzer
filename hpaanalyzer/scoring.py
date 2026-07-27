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

import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .kube import (JVM_EVIDENCE_INPUTS, UNSCALABLE_KINDS, jvm_evidence,
                   scale_candidates, scale_class,
                   workload_resources_all_helper)
from .models import AnalysisResult, Basis, Category, Finding, Severity

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


_GRADE_ORDER = ["F", "D", "C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+"]

# Gate contradictions seen this process, so a sweep over fifteen charts does
# not print the same tool bug fifteen times. The set is keyed on the specific
# contradiction, not on the category, so two different ones both get said.
_GATE_WARNED = set()


def _warn_gate_contradiction(cat: Category, ids: str, reason: str) -> None:
    """Announce that a coverage gate disagreed with the findings, and lost.

    This is a defect in hpa-analyzer, not in the user's chart, so it does not
    become a Finding - deducting points from someone's score because the tool
    contradicted itself would be the tool charging the user for its own bug.
    It goes to stderr, where it is visible to whoever runs the tool and
    invisible to the report they hand to somebody else.

    Silence was the alternative and is worse: the backstop would quietly paper
    over gate bugs forever, and the next one would be found the same way this
    one was - by a fixture's score moving for no reason anyone could name.
    """
    key = (cat.name, ids)
    if key in _GATE_WARNED:
        return
    _GATE_WARNED.add(key)
    print(f"hpa-analyzer: internal inconsistency - the coverage gate for "
          f"{cat.value} reported it unassessable ({reason[:80]}...) while "
          f"{ids} already deducted from it. Keeping the category scored; the "
          f"findings are the measurement and the gate is only a prediction. "
          f"Please report this.", file=sys.stderr)


CRITICAL_GRADE_CAP = "C"


def overall_grade(result: AnalysisResult, score: Optional[float]
                  ) -> Tuple[str, Optional[str]]:
    """(grade, why it was capped or None) for the OVERALL score.

    R14, found by p14 running the corpus on defaults. c07 sets -Xmx3g inside a
    2 GiB limit. The tool detects it (XF001, CRITICAL, OBSERVED), prints the
    arithmetic, and states in its own prose that the container will be
    "OOM-killed ... typically under first real load". Then the front page of
    the same report says:

        GRADE B+  (87.8/100)

    Both numbers are arithmetically correct and together they are a lie. The
    weighted mean is doing exactly what a mean does: nine categories with
    nothing much wrong dilute the one category that says the process cannot
    start. A reader who skims the headline - which is what a headline is FOR -
    reads B+ and ships it.

    The fix is not to re-weight the mean until it produces a number someone
    likes; every version of that fabricates a measurement. It is to stop the
    LABEL from contradicting the findings underneath it. The score stays
    exactly what its docstring says it is - a weighted count of what was
    found - and the grade, which is the part that gets skimmed, is capped when
    the tool has asserted a certain failure. The cap is stated in the report
    with the findings that caused it, so it is a disclosed rule and not a
    hidden thumb on the scale.

    ASSUMED criticals do NOT cap. models.effective_deduction() already limits
    them to HIGH's weight on the grounds that the tool's own uncertainty must
    not sink a grade, and a cap that fired where the deduction does not would
    make the same finding weigh two different amounts in two places.
    """
    if score is None:
        return "-", None
    g = grade(score)
    hard = [f for f in result.findings
            if f.severity is Severity.CRITICAL and f.basis is not Basis.ASSUMED]
    if not hard:
        return g, None
    if _GRADE_ORDER.index(g) <= _GRADE_ORDER.index(CRITICAL_GRADE_CAP):
        return g, None          # already at or below the cap; nothing to do
    ids = ", ".join(sorted({f.rule_id for f in hard}))
    n = len(hard)
    # The counts below are read off THIS result, not written into the prose.
    # An earlier draft said "across ten categories, and nine of them being
    # clean"; on a chart where a category is unassessed that sentence is
    # simply false, and a sentence explaining a cap is the last place that can
    # afford an invented number.
    cov = coverage(result)
    hit = len({f.category for f in hard})
    return CRITICAL_GRADE_CAP, (
        f"capped at {CRITICAL_GRADE_CAP} from {g}: {n} CRITICAL "
        f"finding{'s' if n != 1 else ''} ({ids}) "
        f"{'assert' if n != 1 else 'asserts'} a failure this "
        f"chart will hit, and a grade above {CRITICAL_GRADE_CAP} would "
        f"contradict {'them' if n != 1 else 'it'}. The {score:.1f} is "
        f"unchanged - it is a weighted count of findings across "
        f"{cov.n_assessed} scored categor"
        f"{'ies' if cov.n_assessed != 1 else 'y'}, only {hit} of which "
        f"{'carry' if hit != 1 else 'carries'} a critical, and that dilution "
        f"is exactly why the mean cannot see this")


def not_applicable_reason(cat: Category, ctx) -> Optional[str]:
    """Why this category's SUBJECT cannot exist for this chart, or None.

    R16. The scoring model had two slots and needed three.

    `unassessed_reason` below answers "could the tool see enough to score
    this?". Answering it wrongly in the permissive direction is the
    fabrication this module's docstring names first - "invents a clean bill of
    health for something never looked at" - and R8, R11, R13 and R15 all
    closed one instance of it. R16 found an instance that neither existing
    answer fits.

    `checks_hpa._no_hpa()` returned in silence on a chart whose only workload
    was a DaemonSet, and the silence was CORRECT: an HPA cannot target a
    DaemonSet, so there is nothing to report. But nothing said so to the
    denominator, and a category with no findings scores 100.0 - so a chart
    containing no autoscaler and a workload that structurally cannot have one
    printed:

        | Horizontal Pod Autoscaling             | 100.0        | A+    | 15   |

    Fifteen weighted points of A+ for a question never asked.

    Filing it as unassessed is the tempting fix and it is also false. NOT
    ASSESSED is a statement about the TOOL - it was blind, and the reason
    string tells the reader what input would remove the blindness ("run with
    `helm` on PATH"). Here the tool was not blind. It read the templates,
    parsed the object, identified the kind, and holds a written reason in
    `kube.UNSCALABLE_KINDS` for why no HPA can target it. That is a
    conclusion, and filing a conclusion under "could not tell" throws away a
    fact the tool established and sends the reader looking for input that does
    not exist.

    So the discriminator, which is a test and not a licence:

        Can the tool state, from evidence it HOLDS, that the category's
        subject cannot exist for this chart? Then NOT APPLICABLE. Did it
        merely fail to FIND evidence? Then NOT ASSESSED.

    Applied honestly it rejects most candidates. DOCKERFILE, on a chart with
    no Dockerfile, is blind, not inapplicable: the image may be built from a
    Dockerfile living anywhere, and "I did not find one under the target" is
    the only claim this tool can make. JAVA is the same shape - a JVM inside
    an image the sandbox cannot pull is exactly the case it cannot rule out.
    CROSS with no memory limit is blind to a value that could exist; setting a
    limit makes the category scorable. All three stay NOT ASSESSED. Exactly
    one category qualifies today, and the fact that the test threw out three
    plausible candidates is the evidence that it is a test.

    ARITHMETICALLY the two are identical: both leave the mean, numerator and
    denominator together, because all three of the fabrications this module
    forbids are still fabrications for a category whose subject does not
    exist. Nothing new is invented here. The difference is entirely in what
    the report claims - a gap versus a result - and that difference is worth a
    branch because a reader who is told the tool could not see something will
    go and look for it.
    """
    if cat is not Category.HPA:
        return None
    # Condition 1, and it is the trap in this whole fix. `c22-cronjob-hpa` has
    # a CronJob AND an HPA pointing at it; HP042 fires, CRITICAL, -25. A
    # predicate keyed on workload kind alone would drop from the mean a
    # category that had just deducted from it - which is exactly the R14b bug,
    # re-committed one round after it was fixed. The backstop in coverage()
    # would catch it and print an internal-inconsistency warning, and relying
    # on a backstop to cover a bug you can see from here is not engineering.
    if ctx.hpas:
        return None
    cands = scale_candidates(ctx.docs)
    # Condition 2. No candidate objects at all is blindness, not inapplicability
    # - the templates may not have rendered - and the `not has_docs` branch in
    # unassessed_reason already owns that case.
    if not cands:
        return None
    # Condition 3. ONE scalable object is enough to make the question real; one
    # UNKNOWN object is enough to make the answer unknown (see kube.scale_class
    # - an Argo Rollout does expose /scale). Only an all-unscalable chart can
    # be answered from evidence in hand.
    if any(scale_class(d.kind) != "unscalable" for d in cands):
        return None
    seen: List[Tuple[str, str]] = []
    for d in cands:
        spelling = (d.kind or "").strip()
        why = UNSCALABLE_KINDS[spelling.lower()]
        if (spelling, why) not in seen:
            seen.append((spelling, why))
    if len(seen) == 1:
        spelling, why = seen[0]
        return (f"the only workload kind this chart deploys is {spelling}, and "
                f"{why} - so there is no scale subresource for an HPA to "
                f"target, and no change to the chart would create one")
    parts = "; ".join(f"{k} ({w})" for k, w in seen)
    return (f"no workload this chart deploys can be autoscaled - {parts} - so "
            f"there is no scale subresource for an HPA to target")


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
    # R13. Having a JVM and a workload is not sufficient: every rule in CROSS
    # compares the JVM's memory against limits.memory, so with no limit set
    # the category is empty by construction and scoring it yields the third
    # instance of the fabrication this module's docstring names. The predicate
    # lives beside the rules in proofs.py - see cross_no_limit_reason() for
    # why, and for the deliberate XF006 exception that keeps the category in
    # the mean when a real deduction IS available without a limit.
    if cat is Category.CROSS:
        from .proofs import cross_no_limit_reason   # local: import cycle
        nolimit = cross_no_limit_reason(ctx)
        if nolimit:
            return nolimit
    if cat in (Category.TEMPLATES, Category.RESOURCES, Category.HPA,
               Category.AVAIL, Category.PROBES) and not has_docs:
        return "no Kubernetes objects were parsed from the templates"
    # R16, the third of the three answers in kube.scale_class. An Argo
    # `Rollout` implements /scale, so a Rollout-only chart with no HPA has the
    # same defect HP002 exists to report - but this tool's kind lists have
    # never heard of it, and inventing "that CRD cannot autoscale" from a set
    # that does not mention it is the same fabrication pointed the other way.
    # It was scoring 100.0/A+, measured. What the tool actually has here is
    # ignorance of a specific, nameable kind, and NOT ASSESSED is precisely
    # the slot for that; the reason string names the kind so the reader can
    # answer it themselves in the ten seconds it takes.
    if cat is Category.HPA and has_docs and not ctx.hpas:
        cands = scale_candidates(ctx.docs)
        if cands and not any(scale_class(d.kind) == "scalable" for d in cands):
            unknown = sorted({(d.kind or "").strip() for d in cands
                              if scale_class(d.kind) == "unknown"})
            if unknown:
                return (f"this chart deploys no built-in scalable workload, and "
                        f"whether {', '.join(unknown)} implements the scale "
                        f"subresource is not something this tool knows; it is "
                        f"not scored either way")
    # Every container's requests/limits come from a `define` in a .tpl file
    # that this run did not expand. Scoring RESOURCES anyway yields 100.0 -
    # a full category of clean bill of health for a file that was never read,
    # which is the first fabrication this module's docstring forbids. The
    # sweep includes init containers, so this only fires when NOTHING in the
    # category was legible.
    if cat is Category.RESOURCES and has_docs and workload_resources_all_helper(ctx):
        return ("every container's resources come from a named template "
                "(include/template) whose body was not expanded; run with "
                "`helm` on PATH to score this category")
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
        # R16: two different reasons not to produce a number, and the
        # arithmetic is identical for both - see not_applicable_reason for why
        # the distinction is worth carrying anyway. Callers that need to tell
        # them apart ask coverage(), which is the one place that classifies.
        if (unassessed_reason(cat, ctx) is not None
                or not_applicable_reason(cat, ctx) is not None):
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
    # R16. A third bucket, and it is deliberately a third FIELD rather than a
    # flag on the entries of `unassessed`: every consumer that reads
    # `cov.unassessed` today is making a claim about the tool's blind spots,
    # and quietly widening that list to include categories the tool answered
    # completely would have put "hpa-analyzer could not assess this" under a
    # heading it had just disproved. New meaning, new field; the old field
    # keeps its old meaning exactly.
    not_applicable: List[Tuple[Category, str]] = field(default_factory=list)

    @property
    def weight_total(self) -> int:
        return WEIGHT_TOTAL

    @property
    def complete(self) -> bool:
        """No BLIND SPOTS: everything the tool could assess, it assessed.

        Deliberately unchanged by R16's third bucket, and the choice matters
        because `--require-coverage` gates on this. A DaemonSet-only chart has
        no HPA coverage and never can; failing a build over that would be the
        gate demanding the user add an autoscaler to a DaemonSet, which is the
        advice this entire round exists to stop the tool giving. Use
        `all_scored` for the narrower "the mean really did run over all ten".
        """
        return not self.unassessed

    @property
    def all_scored(self) -> bool:
        """All ten categories produced a number. The only case where the
        weighted mean ran over the full 100 weight points, and therefore the
        only case where no denominator qualifier needs printing."""
        return not self.unassessed and not self.not_applicable

    @property
    def n_assessed(self) -> int:
        return len(self.assessed)

    @property
    def n_not_applicable(self) -> int:
        return len(self.not_applicable)

    @property
    def n_total(self) -> int:
        return (len(self.assessed) + len(self.unassessed)
                + len(self.not_applicable))

    def one_line(self) -> str:
        """The short form, for the terminal summary and the JSON note."""
        if self.all_scored:
            return (f"Scored over all {self.n_total} categories "
                    f"({self.weight_total} of {self.weight_total} weight).")
        head = (f"Scored over {self.n_assessed} of {self.n_total} categories "
                f"({self.weight_assessed} of {self.weight_total} weight)")
        parts = []
        if self.unassessed:
            parts.append("NOT assessed: "
                         + ", ".join(c.name for c, _ in self.unassessed))
        if self.not_applicable:
            parts.append("not applicable: "
                         + ", ".join(c.name for c, _ in self.not_applicable))
        return f"{head}; {'; '.join(parts)}."


def coverage(result: AnalysisResult) -> Coverage:
    """The denominator behind overall_score()."""
    ctx = result.context
    assessed: List[Category] = []
    unassessed: List[Tuple[Category, str]] = []
    weight = 0
    # R14b. A category that produced a finding was assessed, whatever any gate
    # believes. This is a backstop over unassessed_reason(), not a substitute
    # for it, and it exists because the gates keep getting this wrong in one
    # specific direction.
    #
    # The bug that put it here: R13's CROSS gate asks proofs.py whether any
    # JVM container sets limits.memory, reading the BASE context. bad-chart's
    # base values set none - but the analysis also runs each values overlay,
    # and under values-prod.yaml the limit is set and XF001/XF003 both fire.
    # The gate therefore dropped fourteen weight points of REAL deductions out
    # of the denominator, which raises the score of a chart with two critical
    # cross-file faults. That is the same fault R8 named ("invents a clean
    # bill of health") pointing the other way: not a clean category scored
    # 100, but a dirty category scored nothing at all.
    #
    # A gate answers "could this category have deducted?" - a prediction. The
    # findings answer "did it?" - a measurement. Where they disagree the
    # measurement wins, and the disagreement is never silent.
    # DEDUCTED from, not merely "has a finding". DF000 is an INFO whose whole
    # job is to say "no Dockerfile was found" - it is a coverage statement
    # worth 0 points, and it fires precisely on the charts where DOCKERFILE
    # genuinely cannot be assessed. A backstop keyed on findings rather than on
    # deductions kept DOCKERFILE in the denominator at 100.0/A+ on a chart with
    # no Dockerfile, which is the exact fabrication this module forbids. The
    # invariant is narrower and exactly right: no category that lost points may
    # be dropped from the mean that those points were subtracted from.
    scored_from = {f.category for f in result.findings
                   if f.effective_deduction() > 0}
    na: List[Tuple[Category, str]] = []
    for cat in Category:
        reason = unassessed_reason(cat, ctx)
        # R16: the new gate goes through the SAME backstop as the old one, and
        # not because it is expected to fire. not_applicable_reason's condition
        # 1 (no HPA object in the chart) already makes a deduction impossible -
        # HP0xx findings that deduct all require an HPA to exist. That is an
        # argument, and R14b exists precisely because an argument of that shape
        # was made once before, was correct about the base values, and was
        # wrong under a values overlay. A backstop that only guards the gates
        # you already distrust is not a backstop.
        na_reason = None if reason is not None else not_applicable_reason(cat, ctx)
        for r in (reason, na_reason):
            if r is not None and cat in scored_from:
                ids = ", ".join(sorted({f.rule_id for f in result.findings
                                        if f.category is cat
                                        and f.effective_deduction() > 0}))
                _warn_gate_contradiction(cat, ids, r)
                reason = na_reason = None
                break
        if reason is not None:
            unassessed.append((cat, reason))
        elif na_reason is not None:
            na.append((cat, na_reason))
        else:
            assessed.append(cat)
            weight += WEIGHTS[cat]
    return Coverage(assessed=assessed, unassessed=unassessed,
                    weight_assessed=weight, not_applicable=na)


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

"""Plain-text report renderer: scorecard, findings, proof tables, education."""

import re
import textwrap
from datetime import datetime
from typing import List

from . import __version__
from .kube import dockerfile_jvm_evidence, jvm_evidence
from .models import AnalysisResult, Basis, Severity
from .renderplan import capability_gates
from .scoring import (WEIGHTS, category_scores, coverage, grade, overall_grade,
                      overall_score)

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

def score_qualifier_lines(result) -> List[str]:
    """Everything that has to be printed NEXT TO the number, or not at all.

    Two qualifiers, both of which change what the number means:

    1. The category denominator. The overall score is a weighted mean over
       the categories that could be assessed; unassessed ones leave both
       halves of the fraction. Deleting a Dockerfile therefore moves the
       score with no Kubernetes manifest changing - measured at -1.0 on one
       fixture and +4.4 on another (scoring.py records the run). Two scores
       are comparable only when the assessed sets match.

    2. The evidence basis. Before R5 this tool printed
       `GRADE A+ (100.0/100)` for a chart helm had REFUSED to render, in
       byte-identical format to a grade earned from a real render. The same
       code knew how to print NOT GRADED elsewhere, so the machinery to
       withhold existed; it just was not used in the case where the reader
       would be misled. Withholding the grade here would be wrong too - the
       static findings are real - so the grade is printed WITH its basis
       attached rather than dressed up as something it is not.

    3. R9's UNDETERMINED verdicts. The budget table can now say "I cannot
       tell whether this JVM fits", and C2.5 forbids scoring that - the
       tool's ignorance is not the user's defect - so the number does not
       move. On `fixtures/good-chart` the result was a report whose page 3
       says UNDETERMINED and whose terminal block, the eleven lines almost
       every reader actually sees, said:

           GRADE A+  (100.0/100)   0 critical, 0 high, 0 medium, 0 low
           No critical or high findings.

       Both statements are true and together they are the pre-R9 defect
       exactly, moved one screen up: a categorical answer where the tool has
       none. Not scoring it was right; letting the summary imply a pass was
       not. So it is printed here, beside the number, in the same place the
       denominator and the render basis are - because "everything that has
       to be printed next to the number" is what this function is for, and
       an unanswerable question about whether the workload OOMs qualifies.

    Returns [] only when the score is over all ten categories AND came from
    a real helm render AND every JVM fit question was answerable; then there
    is nothing to qualify.
    """
    lines: List[str] = []
    cov = coverage(result)
    # R16: all_scored, not complete. `complete` means "no blind spots", which
    # a DaemonSet chart satisfies while its mean still runs over 85 weight
    # points and not 100 - and the denominator is the whole point of this line.
    if not cov.all_scored:
        lines.append(cov.one_line())
    mode = getattr(result.context, "render_mode", "static")
    if not mode.startswith("helm"):
        lines.append(f"Evidence: static template parsing, NOT a helm render "
                     f"({mode}) - see the coverage section.")
    lines.extend(undetermined_fit_lines(result))
    return lines


def undetermined_fit_lines(result) -> List[str]:
    """One line per container whose JVM fit the tool could not decide.

    Sourced from the coverage rows proofs.py writes rather than recomputed,
    so the summary cannot disagree with the table it is summarising. The
    range is echoed because "UNDETERMINED" on its own invites the reader to
    assume the tool is being coy about a small doubt; `722 MiB - 1.2 GiB`
    against a 1 GiB limit tells them the doubt spans the answer.
    """
    out: List[str] = []
    for row in getattr(result.context, "coverage", []) or []:
        if not (str(row[0]).startswith("JVM memory fit")
                and "UNDETERMINED" in str(row[1])):
            continue
        who = str(row[0])[len("JVM memory fit - "):] or "this container"
        # The range is `722 MiB-1.2 GiB` - a value with a space inside it, on
        # both sides of a hyphen. A first draft ended the capture at `\S+`
        # and printed "model range 722", which is not a range, is not a
        # quantity, and is the one number in the sentence that means nothing
        # on its own. Anchored on the following clause instead.
        m = re.search(r"the limit (.+?) lies inside the model's range "
                      r"(.+?), so ", str(row[1]))
        span = f" (limit {m.group(1)} vs model range {m.group(2)})" if m else ""
        # The remedy is taken from the row too, for the same reason the range
        # is: after a partial `--measured` run the flags that would settle it
        # are not the ones a canned sentence would name. proofs.py computes
        # that list from the components still estimated; repeating the
        # computation here would be a second place for it to drift.
        f = re.search(r"re-run with --measured (\S+)\s*$", str(row[1]))
        how = f" Settle it with `--measured {f.group(1)}`." if f else \
            " Settle it by measuring the non-heap components (--measured)."
        out.append(f"JVM fit UNDETERMINED{span} for {who} - not scored, "
                   f"and NOT a pass.{how}")
    return out


def render_mode_paragraphs(ctx) -> List[str]:
    """What the reader must know about WHERE these facts came from.

    Three states, not two. Before R4 the report had only "helm rendered it"
    and "helm did not render it", and the second one always ended with
    "Install helm on PATH and re-run" - which is excellent advice when helm
    is missing and actively misleading when helm is installed, ran, and
    refused the chart because its declared kubeVersion excludes helm's
    compiled-in default (v1.20.0 on helm 3; a recent release on helm 4 -
    measured into ctx.helm_default_version). That reader installs helm twice
    and gets the same report, because the thing to fix was never the missing
    binary.
    """
    out: List[str] = []
    if ctx.render_mode == "helm":
        at = ctx.render_kube_version
        if at:
            out.append(
                f"Mode: `helm template --kube-version {at}` rendered the chart "
                f"with its real template engine, so conditional logic, loops "
                f"and helpers are evaluated exactly as a deploy would. "
                f"Manifests below are rendered truth FOR A {at} CLUSTER - "
                f"`.Capabilities.KubeVersion` was answered for that version "
                f"and no other. Why {at}: {ctx.render_version_reason}. "
                f"Pass --kube-version to render for the cluster you actually "
                f"run.")
        else:
            default = getattr(ctx, "helm_default_version", None)
            named = (f"its compiled-in default of v{default} (measured from "
                     f"the installed helm)" if default else
                     "its compiled-in default (v1.20.0 on helm 3, newer on "
                     "helm 4; measuring it from this binary failed)")
            out.append(
                "Mode: `helm template` rendered the chart with its real "
                "template engine, but NO --kube-version could be derived "
                f"({ctx.render_version_reason or 'chart declares no kubeVersion'}), "
                f"so helm used {named} - a constant of the binary, not a "
                "fact about your cluster. Any `.Capabilities` test in these "
                "templates was answered for that version. Pass "
                "--kube-version to fix that.")
        out.append(
            "Templates that do not render with these values were additionally "
            "analyzed statically and are labeled 'conditional' wherever they "
            "appear.")
        # The one capability `--kube-version` does NOT control. Stated here
        # rather than only in CH016 because it qualifies the phrase "rendered
        # truth" three lines above, and a qualification the reader meets 200
        # lines later has already failed.
        gates = capability_gates(ctx.template_raw)
        if gates:
            gvs = sorted({g for _p, _l, g in gates if g})
            out.append(
                f"One capability was NOT answered for {at or 'that version'}: "
                f"this chart branches on `.Capabilities.APIVersions` in "
                + ", ".join(sorted({p for p, _l, _g in gates}))
                + (f" (querying {', '.join(gvs)})" if gvs else "")
                + ". Under `helm template` that set is the group/versions "
                  "compiled into the helm binary, identical at every "
                  "--kube-version and matching no real cluster, and "
                  "`--api-versions` can only add to it. The arm helm took is "
                  "therefore not evidence about your cluster and the other arm "
                  "was never analyzed. See CH016.")
        div = ctx.render_divergence
        if div and div.get("checked") and div.get("diverges"):
            only_at = ", ".join(div.get("only_at") or []) or "(none)"
            only_probe = ", ".join(div.get("only_at_probe") or []) or "(none)"
            out.append(
                f"This chart does NOT emit the same objects across its own "
                f"declared range: at {div['at']} it emits {only_at} which it "
                f"does not emit at {div['probe']}, and at {div['probe']} it "
                f"emits {only_probe} which it does not emit at {div['at']}. "
                f"This report describes the {div['at']} render. See CH015.")
        elif div and div.get("checked"):
            out.append(
                f"Cross-checked: rendering at {div['probe']} (the bottom of "
                f"the chart's declared range) emits the same "
                f"{div['n_probe']} object(s), so this report's object set does "
                f"not depend on which end of the range was chosen.")
        elif div and not div.get("checked"):
            out.append(
                f"NOT cross-checked: the second render at {div.get('probe')} "
                f"failed ({div.get('error')}), so whether this chart emits the "
                f"same objects across its declared range is unknown - not "
                f"confirmed.")
        return out

    # --- static ----------------------------------------------------------
    out.append(
        f"Analysis mode: {ctx.render_mode}. Templates were parsed with "
        "Go-template expressions scrubbed and, where possible, resolved from "
        "values.yaml, WITHOUT executing helm. Conditional blocks are analyzed "
        "as if taken; complex expressions (tpl, printf, required, subcharts) "
        "are beyond static resolution and files that failed to parse produced "
        "no findings at all - the coverage section lists every such gap.")
    if not ctx.helm_present:
        out.append(
            "helm is not on PATH. Installing it and re-running upgrades this "
            "report to rendered-truth analysis, which materially improves "
            "precision.")
    elif ctx.helm_error:
        out.append(
            f"helm IS installed - installing it again will not change this "
            f"report. It ran and refused the chart: {ctx.helm_error}."
            + _helm_refusal_advice(ctx))
    else:
        out.append(
            "helm is installed but was not used for this run (--helm off, or "
            "no chart directory was found).")
    return out


def _helm_refusal_advice(ctx) -> str:
    """What to actually do about a helm render failure.

    R15. This used to be one canned sentence appended to every refusal: "the
    usual cause is that helm defaults to a v1.20.0 cluster ... re-run with an
    explicit --kube-version matching your cluster, e.g. `--kube-version
    1.31.0`". It was wrong in two different ways at once.

    It was wrong when the refusal had nothing to do with kubeVersion - a
    `required` on an unset value, a template syntax error, a missing subchart
    - because it then explained a cause that was not the cause, and the reader
    who follows advice about a diagnosis they were handed confidently is not
    the one who made the mistake.

    And it was wrong in the case it was written for. The version in the
    example was interpolated from the run's own `--kube-version`, so a run
    invoked with `--kube-version 1.31.0` ended with the tool telling its
    operator to re-run with `--kube-version 1.31.0`. Advice generated without
    reading the arguments it is advising about will eventually advise doing
    the thing that was already done; here it did so in the one case where the
    operator had done everything right and the CHART was at fault.
    """
    err = ctx.helm_error or ""
    supplied = getattr(ctx, "kube_version_override", None)
    is_kubeversion = "kubeVersion" in err and "incompatible" in err

    if not is_kubeversion:
        return (" That is not a kubeVersion problem - the message above names "
                "the actual cause. Reproduce it directly with `helm template "
                "release-name <chart>` and fix what it names; no flag of this "
                "analyzer will change it.")

    if supplied:
        return (f" You already supplied `--kube-version {supplied}`, so this "
                f"is not helm's default-cluster behaviour: the chart's own "
                f"kubeVersion constraint genuinely excludes the cluster you "
                f"named. Either that constraint is stale and should be widened "
                f"in Chart.yaml, or this chart is not meant for a "
                f"{supplied} cluster. This analyzer cannot decide which - but "
                f"note that helm will refuse the real `helm install` for the "
                f"same reason, so this is not a reporting artefact.")

    default = getattr(ctx, "helm_default_version", None)
    cluster = (f"a v{default} cluster (its compiled-in default, measured "
               f"from the installed binary)" if default else
               "its compiled-in default cluster (v1.20.0 on helm 3, a recent "
               "release on helm 4)")
    return (f" The usual cause is that, given no --kube-version, helm "
            f"renders for {cluster} and enforces the chart's own kubeVersion "
            f"against it, so a chart whose declared range excludes that "
            f"default is refused even though it may be fine on your real "
            f"cluster. Re-run with `--kube-version` set to the version of "
            f"the cluster you deploy to.")


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
        g_capped, cap_why = overall_grade(result, score)
        L.append(f"  GRADE {g_capped}  ({score:.1f}/100)   "
                 f"{counts[Severity.CRITICAL]} critical, "
                 f"{counts[Severity.HIGH]} high, "
                 f"{counts[Severity.MEDIUM]} medium, {counts[Severity.LOW]} low")
        # The cap is never silent. A grade the reader cannot reconcile with
        # the score beside it is worse than the uncapped grade was.
        if cap_why:
            L.append(_wrap(f"GRADE {cap_why}.", indent=2))
        # The denominator travels with the number. A score computed over
        # seven categories must not be readable as if it were computed over
        # ten - see scoring.py for the measured case where deleting a file
        # RAISED the score by 4.4 points.
        for line in score_qualifier_lines(result):
            L.append(f"  {line}")
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
        # C2.5: absence of a finding is not a claim of correctness. It is
        # nearly one when the tool has just said it cannot decide whether the
        # workload OOMs, so that case gets its own wording rather than the
        # clean-baseline one.
        L.append("  No critical or high findings"
                 + (" - but see the UNDETERMINED item above."
                    if undetermined_fit_lines(result) else "."))
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
    # R14. The OVERALL grade is capped by non-ASSUMED CRITICALs; the numeric
    # score is not. See scoring.overall_grade for why the mean cannot see a
    # single fatal finding, and why the label - not the arithmetic - is what
    # gets corrected. Per-category grades below stay uncapped.
    g, cap_why = overall_grade(result, score)
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
        # R8, fifth site. "Java version unknown" is a statement about a JVM
        # whose version could not be read. Printed against `FROM nginx:alpine`
        # it is instead a statement that there is a JVM here at all, which is
        # the invention half of R8 wearing a different hat - and it is the
        # FIRST line of the report, so it frames everything under it. Ask the
        # evidence function, not the filename: unknown version and no version
        # are different facts and the inventory has to distinguish them.
        if d.java_major:
            java = f"Java {d.java_major}" + (
                f"u{d.java_update}" if d.java_update and d.java_major == 8 else
                (f".0.{d.java_update}" if d.java_update and d.java_major != 8
                 else ""))
        elif dockerfile_jvm_evidence(d):
            java = "Java version unknown"
        else:
            java = "no JVM detected"
        inv.append(f"  dockerfile : {d.path}  [{java}"
                   f"{', ' + d.java_flavor if d.java_flavor else ''}]")
    # R8, thirteenth site - a gap rather than a wrong answer, and it survived
    # the first twelve because nothing here was false. The inventory is a list
    # of FILES, so on the chart whose JVM is declared in its pod spec and
    # nowhere else it said nothing about a JVM at all - while the same chart's
    # report went on to compute heap-vs-limit arithmetic and raise a CRITICAL.
    # The reader's first block has to state the finding that everything below
    # it rests on, and "which file was that in" is the wrong axis for a fact
    # that need not live in a file.
    _jev = jvm_evidence(ctx)
    _jtext = (_jev[0] if _jev else
              "none detected (checked pod-spec env, container image names, "
              "Dockerfile FROM/flags)")
    _jlines = textwrap.wrap(_jtext, width=WIDTH - 15) or [_jtext]
    inv.append(f"  jvm        : {_jlines[0]}")
    inv.extend(" " * 15 + ln for ln in _jlines[1:])
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
        cov = coverage(result)
        L.append("")
        # Never silent. A grade the reader cannot reconcile with the number
        # printed beside it is worse than the uncapped grade was.
        if cap_why:
            L.append(_wrap(f"GRADE {cap_why}.", indent=2))
            L.append("")
        L.append(_wrap(
            f"What this number is: a weighted count of what THIS TOOL found. "
            f"Each category starts at 100 and loses points per finding. It is "
            f"not an estimate of risk and not a prediction that the service "
            f"will hold up - a chart can score {100.0:.0f} and still fall over, "
            f"because only the things the tool knows how to look for can "
            f"subtract.", indent=2))
        L.append("")
        if cov.all_scored:
            L.append(f"  {'Computed over':<21} : all {cov.n_total} categories "
                     f"({cov.weight_total} of {cov.weight_total} weight points)")
        else:
            L.append(f"  {'Computed over':<21} : {cov.n_assessed} of "
                     f"{cov.n_total} categories ({cov.weight_assessed} of "
                     f"{cov.weight_total} weight points)")
            if cov.unassessed:
                L.append(f"  {'NOT assessed':<21} :")
                for cat, reason in cov.unassessed:
                    L.append(_wrap(f"{cat.value} - {reason}", indent=6))
            if cov.not_applicable:
                L.append(f"  {'NOT applicable':<21} :")
                for cat, reason in cov.not_applicable:
                    L.append(_wrap(f"{cat.value} - {reason}", indent=6))
            L.append("")
            # R16: the second sentence is about MISSING INPUT, and on a chart
            # whose only exclusion is "not applicable" there is no missing
            # input to add - saying so would send the reader looking for a
            # file that cannot exist. The first and last sentences are true of
            # both cases (the arithmetic is identical), so they always print.
            comparability = (
                "This score is therefore NOT comparable with a score computed "
                "over a different set of categories.")
            if cov.unassessed:
                comparability += (
                    " Adding the missing input can move it in either "
                    "direction, because the excluded categories leave the "
                    "numerator and the denominator together: on one of this "
                    "project's own fixtures, deleting the Dockerfile RAISED "
                    "the score by 4.4 points with every Kubernetes manifest "
                    "byte-identical.")
            else:
                comparability += (
                    " The excluded categories left the numerator and the "
                    "denominator together, which renormalises the rest - so "
                    "the number above is a mean over what is left, not a mean "
                    "over ten. No input would change that here; the exclusion "
                    "is a property of the chart, not a gap in the run.")
            comparability += " Compare runs only when these lists match."
            L.append(_wrap(comparability, indent=2))
            L.append("")
        for line in score_qualifier_lines(result):
            if line.startswith("Evidence:"):
                L.append("")
                L.append(_wrap(line, indent=2))
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
    elif undetermined_fit_lines(result):
        L.append("\n  No critical or high findings - but the JVM memory fit "
                 "below is UNDETERMINED, which is not the same as a pass.")
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
        L.append("")
        for para in render_mode_paragraphs(ctx):
            L.append(_wrap(para, indent=0))

    # ----- scorecard (all levels) ------------------------------------------
    L.append(sec("Scorecard by category"))
    cov = coverage(result)
    # R16: three states, three cells. Both blank-score states used to print the
    # same words, and one of them was a lie in the reader's favour - the tool
    # HAD assessed HPA on a DaemonSet chart, completely, and the answer was
    # "the question does not arise". Printing "not assessed" there tells a
    # reader to go find input that does not exist.
    na_cats = {c for c, _ in cov.not_applicable}
    rows = []
    for cat, cscore, cfind in category_scores(result):
        n_by_sev = ", ".join(
            f"{sum(1 for f in cfind if f.severity is s)}{s.label[0]}"
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                      Severity.LOW) if any(f.severity is s for f in cfind)) or "-"
        if cscore is None:
            cell = "not applicable" if cat in na_cats else "not assessed"
        else:
            cell = f"{cscore:5.1f}"
        rows.append([
            cat.value,
            cell,
            "-" if cscore is None else grade(cscore),
            str(WEIGHTS[cat]),
            n_by_sev,
        ])
    L.append(_table(["Category", "Score", "Grade", "Weight", "Findings (C/H/M/L)"], rows))
    if cov.unassessed:
        L.append("")
        L.append("  Why a category is 'not assessed':")
        for cat, reason in cov.unassessed:
            L.append(_wrap(f"{cat.value} - {reason}", indent=6))
    if cov.not_applicable:
        L.append("")
        L.append("  Why a category is 'not applicable' (asked and answered, "
                 "not skipped):")
        for cat, reason in cov.not_applicable:
            L.append(_wrap(f"{cat.value} - {reason}", indent=6))
    # The pre-R5 wording here was "N/A categories are excluded, not free
    # points". True as far as it went, and it left the reader believing
    # exclusion was safe. Exclusion RENORMALISES: the remaining categories
    # are re-weighted over a smaller denominator, which moves the score in
    # whichever direction the dropped categories sat relative to the rest.
    L.append(_wrap("\nScoring model: each category starts at 100; deductions "
                   "are CRITICAL -25, HIGH -12, MEDIUM -6, LOW -3, INFO -0, "
                   "floored at 0. Overall = weighted mean over the ASSESSED "
                   "categories only. An unassessed category is not scored 0 "
                   "and not scored 100 - there is no honest number for "
                   "'not looked at' - so it leaves the mean entirely, "
                   "numerator and denominator together. That renormalises "
                   "the rest, which is why the overall score above is "
                   "printed with the count it was computed over, and why two "
                   "scores are only comparable when those counts and these "
                   "N/A rows match. A 'not applicable' category leaves the "
                   "mean by the same arithmetic and for a different reason: "
                   "not that the tool could not look, but that the thing it "
                   "would have scored cannot exist for this chart - an HPA "
                   "has no scale subresource to attach to on a DaemonSet, and "
                   "no edit to the chart would give it one. Scoring that 100 "
                   "would have been a clean bill of health for a question "
                   "never asked."))

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
                "their output - it ran them and reports their own findings "
                "verbatim. Absent tools show an install command. Tools "
                "that need rendered manifests are skipped (with a reason) when "
                "helm is unavailable to render."))
            L.append(_wrap(
                "The Status column is NOT a re-reading of each tool's exit "
                "code. Two of these tools do not encode a verdict in their "
                "exit status at all: polaris exits 0 whether it found nothing "
                "or found danger, and kube-score exits 1 both when it dislikes "
                "a manifest and when it could not parse one. Status is derived "
                "from each tool's own printed tally instead, and the 'derived "
                "from' line under each tool names exactly which signal was "
                "read. The raw output is printed below each tool so you can "
                "check the transcription; long output is cut, and where it is "
                "cut the excerpt says how many lines were dropped - the "
                "tallies are computed over the full output, so counting the "
                "excerpt alone will undercount."))
            L.append(_wrap(
                "Status is three-state on purpose. UNKNOWN means the validator "
                "ran and could not reach a verdict - most often because it "
                "could not fetch a schema - and is NOT a failure of your "
                "chart. Reading a non-zero exit as FAIL would tell you your "
                "manifests are broken when nothing was actually checked."))
            xrows = []
            for e in external:
                if not e.installed:
                    status = "not installed"
                elif not e.ran:
                    status = "skipped"
                else:
                    status = e.verdict
                summary = e.summary
                if e.indeterminate and e.indeterminate_why:
                    summary = f"{summary}  [{e.indeterminate_why}]"
                xrows.append([e.name, status, summary])
            L.append("")
            L.append(_table(["Tool", "Status", "Result / reason"], xrows))
            for e in external:
                if e.ran and e.verdict_basis:
                    L.append(_wrap(f"{e.name} status derived from: "
                                   f"{e.verdict_basis}", indent=2))
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
            L.append(_education(jvm_evidence(ctx)))

    # ----- methodology (all levels) ----------------------------------------
    L.append(sec("Methodology and limitations"))
    mode_para = " ".join(render_mode_paragraphs(ctx)) + " "
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

def _education(jvm_ev=None) -> str:
    """The reference appendix. `jvm_ev` is jvm_evidence(ctx) for the chart
    being reported on, or None/empty when nothing in it indicates a JVM.

    R8, twelfth site, and the only one where the remedy is NOT to remove the
    JVM material. Sections 6.2-6.4 are a manual, not a claim about the target:
    printing them does not assert that this chart runs Java. But four JVM
    chapters in a report about an nginx pod read as an assertion whether or
    not one was made, and the reader has no way to tell a reference chapter
    from a conclusion.

    Deleting them for non-JVM charts would be the wrong fix, and CLAIM 6 of
    proof/p8b_bar2.py is the reason: the reader this tool CANNOT detect - the
    opaque `corp.registry/payments-api:4.2` image with its flags baked in - is
    a Java operator whose report says "no JVM evidence". Withholding the heap
    arithmetic from exactly that person would turn an admitted blind spot into
    a withheld explanation. So the material stays and is labelled instead:
    reference, not finding, with the detection result stated so the reader can
    place it.
    """
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
    if not jvm_ev:
        E.append(_wrap(
            "[reference only - nothing in this chart indicates a JVM, so "
            "6.2-6.4 describe a runtime that was NOT detected here and no "
            "finding in this report rests on them. They are kept because a "
            "JVM whose flags are baked into an opaque image is invisible to "
            "this tool: if that is your workload, this is the arithmetic it "
            "would have checked.]", indent=2))
    else:
        E.append(_wrap(f"[applies to this chart - {jvm_ev[0]}]", indent=2))
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

"""Checks: HorizontalPodAutoscaler correctness and HPA<->workload interplay."""

import re
from typing import Any, Dict, List, Optional

from .helmyaml import enclosing_conditions, line_of, values_lookup
from .kube import (REPLICA_MANAGED_KINDS, UNSCALABLE_KINDS,
                   as_int, containers,
                   container_jvm_env_flags, doc_name,
                   helper_resources_ref, is_jvm_image, scale_candidates,
                   scale_class)
from .models import (AnalysisResult, Basis, Category, ChartContext, Finding,
                     ManifestDoc, Severity)
from .quantity import parse_cpu, parse_memory

_REPLICAS_LINE_RE = r"^\s{0,4}replicas\s*:"


def _classify_replicas_gate(conds) -> str:
    """'gated' | 'inverse' | 'other' | 'none' for the replicas field's guard."""
    if not conds:
        return "none"
    for c in conds:
        cl = str(c).lower()
        if re.search(r"autoscal|\bhpa\b|hpa\.", cl):
            negated = re.search(r"\bnot\b|\beq\b[^)]*\bfalse\b|\bne\b[^)]*\btrue\b", cl)
            return "gated" if negated else "inverse"
    return "other"


def run(ctx: ChartContext, result: AnalysisResult) -> None:
    hpas = ctx.hpas

    if not hpas:
        _no_hpa(ctx, result)
        return

    seen_targets: Dict[str, List[str]] = {}
    for hpa in hpas:
        name = doc_name(hpa)
        spec = hpa.data.get("spec") if isinstance(hpa.data, dict) else {}
        if not isinstance(spec, dict):
            continue
        target = _target_workload(ctx, spec)
        _replica_bounds(ctx, result, hpa, name, spec, target)
        _metrics(ctx, result, hpa, name, spec, target)
        _behavior(ctx, result, hpa, name, spec)
        _target_ref(ctx, result, hpa, name, spec, target, seen_targets)

    for target_key, hpa_names in seen_targets.items():
        if len(hpa_names) > 1:
            result.add(Finding(
                rule_id="HP010", severity=Severity.CRITICAL, category=Category.HPA,
                title="Multiple HPAs target the same workload", file="",
                detail=f"{', '.join(hpa_names)} all target {target_key}.",
                why="Two autoscalers issuing conflicting desired-replica values "
                    "fight each other; replica count oscillates.",
                fix="Keep exactly one HPA per workload."))

    _replicas_conflict(ctx, result)


def _add(result, **kw):
    result.add(Finding(**kw))


def _no_hpa(ctx, result):
    """HP001/HP002: a chart that could carry an HPA and does not.

    R16. Two things were wrong with the line below, and they are different
    faults with different fixes.

    It used to read `in ("deployment", "statefulset")` - a second, inline copy
    of a list that already exists as kube.SCALABLE_KINDS, and one that had
    drifted from it. SCALABLE_KINDS also contains `replicaset` and
    `replicationcontroller`, both of which implement the `scale` subresource
    and are therefore exactly what HP002 is about. A ReplicaSet chart with no
    autoscaler got silence. There is no argument for that; it is a copy that
    rotted, and the copy is deleted.

    CORRECTION, recorded rather than quietly fixed. The paragraph above was
    written first and claimed that swapping in SCALABLE_KINDS also recovered
    ReplicationController. It did not, and running the case is what showed it:

        kind                    HPA findings   HPA score
        ReplicaSet              ['HP002']           94.0
        ReplicationController   []                 100.0

    because the list this function was handed is `ctx.workloads`, whose own
    literal never mentions ReplicationController - so the RC document was
    filtered out one level ABOVE the bug being fixed here, and fixing the copy
    inside this function could not reach it. The same measurement turned up a
    third case the constant cannot answer at all: an Argo `Rollout` DOES expose
    /scale, is absent from both sets, and was likewise scoring 100.0. So the
    input is now `kube.scale_candidates(ctx.docs)` and the test is
    `kube.scale_class`, which has three answers instead of two. Two copies of a
    two-valued list were the visible fault; the fact underneath was never
    two-valued.

    The `return` is the second fault and it is subtler. On a chart whose only
    workload is a DaemonSet or a CronJob, silence here is RIGHT - telling an
    operator to put an HPA on a DaemonSet would be worse than saying nothing.
    But the same `return` was also, silently, the answer to a question nobody
    asked it: "was this category assessed?" It was not, and scoring.py went on
    to score the category 100.0 at weight 15 and print A+ for Horizontal Pod
    Autoscaling on a chart with no autoscaler in it. That decision does not
    belong here and is no longer made here - see scoring.not_applicable_reason,
    which asks the same question of the same constant and answers it in the one
    place that is entitled to.

    This is the sixth time a filter written to choose findings turned out to be
    choosing the denominator too (R8, R11, R13, R14b, R15 D4, and now this).
    """
    scalable = [d for d in scale_candidates(ctx.docs)
                if scale_class(d.kind) == "scalable"]
    if not scalable:
        return
    f_auto, auto_en = values_lookup(ctx.values, "autoscaling.enabled")
    if f_auto:
        detail = (f"values declare autoscaling.enabled={auto_en} but no "
                  f"HorizontalPodAutoscaler template exists in the chart.")
        sev = Severity.HIGH if auto_en else Severity.MEDIUM
        why = ("The values file promises autoscaling that the chart cannot "
               "deliver - a reviewer reading values.yaml is misled, and flipping "
               "the flag does nothing.")
        fix = "Add templates/hpa.yaml gated on .Values.autoscaling.enabled."
        if auto_en:
            why = ("autoscaling.enabled is TRUE but there is no hpa.yaml template "
                   "- the chart silently never scales.")
        _add(result, rule_id="HP001", severity=sev, category=Category.HPA,
             title="autoscaling values exist but no HPA template", file="",
             detail=detail, why=why, fix=fix)
    else:
        _add(result, rule_id="HP002", severity=Severity.MEDIUM, category=Category.HPA,
             title="No HPA (and no autoscaling values)", file="",
             detail="Chart deploys a scalable workload with a fixed replica count "
                    "and no HorizontalPodAutoscaler.",
             why="Fixed replicas must be sized for PEAK load and therefore waste "
                 "capacity off-peak - or are sized for average and fall over at "
                 "peak. An HPA sizes for now.",
             fix="Add an autoscaling/v2 HPA on CPU (target 60-75%) once resource "
                 "requests are set correctly.",
             math="Cost of fixed sizing: replicas_fixed = ceil(peak/target_per_pod)."
                  " With peak:offpeak = 4:1 you idle ~75% of capacity off-peak.")


# Scrub placeholders (helmyaml.scrub_template): a name containing any of these
# is NOT a resolvable literal - it depends on release-time values/helpers, so a
# textual "mismatch" against another scrubbed name proves nothing.
_TEMPLATE_MARKERS = ("HELM", "RELEASE-NAME", "RELEASE-NAMESPACE", "<")


def _is_resolvable_literal_name(rn: str) -> bool:
    """True when scaleTargetRef.name is a concrete name we can compare, i.e.
    NOT an unresolved template marker/placeholder. Only for these can a name
    that fails to match be trusted as a real mismatch (so the single-workload
    fallback must NOT paper over it)."""
    if not rn:
        return False
    return not any(m in rn for m in _TEMPLATE_MARKERS)


def _target_workload(ctx, spec) -> Optional[ManifestDoc]:
    ref = spec.get("scaleTargetRef")
    if not isinstance(ref, dict):
        return None
    rk, rn = str(ref.get("kind", "")).lower(), str(ref.get("name", ""))
    for w in ctx.workloads:
        if (w.kind or "").lower() == rk and (doc_name(w) == rn or rn.startswith("HELM")):
            return w
    # F3: single-workload fallback assumes the obvious pairing - but ONLY when
    # the name is a template marker we could not resolve. A resolvable literal
    # that matches nothing is a real dangling target (HP041), not a pairing to
    # guess; guessing here suppressed the true bug AND inverted the fix.
    if _is_resolvable_literal_name(rn):
        return None
    if len(ctx.workloads) == 1 and rk == (ctx.workloads[0].kind or "").lower():
        return ctx.workloads[0]
    return None


def _replica_bounds(ctx, result, hpa, name, spec, target):
    mn_raw, mx_raw = spec.get("minReplicas"), spec.get("maxReplicas")
    # N1: quoted numerics ('6') must not silently disable min/max checks.
    mn, mx = as_int(mn_raw), as_int(mx_raw)
    quoted = [f"{k}={v!r}" for k, v in
              (("minReplicas", mn_raw), ("maxReplicas", mx_raw))
              if isinstance(v, str) and as_int(v) is not None]
    if quoted:
        _add(result, rule_id="HP008", severity=Severity.HIGH, category=Category.HPA,
             title="HPA replica bound is a quoted string, not an integer",
             file=hpa.file,
             detail=f"HPA '{name}': {', '.join(quoted)} is a string. The API "
                    f"server requires integers for minReplicas/maxReplicas.",
             why="A quoted integer (often from `| quote` in a template) fails "
                 "server-side validation - `helm upgrade`/apply is rejected and "
                 "the HPA never takes effect. It also silently disabled this "
                 "tool's min/max sanity checks until now.",
             fix="Emit the value as a bare integer (drop the quotes / `| quote`).")

    if mx is None:
        _add(result, rule_id="HP003", severity=Severity.HIGH, category=Category.HPA,
             title="HPA missing maxReplicas", file=hpa.file,
             detail=f"HPA '{name}' has no maxReplicas (required field).",
             why="The API server rejects an HPA without maxReplicas.",
             fix="Set maxReplicas.")
    if isinstance(mn, int) and isinstance(mx, int):
        if mn > mx:
            _add(result, rule_id="HP004", severity=Severity.CRITICAL, category=Category.HPA,
                 title="HPA minReplicas > maxReplicas (invalid)", file=hpa.file,
                 detail=f"HPA '{name}': minReplicas={mn} > maxReplicas={mx}.",
                 why="Invalid object - the API server rejects it, so the workload "
                     "has NO autoscaling and helm upgrade fails.",
                 fix="Make min <= max.",
                 math=f"Constraint violated: {mn} <= {mx} is false.")
        elif mn == mx:
            _add(result, rule_id="HP005", severity=Severity.MEDIUM, category=Category.HPA,
                 title="HPA min == max (autoscaler cannot scale)", file=hpa.file,
                 detail=f"HPA '{name}': minReplicas = maxReplicas = {mn}.",
                 why="The HPA can only ever choose one value; you pay the "
                     "metrics-pipeline cost for zero elasticity.",
                 fix="Widen the band (e.g. min=2, max=3x expected peak need) or "
                     "delete the HPA.",
                 math=f"desired = clamp(ceil(current x usage/target), {mn}, {mx}) "
                      f"= {mn} for every possible usage.")
    if isinstance(mn, int) and mn < 2:
        _add(result, rule_id="HP006", severity=Severity.MEDIUM, category=Category.AVAIL,
             title="HPA minReplicas=1", file=hpa.file,
             detail=f"HPA '{name}': minReplicas={mn}.",
             why="At quiet times the HPA scales to a single pod: every voluntary "
                 "disruption or crash at min-scale is then a full outage, and "
                 "recovery requires a cold JVM start under rising load.",
             fix="minReplicas: 2 for anything user-facing.")
    if isinstance(mn, int) and isinstance(mx, int) and mx > mn and mx > 1 and mx / max(mn, 1) > 10:
        _add(result, rule_id="HP007", severity=Severity.LOW, category=Category.HPA,
             title="Very wide HPA range", file=hpa.file,
             detail=f"HPA '{name}': min={mn}, max={mx} ({mx//max(mn,1)}x).",
             why="A 10x+ band usually means requests were never right-sized; "
                 "check the cluster can actually schedule max pods "
                 "(max x request <= cluster headroom) or scaling silently stops "
                 "at Pending pods.",
             fix="Verify capacity: maxReplicas x cpu request and x memory request.")


def _metrics(ctx, result, hpa, name, spec, target):
    api_v1 = (hpa.api_version or "").startswith("autoscaling/v1")
    metrics = spec.get("metrics")
    tcup = spec.get("targetCPUUtilizationPercentage")

    metric_entries: List[Dict[str, Any]] = []
    if isinstance(metrics, list):
        metric_entries = [m for m in metrics if isinstance(m, dict)]

    if api_v1 and tcup is None and not metric_entries:
        _add(result, rule_id="HP020", severity=Severity.HIGH, category=Category.HPA,
             title="autoscaling/v1 HPA with no CPU target", file=hpa.file,
             detail=f"HPA '{name}' (autoscaling/v1) sets no "
                    f"targetCPUUtilizationPercentage.",
             why="Defaults to a cluster-level value (usually 80%) that nobody "
                 "chose for this app; the scaling behavior is undocumented and "
                 "environment-dependent.",
             fix="Migrate to autoscaling/v2 and set an explicit CPU utilization "
                 "target.")
    if not api_v1 and not metric_entries and tcup is None:
        _add(result, rule_id="HP021", severity=Severity.HIGH, category=Category.HPA,
             title="HPA has no metrics", file=hpa.file,
             detail=f"HPA '{name}' defines no metrics[].",
             why="Without metrics the controller defaults to 80% CPU - implicit, "
                 "surprising behavior.",
             fix="Define metrics explicitly.")

    # gather workload requests for utilization math
    req_cpu = req_mem = None
    helper_res: List[str] = []          # containers whose resources came from a .tpl
    if target:
        for c in containers(target):
            h = helper_resources_ref(c)
            if h is not None:
                helper_res.append(h)
                continue
            r = c.get("resources")
            if isinstance(r, dict) and isinstance(r.get("requests"), dict):
                req_cpu = req_cpu or parse_cpu(r["requests"].get("cpu"))
                req_mem = req_mem or parse_memory(r["requests"].get("memory"))

    targets_cpu = tcup is not None
    for m in metric_entries:
        mtype = str(m.get("type", "")).lower()
        if mtype == "resource":
            res = m.get("resource") if isinstance(m.get("resource"), dict) else {}
            rname = str(res.get("name", "")).lower()
            tgt = res.get("target") if isinstance(res.get("target"), dict) else {}
            avg_util = tgt.get("averageUtilization")
            if rname == "cpu":
                targets_cpu = True
                if isinstance(avg_util, int):
                    _cpu_target_quality(ctx, result, hpa, name, avg_util)
            if rname == "memory":
                _memory_metric(ctx, result, hpa, name, tgt, req_mem, target)
        # external/pods/object metrics: fine, no static validation

    if targets_cpu and target is not None and req_cpu is None and helper_res:
        # `req_cpu is None` has two causes and they are not interchangeable:
        # no cpu request was written, or a request may well be written inside a
        # named template this run never expanded. HP022 is a CRITICAL that says
        # the HPA will never scale; asserting that from an unread .tpl file
        # would be a guess wearing a fact's severity.
        _add(result, rule_id="HP032", severity=Severity.INFO, category=Category.HPA,
             title="HPA CPU target could not be checked against the workload's "
                   "request (resources come from a named template)",
             file=hpa.file,
             detail=f"HPA '{name}' scales on CPU utilization; the target "
                    f"workload's resources are supplied by "
                    + ", ".join(f'include "{h}"' for h in sorted(set(helper_res)))
                    + ", whose body was not expanded, so no cpu request was read.",
             why="If that template really sets no cpu request, this HPA never "
                 "scales at all (HP022 - utilization is usage/request, "
                 "undefined without one). The tool is not claiming that here: "
                 "it did not read the file, so it reports the gap instead of "
                 "the verdict.",
             fix=f"Run the same command with `helm` on PATH - the rendered "
                 f"path expands the template and this check applies normally.",
             basis=Basis.DERIVED)
    elif targets_cpu and target is not None and req_cpu is None:
        _add(result, rule_id="HP022", severity=Severity.CRITICAL, category=Category.HPA,
             title="HPA scales on CPU but target workload has no CPU request",
             file=hpa.file,
             detail=f"HPA '{name}' uses CPU utilization; the target workload's "
                    f"containers define no cpu request.",
             why="CPU 'utilization' is defined as usage / REQUEST. With no "
                 "request the controller cannot compute it: the HPA goes "
                 "ScalingActive=False with FailedGetResourceMetric and NEVER "
                 "scales. This is the single most common way an HPA silently "
                 "does nothing.",
             fix="Set resources.requests.cpu on every container in the pod "
                 "(the calculation averages across containers).",
             math="utilization% = 100 x usage_m / request_m; request_m = nil "
                  "=> undefined for the whole pod.")
    if isinstance(tcup, int):
        _cpu_target_quality(ctx, result, hpa, name, tcup)


def _cpu_target_quality(ctx, result, hpa, name, target_pct: int):
    if target_pct <= 0:
        _add(result, rule_id="HP026", severity=Severity.CRITICAL, category=Category.HPA,
             title=f"HPA CPU target {target_pct}% is invalid", file=hpa.file,
             detail=f"HPA '{name}' targets averageUtilization={target_pct}.",
             why="Utilization targets must be positive; the API server rejects "
                 "this object, so the workload has no autoscaling at all.",
             fix="Set a target between 1 and 100 (60-75 typical for JVMs).",
             math=f"desired = ceil(current x usage / {target_pct}) is "
                  f"undefined or divides by zero.")
        return
    if target_pct > 90:
        _add(result, rule_id="HP023", severity=Severity.HIGH, category=Category.HPA,
             title=f"HPA CPU target {target_pct}% leaves no scaling headroom",
             file=hpa.file,
             detail=f"HPA '{name}' targets averageUtilization={target_pct}%.",
             why="Scaling is not instantaneous: metrics lag (15-60s), pods "
                 "schedule, images pull, and a JVM warms up. During that window "
                 "existing pods must absorb the excess ABOVE the target. At "
                 f"{target_pct}% the buffer before saturation is only "
                 f"{100-target_pct}%.",
             fix="Target 60-75% for JVM services; lower if startup is slow.",
             math=f"Absorbable load growth while scaling = 100/{target_pct} - 1 "
                  f"= {100/target_pct - 1:.0%}. With a 90s JVM startup, load "
                  f"growing faster than {(100/target_pct - 1)*100:.0f}% per "
                  f"~2 min saturates pods before help arrives.")
    elif target_pct < 40:
        _add(result, rule_id="HP024", severity=Severity.LOW, category=Category.HPA,
             title=f"HPA CPU target {target_pct}% is very conservative", file=hpa.file,
             detail=f"HPA '{name}' targets averageUtilization={target_pct}%.",
             why=f"You provision 100/{target_pct} = {100/target_pct:.1f}x the CPU "
                 f"you actually use, at steady state, forever.",
             fix="60-75% is typical; keep low targets only for spiky, "
                 "latency-critical traffic.",
             math=f"Steady-state overprovision factor = 100/target = "
                  f"{100/target_pct:.2f}x.")


_NONJVM_IMAGE_HINTS = ("nginx", "redis", "postgres", "mysql", "mariadb",
                       "memcached", "haproxy", "envoy", "traefik", "busybox",
                       "alpine", "httpd", "rabbitmq", "mongo", "node:", "python:",
                       "golang", "/go:", "caddy")


def _target_is_jvm(ctx, target):
    """(is_jvm, basis) scoped to the HPA's ACTUAL target workload.

    R3: the old check was chart-global - one Java Dockerfile anywhere made
    EVERY memory-metric HPA a 'JVM ratchet' CRITICAL, even one targeting nginx.
    Prefer positive evidence on the target itself; only guess (ASSUMED) when
    the pairing is unambiguous.

    R8, eighth site, two separate defects:

    1. This module carried its own _JAVA_IMAGE_HINTS list - a second, drifted
       copy of the same knowledge kube._JVM_IMAGE_RE holds. It had no tomcat,
       jetty, wildfly or jboss, so a Tomcat HPA scaling on memory was a MEDIUM
       here while the JAVA category graded the same image as a JVM. Two
       answers to one question in one report is the defect R8 is about,
       whatever each answer is. It now calls the shared function; the
       NON-JVM list stays local because it answers a different question
       (positive evidence that this is something else) that kube.py does not.

    2. The tail returned `False, OBSERVED` - "we looked and it is not a JVM" -
       when nothing had been determined at all. That is C2.2: a limit of the
       method reported as a finding about the target. It picks the lenient
       MEDIUM branch AND stamps it with the tool's highest-confidence label.
       Undetermined is now its own answer, and the caller reports it as such.
    """
    if target is not None:
        for c in containers(target):
            img = str(c.get("image", "")).lower()
            if container_jvm_env_flags(c) or is_jvm_image(img):
                return True, Basis.OBSERVED
            if any(h in img for h in _NONJVM_IMAGE_HINTS):
                return False, Basis.OBSERVED
    jvm_dfs = [d for d in ctx.dockerfiles
               if d.java_major or d.java_opts or d.jvm_flags]
    # R17 measured it. R16 parked this copy with "widening it moves scores on
    # charts nobody has measured", which was the right call at the time and the
    # wrong guess about the direction. The defect is not that the finding fires
    # on too few charts - it is that the BASIS of the finding depends on the
    # kind of a workload that has nothing to do with the question.
    #
    # `len(scalable) <= 1` means "only one thing here, so the pairing is
    # obvious". With the inline pair, a second workload only counted if it was
    # a Deployment or a StatefulSet. Five charts, identical but for the kind of
    # a second workload that no HPA references:
    #
    #     one Deployment only      HP025 assumed
    #     + a second Deployment    HP025 derived     <- ambiguous, says so
    #     + a ReplicaSet           HP025 assumed     <- equally ambiguous
    #     + a Rollout              HP025 assumed     <-      "
    #     + a StatefulSet          HP025 derived
    #
    # ASSUMED is not a label, it is arithmetic: Finding.effective_deduction()
    # caps ASSUMED at HIGH, so the two spellings of the same ambiguity also
    # score differently. Rows 3 and 4 claim an obvious pairing on a chart with
    # two workloads. That is the tool inventing confidence out of a kind name.
    scalable = [w for w in ctx.workloads
                if (w.kind or "").lower() in REPLICA_MANAGED_KINDS]
    if jvm_dfs and len(scalable) <= 1:
        # single workload + a Java image: the obvious pairing, but a guess
        return True, Basis.ASSUMED
    return None, Basis.DERIVED


def _memory_metric(ctx, result, hpa, name, tgt, req_mem, target=None):
    is_jvm, jvm_basis = _target_is_jvm(ctx, target)
    avg_util = tgt.get("averageUtilization")
    # is_jvm is now three-valued: True, False, and None for "could not be
    # determined". None must not collapse into False - that would restore the
    # exact reading R8 removed, in which the tool's silence about the workload
    # is printed as a fact about the workload.
    sev = Severity.CRITICAL if is_jvm else Severity.MEDIUM
    if is_jvm:
        why = ("Memory-utilization HPA assumes memory falls when load falls. A "
               "JVM violates that assumption: committed heap stays at or near "
               "its high-water mark (most collectors return memory to the OS "
               "reluctantly or never), so measured 'utilization' stays high "
               "after load drops. Result: the HPA scales UP under load but "
               "never scales back DOWN - it ratchets to maxReplicas and stays "
               "there.")
    elif is_jvm is False:
        why = ("Memory-based scaling only works for workloads whose RSS tracks "
               "load closely and is released promptly - rare in practice.")
    else:
        why = ("Memory-based scaling only works for workloads whose RSS tracks "
               "load closely and is released promptly - rare in practice. This "
               "tool could not determine what this HPA targets, so it does not "
               "know whether that holds here; if the target is a JVM (or any "
               "runtime with a caching allocator) the failure is worse than "
               "MEDIUM - committed heap never falls, so the scale-down "
               "condition is unreachable and the HPA ratchets to maxReplicas.")
    math = None
    if isinstance(avg_util, int):
        math = (f"Example with Xmx-bound JVM: after warmup RSS ~= "
                f"heap_committed + off-heap ~= constant C. utilization = "
                f"C/request stays > {avg_util}% regardless of traffic => "
                f"desired = ceil(current x util/{avg_util}) >= current forever "
                f"(HPA tolerance +/-10%). Scale-down condition util < "
                f"{avg_util}% is unreachable.")
    assumes = None
    if is_jvm and jvm_basis is Basis.ASSUMED:
        assumes = ("the workload this HPA targets is the Java service (inferred "
                   "from a single workload + a Java Dockerfile; the HPA's target "
                   "was not resolvable by name)")
    elif is_jvm is None:
        # C2.2 / C2.3: name the gap where the reader meets the number, not
        # only in a coverage table three sections away. The severity below the
        # sentence is the lenient one, and the reader is entitled to know it
        # was picked in the absence of evidence rather than because of it.
        assumes = ("that the target is NOT a JVM-style workload - the HPA's "
                   "scaleTargetRef could not be resolved to a workload in this "
                   "chart, so nothing about the target was read; severity is "
                   "the non-JVM one for that reason, and would be CRITICAL if "
                   "the target turns out to be a JVM")
    basis = (jvm_basis if is_jvm else
             (Basis.OBSERVED if is_jvm is False else Basis.DERIVED))
    _add(result, rule_id="HP025", severity=sev, category=Category.HPA,
         title="HPA scales on memory" + (" for a JVM workload" if is_jvm else ""),
         file="", basis=basis, assumes=assumes,
         detail=f"HPA '{name}' includes a memory utilization/average-value metric"
                + (f" (target {avg_util}%)" if isinstance(avg_util, int) else "") + ".",
         why=why,
         fix="Scale JVMs on CPU or on a load-proportional metric (requests/sec "
             "via external metrics, queue depth). If memory must gate scaling, "
             "use it only as a secondary metric and remember HPA takes the MAX "
             "of all metric proposals - memory will dominate.",
         math=math)


def _behavior(ctx, result, hpa, name, spec):
    behavior = spec.get("behavior")
    if not isinstance(behavior, dict):
        _add(result, rule_id="HP030", severity=Severity.LOW, category=Category.HPA,
             title="No HPA behavior block (defaults apply)", file=hpa.file,
             detail=f"HPA '{name}' relies on default scaling behavior.",
             why="Defaults: scale-up may double pods every 15s (or +4 pods, "
                 "whichever is larger) with 0s stabilization; scale-down waits "
                 "300s. For slow-starting JVMs an aggressive default scale-up "
                 "adds many cold pods that all JIT-compile at once (CPU burst -> "
                 "even higher utilization -> more scaling: a warmup storm).",
             fix="Add behavior.scaleUp with a stabilizationWindowSeconds of "
                 "60-120s and/or policies limiting pods-per-minute; keep "
                 "scale-down conservative.")
        return
    sd = behavior.get("scaleDown") if isinstance(behavior.get("scaleDown"), dict) else {}
    if isinstance(sd.get("stabilizationWindowSeconds"), int) and sd["stabilizationWindowSeconds"] == 0:
        _add(result, rule_id="HP031", severity=Severity.MEDIUM, category=Category.HPA,
             title="scaleDown stabilization window is 0", file=hpa.file,
             detail=f"HPA '{name}': behavior.scaleDown.stabilizationWindowSeconds=0.",
             why="Zero stabilization lets the HPA remove pods the instant a "
                 "metric dips - flapping traffic then kills warm JVMs it will "
                 "need again 30 seconds later (and cold starts are the expensive "
                 "part).",
             fix="Use >= 300s (the default) for JVM workloads.")


def _target_is_out_of_scope(ctx, ref, hpa_name) -> bool:
    """True when 'no workload matches this ref' is a fact about where this
    tool looks, not a fact about the chart. Records why, and suppresses HP041.

    Two distinct situations, and neither is a defect in the user's chart:

      1. The target IS provided, by a subchart. `helm template` rendered it in
         the same run; the analyzer parks those objects in ctx.subchart_docs
         instead of grading them. The reference resolves. Saying it dangles is
         false - it was the pre-R7 behaviour and it cost the chart 12 points
         and shipped a fix instruction for a bug that was not there.

      2. Subcharts exist but none of their objects were visible - static mode
         renders nothing, and a subchart gated off by a condition emits
         nothing. Then the tool cannot tell 'this target is missing' from
         'this target is somewhere I did not read', and C2.2 is explicit about
         which of those it is allowed to print.

    Case 2 is the conservative half of the trade and it is worth naming: a
    genuinely dangling ref in an umbrella chart analysed statically now goes
    unreported. That is the correct direction to err - a false HIGH sends
    someone to edit correct code, while this leaves an itemised coverage row
    saying exactly which claim was not checked and why - but it IS a loss, so
    it is stated here and in the report rather than left for someone to find.

    A chart with no charts/ directory reaches neither branch: HP041 keeps
    firing exactly as it did, which is what CLAIM 4 of proof/p7_subcharts.py
    pins with a deliberately typo'd ref.
    """
    if not ctx.subcharts_present:
        return False
    rk = str(ref.get("kind", "")).lower()
    rn = str(ref.get("name", ""))
    key = f"{ref.get('kind')}/{ref.get('name')}"
    names = ", ".join(ctx.subchart_names) or "(unnamed)"

    for d in getattr(ctx, "subchart_docs", []):
        if (d.kind or "").lower() != rk:
            continue
        dn = ""
        if isinstance(d.data, dict):
            dn = str((d.data.get("metadata") or {}).get("name") or "")
        if dn == rn:
            ctx.coverage.append(
                [f"HPA '{hpa_name}' -> {key}",
                 f"RESOLVES to an object rendered from {d.file}, i.e. from "
                 f"subchart '{d.file.split('/')[1]}'. The reference is not "
                 f"dangling. That workload is out of scope, so its resources, "
                 f"probes and JVM settings are NOT graded and the scaling "
                 f"arithmetic in this report is about the HPA alone, not about "
                 f"the pod it scales."])
            return True

    if not getattr(ctx, "subchart_docs", []):
        ctx.coverage.append(
            [f"HPA '{hpa_name}' -> {key}",
             f"UNDETERMINED - no workload here matches, and subchart(s) "
             f"{names} were not rendered (render mode: {ctx.render_mode}), so "
             f"the tool cannot tell a dangling reference from one satisfied "
             f"inside a subchart. Not reported as a finding either way. To "
             f"settle it: helm template <chart> | grep -A2 'kind: "
             f"{ref.get('kind')}'."])
        return True
    return False


def _target_kind_scalable(ctx, result, hpa, name, ref):
    """HP042: the target kind has no `scale` subresource, so the HPA is inert.

    R15. HP041 already proved this tool resolves scaleTargetRef NAMES
    correctly - corpus chart c27's deliberate case mismatch is caught - so the
    gap here was never parsing. The `kind` was simply never compared against
    the set of kinds that can be scaled at all, and an HPA pointed at a
    CronJob was accepted in silence while the report went on to print a full
    scaling-arithmetic table for it.

    The failure mode is quiet and permanent. The HPA controller cannot fetch a
    scale for the target, sets AbleToScale=False with FailedGetScale, and
    logs. Nothing crashes, no pod restarts, no alert fires by default: the
    autoscaler simply never acts, and the team believes the service scales
    because the object exists and `kubectl get hpa` prints a row for it.

    An unrecognised kind gets no finding. Argo Rollouts, KEDA ScaledObjects
    and any number of CRDs implement `scale` properly, and this tool does not
    have a list of every CRD in the world. Withholding a claim never becomes
    asserting one.
    """
    kind = str(ref.get("kind") or "").strip()
    if not kind:
        return
    why_not = UNSCALABLE_KINDS.get(kind.lower())
    if why_not is None:
        return
    api = str(ref.get("apiVersion") or "").strip()
    tgt = f"{api}/{kind}" if api else kind
    _add(result, rule_id="HP042", severity=Severity.CRITICAL,
         category=Category.HPA,
         title=f"HPA targets a {kind}, which cannot be scaled",
         file=hpa.file,
         detail=f"HPA '{name}' has scaleTargetRef {tgt} "
                f"'{ref.get('name')}'. {kind} does not implement the `scale` "
                f"subresource: {why_not}.",
         why="The HPA controller reaches its target through `scale` and "
             "through nothing else. With no such subresource it reports "
             "AbleToScale=False / FailedGetScale on every sync and never "
             "acts. This does not fail loudly - the object applies cleanly, "
             "`kubectl get hpa` lists it, and the only symptom is that "
             "scaling silently never happens. A team that believes this "
             "workload autoscales will find out during the incident that "
             "autoscaling would have prevented.",
         fix=f"Point the HPA at a Deployment or StatefulSet. If the intent "
             f"was to size {kind} work, that is a different mechanism: "
             f"parallelism for Jobs, node count for DaemonSets, or KEDA for "
             f"event-driven scaling.")


def _target_ref(ctx, result, hpa, name, spec, target, seen_targets):
    ref = spec.get("scaleTargetRef")
    if not isinstance(ref, dict):
        _add(result, rule_id="HP040", severity=Severity.HIGH, category=Category.HPA,
             title="HPA missing scaleTargetRef", file=hpa.file,
             detail=f"HPA '{name}' has no scaleTargetRef.",
             why="Required - the HPA does not know what to scale.",
             fix="Point scaleTargetRef at the Deployment (apiVersion apps/v1).")
        return
    key = f"{ref.get('kind')}/{ref.get('name')}"
    seen_targets.setdefault(key, []).append(name)
    _target_kind_scalable(ctx, result, hpa, name, ref)
    if target is None and ctx.workloads and _target_is_out_of_scope(ctx, ref, name):
        return
    if target is None and ctx.workloads:
        _add(result, rule_id="HP041", severity=Severity.HIGH, category=Category.HPA,
             title="HPA target does not match any workload in the chart", file=hpa.file,
             detail=f"HPA '{name}' targets {key}, which matches no "
                    f"Deployment/StatefulSet template here (name comparison is "
                    f"static - template expressions can defeat it; verify).",
             why="A dangling scaleTargetRef means the HPA controls nothing "
                 "(AbleToScale=False) while everyone assumes autoscaling works.",
             fix="Make the ref use the same fullname helper as the Deployment.")


_HP050_WHY = ("Helm and the HPA now fight over the same field. Every 'helm "
              "upgrade' resets replicas to the template value; if the HPA had "
              "scaled to 10 and the template says 2, the deploy instantly "
              "kills 8 loaded pods mid-traffic. The HPA scales back up "
              "minutes later - after your users noticed.")
_HP050_FIX = ("Omit spec.replicas entirely when autoscaling is enabled:\n"
              "        {{- if not .Values.autoscaling.enabled }}\n"
              "        replicas: {{ .Values.replicaCount }}\n"
              "        {{- end }}")
_HP050_MATH = ("Upgrade at peak: pods 10 -> 2 (helm apply) => per-pod load "
               "x5 instantly; if pods saturate at ~2x, the service is down "
               "until HPA re-adds pods (>= 1 metric period + JVM startup).")


def _replicas_conflict(ctx, result):
    """spec.replicas set on a workload that an HPA also scales.

    helm mode: rendered output is ground truth (replicas present in the
    render + HPA rendered => real conflict, no guessing). static mode:
    the guard around 'replicas:' is resolved with a control-flow stack
    scan (enclosing_conditions), not a single-idiom regex - any negated
    autoscaling/hpa condition counts as correctly gated; an un-negated one
    is the INVERSE bug; an unrelated condition downgrades to 'verify'.
    """
    helm_truth = ctx.render_mode == "helm"

    def hpa_targets(w, rendered_only: bool) -> bool:
        wname, wkind = doc_name(w), (w.kind or "").lower()
        candidates = [h for h in ctx.hpas
                      if not rendered_only or getattr(h, "rendered", True)]
        any_literal_mismatch = False
        for h in candidates:
            spec = h.data.get("spec") if isinstance(h.data, dict) else {}
            ref = spec.get("scaleTargetRef") if isinstance(spec, dict) else None
            if isinstance(ref, dict):
                rk = str(ref.get("kind", "")).lower()
                rn = str(ref.get("name", ""))
                if rk == wkind and (rn == wname or rn.startswith("HELM")
                                    or wname.startswith("<")):
                    return True
                if _is_resolvable_literal_name(rn):
                    any_literal_mismatch = True
        # F3: single HPA + single scalable workload -> assume the pairing, but
        # NOT when the HPA names a concrete workload that simply is not this one
        # (that is a dangling target, HP041 - not a replicas-vs-HPA conflict).
        if any_literal_mismatch:
            return False
        # R17 LEFT THIS ONE ALONE, and the reason is a measurement that did
        # NOT come out, which is worth more written down than repeated.
        #
        # Two constructed attempts failed to reach this line. The first used a
        # scaleTargetRef of `{{ .Release.Name }}-x`, which survives static
        # parsing as a resolvable literal, so `any_literal_mismatch` returned
        # False three lines above. The second named a `_helpers.tpl` include,
        # which the static parser rewrites to `HELM_TPL_n` - and the loop above
        # matches anything starting with "HELM" and returns True before F3 is
        # consulted. Five charts differing only in a second workload's kind
        # emitted identical HP050 in both attempts.
        #
        # So the branch is reachable only when the ref name contains "<" and
        # does not begin with "HELM", a parser state neither probe produced.
        # Changing an unreached predicate is not a fix, it is a guess with a
        # diff attached - and this whole family exists because someone once
        # made exactly that edit. Note the direction if it IS reached: this is
        # a COUNT used as a confidence test, not a filter, so widening it would
        # make HP050 fire LESS. That is the opposite of the site below, which
        # is why "replace all five with one set" would have been wrong.
        scalable = [x for x in ctx.workloads
                    if (x.kind or "").lower() in ("deployment", "statefulset")]
        return bool(candidates) and len(candidates) == 1 and len(scalable) == 1

    # R17. HP050 is CRITICAL and R14 caps the OVERALL grade at C when a
    # non-ASSUMED critical is present, so this `continue` was not skipping a
    # finding - it was skipping a grade cap. One chart per kind, each with
    # `replicas: 3` and an HPA naming that same object:
    #
    #     Deployment              C-  71.3   HP050
    #     StatefulSet             C-  71.3   HP050
    #     ReplicaSet              C   78.3   (none)
    #     Rollout                 C   77.9   (none)
    #
    # The ReplicaSet and the Rollout have the identical defect and score SEVEN
    # POINTS HIGHER for it. Both implement /scale, both take spec.replicas,
    # and `helm upgrade` resets that field on both at exactly the same moment.
    for w in ctx.workloads:
        if (w.kind or "").lower() not in REPLICA_MANAGED_KINDS:
            continue
        spec = w.data.get("spec") if isinstance(w.data, dict) else {}
        if not isinstance(spec, dict) or "replicas" not in spec:
            continue
        if not getattr(w, "rendered", True):
            continue    # replicas only exists in a branch that is off
        if not hpa_targets(w, rendered_only=False):
            continue    # no HPA (rendered or conditional) manages this workload
        hpa_rendered = hpa_targets(w, rendered_only=True)
        replicas = spec.get("replicas")
        rep_str = replicas if isinstance(replicas, int) else "<from values>"
        raw = ctx.template_raw.get(w.file, "")
        conds = enclosing_conditions(raw, _REPLICAS_LINE_RE) if raw else None
        gate = _classify_replicas_gate(conds)
        rep_line = line_of(raw, _REPLICAS_LINE_RE)
        name = doc_name(w)

        if helm_truth and hpa_rendered:
            _add(result, rule_id="HP050", severity=Severity.CRITICAL, category=Category.HPA,
                 # R17: the title said "Rendered Deployment" while the detail
                 # beside it already interpolated w.kind. Once the loop above
                 # reaches ReplicaSet and Rollout, a fixed noun here would
                 # print "Rendered Deployment sets spec.replicas" over a
                 # finding whose own detail says Rollout - and a reader who
                 # greps their templates for a Deployment finds nothing and
                 # concludes the tool is broken.
                 title=f"Rendered {w.kind} sets spec.replicas while an HPA "
                       f"manages it",
                 file=w.file, line=rep_line,
                 detail=f"`helm template` with the current values renders BOTH "
                        f"spec.replicas={rep_str} on {w.kind} '{name}' AND an "
                        f"HPA targeting it. This is the rendered output, not a "
                        f"static guess.",
                 why=_HP050_WHY, fix=_HP050_FIX, math=_HP050_MATH)
            continue
        if helm_truth and not hpa_rendered:
            if gate == "gated":
                continue    # guard exists and will drop replicas when enabled
            _add(result, rule_id="HP051", severity=Severity.HIGH, category=Category.HPA,
                 title="Enabling the HPA will collide with spec.replicas",
                 file=w.file, line=rep_line,
                 detail=f"The HPA template exists (currently disabled by "
                        f"values) but spec.replicas on {w.kind} '{name}' is "
                        f"not guarded by a 'not ...enabled' condition "
                        f"(guards found: {conds if conds else 'none'}).",
                 why="The moment someone flips autoscaling.enabled=true, helm "
                     "will keep resetting replicas on every upgrade - the "
                     "classic HPA fight, pre-armed.",
                 fix=_HP050_FIX, math=_HP050_MATH)
            continue

        # static mode
        if not ctx.hpas:
            continue
        if gate == "gated":
            continue
        if gate == "inverse":
            _add(result, rule_id="HP050", severity=Severity.CRITICAL, category=Category.HPA,
                 title="replicas guarded by autoscaling ENABLED (inverted gate)",
                 file=w.file, line=rep_line,
                 detail=f"{w.kind} '{name}': the guard around spec.replicas is "
                        f"{conds} - replicas is set precisely WHEN the HPA is "
                        f"active, the exact opposite of the correct gate.",
                 why=_HP050_WHY, fix=_HP050_FIX, math=_HP050_MATH)
        elif gate == "other":
            _add(result, rule_id="HP052", severity=Severity.MEDIUM, category=Category.HPA,
                 title="spec.replicas is conditional - verify the gate matches the HPA",
                 file=w.file, line=rep_line,
                 detail=f"{w.kind} '{name}' sets spec.replicas inside condition(s) "
                        f"{conds}, which this static analysis cannot prove "
                        f"equivalent to 'not autoscaling.enabled'. An HPA "
                        f"exists in this chart.",
                 why="If that condition can be true while the HPA is active, "
                     "helm upgrades will reset replicas mid-traffic "
                     "(see the HP050 rationale).",
                 fix="Make the guard exactly the negation of the HPA's enable "
                     "flag - or run this tool with helm on PATH for a "
                     "rendered-truth answer.",
                 math=_HP050_MATH)
        else:
            _add(result, rule_id="HP050", severity=Severity.CRITICAL, category=Category.HPA,
                 title="Deployment sets spec.replicas while an HPA manages it",
                 file=w.file, line=rep_line,
                 detail=f"{w.kind} '{name}' sets spec.replicas={rep_str} with "
                        f"no guard at all, AND an HPA targets this workload.",
                 why=_HP050_WHY, fix=_HP050_FIX, math=_HP050_MATH)

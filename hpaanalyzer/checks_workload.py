"""Checks: workload resources/QoS, probes, availability, security posture."""

import re
from typing import Any, Dict, List, Optional

from . import qos as qosmod
from .helmyaml import is_unresolved, line_of
from .kube import (containers, doc_name, is_sidecar, pod_spec,
                   this_container_is_jvm)
from .models import (AnalysisResult, Basis, Category, ChartContext, Finding,
                     Severity)
from .podresources import pod_resources, pods_per_node
from .qos import pod_qos
from .quantity import (fmt_bytes, fmt_millicores, is_byte_scale_suspect,
                       is_decimal_mem, is_millibytes, parse_cpu, parse_memory)


def run(ctx: ChartContext, result: AnalysisResult) -> None:
    for doc in ctx.workloads:
        where = f"{doc.kind} '{doc_name(doc)}'"
        _resources(ctx, result, doc, where)
        _qos(ctx, result, doc, where)
        _footprint(ctx, result, doc, where)
        _probes(ctx, result, doc, where)
        _availability(ctx, result, doc, where)
        _security(ctx, result, doc, where)
        _lifecycle(ctx, result, doc, where)
    _pdb(ctx, result)


def _add(result, **kw):
    result.add(Finding(**kw))


_NODE_ALLOCATABLE = 8 * 1024 ** 3      # the worked example's node size


# ---------------------------------------------------------------------------
# Whose container is this?  (docs/ITERATIONS.md R2, "the second defect")
#
# A finding's `why` and `fix` are the whole product; the rule id and the
# severity are packaging. When they describe a workload the container is not,
# the user is asked to reason from a false premise, and the two available
# outcomes are both bad: either they act on advice that does not apply, or
# they learn the prose is decorative and stop reading it - which discards the
# findings that were right. proof/p2b_rationale.py measured 8 such premises on
# one 2-container fixture, on all 4 of the fix-first entries.
# ---------------------------------------------------------------------------

def _infra(c: Dict[str, Any]) -> bool:
    """True when a finding's prose must not assume this container is the app.

    kube.is_sidecar() is a heuristic over container names and image
    substrings - ASSUMED, never OBSERVED. It is sound to consult it here, and
    only for this purpose, because of an asymmetry: the flag WITHHOLDS a
    claim, it never withholds a finding. Misclassifying the app as infra costs
    the reader one JVM-specific sentence they did not need; it hides no
    defect. Using the same heuristic to suppress a finding would not be safe,
    and this helper must not be repurposed that way.
    """
    return is_sidecar(c.get("name", ""), c.get("image", ""))


def _pick(infra: bool, app_text: str, infra_text: str) -> str:
    return infra_text if infra else app_text


def _overcommit_math(doc, cname, req_mem, lim_mem) -> str:
    """The node-fit worked example for RS008.

    This used to divide node allocatable by the CONTAINER's request and call
    the answer "such pods". The scheduler places pods, not containers: on
    fixtures/sidecar-chart that sentence claimed 64 pods per 8 GiB node where
    the upstream formula gives 3, a 21x overstatement in the direction that
    makes the problem look survivable. See docs/ITERATIONS.md R2 and
    proof/p2_sidecar.py.
    """
    ratio = lim_mem / req_mem
    pr = pod_resources(pod_spec(doc))
    pod_req = pr.requests.get("memory")
    pod_lim = pr.limits.get("memory")

    if not pr.decided or not pod_req:
        # C2.2: no pod total -> no capacity claim. Say why instead of guessing.
        return (f"requests.memory={fmt_bytes(req_mem)} vs "
                f"limits.memory={fmt_bytes(lim_mem)} = {ratio:.1f}x headroom "
                f"this container may take beyond what the scheduler reserved "
                f"for it. A node-capacity example needs the whole pod's "
                f"request, which could not be totalled here"
                f"{' (unresolved quantities)' if not pr.decided else ''}.")

    fit = pods_per_node(pod_req, _NODE_ALLOCATABLE)
    names = ", ".join(f"{s.name} {fmt_bytes(s.requests.get('memory') or 0)}"
                      for s in pr.shares if s.summed)
    line = (f"Container ratio: {fmt_bytes(lim_mem)} limit / "
            f"{fmt_bytes(req_mem)} request = {ratio:.1f}x. "
            f"Node fit is a POD question, so it uses the pod's request "
            f"({names}"
            f"{'; init peak dominates' if pr.init_dominates else ''}) "
            f"= {fmt_bytes(pod_req)}: an 8 GiB node packs "
            f"floor(8 GiB / {fmt_bytes(pod_req)}) = {fit} of these pods.")
    if pr.limits_complete and pod_lim:
        worst = fit * pod_lim
        line += (f" Worst case those {fit} pods may take "
                 f"{fit} x {fmt_bytes(pod_lim)} = {fmt_bytes(worst)} "
                 f"({worst / _NODE_ALLOCATABLE:.1f}x allocatable) -> the "
                 f"kernel OOM-killer picks the victim, not you.")
    else:
        line += (" Worst-case demand cannot be bounded: at least one "
                 "container in this pod sets no memory limit, so the pod's "
                 "ceiling is the node's capacity.")
    return line


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

def _get_res(c: Dict, section: str, name: str):
    res = c.get("resources")
    if not isinstance(res, dict):
        return None
    sec = res.get(section)
    if not isinstance(sec, dict):
        return None
    return sec.get(name)


def _resources(ctx, result, doc, where):
    for c in containers(doc):
        cname = c.get("name", "?")
        res = c.get("resources")
        loc = f"{where}, container '{cname}'"

        if res is None or res == {} or is_unresolved(res):
            if is_unresolved(res):
                # resources templated from values but values had nothing usable
                detail = (f"{loc}: resources come from an unresolved template "
                          f"expression and the values file provides no concrete "
                          f"requests/limits.")
            else:
                detail = f"{loc}: no resources block at all."
            _add(result, rule_id="RS001", severity=Severity.CRITICAL, category=Category.RESOURCES,
                 title="Container has no resource requests/limits", file=doc.file,
                 detail=detail,
                 why="No requests => QoS class BestEffort: first to be evicted "
                     "under node pressure, scheduled onto nodes with zero "
                     "guaranteed capacity, and *invisible* to the HPA (CPU "
                     "utilization is computed as usage/request - undefined without "
                     "a request). No limits => one leaking JVM can take the node "
                     "down with it.",
                 fix="Set resources.requests (cpu+memory) and at minimum a memory "
                     "limit. Size from observed P99 usage; see proof tables.",
                 math="HPA: desiredReplicas = ceil(current * usage/ (target% x "
                      "request)). request = nil => division undefined => HPA "
                      "reports FailedGetResourceMetric and never scales.")
            continue

        req_cpu_raw, req_mem_raw = _get_res(c, "requests", "cpu"), _get_res(c, "requests", "memory")
        lim_cpu_raw, lim_mem_raw = _get_res(c, "limits", "cpu"), _get_res(c, "limits", "memory")
        req_cpu, req_mem = parse_cpu(req_cpu_raw), parse_memory(req_mem_raw)
        lim_cpu, lim_mem = parse_cpu(lim_cpu_raw), parse_memory(lim_mem_raw)

        # millibytes typo: memory: 512m
        for label, raw in (("requests.memory", req_mem_raw), ("limits.memory", lim_mem_raw)):
            if is_millibytes(raw):
                # the literal usually lives in a values file, not the template
                pat = r"memory:\s*['\"]?" + re.escape(str(raw))
                found_file, found_line = doc.file, line_of(
                    ctx.template_raw.get(doc.file, ""), pat)
                if found_line is None:
                    for vf, vraw in ctx.values_raw.items():
                        ln = line_of(vraw, pat)
                        if ln is not None:
                            found_file, found_line = vf, ln
                            break
                _add(result, rule_id="RS002", severity=Severity.CRITICAL, category=Category.RESOURCES,
                     title="Memory quantity uses 'm' (MILLI-bytes)",
                     file=found_file, line=found_line,
                     detail=f"{loc}: {label} = {raw!r}.",
                     why="Lowercase 'm' is a legal Kubernetes suffix meaning 1/1000 "
                         "of a byte. '512m' is 0.512 BYTES, not 512 MiB. As a "
                         "request it schedules the pod as if it needs nothing; as a "
                         "limit the container is OOM-killed on its first allocation.",
                     fix=f"Use '{str(raw)[:-1]}Mi'.",
                     math=f"'{raw}' = {float(str(raw)[:-1])/1000:g} bytes; "
                          f"'{str(raw)[:-1]}Mi' = {parse_memory(str(raw)[:-1]+'Mi'):,} bytes "
                          f"- a factor of 1000 x 1024^2 ~= 1.05 billion.")
            elif is_byte_scale_suspect(raw):
                _add(result, rule_id="RS013", severity=Severity.CRITICAL, category=Category.RESOURCES,
                     title="Memory quantity is a bare byte count (missing Mi/Gi)",
                     file=doc.file,
                     detail=f"{loc}: {label} = {raw!r} - with no unit this is "
                            f"{int(float(str(raw)))} BYTES, not {raw}Mi.",
                     why="A unit-less integer is bytes. As a limit the container "
                         "is OOM-killed on its very first allocation and never "
                         "starts (not 'hours-to-days in' - immediately); as a "
                         "request the scheduler treats the pod as needing "
                         "nothing. This is the same typo class as '512m', which "
                         "is already CRITICAL.",
                     fix=f"Use '{str(raw).strip()}Mi' (or Gi) - add the binary "
                         f"unit.",
                     math=f"'{str(raw).strip()}' = {int(float(str(raw)))} B; "
                          f"'{str(raw).strip()}Mi' = "
                          f"{parse_memory(str(raw).strip()+'Mi'):,} B "
                          f"- off by a factor of 1024^2.")
            elif is_decimal_mem(raw):
                _add(result, rule_id="RS003", severity=Severity.LOW, category=Category.RESOURCES,
                     title="Memory uses decimal units (M/G) not binary (Mi/Gi)", file=doc.file,
                     detail=f"{loc}: {label} = {raw!r}.",
                     why="512M = 500,000,000 bytes but 512Mi = 536,870,912 bytes "
                         "(7.4% more). Mixing them causes silent under-provisioning "
                         "when people assume they are equal.",
                     fix="Standardize on binary suffixes (Mi/Gi) - they match how "
                         "the kernel and the JVM account memory.")

        missing_req = req_cpu is None or req_mem is None
        if missing_req and not (res is None):
            missing = [n for n, v in (("cpu", req_cpu_raw), ("memory", req_mem_raw)) if v is None]
            if missing:
                _add(result, rule_id="RS004", severity=Severity.HIGH, category=Category.RESOURCES,
                     title="Missing resource requests", file=doc.file,
                     detail=f"{loc}: requests missing for {', '.join(missing)}.",
                     why="Requests are what the scheduler and the HPA arithmetic "
                         "use. A missing CPU request also means the pod gets the "
                         "minimal CPU shares (cpu.weight) under contention.",
                     fix="Set both cpu and memory requests.")

        if lim_mem is None and lim_mem_raw is None and res:
            _add(result, rule_id="RS005", severity=Severity.HIGH, category=Category.RESOURCES,
                 title="No memory limit", file=doc.file,
                 detail=f"{loc}: limits.memory is not set.",
                 why="Memory is incompressible: when a node runs out, the kernel "
                     "OOM-killer picks victims. An unlimited JVM with a native leak "
                     "or unbounded -Xmx can evict every other pod on the node. For "
                     "JVM workloads a memory limit is the container's contract with "
                     "the JVM's container-awareness (MaxRAMPercentage is computed "
                     "FROM it).",
                 fix="Set limits.memory (commonly = requests.memory for JVMs, "
                     "giving Guaranteed-style memory QoS).")

        # limits < requests: rejected by API server
        if req_cpu is not None and lim_cpu is not None and lim_cpu < req_cpu:
            _add(result, rule_id="RS006", severity=Severity.CRITICAL, category=Category.RESOURCES,
                 title="CPU limit below CPU request (invalid)", file=doc.file,
                 detail=f"{loc}: requests.cpu={req_cpu_raw} > limits.cpu={lim_cpu_raw}.",
                 why="Kubernetes requires limit >= request; the API server rejects "
                     "this pod spec and the Deployment can never roll out.",
                 fix="Raise the limit or lower the request.",
                 math=f"{fmt_millicores(lim_cpu)} (limit) < {fmt_millicores(req_cpu)} (request).")
        if req_mem is not None and lim_mem is not None and lim_mem < req_mem:
            _add(result, rule_id="RS007", severity=Severity.CRITICAL, category=Category.RESOURCES,
                 title="Memory limit below memory request (invalid)", file=doc.file,
                 detail=f"{loc}: requests.memory={req_mem_raw} > limits.memory={lim_mem_raw}.",
                 why="limit >= request is mandatory; the API server rejects the pod.",
                 fix="Raise the limit or lower the request.",
                 math=f"{fmt_bytes(lim_mem)} (limit) < {fmt_bytes(req_mem)} (request).")

        # memory request << limit: overcommit / OOM roulette
        if req_mem and lim_mem and lim_mem >= req_mem and req_mem > 0:
            ratio = lim_mem / req_mem
            if ratio > 2.0:
                _add(result, rule_id="RS008", severity=Severity.HIGH, category=Category.RESOURCES,
                     title="Memory limit far above request (node overcommit)", file=doc.file,
                     detail=f"{loc}: requests.memory={req_mem_raw}, "
                            f"limits.memory={lim_mem_raw} (ratio {ratio:.1f}x).",
                     why="The scheduler packs nodes by REQUESTS, but pods may "
                         "legally use up to LIMITS. If every pod on a node bursts "
                         "toward a limit 2x+ its request, the node overcommits and "
                         "the kernel OOM-killer, not you, chooses which pod dies. "
                         + _pick(_infra(c),
                                 "For a JVM with fixed -Xmx there is no benefit: "
                                 "the JVM cannot 'burst' heap above -Xmx anyway.",
                                 f"'{cname}' looks like an infrastructure sidecar "
                                 "(proxy, agent, log shipper). Those have a "
                                 "steady, measurable footprint set by connection "
                                 "and config volume, not a tunable heap, so the "
                                 "gap between request and limit is not headroom "
                                 "anyone is using - it is unbooked risk on every "
                                 "node the pod lands on."),
                     fix=_pick(_infra(c),
                               "For JVM services set requests.memory = "
                               "limits.memory (memory is not compressible; "
                               "burstable memory is risk, not headroom).",
                               f"Measure '{cname}' under real traffic "
                               "(`kubectl top pod --containers`) and set "
                               "requests.memory = limits.memory at the observed "
                               "p99. Sidecar sizing is an empirical question; "
                               "the vendor's default manifest is a starting "
                               "point, not a measurement of your traffic."),
                     math=_overcommit_math(doc, cname, req_mem, lim_mem))

        # tiny CPU request with big limit -> throttle surprise + HPA distortion
        if req_cpu and lim_cpu and req_cpu > 0 and lim_cpu / req_cpu > 4:
            _add(result, rule_id="RS009", severity=Severity.MEDIUM, category=Category.RESOURCES,
                 title="CPU limit much larger than request", file=doc.file,
                 detail=f"{loc}: requests.cpu={req_cpu_raw}, limits.cpu={lim_cpu_raw} "
                        f"(ratio {lim_cpu/req_cpu:.1f}x).",
                 why="HPA %CPU is measured against the REQUEST. A pod cruising at "
                     "the limit runs at limit/request x 100% 'utilization', so the "
                     "HPA scales out violently even though the node still has CPU. "
                     "It also misleads bin-packing the same way memory does.",
                 fix="Bring request closer to typical usage (<= 2x gap), or drop "
                     "the CPU limit entirely and rely on requests + node capacity.",
                 math=f"Usage at limit -> utilization = {fmt_millicores(lim_cpu)}/"
                      f"{fmt_millicores(req_cpu)} = {100*lim_cpu//req_cpu}% of request.")

        # Very small cpu request for a JVM (F5: not for infra sidecars).
        #
        # R8, seventh site. The condition was `and ctx.dockerfiles`, and every
        # word of this finding is about the JVM: the title says JVM, the why
        # says class loading and JIT, the fix says "for JVM services". Keying
        # that on a filename got it wrong in both directions at once - it told
        # an nginx chart that shipped a Dockerfile its 100m request was too
        # small "for a JVM", and it said nothing to a Spring service whose pod
        # spec sets JAVA_TOOL_OPTIONS but whose image is built elsewhere.
        #
        # Unlike PB004 the finding does NOT survive without the claim: 100m is
        # a defensible request for a Go sidecar or a cron job, and the reason
        # to object is entirely that a JVM spends its first minute compiling.
        # So here the evidence gates the finding, not just the wording - and
        # the evidence is quoted, so the reader can check the inference.
        jvm_ev = this_container_is_jvm(ctx, c)
        if req_cpu is not None and req_cpu < 250 and jvm_ev:
            _add(result, rule_id="RS010", severity=Severity.MEDIUM, category=Category.RESOURCES,
                 title="CPU request likely too small for a JVM", file=doc.file,
                 detail=f"{loc}: requests.cpu={req_cpu_raw}. Treated as a JVM "
                        f"because {jvm_ev}.",
                 why="JVM startup (class loading + JIT) is CPU-hungry. Under node "
                     "contention a pod is guaranteed only its request; at "
                     f"{fmt_millicores(req_cpu)} a Spring-style app can take "
                     "minutes to become ready and trip liveness probes.",
                 fix="Request >= 250-500m for JVM services; consider a startupProbe.")


# ---------------------------------------------------------------------------
# QoS - computed for the POD, per upstream ComputePodQOS. See hpaanalyzer/qos.py
# for the ported algorithm and the sources it is ported from.
# ---------------------------------------------------------------------------

def _qos(ctx, result, doc, where):
    pq = pod_qos(pod_spec(doc))

    if pq.qos == qosmod.UNKNOWN:
        _add(result, rule_id="RS014", severity=Severity.INFO, category=Category.RESOURCES,
             title="Pod QoS class could not be determined", file=doc.file,
             detail=f"{where}: {pq.reason}.",
             why="QoS decides eviction order under node pressure. The tool "
                 "refuses to guess it from values it could not resolve; a "
                 "plausible wrong QoS is worse than none.",
             fix="Re-run with `helm` on PATH (rendered values resolve), or "
                 "check the live pod: kubectl get pod -l <selector> "
                 "-o jsonpath='{.items[*].status.qosClass}'.",
             basis=Basis.DERIVED)
        return

    if pq.qos == qosmod.BESTEFFORT:
        _add(result, rule_id="RS011", severity=Severity.HIGH, category=Category.RESOURCES,
             title="Pod QoS class is BestEffort", file=doc.file,
             detail=f"{where}: {pq.reason}.",
             why="BestEffort pods are evicted FIRST under node memory "
                 "pressure, before any Burstable/Guaranteed pod, regardless of "
                 "actual usage. They are also invisible to a CPU-target HPA, "
                 "which divides by the request.",
             fix="Add requests/limits; aim for Guaranteed (request=limit) for "
                 "latency-sensitive JVMs.")
        return

    # The surprise case that per-container analysis cannot see: the JVM
    # container is Guaranteed, yet the POD is Burstable because some other
    # container in the same pod is not. Upstream: one Burstable container, or
    # a mix of classes, makes the whole pod Burstable.
    if pq.qos == qosmod.BURSTABLE:
        app = [d for d in pq.containers
               if d.kind == "container" and d.qos == qosmod.GUARANTEED]
        drags = [d for d in pq.containers if d.qos != qosmod.GUARANTEED]
        if app and drags:
            names = ", ".join(f"'{d.name}' ({d.kind}, {d.qos})" for d in drags)
            # Severity HIGH, and the rule is narrow enough to earn it: this
            # fires ONLY when a regular container already has request == limit
            # for both cpu and memory - i.e. the author demonstrably intended
            # Guaranteed and paid its price (pinned requests, no burst
            # headroom, a harder pod to schedule) while receiving none of its
            # benefit. That configuration is strictly dominated: fixing the
            # other containers or relaxing this one is better on every axis.
            # It was MEDIUM until iteration 1's Bar 2 evaluation showed the
            # finding never reached the terminal fix-first list (which is
            # CRITICAL/HIGH only) - see docs/ITERATIONS.md R1, "Bar 2".
            _add(result, rule_id="RS015", severity=Severity.HIGH,
                 category=Category.RESOURCES,
                 title="Pod is Burstable although the app container is Guaranteed",
                 file=doc.file,
                 detail=f"{where}: container "
                        f"'{app[0].name}' has request == limit for cpu and memory, "
                        f"but the POD is Burstable because {names} "
                        f"{'does' if len(drags) == 1 else 'do'} not.",
                 why="QoS is a property of the pod, not of a container "
                     "(ComputePodQOS iterates initContainers then containers and "
                     "returns Burstable as soon as one differs). A sidecar or "
                     "init container without matching requests/limits therefore "
                     f"costs '{app[0].name}' its Guaranteed eviction priority - "
                     "and its static CPU-set/memory-manager eligibility - even "
                     "though that container is configured correctly.",
                 fix="Give every container in the pod - including init and native "
                     "sidecar containers - equal cpu and memory requests and "
                     "limits, or accept Burstable deliberately.",
                 math="pod QoS = Guaranteed iff every container is Guaranteed; "
                      f"here {len(drags)} of {len(pq.containers)} "
                      f"{'is' if len(drags) == 1 else 'are'} not.")


# ---------------------------------------------------------------------------
# Pod scheduling footprint (contract C1.5)
# ---------------------------------------------------------------------------

def _footprint(ctx, result, doc, where):
    """Defects that exist only at pod scope, and are therefore invisible to
    any per-container check however careful it is."""
    ps = pod_spec(doc)
    pr = pod_resources(ps)
    if not pr.shares or pr.pod_level:
        return

    replicas = None
    data = doc.data if isinstance(doc.data, dict) else {}
    if isinstance(data.get("spec"), dict):
        from .kube import as_int
        replicas = as_int(data["spec"].get("replicas"))

    # --- RS016: a transient init container reserves capacity permanently ----
    for res, fmt, unit in (("memory", fmt_bytes, ""), ("cpu", fmt_millicores, "")):
        peak = pr.init_peak.get(res) or 0
        steady = pr.steady.get(res) or 0
        if peak <= steady or not steady:
            continue
        ratio = peak / steady
        # An init container that exceeds the steady state by a hair is
        # arithmetically the deciding term but not a defect worth a page.
        if ratio < 1.25:
            continue
        biggest = max((s for s in pr.shares if s.kind == "init"),
                      key=lambda s: s.requests.get(res) or 0, default=None)
        waste = peak - steady
        scale = (f" Across replicas: {replicas} x {fmt(waste)} = "
                 f"{fmt(waste * replicas)} of cluster capacity reserved and "
                 f"unused after startup." if replicas else "")
        _add(result, rule_id="RS016",
             severity=Severity.HIGH if ratio >= 2 else Severity.MEDIUM,
             category=Category.RESOURCES,
             title=f"Init container sets the pod's {res} reservation "
                   f"({ratio:.1f}x the steady state)", file=doc.file,
             detail=f"{where}: init container "
                    f"'{biggest.name if biggest else '?'}' requests "
                    f"{fmt(biggest.requests.get(res) or 0) if biggest else '?'} "
                    f"{res}, making the pod's {res} request {fmt(peak)} while "
                    f"the running containers only need {fmt(steady)}.",
             why="A pod's request is max(steady state, init peak) per "
                 "resource, and it does not shrink when the init container "
                 "exits. The node keeps that capacity reserved for the pod's "
                 "entire life, so a 30-second migration job is billed for as "
                 "long as the pod runs - and the pod may sit Pending on a "
                 "cluster that has ample room for what it actually uses.",
             fix="Give the init container the smallest request that lets it "
                 "finish, or move the work out of the pod (a Job, an "
                 "initialisation hook, or an operator) so it is scheduled and "
                 "released independently.",
             math=f"pod.{res} = max(steady {fmt(steady)}, init peak "
                  f"{fmt(peak)}) = {fmt(peak)}; "
                  f"waste after startup = {fmt(waste)} "
                  f"({100 * waste / peak:.0f}% of the reservation).{scale}",
             basis=Basis.DERIVED)

    # --- RS017: a native sidecar the scheduler was told nothing about -------
    #
    # Severity is pinned to RS001's, deliberately, and the reasoning is worth
    # writing down because the number looks aggressive on its own.
    #
    # RS001 ("container has no resource requests/limits") is CRITICAL. A
    # native sidecar is, to the scheduler and to the QoS classifier, a regular
    # container: KEP-753 sums it into the pod's request and ComputePodQOS
    # iterates it. The failure is therefore not similar to RS001's, it is
    # RS001's - BestEffort-shaped capacity accounting on a process that runs
    # for the pod's entire life.
    #
    # The only reason a separate rule exists at all is a limitation in this
    # tool, not a distinction in Kubernetes: kube.containers() defaults to
    # walking spec.containers only, so RS001 has never looked inside
    # initContainers and a sidecar declared there escaped every resource check
    # the tool has. Giving the same defect a lower severity because the tool
    # found it in a different list would encode that blind spot as a judgement
    # about severity, which is the sort of thing that survives for years.
    #
    # The one gradation that IS about the author rather than the tool: a
    # container with no resources block at all was never sized (RS001's
    # case, CRITICAL); a block that sets limits but omits requests is a
    # sizing mistake with a visible intent behind it, and is a step less bad
    # because the limit at least bounds the damage - HIGH.
    blind = [s for s in pr.sidecars()
             if not (s.requests.get("cpu") or s.requests.get("memory"))]
    if blind:
        names = ", ".join(f"'{s.name}'" for s in blind)
        undeclared = [s for s in blind if not s.declared]
        _add(result, rule_id="RS017",
             severity=Severity.CRITICAL if undeclared else Severity.HIGH,
             category=Category.RESOURCES,
             title="Native sidecar runs for the pod's whole life with no "
                   "resource requests", file=doc.file,
             detail=f"{where}: {names} "
                    f"{'is' if len(blind) == 1 else 'are'} declared as "
                    f"initContainer(s) with restartPolicy: Always, so "
                    f"{'it runs' if len(blind) == 1 else 'they run'} alongside "
                    f"the app for the pod's entire lifetime - but "
                    f"{'contributes' if len(blind) == 1 else 'contribute'} "
                    f"0 to the pod's request"
                    + (" (no resources block at all)." if undeclared
                       else " (a resources block is present but sets no "
                            "cpu/memory request)."),
             why="A native sidecar is summed into the pod's request exactly "
                 "like a regular container (KEP-753), and counted like one by "
                 "ComputePodQOS. With no requests it is summed as zero: the "
                 "scheduler places the pod believing the sidecar is free, then "
                 "the sidecar consumes real memory on a node that reserved "
                 "none for it, and the pod cannot be Guaranteed however "
                 "carefully the app container is configured. Because a sidecar "
                 "never exits, this is not a startup spike - it is permanent, "
                 "on every replica, on every node they land on.",
             fix="Set requests (and limits) on the sidecar, in the "
                 "initContainers entry - not in spec.containers, where it does "
                 "not live. If you cannot size it from the vendor's docs, run "
                 "one and measure: `kubectl top pod --containers`.",
             math=f"pod request = sum(regular) + sum(sidecars) = "
                  f"{fmt_millicores(pr.steady.get('cpu') or 0)} / "
                  f"{fmt_bytes(pr.steady.get('memory') or 0)}, of which "
                  f"{names} contribute 0. Every byte the sidecar actually uses "
                  f"is therefore unbooked on the node.",
             basis=Basis.OBSERVED)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_time(p: Dict[str, Any]) -> Dict[str, int]:
    def gi(key, default):
        v = p.get(key, default)
        return v if isinstance(v, int) else default
    return {
        "initialDelaySeconds": gi("initialDelaySeconds", 0),
        "periodSeconds": gi("periodSeconds", 10),
        "timeoutSeconds": gi("timeoutSeconds", 1),
        "failureThreshold": gi("failureThreshold", 3),
        "successThreshold": gi("successThreshold", 1),
    }


def _probes(ctx, result, doc, where):
    kind = (doc.kind or "").lower()
    if kind in ("job", "cronjob"):
        return
    for c in containers(doc):
        cname = c.get("name", "?")
        loc = f"{where}, container '{cname}'"
        live, ready, startup = c.get("livenessProbe"), c.get("readinessProbe"), c.get("startupProbe")

        if not isinstance(ready, dict):
            _add(result, rule_id="PB001", severity=Severity.HIGH, category=Category.PROBES,
                 title="No readinessProbe", file=doc.file,
                 detail=f"{loc}: readinessProbe is not defined.",
                 why="Without readiness, the Service sends traffic the moment the "
                     "container starts - "
                     + _pick(_infra(c),
                             "for a JVM that means 503s/timeouts during the "
                             "whole warmup window on every deploy and every "
                             "scale-out (which the HPA triggers under load, "
                             "i.e. at the worst time).",
                             "and a pod is Ready only when EVERY container in "
                             "it is. Without a readiness probe this sidecar is "
                             "considered ready immediately, so the pod can be "
                             "put in rotation before the proxy or agent has "
                             "its configuration - traffic then fails inside "
                             "the pod, where the app's own health endpoint "
                             "cannot see it."),
                 fix=_pick(_infra(c),
                           "Add a readinessProbe hitting a real health "
                           "endpoint (e.g. /actuator/health/readiness).",
                           f"Add a readinessProbe on the health endpoint "
                           f"'{cname}' actually exposes - infra sidecars "
                           "publish their own (Envoy/istio-proxy: /ready on "
                           "the admin port 15021; most agents: a /healthz or "
                           "/-/ready on a metrics port). Check the image's "
                           "documentation rather than reusing the app's path."))

        if not isinstance(live, dict):
            _add(result, rule_id="PB002", severity=Severity.MEDIUM, category=Category.PROBES,
                 title="No livenessProbe", file=doc.file,
                 detail=f"{loc}: livenessProbe is not defined.",
                 why=_pick(_infra(c),
                           "A deadlocked or wedged JVM (e.g. OutOfMemoryError "
                           "swallowed by a thread pool) will sit broken "
                           "forever without liveness.",
                           "A wedged sidecar process stays wedged forever "
                           "without liveness, and nothing else will notice: "
                           "the app container is healthy, so the pod is not "
                           "restarted and no alert fires on it."),
                 fix="Add a livenessProbe, more tolerant than readiness "
                     "(higher failureThreshold/period).")

        if isinstance(live, dict) and isinstance(ready, dict):
            l_cmp = {k: v for k, v in live.items() if k in
                     ("httpGet", "tcpSocket", "exec", "grpc")}
            r_cmp = {k: v for k, v in ready.items() if k in
                     ("httpGet", "tcpSocket", "exec", "grpc")}
            if l_cmp and l_cmp == r_cmp:
                lt, rt = _probe_time(live), _probe_time(ready)
                if lt == rt:
                    _add(result, rule_id="PB003", severity=Severity.MEDIUM, category=Category.PROBES,
                         title="Liveness and readiness probes are identical", file=doc.file,
                         detail=f"{loc}: same endpoint AND same timings.",
                         why="Readiness failure should shed traffic (recoverable); "
                             "liveness failure RESTARTS the pod. Identical probes "
                             "turn every transient slowdown ("
                             + _pick(_infra(c), "GC pause, downstream hiccup",
                                     "config push, downstream hiccup")
                             + ") into a restart storm"
                             + _pick(_infra(c),
                                     " - and restarts of a slow-starting JVM "
                                     "amplify the outage.",
                                     " - and a restart here takes the whole "
                                     "pod down, application container "
                                     "included."),
                         fix="Make liveness strictly more tolerant: longer period, "
                             "higher failureThreshold, and an endpoint that does "
                             "NOT check downstream dependencies.")

        if isinstance(live, dict):
            t = _probe_time(live)
            kill_after = t["initialDelaySeconds"] + t["periodSeconds"] * t["failureThreshold"]
            # R8, sixth site. This used to end `and ctx.dockerfiles`, so a
            # liveness probe that starts killing at 5s with no startupProbe -
            # a HIGH, and pure probe arithmetic - went unreported unless the
            # chart happened to ship a Dockerfile. Measured on byte-identical
            # manifests, adding an unrelated `FROM nginx` file was the whole
            # difference between the finding and silence, while PB005 three
            # lines below fired either way. The probe fields are in the pod
            # spec; nothing about this finding needs an image.
            #
            # What the Dockerfile was standing in for is the PROSE: the JVM
            # explanation should only be given to a container that looks like
            # a JVM. So the evidence now selects the wording, three ways, and
            # the finding itself is unconditional.
            if not isinstance(startup, dict) and t["initialDelaySeconds"] < 30:
                jvm_ev = this_container_is_jvm(ctx, c)
                if jvm_ev:
                    pb4_title = "Liveness can kill a still-starting JVM"
                    pb4_why = ("JVM apps routinely need 30-120s+ to start (class "
                               "loading, JIT, Spring context, connection pools) - "
                               "especially with small CPU requests. If liveness "
                               "fires before the app can answer, kubelet kills it, "
                               "the restart is even slower (cold cache + CPU "
                               "contention), and the pod enters CrashLoopBackOff "
                               "without ever being unhealthy. "
                               f"(JVM here: {jvm_ev}.)")
                elif _infra(c):
                    pb4_title = "Liveness can kill a still-starting sidecar"
                    pb4_why = ("A sidecar's startup is usually fast, but it is "
                               "not local: a service-mesh proxy is not serving "
                               "until it has pulled configuration from the "
                               "control plane, and an agent may block on a "
                               "collector endpoint. When that dependency is slow "
                               "- exactly when the cluster is already unwell - "
                               "liveness kills a container that was never "
                               "unhealthy, and takes the application container "
                               "with it.")
                else:
                    pb4_title = "Liveness can kill a still-starting container"
                    pb4_why = ("Nothing here indicates a JVM, so this is stated "
                               "without one: a liveness probe with no "
                               "startupProbe begins killing on a fixed clock "
                               "from container start. Any first-run work - "
                               "migrations, cache warm, config fetch, a cold "
                               "page cache on a busy node - that outlasts that "
                               "clock produces CrashLoopBackOff on a container "
                               "that was never unhealthy, and it will happen "
                               "first under exactly the load that made startup "
                               "slow.")
                _add(result, rule_id="PB004", severity=Severity.HIGH, category=Category.PROBES,
                     title=pb4_title,
                     file=doc.file,
                     detail=f"{loc}: no startupProbe and liveness "
                            f"initialDelaySeconds={t['initialDelaySeconds']}s.",
                     why=pb4_why,
                     fix="Add a startupProbe (e.g. periodSeconds=5, "
                         "failureThreshold=36 -> up to 180s grace) - liveness only "
                         "begins after startup succeeds.",
                     math=f"Worst-case time-to-kill = initialDelay({t['initialDelaySeconds']}) "
                          f"+ period({t['periodSeconds']}) x failureThreshold({t['failureThreshold']}) "
                          f"= {kill_after}s. Anything needing more than "
                          f"{kill_after}s to start NEVER becomes live.")
            if t["timeoutSeconds"] <= 1:
                _add(result, rule_id="PB005", severity=Severity.MEDIUM, category=Category.PROBES,
                     title=_pick(_infra(c),
                                 "Probe timeoutSeconds = 1 (default) is "
                                 "fragile for JVMs",
                                 "Probe timeoutSeconds = 1 (default) is "
                                 "fragile under load"),
                     file=doc.file,
                     detail=f"{loc}: livenessProbe timeoutSeconds="
                            f"{t['timeoutSeconds']}s.",
                     why=_pick(_infra(c),
                               "A single stop-the-world GC pause > 1s fails the "
                               "probe. Three in a row (default "
                               "failureThreshold=3) restarts a healthy pod under "
                               "exactly the load that caused the GC pressure - "
                               "positive feedback into an outage.",
                               "One second is the time budget for the probe to "
                               "be scheduled, served and answered. Under CPU "
                               "throttling - which a sidecar with a small CPU "
                               "request meets first - a healthy process misses "
                               "it. Three misses restart the whole pod under "
                               "exactly the load that caused the throttling."),
                     fix=_pick(_infra(c),
                               "Set timeoutSeconds to 3-5s for JVM services.",
                               "Set timeoutSeconds to 3-5s."))


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

def _availability(ctx, result, doc, where):
    if (doc.kind or "").lower() not in ("deployment", "statefulset", "rollout"):
        return
    data = doc.data
    spec = data.get("spec") if isinstance(data, dict) else {}
    if not isinstance(spec, dict):
        return

    replicas = spec.get("replicas")
    has_hpa = bool(ctx.hpas)
    if isinstance(replicas, int) and replicas == 1 and not has_hpa:
        _add(result, rule_id="AV001", severity=Severity.MEDIUM, category=Category.AVAIL,
             title="Single replica workload", file=doc.file,
             detail=f"{where}: replicas=1, no HPA present.",
             why="One pod = zero redundancy. Node drain, image pull failure, OOM "
                 "kill or deploy all cause full downtime.",
             fix="Run >= 2 replicas with anti-affinity, or add an HPA with "
                 "minReplicas >= 2.")

    strategy = spec.get("strategy") if isinstance(spec.get("strategy"), dict) else {}
    if strategy.get("type") == "Recreate":
        _add(result, rule_id="AV002", severity=Severity.MEDIUM, category=Category.AVAIL,
             title="Deployment strategy Recreate", file=doc.file,
             detail=f"{where}: strategy.type=Recreate.",
             why="Recreate deletes ALL old pods before starting new ones - "
                 "guaranteed downtime on every deploy, magnified by JVM startup "
                 "time.",
             fix="Use RollingUpdate unless the app truly cannot run two versions "
                 "concurrently.")

    ps = pod_spec(doc)
    if isinstance(ps, dict):
        has_spread = bool(ps.get("topologySpreadConstraints")) or bool(
            isinstance(ps.get("affinity"), dict) and ps["affinity"].get("podAntiAffinity"))
        eff_replicas = replicas if isinstance(replicas, int) else None
        if not has_spread and (eff_replicas is None or eff_replicas >= 2 or has_hpa):
            _add(result, rule_id="AV003", severity=Severity.LOW, category=Category.AVAIL,
                 title="No pod anti-affinity / topology spread", file=doc.file,
                 detail=f"{where}: neither podAntiAffinity nor "
                        f"topologySpreadConstraints set.",
                 why="Multiple replicas may all land on ONE node; a single node "
                     "failure then behaves exactly like replicas=1. Scaling out "
                     "via HPA without spreading also concentrates the new load.",
                 fix="Add topologySpreadConstraints on kubernetes.io/hostname "
                     "(and zone) with maxSkew: 1.")


def _pdb(ctx, result):
    pdbs = ctx.docs_of_kind("PodDisruptionBudget")
    deployments = [d for d in ctx.workloads
                   if (d.kind or "").lower() in ("deployment", "statefulset")]
    if deployments and not pdbs:
        _add(result, rule_id="AV010", severity=Severity.MEDIUM, category=Category.AVAIL,
             title="No PodDisruptionBudget", file="",
             detail="Chart ships Deployments/StatefulSets but no PDB.",
             why="Without a PDB, voluntary disruptions (node drains, cluster "
                 "upgrades, spot reclaims via drain) may evict ALL replicas "
                 "simultaneously. With an HPA this is worse: cluster-autoscaler "
                 "consolidation happily drains nodes hosting every replica.",
             fix="Add a PDB with maxUnavailable: 1 (or 25%) selecting the same "
                 "pods.")
    for pdb in pdbs:
        spec = pdb.data.get("spec") if isinstance(pdb.data, dict) else {}
        if not isinstance(spec, dict):
            continue
        min_av, max_un = spec.get("minAvailable"), spec.get("maxUnavailable")
        # find replica count to compare
        replicas = None
        for d in deployments:
            r = d.data.get("spec", {}).get("replicas") if isinstance(d.data, dict) else None
            if isinstance(r, int):
                replicas = r
                break
        if min_av is not None and isinstance(min_av, int) and replicas is not None \
                and min_av >= replicas:
            _add(result, rule_id="AV011", severity=Severity.HIGH, category=Category.AVAIL,
                 title="PDB minAvailable blocks all voluntary disruption", file=pdb.file,
                 detail=f"PDB minAvailable={min_av} with replicas={replicas}.",
                 why="Allowed disruptions = replicas - minAvailable = "
                     f"{replicas - min_av}. Zero means kubectl drain hangs forever "
                     "- node upgrades and autoscaler consolidation are blocked, "
                     "and ops teams end up force-deleting pods (worse than no PDB).",
                 fix="Use maxUnavailable: 1, or ensure minAvailable < replicas "
                     "(and remember HPA can scale BELOW your assumption - align "
                     "with hpa.minReplicas).",
                 math=f"allowedDisruptions = replicas({replicas}) - "
                      f"minAvailable({min_av}) = {replicas - min_av} <= 0.")
        if min_av is None and max_un is None:
            _add(result, rule_id="AV012", severity=Severity.MEDIUM, category=Category.AVAIL,
                 title="PDB with neither minAvailable nor maxUnavailable", file=pdb.file,
                 detail="Empty PDB spec.",
                 why="An empty PDB protects nothing.",
                 fix="Set maxUnavailable: 1 (percentage forms also work).")


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

def _security(ctx, result, doc, where):
    ps = pod_spec(doc)
    if not ps:
        return
    pod_sc = ps.get("securityContext") if isinstance(ps.get("securityContext"), dict) else {}
    for c in containers(doc):
        cname = c.get("name", "?")
        loc = f"{where}, container '{cname}'"
        sc = c.get("securityContext") if isinstance(c.get("securityContext"), dict) else {}

        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if run_as_non_root is not True and (not isinstance(run_as_user, int) or run_as_user == 0):
            _add(result, rule_id="SC001", severity=Severity.HIGH, category=Category.SECURITY,
                 title="Container may run as root", file=doc.file,
                 detail=f"{loc}: neither runAsNonRoot: true nor a non-zero "
                        f"runAsUser is set.",
                 why="A container escape from a root process is a node compromise. "
                     "'Restricted' Pod Security Standard requires runAsNonRoot; "
                     "clusters enforcing it will refuse this pod.",
                 fix=_pick(_infra(c),
                           "Set securityContext.runAsNonRoot: true "
                           "(+ runAsUser) and add USER in the Dockerfile.",
                           "Set securityContext.runAsNonRoot: true (+ runAsUser) "
                           "on this container. Do not reach for the Dockerfile: "
                           "this is a third-party image you do not build. Check "
                           "the vendor's documented non-root UID first - most "
                           "publish one (istio-proxy: 1337) - because forcing an "
                           "arbitrary UID onto an image that expects its own "
                           "will fail on file permissions at startup."))

        if sc.get("allowPrivilegeEscalation") is not False:
            _add(result, rule_id="SC002", severity=Severity.MEDIUM, category=Category.SECURITY,
                 title="allowPrivilegeEscalation not disabled", file=doc.file,
                 detail=f"{loc}: allowPrivilegeEscalation is not set to false.",
                 why="Defaults to true; permits setuid binaries to gain "
                     "privileges. Required false by the Restricted PSS profile.",
                 fix="Set securityContext.allowPrivilegeEscalation: false.")

        caps = sc.get("capabilities") if isinstance(sc.get("capabilities"), dict) else {}
        drop = caps.get("drop") or []
        if not (isinstance(drop, list) and any(str(d).upper() == "ALL" for d in drop)):
            _add(result, rule_id="SC003", severity=Severity.LOW, category=Category.SECURITY,
                 title="Linux capabilities not dropped", file=doc.file,
                 detail=f"{loc}: capabilities.drop does not include ALL.",
                 why="Default capability set includes NET_RAW etc.; "
                     + ("a Java service needs none of them."
                        if this_container_is_jvm(ctx, c)
                        else "an ordinary network service needs none of them."),
                 fix="capabilities: { drop: [ALL] }.")

        if sc.get("readOnlyRootFilesystem") is not True:
            _add(result, rule_id="SC004", severity=Severity.LOW, category=Category.SECURITY,
                 title="Root filesystem writable", file=doc.file,
                 detail=f"{loc}: readOnlyRootFilesystem not true.",
                 # R8, eleventh site - and the smallest, which is why it
                 # survived the first ten. Nothing here GATES on a JVM; the
                 # prose simply assumes one. Printed on a pure nginx chart it
                 # read "JVMs typically only need /tmp" and told the reader to
                 # "add -Djava.io.tmpdir if needed" - advice about a runtime
                 # they do not run, in a finding that is otherwise correct.
                 # A false sentence attached to a true finding is the FACE B
                 # failure in miniature: it costs the finding its credibility
                 # and buys nothing.
                 why="Read-only rootfs blocks attackers dropping tools/persisting; "
                     + ("JVMs typically only need /tmp (mount an emptyDir)."
                        if this_container_is_jvm(ctx, c)
                        else "most services need only a writable /tmp "
                             "(mount an emptyDir)."),
                 fix="Set readOnlyRootFilesystem: true and mount emptyDir at /tmp"
                     + (" (add -Djava.io.tmpdir if needed)."
                        if this_container_is_jvm(ctx, c) else "."))

        if str(c.get("imagePullPolicy", "")) == "Always" and ":latest" not in str(c.get("image", "")):
            pass  # covered at values level (VA003)

    if ps.get("hostNetwork") is True or ps.get("hostPID") is True or ps.get("hostIPC") is True:
        _add(result, rule_id="SC005", severity=Severity.HIGH, category=Category.SECURITY,
             title="Pod uses host namespaces", file=doc.file,
             detail=f"{where}: hostNetwork/hostPID/hostIPC enabled.",
             why="Host namespaces break isolation between the pod and the node.",
             fix="Remove unless this is genuinely a node-level agent.")

    if ps.get("automountServiceAccountToken") is not False and \
            not any(k for k in ctx.docs_of_kind("Role", "ClusterRole")):
        _add(result, rule_id="SC006", severity=Severity.INFO, category=Category.SECURITY,
             title="ServiceAccount token automounted", file=doc.file,
             detail=f"{where}: automountServiceAccountToken not disabled and the "
                    f"chart defines no RBAC of its own.",
             why="Apps that never call the Kubernetes API should not carry API "
                 "credentials in /var/run/secrets - it is free attack surface.",
             fix="Set automountServiceAccountToken: false on the pod spec (or SA).")


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def _lifecycle(ctx, result, doc, where):
    ps = pod_spec(doc)
    if not ps:
        return
    tgps = ps.get("terminationGracePeriodSeconds")
    if isinstance(tgps, int) and tgps < 20:
        _add(result, rule_id="LC001", severity=Severity.MEDIUM, category=Category.PROBES,
             title="Short terminationGracePeriodSeconds", file=doc.file,
             detail=f"{where}: terminationGracePeriodSeconds={tgps}s.",
             why="On SIGTERM a JVM must stop accepting traffic, drain in-flight "
                 "requests, close pools and (often) deregister from discovery. "
                 f"{tgps}s is rarely enough; kubelet then SIGKILLs mid-request.",
             fix="Use >= 30s (default) and ensure the app handles SIGTERM (see "
                 "Dockerfile ENTRYPOINT findings).")

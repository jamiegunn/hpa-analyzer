"""Checks: workload resources/QoS, probes, availability, security posture."""

import re
from typing import Any, Dict, List, Optional

from .helmyaml import is_unresolved, line_of
from .kube import containers, doc_name, is_sidecar, pod_spec, qos_class
from .models import AnalysisResult, Category, ChartContext, Finding, Severity
from .quantity import (fmt_bytes, fmt_millicores, is_byte_scale_suspect,
                       is_decimal_mem, is_millibytes, parse_cpu, parse_memory)


def run(ctx: ChartContext, result: AnalysisResult) -> None:
    for doc in ctx.workloads:
        where = f"{doc.kind} '{doc_name(doc)}'"
        _resources(ctx, result, doc, where)
        _probes(ctx, result, doc, where)
        _availability(ctx, result, doc, where)
        _security(ctx, result, doc, where)
        _lifecycle(ctx, result, doc, where)
    _pdb(ctx, result)


def _add(result, **kw):
    result.add(Finding(**kw))


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
                         "For a JVM with fixed -Xmx there is no benefit: the JVM "
                         "cannot 'burst' heap above -Xmx anyway.",
                     fix="For JVM services set requests.memory = limits.memory "
                         "(memory is not compressible; burstable memory is risk, "
                         "not headroom).",
                     math=f"Node fit example: node allocatable 8 GiB packs "
                          f"floor(8GiB/{fmt_bytes(req_mem)}) = "
                          f"{int((8*1024**3)//req_mem)} such pods by request, but "
                          f"worst-case demand = that x {fmt_bytes(lim_mem)} = "
                          f"{fmt_bytes(int((8*1024**3)//req_mem)*lim_mem)} "
                          f"({(int((8*1024**3)//req_mem)*lim_mem)/(8*1024**3):.1f}x "
                          f"allocatable) -> OOM roulette.")

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

        # very small cpu request for a JVM (F5: not for infra sidecars)
        if req_cpu is not None and req_cpu < 250 and ctx.dockerfiles \
                and not is_sidecar(cname, c.get("image", "")):
            _add(result, rule_id="RS010", severity=Severity.MEDIUM, category=Category.RESOURCES,
                 title="CPU request likely too small for a JVM", file=doc.file,
                 detail=f"{loc}: requests.cpu={req_cpu_raw}.",
                 why="JVM startup (class loading + JIT) is CPU-hungry. Under node "
                     "contention a pod is guaranteed only its request; at "
                     f"{fmt_millicores(req_cpu)} a Spring-style app can take "
                     "minutes to become ready and trip liveness probes.",
                 fix="Request >= 250-500m for JVM services; consider a startupProbe.")

        # QoS classification (informational unless BestEffort)
        qos = qos_class(req_cpu, req_mem, lim_cpu, lim_mem,
                        has_requests=req_cpu is not None or req_mem is not None,
                        has_limits=lim_cpu is not None or lim_mem is not None)
        if qos == "BestEffort":
            _add(result, rule_id="RS011", severity=Severity.HIGH, category=Category.RESOURCES,
                 title="Pod QoS class is BestEffort", file=doc.file,
                 detail=f"{loc}: no effective requests or limits -> BestEffort.",
                 why="BestEffort pods are evicted FIRST under node memory "
                     "pressure, before any Burstable/Guaranteed pod, regardless of "
                     "actual usage.",
                 fix="Add requests/limits; aim for Guaranteed (request=limit) for "
                     "latency-sensitive JVMs.")


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
                     "container starts - for a JVM that means 503s/timeouts during "
                     "the whole warmup window on every deploy and every scale-out "
                     "(which the HPA triggers under load, i.e. at the worst time).",
                 fix="Add a readinessProbe hitting a real health endpoint (e.g. "
                     "/actuator/health/readiness).")

        if not isinstance(live, dict):
            _add(result, rule_id="PB002", severity=Severity.MEDIUM, category=Category.PROBES,
                 title="No livenessProbe", file=doc.file,
                 detail=f"{loc}: livenessProbe is not defined.",
                 why="A deadlocked or wedged JVM (e.g. OutOfMemoryError swallowed "
                     "by a thread pool) will sit broken forever without liveness.",
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
                             "turn every transient slowdown (GC pause, downstream "
                             "hiccup) into a restart storm - and restarts of a slow-"
                             "starting JVM amplify the outage.",
                         fix="Make liveness strictly more tolerant: longer period, "
                             "higher failureThreshold, and an endpoint that does "
                             "NOT check downstream dependencies.")

        if isinstance(live, dict):
            t = _probe_time(live)
            kill_after = t["initialDelaySeconds"] + t["periodSeconds"] * t["failureThreshold"]
            if not isinstance(startup, dict) and t["initialDelaySeconds"] < 30 and ctx.dockerfiles:
                _add(result, rule_id="PB004", severity=Severity.HIGH, category=Category.PROBES,
                     title="Liveness can kill a still-starting JVM", file=doc.file,
                     detail=f"{loc}: no startupProbe and liveness "
                            f"initialDelaySeconds={t['initialDelaySeconds']}s.",
                     why="JVM apps routinely need 30-120s+ to start (class "
                         "loading, JIT, Spring context, connection pools) - "
                         "especially with small CPU requests. If liveness fires "
                         "before the app can answer, kubelet kills it, the restart "
                         "is even slower (cold cache + CPU contention), and the pod "
                         "enters CrashLoopBackOff without ever being unhealthy.",
                     fix="Add a startupProbe (e.g. periodSeconds=5, "
                         "failureThreshold=36 -> up to 180s grace) - liveness only "
                         "begins after startup succeeds.",
                     math=f"Worst-case time-to-kill = initialDelay({t['initialDelaySeconds']}) "
                          f"+ period({t['periodSeconds']}) x failureThreshold({t['failureThreshold']}) "
                          f"= {kill_after}s. A JVM needing more than {kill_after}s "
                          f"to start NEVER becomes live.")
            if t["timeoutSeconds"] <= 1:
                _add(result, rule_id="PB005", severity=Severity.MEDIUM, category=Category.PROBES,
                     title="Probe timeoutSeconds = 1 (default) is fragile for JVMs",
                     file=doc.file,
                     detail=f"{loc}: livenessProbe timeoutSeconds="
                            f"{t['timeoutSeconds']}s.",
                     why="A single stop-the-world GC pause > 1s fails the probe. "
                         "Three in a row (default failureThreshold=3) restarts a "
                         "healthy pod under exactly the load that caused the GC "
                         "pressure - positive feedback into an outage.",
                     fix="Set timeoutSeconds to 3-5s for JVM services.")


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
                 fix="Set securityContext.runAsNonRoot: true (+ runAsUser) and add "
                     "USER in the Dockerfile.")

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
                 why="Default capability set includes NET_RAW etc.; a Java service "
                     "needs none of them.",
                 fix="capabilities: { drop: [ALL] }.")

        if sc.get("readOnlyRootFilesystem") is not True:
            _add(result, rule_id="SC004", severity=Severity.LOW, category=Category.SECURITY,
                 title="Root filesystem writable", file=doc.file,
                 detail=f"{loc}: readOnlyRootFilesystem not true.",
                 why="Read-only rootfs blocks attackers dropping tools/persisting; "
                     "JVMs typically only need /tmp (mount an emptyDir).",
                 fix="Set readOnlyRootFilesystem: true and mount emptyDir at /tmp "
                     "(add -Djava.io.tmpdir if needed).")

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

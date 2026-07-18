"""Cross-file analysis: JVM configuration vs chart resources, with proof tables.

Every table states its assumptions explicitly and derives a verdict from
arithmetic the reader can re-check by hand.
"""

import math
from typing import Any, Dict, List, Optional, Tuple

from .dockerparse import effective_flags, flag_val, has_flag
from .kube import (SIDECAR_NAMES, as_int, containers, container_jvm_env_flags,
                   doc_name, is_sidecar, qos_class)
from .models import (AnalysisResult, Basis, Category, ChartContext,
                     DockerfileInfo, Finding, ProofTable, Severity)
from .quantity import fmt_bytes, fmt_millicores, parse_cpu, parse_jvm_size, parse_memory

MiB = 1024 ** 2
GiB = 1024 ** 3

# Documented estimation constants (surfaced in the tables)
EST_METASPACE = 128 * MiB      # typical Spring/framework app: 80-180 MiB
EST_CODECACHE = 64 * MiB       # JIT code cache steady state
EST_THREADS = 100              # typical service thread count
EST_DIRECT = 64 * MiB          # netty/NIO direct buffers
EST_GC_OTHER = 48 * MiB        # GC bookkeeping, symbols, JVM itself
ASSUMED_NODE_RAM = 16 * GiB    # for "JVM cannot see the limit" scenarios
JVM_STARTUP_TYPICAL = 60       # seconds, mid-size Spring app


def run(ctx: ChartContext, result: AnalysisResult) -> None:
    # JVM-specific modelling requires an actual Dockerfile: inventing a JVM
    # memory budget for a chart that may run nginx would be fiction.
    if ctx.dockerfiles:
        for doc, container, df in _pairs(ctx):
            _memory_budget(ctx, result, doc, container, df)
            _cpu_view(ctx, result, doc, container, df)
        _probe_vs_startup(ctx, result)
    _qos_table(ctx, result)
    _hpa_math(ctx, result)
    _availability_math(ctx, result)


def _pairs(ctx) -> List[Tuple[Any, Dict, Optional[DockerfileInfo]]]:
    """(workload doc, container, dockerfile) triples worth analyzing.

    Sidecars (istio-proxy etc.) are excluded from JVM modelling - handing
    an Envoy proxy a JVM memory budget would be nonsense. If several
    Dockerfiles exist, the first Java-identifiable one is used and that
    assumption is stated in every table it produces.
    """
    df = None
    for d in ctx.dockerfiles:
        if d.java_major or d.jvm_flags or d.java_opts:
            df = d
            break
    if df is None and ctx.dockerfiles:
        df = ctx.dockerfiles[0]
    out = []
    for doc in ctx.workloads:
        if (doc.kind or "").lower() not in ("deployment", "statefulset", "daemonset"):
            continue
        for c in containers(doc):
            if is_sidecar(c.get("name", ""), c.get("image", "")):
                continue
            out.append((doc, c, df))
    return out


def _df_assumption(ctx, df: Optional[DockerfileInfo]) -> str:
    if df is None:
        return ""
    if len(ctx.dockerfiles) > 1:
        return (f" JVM config taken from '{df.path}' (first Java-identifiable "
                f"of {len(ctx.dockerfiles)} Dockerfiles - verify the pairing).")
    return ""


def _cond_note(doc) -> str:
    return "" if getattr(doc, "rendered", True) else \
        " [CONDITIONAL - this object does not render with current values]"


def _res(c: Dict, section: str, name: str):
    try:
        raw = c["resources"][section][name]
    except (KeyError, TypeError):
        return None, None
    return raw, (parse_cpu(raw) if name == "cpu" else parse_memory(raw))


def _effective_flags(df: Optional[DockerfileInfo],
                     container: Optional[Dict] = None) -> List[str]:
    """Applied JVM flags: image-level (dockerparse) plus any set via the pod's
    own env (JAVA_TOOL_OPTIONS etc.), which the JVM reads unaided. Feeding env
    flags in here is what stops the memory budget from assuming a default 25%
    heap when the chart actually set 75% via env (F4 false absolution)."""
    flags = list(effective_flags(df)) if df is not None else []
    if container is not None:
        flags += container_jvm_env_flags(container)
    return flags


def _jvm_sees_limit(df: Optional[DockerfileInfo]) -> Tuple[bool, str]:
    """Can this JVM be trusted to observe the cgroup memory limit?"""
    if df is None or df.java_major is None:
        return True, ("assumed container-aware (version unknown - re-run "
                      "with --assume-java for a real answer)")
    m, u = df.java_major, df.java_update
    flags = _effective_flags(df)
    if has_flag(flags, "-XX:-UseContainerSupport"):
        return False, "UseContainerSupport disabled by flag"
    if m == 8:
        if u is not None and u < 131:
            return False, f"8u{u} predates all cgroup support"
        if u is not None and u < 191:
            if has_flag(flags, "UseCGroupMemoryLimitForHeap"):
                return True, f"8u{u} + experimental cgroup flag (v1 only)"
            return False, f"8u{u} without applied experimental cgroup flags"
        if u is not None and u < 372:
            return True, f"8u{u}: cgroup v1 only - BLIND on cgroup-v2 nodes"
        if u is None:
            return True, "Java 8, unknown update - unverifiable"
    if m in (9, 10, 12, 13, 14):
        return True, f"Java {m}: cgroup v1 only - BLIND on cgroup-v2 nodes"
    if m == 11 and u is not None and u < 16:
        return True, f"11.0.{u}: cgroup v1 only - BLIND on cgroup-v2 nodes"
    return True, "container-aware"


# ---------------------------------------------------------------------------
# 1. Memory budget
# ---------------------------------------------------------------------------

def _memory_budget(ctx, result, doc, c, df: Optional[DockerfileInfo]):
    cname = c.get("name", "?")
    lim_raw, lim = _res(c, "limits", "memory")
    req_raw, req = _res(c, "requests", "memory")
    flags = _effective_flags(df, c)

    xmx = parse_jvm_size(flag_val(flags, "Xmx") or "") if flags else None
    pct_s = flag_val(flags, "MaxRAMPercentage") if flags else None
    try:
        pct = float(pct_s) if pct_s else None
    except ValueError:
        pct = None
    xss = parse_jvm_size(flag_val(flags, "Xss") or "") if flags else None
    xss = xss or MiB
    maxdirect = parse_jvm_size(flag_val(flags, "MaxDirectMemorySize") or "") if flags else None
    sees, sees_note = _jvm_sees_limit(df)

    # ----- derive effective max heap (and how confidently we know it) -----
    if xmx is not None:
        heap = xmx
        heap_src = f"-Xmx ({fmt_bytes(xmx)})"
        heap_basis = Basis.OBSERVED
    elif pct is not None and lim is not None and sees:
        heap = int(lim * pct / 100)
        heap_src = f"MaxRAMPercentage={pct:g}% x limit {fmt_bytes(lim)}"
        heap_basis = Basis.OBSERVED   # exact arithmetic on two observed values
    elif lim is not None and sees:
        heap = int(lim * 0.25)
        heap_src = f"JVM default 25% x limit {fmt_bytes(lim)}"
        heap_basis = Basis.DERIVED    # heap not set; relies on the JVM default
    elif not sees:
        heap = int(ASSUMED_NODE_RAM * (pct if pct else 25) / 100)
        heap_src = (f"JVM CANNOT see the limit ({sees_note}); default "
                    f"{pct if pct else 25:g}% x assumed node RAM "
                    f"{fmt_bytes(ASSUMED_NODE_RAM)}")
        heap_basis = Basis.ASSUMED    # rests on an assumed node RAM size
    else:
        heap = None
        heap_src = "no limit and no explicit sizing - unbounded"
        heap_basis = Basis.OBSERVED

    # non-heap components are always estimates -> anything summing them is at
    # best DERIVED; if even the heap was assumed, the whole total is ASSUMED.
    total_basis = Basis.ASSUMED if heap_basis is Basis.ASSUMED else Basis.DERIVED
    node_assumes = ("the node has ~16 GiB RAM (used only because this JVM "
                    "cannot see the container limit)")

    direct = maxdirect if maxdirect is not None else (EST_DIRECT if xmx is None else min(xmx, EST_DIRECT))
    stacks = EST_THREADS * xss
    if heap is not None:
        total = heap + EST_METASPACE + EST_CODECACHE + stacks + direct + EST_GC_OTHER
    else:
        total = None

    where = f"{doc.kind} '{doc_name(doc)}' / container '{cname}'"
    rows = [
        ["Container memory limit", fmt_bytes(lim) if lim else "NOT SET",
         lim_raw if lim_raw else "-"],
        ["Max heap (H)", fmt_bytes(heap) if heap else "UNBOUNDED", heap_src],
        ["Metaspace (est.)", fmt_bytes(EST_METASPACE), "typical framework app 80-180 MiB"],
        ["JIT code cache (est.)", fmt_bytes(EST_CODECACHE), "steady-state"],
        [f"Thread stacks ({EST_THREADS} x {fmt_bytes(xss)})", fmt_bytes(stacks),
         "-Xss x thread count"],
        ["Direct buffers (est.)", fmt_bytes(direct),
         ("MaxDirectMemorySize (explicit)" if maxdirect is not None else
          (f"est. 64 MiB typical; NOTE the JVM's cap defaults to Xmx "
           f"({fmt_bytes(xmx)}) - a buffer leak can go far past this estimate"
           if xmx else "est. 64 MiB typical"))],
        ["GC + JVM internal (est.)", fmt_bytes(EST_GC_OTHER), "card tables, symbols"],
        ["ESTIMATED PEAK RSS (T)", fmt_bytes(total) if total else "UNBOUNDED",
         "T = H + non-heap components"],
    ]
    if lim and total:
        margin = lim - total
        rows.append(["Margin (limit - T)",
                     ("+" if margin >= 0 else "") + fmt_bytes(abs(margin)) if margin >= 0
                     else "-" + fmt_bytes(abs(margin)),
                     f"{100*margin/lim:+.0f}% of limit"])
        if margin < 0:
            certainty = ("This follows from your own numbers alone."
                         if xmx is not None and heap is not None and heap >= lim
                         else "Estimate-based: the non-heap components are "
                              "assumptions (stated above) - substitute measured "
                              "values, but a negative margin this size rarely "
                              "reverses.")
            verdict = (f"T exceeds the limit by {fmt_bytes(-margin)}: expect "
                       f"kernel OOM kills (exit 137) once the heap approaches "
                       f"{fmt_bytes(heap)} under sustained load. {certainty}")
        elif margin < int(0.1 * lim):
            verdict = (f"Margin {fmt_bytes(margin)} (<10% of limit) - one traffic "
                       f"spike, classloading burst or extra threads away from an "
                       f"OOM kill.")
        else:
            verdict = (f"Fits with {fmt_bytes(margin)} headroom "
                       f"({100*margin/lim:.0f}% of limit).")
            if heap and lim and heap < 0.35 * lim and xmx is None and pct is None:
                verdict += (f" BUT heap is only {100*heap/lim:.0f}% of the limit "
                            f"(JVM default) - you pay for memory the JVM will "
                            f"never use; raise MaxRAMPercentage deliberately.")
                result.add(Finding(
                    rule_id="XF005", severity=Severity.LOW, category=Category.CROSS,
                    title="Heap defaulted to ~25% of the limit (paid-for memory unused)",
                    file=doc.file, basis=Basis.DERIVED,
                    detail=f"{where}: no applied heap sizing, so the JVM "
                           f"defaults to ~{fmt_bytes(heap)} heap inside a "
                           f"{fmt_bytes(lim)} limit.",
                    why="You reserve (and are billed/bin-packed for) the full "
                        "limit, but the JVM will never use most of it for "
                        "heap; meanwhile GC pressure is higher than it needs "
                        "to be.",
                    fix="Set -XX:MaxRAMPercentage=50-75 explicitly.",
                    math=f"Unused-by-heap = L - (H + non-heap) ~= "
                         f"{fmt_bytes(max(0, lim - total))} of {fmt_bytes(lim)}."))
    elif not lim:
        verdict = ("No memory limit: the JVM competes with every pod on the "
                   "node; a leak becomes the node's problem. Set a limit and "
                   "size the heap from it.")
    else:
        verdict = "Heap unbounded - set -Xmx or MaxRAMPercentage."

    result.add_proof(ProofTable(
        title=f"JVM memory budget - {where}{_cond_note(doc)}",
        intro=(f"Container memory must hold the WHOLE JVM, not just the heap. "
               f"Estimation model: T = H + Metaspace + CodeCache + threads*Xss "
               f"+ DirectBuffers + GC/internal. JVM visibility of the limit: "
               f"{sees_note}.{_df_assumption(ctx, df)}"),
        headers=["Component", "Size", "Basis"],
        rows=rows,
        conclusion=verdict))

    if lim and total and 0 <= (lim - total) < int(0.1 * lim):
        result.add(Finding(
            rule_id="XF004", severity=Severity.MEDIUM, category=Category.CROSS,
            title="JVM memory margin under 10% of the limit", file=doc.file,
            basis=total_basis,
            assumes=(node_assumes if heap_basis is Basis.ASSUMED else None),
            detail=f"{where}: estimated peak RSS {fmt_bytes(total)} vs limit "
                   f"{fmt_bytes(lim)} - margin {fmt_bytes(lim - total)} "
                   f"({100*(lim-total)/lim:.0f}%).",
            why="The estimate uses typical non-heap components (stated in the "
                "budget table); real Spring apps routinely exceed them "
                "(metaspace growth, more threads, bigger direct buffers). A "
                "single-digit margin means routine variance ends in a kernel "
                "OOM kill.",
            fix="Either lower the heap (MaxRAMPercentage/-Xmx) or raise "
                "limits.memory until the margin is >= 15-25%, then validate "
                "against measured RSS.",
            math=f"margin = L({fmt_bytes(lim)}) - T({fmt_bytes(total)}) = "
                 f"{fmt_bytes(lim-total)} = {100*(lim-total)/lim:.0f}% of L."))

    # findings derived from the same arithmetic
    if lim and heap and heap >= lim:
        result.add(Finding(
            rule_id="XF001", severity=Severity.CRITICAL, category=Category.CROSS,
            title="Max heap >= container memory limit", file=doc.file,
            basis=heap_basis,
            assumes=(node_assumes if heap_basis is Basis.ASSUMED else None),
            detail=f"{where}: effective max heap {fmt_bytes(heap)} "
                   f"({heap_src}) vs limits.memory {fmt_bytes(lim)}.",
            why="The heap ALONE meets or exceeds the limit before counting "
                "metaspace, stacks and buffers. The kernel will OOM-kill the "
                "container (exit 137, no Java stack trace, no heap dump) as "
                "soon as the heap fills - typically under first real load.",
            fix="Heap <= 50-75% of the limit. Either raise limits.memory or "
                "lower -Xmx/MaxRAMPercentage.",
            math=f"H({fmt_bytes(heap)}) >= L({fmt_bytes(lim)}); "
                 f"required: H + ~{fmt_bytes(EST_METASPACE+EST_CODECACHE+stacks+direct+EST_GC_OTHER)} "
                 f"(non-heap) <= L."))
    elif lim and total and total > lim:
        result.add(Finding(
            rule_id="XF002", severity=Severity.HIGH, category=Category.CROSS,
            title="Estimated JVM footprint exceeds memory limit", file=doc.file,
            basis=total_basis,
            assumes=(node_assumes if heap_basis is Basis.ASSUMED else None),
            detail=f"{where}: estimated peak RSS {fmt_bytes(total)} > limit "
                   f"{fmt_bytes(lim)} (see memory budget table).",
            why="Heap fits but heap+non-heap does not; the pod dies by kernel "
                "OOM under sustained load, usually hours-to-days in, which "
                "looks like a 'random restart' problem.",
            fix=f"Raise limits.memory to >= {fmt_bytes(int(total*1.15))} or "
                f"reduce heap.",
            math=f"T({fmt_bytes(total)}) > L({fmt_bytes(lim)}) by "
                 f"{fmt_bytes(total-lim)}."))
    if lim and req and lim == req and heap and total and total <= lim:
        pass  # ideal; no finding
    if not sees and lim:
        result.add(Finding(
            rule_id="XF003", severity=Severity.CRITICAL, category=Category.CROSS,
            title="JVM cannot see the container memory limit", file=df.path if df else "",
            basis=Basis.DERIVED, assumes=node_assumes,
            detail=f"{sees_note}; the chart sets limits.memory={fmt_bytes(lim)} "
                   f"but the JVM sizes itself from the node.",
            why="Limits only constrain (kill); they do not inform an unaware "
                "JVM. The JVM aims for a heap derived from NODE RAM and is "
                "OOM-killed at the container limit it never knew about.",
            fix="Upgrade the JDK (8u191+/11.0.16+/17+) or set explicit -Xmx.",
            math=f"Default heap = node_RAM/4 = {fmt_bytes(ASSUMED_NODE_RAM//4)} "
                 f"(assumed {fmt_bytes(ASSUMED_NODE_RAM)} node) vs limit "
                 f"{fmt_bytes(lim)} => kill at "
                 f"{100*lim/(ASSUMED_NODE_RAM//4):.0f}% of the JVM's target."))


# ---------------------------------------------------------------------------
# 2. CPU view
# ---------------------------------------------------------------------------

def _cpu_view(ctx, result, doc, c, df: Optional[DockerfileInfo]):
    cname = c.get("name", "?")
    lim_raw, lim = _res(c, "limits", "cpu")
    req_raw, req = _res(c, "requests", "cpu")
    if lim is None and req is None:
        return
    flags = _effective_flags(df, c)
    apc = flag_val(flags, "ActiveProcessorCount") if flags else None

    major = df.java_major if df else None
    upd = df.java_update if df else None
    # R5: JDK 11.0.17+ / 17.0.5+ / 19+ (JDK-8281181) NO LONGER derive
    # availableProcessors() from cpu.shares - with no CPU limit they see ALL
    # node CPUs. Printing ceil(request/1000)=1 for such a JVM is false by its
    # own footnote. Branch on the detected version instead of asserting one.
    shares_ignored = (major is not None and
                      (major >= 17 or (major == 11 and (upd or 0) >= 17)))
    cpus_seen = None
    basis = ""
    if apc:
        cpus_seen, basis = apc, "-XX:ActiveProcessorCount (explicit - authoritative)"
    elif lim is not None:
        cpus_seen = max(1, math.ceil(lim / 1000))
        basis = f"ceil(limit {fmt_millicores(lim)} / 1000m)"
    elif req is not None and shares_ignored:
        cpus_seen = "ALL node CPUs"
        basis = (f"no CPU limit set and this JDK (>= 11.0.17 / 17) ignores "
                 f"cpu.shares - availableProcessors() = the node's full CPU "
                 f"count, NOT ceil(request/1000). Pin -XX:ActiveProcessorCount "
                 f"for stable pool sizing.")
    elif req is not None:
        cpus_seen = max(1, math.ceil(req / 1000))
        ver = (f"Java {major}" + (f"u{upd}" if major == 8 and upd else "")
               if major else "the detected JDK")
        basis = (f"cpu.shares heuristic: ceil(request {fmt_millicores(req)} / "
                 f"1000m) - applies to {ver} (JDK 8 / pre-11.0.17). JDK "
                 f"11.0.17+/17+ would instead see ALL node CPUs here.")

    where = f"{doc.kind} '{doc_name(doc)}' / container '{cname}'"
    rows = [
        ["CPU request", fmt_millicores(req) if req is not None else "NOT SET",
         "guaranteed share under contention; HPA denominator"],
        ["CPU limit", fmt_millicores(lim) if lim is not None else "none",
         "hard CFS quota per 100ms period" if lim is not None else
         "pod may use idle node CPU"],
        ["availableProcessors()", str(cpus_seen), basis],
        ["Consequences", "",
         f"sizes GC threads, ForkJoinPool, C2 compiler threads, "
         f"Netty event loops"],
    ]
    concl = []
    if lim is not None and lim < 2000:
        concl.append(
            f"With {fmt_millicores(lim)} limit the JVM sees "
            f"{max(1, math.ceil(lim/1000))} CPU(s): ergonomics may select "
            f"SerialGC (<2 cpus) and common pools collapse to 1 thread.")
    if lim is not None and req is not None and lim == req and lim < 1000:
        concl.append(
            f"Guaranteed-but-tiny CPU: JVM startup (JIT) on "
            f"{fmt_millicores(lim)} typically multiplies startup time by "
            f"{max(1, round(2000/lim))}x vs 2 cores.")
    cpus_int = (cpus_seen if isinstance(cpus_seen, int)
                else int(cpus_seen) if str(cpus_seen).isdigit() else 2)
    if lim is not None:
        concl.append(
            f"CFS math: quota = {lim/1000:.2f} x 100ms = {lim/10:.0f}ms "
            f"runnable per 100ms window across ALL threads; a "
            f"{max(2, cpus_int)}-thread GC burst of 100ms wall time is "
            f"throttled for the remainder of each window (visible as latency "
            f"spikes at p99).")
    else:
        concl.append("No CPU limit: generally GOOD for JVMs (no CFS throttle); "
                     "requests still guarantee fair share under contention.")
    result.add_proof(ProofTable(
        title=f"CPU as seen by the JVM - {where}",
        intro="Kubernetes CPU limits are CFS quotas; the JVM derives its "
              "parallelism from them.",
        headers=["Item", "Value", "Meaning"],
        rows=rows,
        conclusion=" ".join(concl)))


# ---------------------------------------------------------------------------
# 3. QoS / bin-packing
# ---------------------------------------------------------------------------

def _qos_table(ctx, result):
    rows = []
    for doc in ctx.workloads:
        for c in containers(doc):
            cname = c.get("name", "?")
            _, rc = _res(c, "requests", "cpu")
            _, rm = _res(c, "requests", "memory")
            _, lc = _res(c, "limits", "cpu")
            _, lm = _res(c, "limits", "memory")
            qos = qos_class(rc, rm, lc, lm,
                            has_requests=rc is not None or rm is not None,
                            has_limits=lc is not None or lm is not None)
            rows.append([
                f"{doc.kind}/{doc_name(doc)}:{cname}",
                fmt_millicores(rc) if rc is not None else "-",
                fmt_bytes(rm) if rm is not None else "-",
                fmt_millicores(lc) if lc is not None else "-",
                fmt_bytes(lm) if lm is not None else "-",
                qos,
                "evicted FIRST" if qos == "BestEffort" else
                ("evicted before Guaranteed" if qos == "Burstable" else
                 "evicted last"),
            ])
    if not rows:
        return
    result.add_proof(ProofTable(
        title="QoS class and eviction order",
        intro="QoS derivation: Guaranteed iff requests == limits for BOTH cpu "
              "and memory on every container; BestEffort iff none set; else "
              "Burstable. Under node memory pressure kubelet evicts "
              "BestEffort, then Burstable exceeding requests, then Guaranteed "
              "last.",
        headers=["Container", "req CPU", "req Mem", "lim CPU", "lim Mem",
                 "QoS", "Eviction"],
        rows=rows,
        conclusion="For latency-sensitive JVMs aim for Guaranteed memory "
                   "(request = limit) and request-only CPU."))


# ---------------------------------------------------------------------------
# 4. HPA scaling arithmetic
# ---------------------------------------------------------------------------

def _hpa_math(ctx, result):
    for hpa in ctx.hpas:
        spec = hpa.data.get("spec") if isinstance(hpa.data, dict) else {}
        if not isinstance(spec, dict):
            continue
        name = doc_name(hpa)
        mn = as_int(spec.get("minReplicas"))
        mn = mn if mn is not None else 1
        mx = as_int(spec.get("maxReplicas"))
        target_pct = None
        if isinstance(spec.get("targetCPUUtilizationPercentage"), int):
            target_pct = spec["targetCPUUtilizationPercentage"]
        for m in spec.get("metrics") or []:
            if isinstance(m, dict) and str(m.get("type", "")).lower() == "resource":
                r = m.get("resource") or {}
                if str(r.get("name", "")).lower() == "cpu":
                    t = r.get("target") or {}
                    if isinstance(t.get("averageUtilization"), int):
                        target_pct = t["averageUtilization"]
        if target_pct is None or target_pct <= 0:
            continue    # invalid target: finding HP026 covers it; no table

        # find a cpu request to anchor the math
        req = None
        for w in ctx.workloads:
            for c in containers(w):
                _, rc = _res(c, "requests", "cpu")
                if rc:
                    req = rc
                    break
            if req:
                break

        rows = []
        cur = max(mn, 1)
        scenarios = [0.5, 0.9, 1.0, 1.11, 1.5, 2.0, 3.0]
        for s in scenarios:
            util = int(round(s * target_pct))
            desired = math.ceil(cur * util / target_pct) if target_pct else cur
            within_tol = abs(util / target_pct - 1) <= 0.10
            if within_tol:
                action = "no change (within 10% tolerance)"
                desired_c = cur
            else:
                desired_c = desired
                if mx is not None:
                    desired_c = min(max(desired, mn), mx)
                action = ("scale DOWN" if desired_c < cur else
                          "scale UP" if desired_c > cur else "no change")
            usage_str = (f"{int(util*req/100)}m/pod" if req else f"{util}% of request")
            rows.append([f"{util}%", usage_str,
                         f"ceil({cur} x {util}/{target_pct}) = {desired}",
                         str(desired_c), action])
        concl = (f"Formula: desired = ceil(current x currentUtil / target), "
                 f"clamped to [{mn}, {mx if mx is not None else '?'}], with a "
                 f"+/-10% tolerance dead-band. ")
        if req:
            trigger = int(req * target_pct / 100 * 1.1)
            concl += (f"With cpu request {fmt_millicores(req)} and target "
                      f"{target_pct}%, scale-out begins once average usage "
                      f"exceeds ~{trigger}m per pod "
                      f"({target_pct}% x {fmt_millicores(req)} x 1.1).")
        else:
            concl += ("No CPU request found on the target workload: this whole "
                      "table is THEORETICAL - the controller cannot compute "
                      "utilization at all (see finding HP022).")
        result.add_proof(ProofTable(
            title=f"HPA scaling arithmetic - HPA '{name}'",
            intro=f"How the HPA converts measured CPU into replica counts "
                  f"(current replicas = {cur} for illustration).",
            headers=["Avg utilization", "Per-pod usage", "Raw formula",
                     "Desired (clamped)", "Action"],
            rows=rows,
            conclusion=concl))


# ---------------------------------------------------------------------------
# 5. Probe timing vs JVM startup
# ---------------------------------------------------------------------------

_PROBE_TABLE_CAP = 4    # one per liveness-bearing container, bounded


def _probe_vs_startup(ctx, result):
    emitted = 0
    for doc in ctx.workloads:
        for c in containers(doc):
            if is_sidecar(c.get("name", ""), c.get("image", "")):
                continue
            live = c.get("livenessProbe")
            if not isinstance(live, dict):
                continue
            startup = c.get("startupProbe")
            def gi(p, k, d):
                v = p.get(k, d)
                return v if isinstance(v, int) else d
            init = gi(live, "initialDelaySeconds", 0)
            period = gi(live, "periodSeconds", 10)
            fail = gi(live, "failureThreshold", 3)
            kill = init + period * fail
            grace = 0
            if isinstance(startup, dict):
                grace = (gi(startup, "initialDelaySeconds", 0)
                         + gi(startup, "periodSeconds", 10)
                         * gi(startup, "failureThreshold", 3))
            budget = grace if grace else kill
            rows = [
                ["startupProbe window",
                 f"{grace}s" if grace else "none",
                 "liveness is suspended until startup succeeds" if grace else
                 "liveness starts immediately"],
                ["liveness initialDelaySeconds", f"{init}s", ""],
                ["liveness period x failureThreshold",
                 f"{period}s x {fail} = {period*fail}s", ""],
                ["Worst-case time-to-kill",
                 f"{budget}s",
                 ("startup window" if grace else
                  f"init({init}) + period({period}) x failures({fail})")],
                ["Typical JVM app startup", f"~{JVM_STARTUP_TYPICAL}s",
                 "mid-size Spring Boot on ~1 CPU (assumption; measure yours)"],
            ]
            if budget < JVM_STARTUP_TYPICAL:
                concl = (f"BUDGET {budget}s < startup ~{JVM_STARTUP_TYPICAL}s: "
                         f"kubelet kills the pod BEFORE the app can come up; "
                         f"each restart is slower (CPU contention) => "
                         f"CrashLoopBackOff of a perfectly healthy build.")
            else:
                concl = (f"Budget {budget}s >= ~{JVM_STARTUP_TYPICAL}s "
                         f"assumed startup: OK, provided startup never exceeds "
                         f"the budget under CPU pressure (verify with the CPU "
                         f"table above).")
            result.add_proof(ProofTable(
                title=f"Probe budget vs JVM startup - {doc.kind} "
                      f"'{doc_name(doc)}' / '{c.get('name','?')}'"
                      f"{_cond_note(doc)}",
                intro="A liveness probe that fires before the JVM can answer "
                      "does not detect failure - it CAUSES it.",
                headers=["Quantity", "Value", "Note"],
                rows=rows,
                conclusion=concl))
            emitted += 1
            if emitted >= _PROBE_TABLE_CAP:
                return


# ---------------------------------------------------------------------------
# 6. Availability math
# ---------------------------------------------------------------------------

def _availability_math(ctx, result):
    replicas = None
    for doc in ctx.workloads:
        if (doc.kind or "").lower() in ("deployment", "statefulset"):
            spec = doc.data.get("spec") if isinstance(doc.data, dict) else {}
            r = spec.get("replicas") if isinstance(spec, dict) else None
            if isinstance(r, int):
                replicas = r
                break
    mn = None
    for hpa in ctx.hpas:
        spec = hpa.data.get("spec") if isinstance(hpa.data, dict) else {}
        if isinstance(spec, dict) and as_int(spec.get("minReplicas")) is not None:
            mn = as_int(spec["minReplicas"])
    effective = mn if mn is not None else replicas
    if effective is None:
        return
    p = 0.995   # assumed per-pod availability incl. deploys/evictions
    rows = []
    for n in sorted(x for x in ({1, 2, 3, 5} | {effective}) if x >= 1):
        avail = 1 - (1 - p) ** n
        downtime_min = (1 - avail) * 30 * 24 * 60
        if downtime_min >= 1:
            dt = f"~{downtime_min:.1f} min/month"
        else:
            dt = f"~{downtime_min*60:.2f} sec/month"
        marker = "  <-- current floor" if n == effective else ""
        rows.append([str(n), f"{avail*100:.6f}%", f"{dt}{marker}"])
    concl = (f"Assuming INDEPENDENT pod failures at {p*100:.1f}% per-pod "
             f"availability, availability = 1-(1-p)^n. Your scale floor is "
             f"n={effective}"
             + (" (HPA minReplicas)" if mn is not None else " (fixed replicas)")
             + ". " + ("n=1 concentrates ~100x more downtime than n=2 - "
                       "redundancy, not pod quality, dominates availability."
                       if effective == 1 else
                       "n>=2 keeps single-failure downtime negligible; "
                       "protect it with a PDB.")
             + " Caveat: the independence assumption is exactly what fails in "
               "correlated events (bad deploy, node/zone outage, shared "
               "dependency down) - those hit ALL replicas at once and no "
               "exponent helps. Treat this table as the upper bound that "
               "redundancy alone can buy.")
    result.add_proof(ProofTable(
        title="Availability vs replica floor",
        intro="Redundancy math for the minimum number of pods the chart "
              "allows to exist.",
        headers=["Replicas n", "Availability 1-(1-p)^n", "Expected downtime"],
        rows=rows,
        conclusion=concl))

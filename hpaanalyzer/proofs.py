"""Cross-file analysis: JVM configuration vs chart resources, with proof tables.

Every table states its assumptions explicitly and derives a verdict from
arithmetic the reader can re-check by hand.
"""

import math
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from .dockerparse import effective_flags, flag_val, has_flag
from .kube import (SIDECAR_NAMES, as_int, containers, container_jvm_env_flags,
                   container_jvm_env_flag_source, container_jvm_evidence,
                   doc_name, is_sidecar, pod_spec)
from .podresources import pod_resources, pods_per_node
from .qos import eviction_note, pod_qos
from .models import (AnalysisResult, Basis, Category, ChartContext,
                     DockerfileInfo, Finding, MeasuredValues, ProofTable,
                     Severity)
from .quantity import fmt_bytes, fmt_millicores, parse_cpu, parse_jvm_size, parse_memory

MiB = 1024 ** 2
GiB = 1024 ** 3

class Est(NamedTuple):
    """An estimation constant that carries its own width and its own source.

    R9. These five numbers used to be bare ints with a comment beside them,
    and the comment was the only place the width existed:

        EST_METASPACE = 128 * MiB   # typical Spring/framework app: 80-180 MiB

    The report even printed that comment, in the Basis cell, next to the
    single value it did not use - and then carried the single value into a
    categorical verdict ("Fits with 108 MiB headroom") and into the grade.
    `proof/p9_estimates.py` measures what that costs: on byte-identical user
    files, moving metaspace to 180 - the number the tool prints in its own
    table - takes the flagship clean fixture from 100.0 and silence to 99.2
    and a MEDIUM finding; adding the Spring Boot Tomcat default of 200
    threads takes it to "expect kernel OOM kills (exit 137)". Three verdict
    categories, from constants the user never sees.

    The fix is not better constants. There is no value of EST_METASPACE that
    is right for every Spring app, and a tool that pretends otherwise is
    wrong in a way no amount of tuning reaches. The fix is to stop throwing
    the width away: carry (lo, point, hi, source) everywhere the number goes,
    report T as an interval, and let the verdict be UNDETERMINED when the
    limit falls inside it (C2.2) instead of picking an end and naming it
    headroom.

    `point` remains what every existing finding fires on, so the findings and
    the grade keep meaning exactly what they meant - now labelled as claims
    about typical values rather than about the user's chart. `lo`/`hi` decide
    only whether the ANSWER is determined. `source` is a citation, because an
    interval invented as freely as the point estimate would be the same
    defect with error bars painted on.
    """
    lo: int
    point: int
    hi: int
    source: str

    def band(self, fmt) -> str:
        return f"{fmt(self.lo)}-{fmt(self.hi)}"


# Documented estimation constants (surfaced in the tables, with their bands)
EST_METASPACE = Est(
    80 * MiB, 128 * MiB, 180 * MiB,
    "typical Spring/framework app; metaspace is uncapped by default and "
    "grows with loaded classes")
EST_CODECACHE = Est(
    32 * MiB, 64 * MiB, 128 * MiB,
    "JIT code cache steady-state occupancy; -XX:ReservedCodeCacheSize "
    "reserves 240 MiB by default but commits far less")
EST_THREADS = Est(
    50, 100, 200,
    "Spring Boot's embedded Tomcat defaults to server.tomcat.threads.max=200; "
    "a low-traffic service settles nearer 50")
EST_DIRECT = Est(
    16 * MiB, 64 * MiB, 128 * MiB,
    "netty/NIO direct buffers at steady state. NOT a cap: with no "
    "-XX:MaxDirectMemorySize the JVM's own limit defaults to max heap, so a "
    "leak goes far past the high end")
EST_GC_OTHER = Est(
    32 * MiB, 48 * MiB, 96 * MiB,
    "GC bookkeeping (card tables, remembered sets), symbol and string tables, "
    "JIT arenas, and the JVM binary itself")
EST_XSS = Est(
    MiB, MiB, MiB,
    "HotSpot ThreadStackSize default on Linux x86-64 = 1 MiB. Used only when "
    "the chart and image set no -Xss; a documented platform default, not an "
    "estimate, so its band has zero width")
ASSUMED_NODE_RAM = 16 * GiB    # for "JVM cannot see the limit" scenarios
JVM_STARTUP_TYPICAL = 60       # seconds, mid-size Spring app

# --measured keys -> the constant each one replaces.
MEASURABLE = {
    "metaspace": ("Metaspace", "bytes"),
    "codecache": ("JIT code cache", "bytes"),
    "threads": ("Thread count", "count"),
    "direct": ("Direct buffers", "bytes"),
    "gc": ("GC + JVM internal", "bytes"),
    "xss": ("Thread stack size", "bytes"),
}


def run(ctx: ChartContext, result: AnalysisResult) -> None:
    # R8. The comment that used to sit here was right about the principle and
    # wrong about the test: "inventing a JVM memory budget for a chart that may
    # run nginx would be fiction" - and then it gated on `ctx.dockerfiles`,
    # which admitted an nginx chart that happened to ship a Dockerfile and
    # turned away a chart whose pod spec asks for -Xmx4g under a 2Gi limit.
    # The guard against fiction is evidence that a JVM is involved, and
    # _pairs() now applies exactly that test. An empty list means no container
    # in this chart looks like a JVM; a non-empty one means at least one does,
    # with a quotable reason attached.
    pairs = _pairs(ctx)
    if pairs:
        for doc, container, df in pairs:
            _memory_budget(ctx, result, doc, container, df)
            _cpu_view(ctx, result, doc, container, df)
        _probe_vs_startup(ctx, result)
    _qos_table(ctx, result)
    _footprint_table(ctx, result)
    _hpa_math(ctx, result)
    _availability_math(ctx, result)


def _pairs(ctx) -> List[Tuple[Any, Dict, Optional[DockerfileInfo]]]:
    """(workload doc, container, dockerfile) triples worth analyzing.

    Sidecars (istio-proxy etc.) are excluded from JVM modelling - handing
    an Envoy proxy a JVM memory budget would be nonsense. If several
    Dockerfiles exist, the first Java-identifiable one is used and that
    assumption is stated in every table it produces.

    R8: the selection test is JVM EVIDENCE, not file existence.

      - A Java-identifiable Dockerfile is evidence for the whole chart, so
        every non-sidecar container is paired with it. That is the pre-R8
        behaviour for charts that had one, unchanged, which is what keeps this
        change strictly additive.
      - The old `df = ctx.dockerfiles[0]` fallback is gone. It was the
        invention half of the defect: it handed an nginx Dockerfile to the JVM
        modeller because it was the only file in the list, and the modeller
        does not read the file - it reads the flags - so a chart got a JVM
        memory budget for owning a filename.
      - With no Java-identifiable Dockerfile, containers qualify one at a time,
        on their own evidence (pod-spec JAVA_TOOL_OPTIONS, a JRE/JDK image),
        paired with df=None. The heap and the limit are both read from the
        chart in that case, so the arithmetic is no weaker for it - only the
        image-level context is missing, and _df_assumption() says so.
    """
    df = None
    for d in ctx.dockerfiles:
        if d.java_major or d.jvm_flags or d.java_opts:
            df = d
            break
    out = []
    for doc in ctx.workloads:
        if (doc.kind or "").lower() not in ("deployment", "statefulset", "daemonset"):
            continue
        for c in containers(doc):
            if is_sidecar(c.get("name", ""), c.get("image", "")):
                continue
            if df is None and not container_jvm_evidence(c):
                continue
            out.append((doc, c, df))
    return out


_NO_DF_ASSUMES = ("that the image's own java command line does not carry its "
                  "own -Xmx: a command-line -Xmx overrides JAVA_TOOL_OPTIONS, "
                  "and with no Dockerfile in scope that cannot be ruled out")


def _df_assumption(ctx, df: Optional[DockerfileInfo]) -> str:
    if df is None:
        # C2.3: say where the inputs came from at the point they are used. The
        # numbers in this table are read from the chart, not guessed - but the
        # reader is entitled to know that the image was never opened, because
        # that is the one place a contradicting -Xmx could be hiding.
        return (" No Java Dockerfile was in scope: the JVM configuration below "
                "was read from the pod spec (env) and the container image name, "
                "and any JVM flags baked into the image are NOT in this budget.")
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

def parse_measured(specs) -> MeasuredValues:
    """`--measured metaspace=210Mi,threads=180` -> {"metaspace": ..., ...}.

    Raises ValueError with a message the CLI prints verbatim. Anything it
    cannot parse is an error rather than a fallback: a user who passes a
    measurement and gets the estimate anyway has been told the opposite of
    the truth by a tool whose whole subject is not doing that.
    """
    out = MeasuredValues()
    for spec in (specs or []):
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                raise ValueError(f"'{part}' is not KEY=VALUE (keys: "
                                 f"{', '.join(sorted(MEASURABLE))})")
            k, v = (s.strip() for s in part.split("=", 1))
            if k not in MEASURABLE:
                raise ValueError(f"'{k}' is not a measurable component "
                                 f"(keys: {', '.join(sorted(MEASURABLE))})")
            kind = MEASURABLE[k][1]
            if kind == "count":
                if not v.isdigit() or int(v) <= 0:
                    raise ValueError(f"{k}='{v}' must be a positive whole "
                                     f"number of threads")
                out[k] = int(v)
            else:
                n = parse_memory(v)
                if n is None or n <= 0:
                    raise ValueError(f"{k}='{v}' is not a positive memory "
                                     f"quantity (try 210Mi, 1Gi, 256M)")
                out[k] = int(n)
            # Recorded only after the value validated, so a rejected spec
            # cannot leave a literal behind for a later key to cite.
            out.literals[k] = v
    return out


class Comp(NamedTuple):
    """One resolved line of the memory budget.

    Carries its own width and its own provenance so that every surface which
    prints it can print WHY, and so that C2.3 - "every estimated input must
    be labelled as an estimate inside the table, at the point of use" - is
    satisfied by construction rather than by remembering to write "(est.)"
    in the label. `basis` is OBSERVED only when the value came out of the
    user's files or off the command line; an estimate is DERIVED and says so
    in its own cell.
    """
    key: str            # --measured key, "" if this line cannot be measured
    label: str
    lo: int
    point: int
    hi: int
    basis: Basis
    source: str

    @property
    def width(self) -> int:
        return self.hi - self.lo

    @property
    def estimated(self) -> bool:
        return self.basis is not Basis.OBSERVED and self.width > 0


def _components(ctx, xss: int, xmx: Optional[int], maxdirect: Optional[int],
                c) -> List[Comp]:
    """The non-heap terms of T, each resolved to (lo, point, hi, basis).

    Resolution order per component: an explicit `--measured` value (OBSERVED,
    zero width - the user measured it, so the tool has nothing to estimate),
    then a value read from the user's files where one exists (also OBSERVED),
    then the documented band.
    """
    m = getattr(ctx, "measured", None) or {}

    def observed(key, label, val, source) -> Comp:
        return Comp(key, label, val, val, val, Basis.OBSERVED, source)

    def resolve(key, label, est: Est, source: str,
                observed_val: Optional[int] = None,
                observed_source: str = "") -> Comp:
        if key in m:
            # `cite` prefers the literal the user typed over the parsed
            # integer; a plain dict (library API, tests) has no literals and
            # falls back to the integer, which is then the whole truth.
            cite = m.cite(key) if isinstance(m, MeasuredValues) \
                else f"{key}={m[key]}"
            return observed(key, label, m[key], f"MEASURED: --measured {cite}")
        if observed_val is not None:
            return observed(key, label, observed_val, observed_source)
        return Comp(key, label, est.lo, est.point, est.hi, Basis.DERIVED,
                    source)

    xss_c = resolve(
        "xss", "Thread stack size", EST_XSS, EST_XSS.source,
        observed_val=xss if xss is not None else None,
        observed_source=f"-Xss ({fmt_bytes(xss)}) from the applied JVM flags"
        if xss is not None else "")
    threads = resolve("threads", "Thread count", EST_THREADS,
                      EST_THREADS.source)

    # Direct buffers: the JVM's own default cap is max heap, so no estimate
    # may exceed it. The clamp is arithmetic on an observed value and is
    # applied to all three ends, not just the point - clamping only the point
    # would let `hi` claim a footprint the JVM would refuse to allocate.
    if maxdirect is not None:
        direct = observed("direct", "Direct buffers", maxdirect,
                          f"-XX:MaxDirectMemorySize ({fmt_bytes(maxdirect)}), "
                          f"explicit")
    elif "direct" in m:
        direct = resolve("direct", "Direct buffers", EST_DIRECT, "")
    else:
        cap = xmx if xmx is not None else None
        lo, pt, hi = EST_DIRECT.lo, EST_DIRECT.point, EST_DIRECT.hi
        src = EST_DIRECT.source
        if cap is not None:
            lo, pt, hi = min(lo, cap), min(pt, cap), min(hi, cap)
            src += (f". Clamped here to -Xmx ({fmt_bytes(cap)}), which is "
                    f"where that default cap lands for this container")
        direct = Comp("direct", "Direct buffers", lo, pt, hi, Basis.DERIVED,
                      src)

    stacks = Comp(
        "", "Thread stacks",
        threads.lo * xss_c.lo, threads.point * xss_c.point,
        threads.hi * xss_c.hi,
        Basis.OBSERVED if (threads.basis is Basis.OBSERVED
                           and xss_c.basis is Basis.OBSERVED) else Basis.DERIVED,
        f"thread count x stack size (both rows below)")

    return [
        resolve("metaspace", "Metaspace", EST_METASPACE, EST_METASPACE.source),
        resolve("codecache", "JIT code cache", EST_CODECACHE,
                EST_CODECACHE.source),
        stacks, threads, xss_c, direct,
        resolve("gc", "GC + JVM internal", EST_GC_OTHER, EST_GC_OTHER.source),
    ]


def _summed(comps: List[Comp]) -> List[Comp]:
    """The components that are TERMS OF T.

    `threads` and `xss` are printed so the reader can see where the stacks
    row came from, but adding them to T would double-count the stacks and
    add a thread COUNT to a pile of bytes. The split is why this function
    exists rather than a slice: a term of T is identified explicitly, not by
    its position in a list somebody may reorder later.
    """
    return [x for x in comps if x.label not in ("Thread count",
                                                "Thread stack size")]


def _stacks(comps: List[Comp]) -> Comp:
    return next(x for x in comps if x.label == "Thread stacks")


def _nonheap(comps: List[Comp]) -> Comp:
    terms = _summed(comps)
    return Comp("", "non-heap total",
                sum(x.lo for x in terms), sum(x.point for x in terms),
                sum(x.hi for x in terms), Basis.DERIVED, "sum of the terms")


def _comp_rows(comps: List[Comp]) -> List[List[str]]:
    """Table rows. Every estimated value states its own band in its own cell.

    This is C2.3 discharged at the point of use. The old table printed
    `Thread stacks (100 x 1 MiB)` over the Basis `-Xss x thread count`, which
    reads as arithmetic on two values the tool had read; on good-chart one of
    them really was read (`-Xss1m` is in its Dockerfile) and the other was
    invented, and on initheavy-chart neither was - the cell cited a flag that
    does not appear anywhere in the user's files.
    """
    rows = []
    for x in comps:
        indent = "  " if x.label in ("Thread count", "Thread stack size") else ""
        if x.label == "Thread count":
            val = (str(x.point) if x.basis is Basis.OBSERVED
                   else f"{x.point} (est. {x.lo}-{x.hi})")
        elif x.estimated:
            val = fmt_bytes(x.point)
        else:
            val = fmt_bytes(x.point)
        label = indent + x.label
        if x.estimated:
            label += " (est.)"
        basis = x.source
        if x.estimated and x.label != "Thread count":
            basis = (f"est. {fmt_bytes(x.point)}, range "
                     f"{fmt_bytes(x.lo)}-{fmt_bytes(x.hi)}; {x.source}")
        elif x.estimated:
            basis = f"est. {x.point}, range {x.lo}-{x.hi}; {x.source}"
        rows.append([label, val, basis])
    return rows


def _crossovers(lim: int, t_point: int, comps: List[Comp]) -> List[Tuple[Comp, str]]:
    """Which single assumption, on its own, decides the answer - and where.

    For each term, hold every other term at its typical value and ask: what
    value of THIS one puts T exactly on the limit? If that value falls inside
    the term's own documented band, then this term alone flips the verdict,
    and the reader is entitled to know which one and at what number. Sorted
    widest band first, because that is the one worth measuring.
    """
    out = []
    for x in _summed(comps):
        if not x.estimated:
            continue
        base = t_point - x.point            # T with this term removed
        cross = lim - base                  # value of this term that hits L
        if not (x.lo <= cross <= x.hi):
            continue
        if x.label == "Thread stacks":
            th = next((t for t in comps if t.label == "Thread count"), None)
            xs = next((s for s in comps if s.label == "Thread stack size"), None)
            if th and xs and xs.point:
                out.append((x, f"{fmt_bytes(cross)} of stacks = "
                               f"{cross // xs.point} threads at "
                               f"{fmt_bytes(xs.point)} each (est. band "
                               f"{th.lo}-{th.hi} threads)"))
                continue
        out.append((x, f"{fmt_bytes(cross)} (est. band "
                       f"{fmt_bytes(x.lo)}-{fmt_bytes(x.hi)})"))
    out.sort(key=lambda p: -p[0].width)
    return out


def _measurable(comps: List[Comp]) -> Tuple[List[str], List[str]]:
    """(--measured keys still estimated, keys the user has already supplied).

    R9's first draft ended every undetermined verdict with the same canned
    string: `--measured metaspace=...,threads=...,direct=...`. Measured
    against a run that had already passed
    `--measured metaspace=210Mi,threads=180`, that advice named two components
    the reader had just supplied and omitted both of the ones still deciding
    the answer - the tool telling somebody to go and do the thing they had
    done, while staying silent about the thing that would have worked.

    C2.8(e) requires the tool to name the observation that would settle it,
    and after a partial measurement that is by definition the observation
    still missing. So the list is derived from the same `Comp` records the
    table prints - `estimated` is the property the row's `(est.)` label is
    also computed from - rather than written out by hand in a sentence.
    """
    still = [c.key for c in comps if c.key and c.estimated]
    done = [c.key for c in comps if c.key and c.source.startswith("MEASURED:")]
    return still, done


def _settle_flags(comps: List[Comp]) -> str:
    still, _ = _measurable(comps)
    return ",".join(f"{k}=..." for k in still)


def _deciding_names(lim: int, total: int,
                    comps: List[Comp]) -> Optional[Tuple[str, int, int]]:
    """The smallest set of estimates that, together, cross the limit.

    Returns (names, movement, gap) or None when even every estimate at its
    worst end does not close the gap. Greedy by REMAINING band width, so the
    set named is the fewest assumptions that would have to be wrong together.

    This is the computation. It has two renderings - the verdict sentence in
    _deciding_set() and the compact coverage-row phrase in _memory_budget() -
    and they share it rather than each doing string surgery on the other's
    prose. An earlier draft had the coverage row `.rstrip(".")` this
    function's finished sentence and concatenate it onto its own clause,
    which produced "...inside its own band No single estimate crosses the
    limit on its own inside its documented band; ...": the same fact stated
    twice, once ungrammatically. Two callers wanting different words is not
    a reason to edit words; it is a reason to return values.
    """
    gap = lim - total
    up = gap >= 0            # fits at typical values -> what would push it over
    room = [(x, (x.hi - x.point) if up else (x.point - x.lo))
            for x in _summed(comps) if x.estimated]
    room = [(x, r) for x, r in room if r > 0]
    room.sort(key=lambda p: -p[1])
    need, chosen, acc = abs(gap), [], 0
    for x, r in room:
        if acc > need:
            break
        chosen.append((x, r))
        acc += r
    if acc <= need or not chosen:
        return None
    names = ", ".join(
        f"{x.label} at its {'high' if up else 'low'} end "
        f"({fmt_bytes(x.hi if up else x.lo)})" for x, _ in chosen)
    return names, acc, need


def _deciding_set(lim: int, total: int, comps: List[Comp]) -> str:
    """When no SINGLE estimate crosses the limit, name the smallest set that does.

    "Undetermined, somewhere in a 500 MiB range" is honest and nearly
    useless; the reader's next question is always "so what would have to be
    true?". On good-chart nothing crosses alone - metaspace would have to
    reach 236 MiB against a documented ceiling of 180 - but thread stacks at
    their high end plus the code cache at its high end covers the 108 MiB
    gap, which is exactly the combination proof/p9_estimates.py drives to
    flip the fixture from silence to "expect kernel OOM kills".
    """
    got = _deciding_names(lim, total, comps)
    if got is None:
        return ""
    names, acc, need = got
    return (f" No single estimate crosses the limit on its own inside its "
            f"documented band; the smallest set that does is {names}, which "
            f"moves T by {fmt_bytes(acc)} against a gap of "
            f"{fmt_bytes(need)}.")


def _undetermined_verdict(lim: int, total: int, t_lo: int, t_hi: int,
                          heap: Optional[int], comps: List[Comp],
                          margin: int) -> str:
    """The third state. C2.2: report it, do not resolve it by picking a side.

    Everything here is measured, not hedged: the range is real arithmetic on
    documented bands, and the crossover values are exact. What the tool does
    NOT do is convert its ignorance into a verdict in either direction -
    neither "fits with headroom" (which is what it used to do, and what
    proof/p9_estimates.py shows costs three verdict categories) nor a
    severity-ranked finding, which would be the same error pointed the other
    way: an assertion about the user's chart manufactured out of the tool's
    own uncertainty.
    """
    deciders = _crossovers(lim, total, comps)
    at_typical = ("fits" if margin >= 0 else "does not fit")
    head = (f"UNDETERMINED: the limit {fmt_bytes(lim)} falls INSIDE the range "
            f"this model can produce ({fmt_bytes(t_lo)} - {fmt_bytes(t_hi)}), "
            f"so whether the JVM fits is decided by the estimates and not by "
            f"your chart. At typical values it {at_typical} "
            f"({'+' if margin >= 0 else '-'}{fmt_bytes(abs(margin))}); that "
            f"number is reported, and findings are raised from it, as a claim "
            f"about typical values only.")
    if deciders:
        comp, where = deciders[0]
        head += (f" The single assumption that decides it is {comp.label}: "
                 f"at {where} the total is exactly on the limit.")
        if len(deciders) > 1:
            head += (" Also decisive on its own: "
                     + ", ".join(f"{c.label} at {w.split(' (est.')[0]}"
                                 for c, w in deciders[1:]) + ".")
    else:
        head += _deciding_set(lim, total, comps)
    still, done = _measurable(comps)
    if done:
        head += (f" You have already measured {', '.join(done)}; what is left "
                 f"undetermined is decided by the "
                 f"{'component' if len(still) == 1 else 'components'} you "
                 f"have not: {', '.join(still)}.")
    head += (" To settle it, measure and re-run: "
             "`kubectl exec POD -- jcmd 1 VM.native_memory summary` "
             "(needs -XX:NativeMemoryTracking=summary)")
    flags = _settle_flags(comps)
    # `flags` is empty only if nothing is estimated, in which case t_lo == t_hi
    # and this verdict is unreachable. Guarded anyway rather than printing a
    # bare `--measured ` with nothing after it: an instruction the reader
    # cannot follow is worse than the sentence ending one clause early.
    if flags:
        head += f", then pass the numbers back with --measured {flags}"
    return head


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
    # R9: this used to read `xss = xss or MiB`, which collapsed "the chart
    # sets -Xss1m" and "the chart sets no -Xss at all" into the same integer,
    # after which the budget table cited "-Xss x thread count" as the Basis
    # on charts containing no -Xss anywhere. The None survives now, and
    # _components() turns it into a documented platform default that says so.
    xss = parse_jvm_size(flag_val(flags, "Xss") or "") if flags else None
    maxdirect = parse_jvm_size(flag_val(flags, "MaxDirectMemorySize") or "") if flags else None
    sees, sees_note = _jvm_sees_limit(df)

    # ----- derive effective max heap (and how confidently we know it) -----
    def _via(needle: str) -> str:
        """' via pod-spec env JAVA_TOOL_OPTIONS', when that is where it came
        from. The reader has to be told which file to edit, and with no
        Dockerfile in scope this is also the only place the report names the
        mechanism that makes the flag apply at all."""
        src = container_jvm_env_flag_source(c, needle)
        return f" via pod-spec env {src}" if src else ""

    if xmx is not None:
        heap = xmx
        heap_src = f"-Xmx ({fmt_bytes(xmx)}){_via('Xmx')}"
        heap_basis = Basis.OBSERVED
    elif pct is not None and lim is not None and sees:
        heap = int(lim * pct / 100)
        heap_src = (f"MaxRAMPercentage={pct:g}%{_via('MaxRAMPercentage')} "
                    f"x limit {fmt_bytes(lim)}")
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

    def _assumes(basis) -> Optional[str]:
        """What could overturn a finding built on this arithmetic.

        R8: with no Dockerfile in scope, both the heap and the limit are still
        read straight out of the user's own files, so the basis stays OBSERVED
        - C2.2 forbids downgrading a fact because the tool wishes it knew more.
        What it requires instead is that the one thing which could overturn the
        conclusion is named, so the reader can check it in ten seconds.
        """
        parts = []
        if basis is Basis.ASSUMED:
            parts.append(node_assumes)
        if df is None:
            parts.append(_NO_DF_ASSUMES)
        return "; ".join(parts) if parts else None

    def _assumes_estimates(basis, comps) -> Optional[str]:
        """`assumes` for a finding whose subject is the SUM.

        R9. XF004's `assumes` was null and XF002's named only the assumption
        the tool had inherited (a command-line -Xmx could override the heap),
        which proved the field was live and reachable on exactly these
        findings - and that none of the five constants supplying 404 of
        good-chart's 916 MiB had ever been written into it. A finding that
        exists only because of an estimate must name the estimate, its band
        and its source, or the reader has no way to know what would overturn
        it.
        """
        parts = [p for p in [_assumes(basis)] if p]
        est = [x for x in _summed(comps) if x.estimated]
        if est:
            named = "; ".join(
                f"{x.label} {fmt_bytes(x.point)} (range "
                f"{fmt_bytes(x.lo)}-{fmt_bytes(x.hi)}: {x.source})"
                for x in est)
            parts.append(
                f"that the non-heap components take their typical values - "
                f"{named}. Each is an estimate, not a measurement; pass "
                f"--measured to replace any of them with a number from "
                f"`jcmd 1 VM.native_memory summary`")
        return "; ".join(parts) if parts else None

    comps = _components(ctx, xss, xmx, maxdirect, c)
    stacks = _stacks(comps).point
    nonheap = _nonheap(comps)
    budget_state = ""       # "over" | "fits" | "undetermined"; "" = no limit
    if heap is not None:
        total = heap + nonheap.point
        t_lo, t_hi = heap + nonheap.lo, heap + nonheap.hi
    else:
        total = t_lo = t_hi = None

    where = f"{doc.kind} '{doc_name(doc)}' / container '{cname}'"
    rows = [
        ["Container memory limit", fmt_bytes(lim) if lim else "NOT SET",
         lim_raw if lim_raw else "-"],
        ["Max heap (H)", fmt_bytes(heap) if heap else "UNBOUNDED", heap_src],
    ]
    rows.extend(_comp_rows(comps))

    # `banded` is false only when the user has measured EVERY non-heap
    # component (--measured), so there is nothing left inside the sum for a
    # range to be a range OF. R9 exists to stop the tool overstating what it
    # knows; printing "T RANGE 852 MiB - 852 MiB" and "still fits with every
    # estimate at its high end" over a sum with no estimates left in it is
    # the same fault pointed the other way - it implies an uncertainty the
    # tool no longer has, and invites the reader to discount a number they
    # measured themselves. When the width is zero, the width is not reported.
    banded = total is not None and t_hi > t_lo
    rows.append(["ESTIMATED PEAK RSS (T)",
                 fmt_bytes(total) if total else "UNBOUNDED",
                 "T = H + non-heap components (typical values)" if banded
                 else "T = H + non-heap components (all measured, no estimates)"])
    if banded:
        rows.append(["T RANGE (lo - hi)", f"{fmt_bytes(t_lo)} - {fmt_bytes(t_hi)}",
                     "every estimate above at its low end, then its high end"])
    if lim and total:
        margin = lim - total
        rows.append(["Margin (limit - T)",
                     ("+" if margin >= 0 else "") + fmt_bytes(abs(margin)) if margin >= 0
                     else "-" + fmt_bytes(abs(margin)),
                     f"{100*margin/lim:+.0f}% of limit"
                     + (", at typical values" if banded else "")])
        if banded:
            rows.append(["MARGIN RANGE", f"{fmt_bytes(lim - t_hi) if lim >= t_hi else '-' + fmt_bytes(t_hi - lim)}"
                                         f" - {fmt_bytes(lim - t_lo) if lim >= t_lo else '-' + fmt_bytes(t_lo - lim)}",
                         "limit - T at the pessimistic end, then the optimistic end"])

        # ---- the three-state verdict (R9) --------------------------------
        #
        # The old code had two branches and no third state: it compared the
        # POINT estimate to the limit and announced the winner. When the
        # limit falls inside the range the estimates can produce, there is no
        # winner to announce, and announcing one anyway is the C2.2 violation
        # this iteration exists to remove.
        #
        # The state is decided by WHERE THE LIMIT SITS relative to [t_lo,
        # t_hi], and by nothing else. A first draft of this used
        # `t_hi <= lim - 10%` as the fits test, which folded a comfort
        # judgement into an epistemic one: a sum whose entire range fits, but
        # with thin headroom, came out UNDETERMINED and printed "the limit
        # falls INSIDE the range (962 MiB - 962 MiB)" - a sentence refuted by
        # the two numbers inside its own parentheses. Whether the JVM fits and
        # whether the margin is comfortable are different questions; the first
        # picks the state here, the second is XF004's, and the 10% threshold
        # belongs only to the second.
        certain_from_heap = heap is not None and heap >= lim
        if t_lo > lim:
            budget_state = "over"
            certainty = ("This follows from your own numbers alone: the heap "
                         "you configured already meets the limit, before any "
                         "estimate is added."
                         if certain_from_heap else
                         "This holds at EVERY value in the ranges above, so "
                         "no substitution of the estimates reverses it.")
            if banded:
                verdict = (f"T exceeds the limit by {fmt_bytes(-margin)} at "
                           f"typical values, and by at least "
                           f"{fmt_bytes(t_lo - lim)} even with every estimate "
                           f"at its low end: expect kernel OOM kills (exit 137) "
                           f"once the heap approaches {fmt_bytes(heap)} under "
                           f"sustained load. {certainty}")
            else:
                verdict = (f"T exceeds the limit by {fmt_bytes(-margin)}: "
                           f"expect kernel OOM kills (exit 137) once the heap "
                           f"approaches {fmt_bytes(heap)} under sustained load. "
                           f"Every non-heap component here was measured and "
                           f"passed in with --measured, so this is arithmetic "
                           f"on observed values only.")
        elif t_hi <= lim:
            budget_state = "fits"
            # It fits at every value the model can produce. The remaining
            # question is only whether it fits COMFORTABLY, which is the same
            # 10% test the tool has always applied and which XF004 raises.
            if margin < int(0.1 * lim):
                verdict = (f"Margin {fmt_bytes(margin)} (<10% of limit) - one "
                           f"traffic spike, classloading burst or extra "
                           f"threads away from an OOM kill."
                           + (f" It fits at every value in the ranges above "
                              f"(worst case {fmt_bytes(lim - t_hi)} spare), so "
                              f"the thin margin is the finding, not the "
                              f"uncertainty." if banded else
                              " Every non-heap component here was measured and "
                              "passed in with --measured, so the thin margin "
                              "is a fact about this process, not an estimate."))
            elif banded:
                verdict = (f"Fits with {fmt_bytes(margin)} headroom "
                           f"({100*margin/lim:.0f}% of limit) at typical values, "
                           f"and still {fmt_bytes(lim - t_hi)} "
                           f"({100*(lim-t_hi)/lim:.0f}%) with every estimate at "
                           f"its high end. The conclusion does not depend on "
                           f"which value inside the ranges is right.")
            else:
                verdict = (f"Fits with {fmt_bytes(margin)} headroom "
                           f"({100*margin/lim:.0f}% of limit). Every non-heap "
                           f"component here was measured and passed in with "
                           f"--measured, so no estimate enters this sum and "
                           f"there is no range for the answer to depend on.")
        else:
            budget_state = "undetermined"
            verdict = _undetermined_verdict(lim, total, t_lo, t_hi, heap,
                                            comps, margin)

        # XF005 is not a claim about the budget at all - it says the heap is
        # a small fraction of memory the user is already paying for. That is
        # arithmetic on two observed values (H and the limit) and none of the
        # estimates enter it, so it fires on exactly the condition it always
        # fired on and the new third state does not touch it. R9's guard, in
        # miniature: widening what the tool admits it does not know must not
        # change what it does know.
        if margin >= int(0.1 * lim):
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

    # C2.2 / C2.5. When the limit falls inside the range the model can
    # produce, "does this JVM fit?" is a question the tool cannot answer from
    # the evidence, and that is a fact about the TOOL. It goes in coverage,
    # where undetermined things go, and NOT into a finding - the precedent is
    # checks_hpa.py's UNDETERMINED coverage rows for subchart-satisfied
    # scaleTargetRefs, which likewise say "not reported as a finding either
    # way" and name the command that settles it. Manufacturing a MEDIUM here
    # would convert the tool's ignorance into a severity-ranked claim about
    # the user's chart: the same C2.2 error, pointed the other way.
    if budget_state == "undetermined":
        deciders = _crossovers(lim, total, comps)
        if deciders:
            who = (f"decided on its own by {deciders[0][0].label} "
                   f"(crossover at {deciders[0][1]})")
        else:
            got = _deciding_names(lim, total, comps)
            who = ("decided by no single estimate but by {0} together "
                   "({1} of movement against a {2} gap)".format(
                       got[0], fmt_bytes(got[1]), fmt_bytes(got[2]))
                   if got else
                   "decided by the estimates collectively; no set of them "
                   "inside its documented bands closes the gap, so the "
                   "range itself is the answer")
        ctx.coverage.append(
            [f"JVM memory fit - {where}",
             f"UNDETERMINED - the limit {fmt_bytes(lim)} lies inside the "
             f"model's range {fmt_bytes(t_lo)}-{fmt_bytes(t_hi)}, so the "
             f"answer is {who}. At typical values T={fmt_bytes(total)} "
             f"(margin {'+' if margin >= 0 else '-'}"
             f"{fmt_bytes(abs(margin))}), and any finding below is raised "
             f"from that point estimate and labelled as such. Not reported "
             f"as a fit or a misfit either way. To settle it: kubectl exec "
             f"POD -- jcmd 1 VM.native_memory summary, then re-run with "
             f"--measured {_settle_flags(comps)}"])

    if lim and total and 0 <= (lim - total) < int(0.1 * lim):
        result.add(Finding(
            rule_id="XF004", severity=Severity.MEDIUM, category=Category.CROSS,
            title="JVM memory margin under 10% of the limit"
                  + (" at typical non-heap values" if banded else ""),
            file=doc.file,
            basis=total_basis,
            assumes=_assumes_estimates(heap_basis, comps),
            detail=f"{where}: estimated peak RSS {fmt_bytes(total)} vs limit "
                   f"{fmt_bytes(lim)} - margin {fmt_bytes(lim - total)} "
                   f"({100*(lim-total)/lim:.0f}%)."
                   + (f" At the ends of the documented ranges T is "
                      f"{fmt_bytes(t_lo)}-{fmt_bytes(t_hi)}." if banded else
                      " Every non-heap component was supplied with --measured, "
                      "so T has no range."),
            why=("The estimate uses typical non-heap components (stated in the "
                 "budget table); real Spring apps routinely exceed them "
                 "(metaspace growth, more threads, bigger direct buffers). A "
                 "single-digit margin means routine variance ends in a kernel "
                 "OOM kill." if banded else
                 "The components are measured, but a measurement is a snapshot "
                 "of one moment in one process: metaspace grows as classes "
                 "load, the thread count moves with traffic, and direct "
                 "buffers move with connections. A single-digit margin means "
                 "routine variance ends in a kernel OOM kill."),
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
            assumes=_assumes(heap_basis),
            detail=f"{where}: effective max heap {fmt_bytes(heap)} "
                   f"({heap_src}) vs limits.memory {fmt_bytes(lim)}.",
            why="The heap ALONE meets or exceeds the limit before counting "
                "metaspace, stacks and buffers. The kernel will OOM-kill the "
                "container (exit 137, no Java stack trace, no heap dump) as "
                "soon as the heap fills - typically under first real load.",
            fix="Heap <= 50-75% of the limit. Either raise limits.memory or "
                "lower -Xmx/MaxRAMPercentage.",
            math=f"H({fmt_bytes(heap)}) >= L({fmt_bytes(lim)}); "
                 f"required: H + ~{fmt_bytes(nonheap.point)} "
                 f"(non-heap, {fmt_bytes(nonheap.lo)}-{fmt_bytes(nonheap.hi)}) "
                 f"<= L. The >= above is arithmetic on two values from your "
                 f"own files; no estimate enters it, and no value of the "
                 f"estimates changes it."))
    elif lim and total and total > lim:
        result.add(Finding(
            rule_id="XF002", severity=Severity.HIGH, category=Category.CROSS,
            title=("Estimated JVM footprint exceeds memory limit"
                   if budget_state == "over" else
                   "Estimated JVM footprint exceeds memory limit at typical "
                   "non-heap values"),
            file=doc.file,
            basis=total_basis,
            assumes=_assumes_estimates(heap_basis, comps),
            detail=f"{where}: estimated peak RSS {fmt_bytes(total)} > limit "
                   f"{fmt_bytes(lim)} (see memory budget table)."
                   + ("" if not banded else
                      f" Across the documented ranges T is "
                      f"{fmt_bytes(t_lo)}-{fmt_bytes(t_hi)}"
                      + (", so the excess holds at every value in them."
                         if budget_state == "over" else
                         f", which spans the limit - see the UNDETERMINED "
                         f"coverage row for {where}.")),
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
    """QoS is a property of the POD. This table shows the per-container inputs
    and then the pod verdict, computed by hpaanalyzer.qos (a port of upstream
    ComputePodQOS). Reading a container row as "the QoS" is the mistake this
    layout exists to prevent, so the pod row is always present and always last
    within its workload."""
    rows = []
    verdicts = []
    for doc in ctx.workloads:
        ps = pod_spec(doc)
        pq = pod_qos(ps)
        by_name = {d.name: d for d in pq.containers}
        wname = f"{doc.kind}/{doc_name(doc)}"

        for c in list(_spec_list(ps, "initContainers")) + list(_spec_list(ps, "containers")):
            cname = str(c.get("name", "?"))
            d = by_name.get(cname)
            rq, rl = _res(c, "requests", "cpu"), _res(c, "limits", "cpu")
            mq, ml = _res(c, "requests", "memory"), _res(c, "limits", "memory")
            def _cell(pair, fmt, res_name, d=d):
                raw, val = pair
                if raw is None:
                    if d and res_name in d.defaulted:
                        return "= limit*"
                    return "-"
                return fmt(val) if val is not None else f"{raw!r} (unparseable)"
            rows.append([
                f"{wname}:{cname}",
                d.kind if d else "container",
                _cell(rq, fmt_millicores, "cpu"),
                _cell(mq, fmt_bytes, "memory"),
                _cell(rl, fmt_millicores, "cpu"),
                _cell(ml, fmt_bytes, "memory"),
                d.qos if d else "?",
            ])
        rows.append([f"{wname}  => POD", "-", "-", "-", "-", "-", pq.qos])
        verdicts.append(f"{wname}: {pq.qos} - {pq.reason}. "
                        f"{eviction_note(pq.qos)}.")

    if not rows:
        return
    result.add_proof(ProofTable(
        title="QoS class and eviction order (pod-level)",
        intro="Derivation, ported from Kubernetes "
              "pkg/apis/core/v1/helper/qos/qos.go: per container and per "
              "resource, request != limit -> Burstable; request == limit == 0 "
              "(or unset) -> BestEffort; request == limit != 0 -> Guaranteed. "
              "The pod is Burstable as soon as ONE container is Burstable or "
              "two containers disagree; init containers are included. "
              "'= limit*' marks a request Kubernetes defaults from the limit "
              "at pod creation (SetDefaults_Pod) - such a container is "
              "Guaranteed even though the chart writes no requests block.",
        headers=["Container", "Role", "req CPU", "req Mem", "lim CPU",
                 "lim Mem", "container QoS"],
        rows=rows,
        conclusion="Pod verdicts: " + "  ".join(verdicts) +
                   "  Only the POD row is the value kubelet uses for eviction; "
                   "verify with kubectl get pod -o jsonpath="
                   "'{.items[*].status.qosClass}'."))


def _spec_list(ps, key):
    v = (ps or {}).get(key)
    return [c for c in v if isinstance(c, dict)] if isinstance(v, list) else []


# ---------------------------------------------------------------------------
# 3b. What the scheduler actually reserves
# ---------------------------------------------------------------------------

def _footprint_table(ctx, result):
    """The pod as the scheduler sees it.

    A per-container resources block answers "what may this process use". It
    does not answer "will this fit", "how many fit per node", or "what does a
    replica cost" - all of which are pod questions, and all of which the tool
    previously answered with a container number (proof/p2_sidecar.py: a 21x
    overstatement on the shipped sidecar fixture).

    Every row that contributes to the total is shown, with HOW it contributes,
    because contract C1.5 requires that any total say which containers are in
    it. That is not decoration: 'summed' vs 'peak only' is the entire
    difference between a native sidecar and an init container, and it is
    invisible in the YAML apart from one `restartPolicy: Always` line.
    """
    rows: List[List[str]] = []
    verdicts: List[str] = []
    notes: List[str] = []

    for doc in ctx.workloads:
        ps = pod_spec(doc)
        pr = pod_resources(ps)
        if not pr.shares and not pr.pod_level:
            continue
        wname = f"{doc.kind}/{doc_name(doc)}"

        # Role and "how it counts" are one column, not two, and the reason is
        # arithmetic rather than taste. At WIDTH=100 five columns left the
        # first one 31 chars wide, and the summary label
        # "Deployment/payments  => POD REQUEST" is 35 - so the renderer wrapped
        # the pod total's own label across two cells, and a reader scanning for
        # it found "=> POD" on one line and "REQUEST" on the next. A label that
        # has to be reassembled by eye is not a label. Merging the two columns
        # (the role IS how it counts: a sidecar is summed *because* it is a
        # sidecar) buys back 12 characters and the label stays whole.
        for s in pr.shares:
            how = {"container": "container, summed",
                   "sidecar": "native sidecar, summed",
                   "init": "init, peak only (max)"}[s.kind]
            rows.append([
                f"{wname}:{s.name}", how,
                fmt_millicores(s.requests.get("cpu") or 0),
                fmt_bytes(s.requests.get("memory") or 0)])

        if pr.overhead and any(pr.overhead.values()):
            rows.append([f"{wname}:<spec.overhead>",
                         "RuntimeClass, summed",
                         fmt_millicores(pr.overhead.get("cpu") or 0),
                         fmt_bytes(pr.overhead.get("memory") or 0)])

        rows.append([f"{wname}  steady state", "sum of the above",
                     fmt_millicores(pr.steady.get("cpu") or 0),
                     fmt_bytes(pr.steady.get("memory") or 0)])
        rows.append([f"{wname}  init peak",
                     "max(init + sidecars before it)",
                     fmt_millicores(pr.init_peak.get("cpu") or 0),
                     fmt_bytes(pr.init_peak.get("memory") or 0)])
        rows.append([f"{wname}  => POD REQUEST",
                     "pod-level spec.resources" if pr.pod_level
                     else "max(steady, init peak)",
                     fmt_millicores(pr.requests.get("cpu") or 0),
                     fmt_bytes(pr.requests.get("memory") or 0)])

        mem, cpu = pr.requests.get("memory"), pr.requests.get("cpu")
        fit = pods_per_node(mem, 8 * GiB)
        v = f"{wname}: reserves {fmt_millicores(cpu or 0)} CPU and " \
            f"{fmt_bytes(mem or 0)} on whichever node it lands."
        if fit is not None:
            v += f" An 8 GiB / 4-core node holds {fit} by memory request"
            if cpu:
                v += f", {(4000 // cpu)} by CPU request"
            v += "."
        verdicts.append(v)

        if pr.init_dominates:
            notes.append(
                f"{wname}: the init peak EXCEEDS the steady state, so the pod "
                f"reserves the larger number for its whole life - the node "
                f"cannot reclaim it once the init container exits.")
        for s in pr.sidecars():
            notes.append(
                f"{wname}: '{s.name}' is a NATIVE SIDECAR (restartPolicy: "
                f"Always on an init container). It is charged to the node "
                f"exactly like a regular container, not max'd like an init "
                f"container.")
        if not pr.decided:
            notes.append(f"{wname}: total is INCOMPLETE - unresolved "
                         f"quantities {sorted(set(pr.undetermined))}.")

    if not rows:
        return
    result.add_proof(ProofTable(
        title="Pod scheduling footprint (what the node reserves)",
        intro="Derivation, ported from Kubernetes component-helpers/resource/"
              "helpers.go (aggregateContainerResourcesByFn) and KEP-753: "
              "regular containers are SUMMED; an init container with "
              "restartPolicy: Always is a native sidecar (GA 1.33) and is also "
              "SUMMED, because it runs for the pod's whole life; a one-shot "
              "init container is MAX'd, against the sidecars declared before "
              "it - InitContainerUse(i) = sum(restartable init containers with "
              "index < i) + resources of the i-th. The pod's request is "
              "max(steady state, init peak), per resource. This is the number "
              "the scheduler compares against node allocatable; no container "
              "row is ever that number.",
        headers=["Container", "How it counts", "req CPU", "req Mem"],
        rows=rows,
        conclusion=" ".join(verdicts) +
                   ("  " + "  ".join(notes) if notes else "") +
                   "  Verify against a live pod with: kubectl get pod <name> "
                   "-o jsonpath='{.spec.containers[*].resources.requests}' "
                   "and kubectl describe node <node> (Allocated resources)."))


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

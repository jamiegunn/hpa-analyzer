"""Checks: Dockerfile quality and Java/JVM container fitness.

All flag-based checks distinguish APPLIED flags (what the JVM will really
see at runtime, per dockerparse.effective_flags) from flags trapped in an
inert JAVA_OPTS that nothing expands (finding DF013). Reality checks
(missing heap bound, missing ExitOnOutOfMemoryError) judge applied flags;
content checks on inert flags are annotated as latent.

JDK container-awareness timeline encoded here:

  Java 8  < 8u131   : zero cgroup awareness (heap sized from HOST RAM)
  8u131 - 8u190     : experimental -XX:+UseCGroupMemoryLimitForHeap only
  8u191+            : UseContainerSupport backported (default ON), MaxRAMPercentage
  Java 10+          : UseContainerSupport default ON
  cgroup v2 support : 8u372+ / 11.0.16+ / 15+ (earlier JVMs are BLIND to
                      limits on cgroup-v2 nodes - the default on modern distros)
"""

import os
import re
from typing import List, Optional

from .dockerparse import (effective_flags, extract_jvm_flags, flag_val,
                          has_flag, inert_opt_vars)
from .kube import (JVM_EVIDENCE_INPUTS, chart_jvm_env_flags, containers,
                   container_jvm_evidence, is_sidecar, jvm_evidence)
from .models import (AnalysisResult, Basis, Category, ChartContext,
                     DockerfileInfo, Finding, Severity)
from .quantity import fmt_bytes, parse_jvm_size


def run(ctx: ChartContext, result: AnalysisResult) -> None:
    # R8: two questions that the pre-R8 code answered with one test.
    #
    #   "Is there a Dockerfile?" decides whether IMAGE-level checks can run -
    #   base image pinning, entrypoint/signal handling, root user, layer
    #   hygiene. Those are properties of a file, so a missing file really is
    #   the end of them.
    #
    #   "Is this a JVM workload?" decides whether JAVA checks apply. That is a
    #   property of the workload, and `ls Dockerfile` is not a way to find it
    #   out. Asking it that way missed a -Xmx4g under a 2Gi limit because the
    #   chart shipped without a Dockerfile, and told an nginx chart to set
    #   -XX:MaxRAMPercentage because it shipped with one.
    #
    # F4: JVM options set via pod-spec env (JAVA_TOOL_OPTIONS etc.) are read by
    # the JVM no matter how the image was built. Fold them into the flags the
    # JVM actually receives so the analyzer neither invents "missing" findings
    # nor falsely absolves an over-large env-set heap.
    env_flags = chart_jvm_env_flags(ctx)
    evidence = jvm_evidence(ctx)

    if not ctx.dockerfiles:
        _no_dockerfile(ctx, result, env_flags, evidence)
        return

    if not evidence:
        _no_jvm_evidence(ctx, result)

    for df in ctx.dockerfiles:
        eff = effective_flags(df)
        applied = eff + env_flags
        eff_set = set(applied)

        def annotate(flag: str) -> str:
            return "" if flag in eff_set else \
                " [currently INERT - defined but never applied; see DF013]"

        _base_image(ctx, result, df, jvm=bool(evidence))
        if evidence:
            _java_container_awareness(ctx, result, df, applied, annotate)
            _jvm_flags(ctx, result, df, applied, annotate, env_flags)
        _entrypoint(ctx, result, df)
        _hygiene(ctx, result, df)


def _no_dockerfile(ctx: ChartContext, result: AnalysisResult,
                   env_flags: List[str], evidence: List[str]) -> None:
    """No Dockerfile: image-level checks are genuinely impossible. The Java
    ones are not, if the chart itself says a JVM is involved.

    DF000 stays - it is a coverage statement, and dropping it while widening
    what runs would trade one silence for another. What changes is that it now
    says which checks were skipped and which were NOT, because "Java/JVM checks
    that need it were skipped" was read (correctly, pre-R8) as "no Java/JVM
    checks ran", and a reader had no way to tell that the heap arithmetic was
    among the casualties.
    """
    if evidence:
        applied = ", ".join(env_flags) if env_flags else "none"
        result.add(Finding(
            rule_id="DF000", severity=Severity.INFO, category=Category.DOCKERFILE,
            title="No Dockerfile found - image-level checks skipped, JVM "
                  "checks ran from the pod spec",
            file="", basis=Basis.OBSERVED,
            detail=f"No Dockerfile in the analyzed directory. NOT CHECKED: "
                   f"base image pinning, JDK version and container awareness, "
                   f"entrypoint/PID-1 signal handling, image user and layer "
                   f"hygiene. STILL CHECKED, from the chart alone: heap vs "
                   f"limits.memory, CPU visibility, and applied JVM flags "
                   f"({applied}). Evidence this is a JVM workload: "
                   f"{'; '.join(evidence[:3])}.",
            why="The JVM reads JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS and "
                "_JAVA_OPTIONS from its environment by itself, so a heap set "
                "there is as real as one baked into the image. Before R8 this "
                "check returned here, and a chart asking for a 4 GiB heap "
                "inside a 2 GiB limit was graded A- in silence.",
            fix="Include the service Dockerfile in the analyzed directory to "
                "restore the image-level checks listed above; the JVM sizing "
                "findings in this report do not depend on it.",
            assumes="that no -Xmx on the image's own java command line "
                    "overrides these env-supplied flags - a command-line -Xmx "
                    "wins over JAVA_TOOL_OPTIONS, and without the Dockerfile "
                    "that cannot be ruled out"))
        # Run the flag-reality checks the DF000 title just promised. Claiming
        # "JVM checks ran from the pod spec" and then not running them would
        # be a worse lie than the silence it replaces.
        if env_flags:
            _jvm_flags(ctx, result, None, list(env_flags), lambda f: "",
                       env_flags, file=_jvm_env_file(ctx))
        return
    result.add(Finding(
        rule_id="DF000", severity=Severity.INFO, category=Category.DOCKERFILE,
        title="No Dockerfile found", file="", basis=Basis.OBSERVED,
        detail="No Dockerfile present in the analyzed directory; image-level "
               "checks (base image, entrypoint, user, hygiene) were skipped.",
        why="Those checks read a Dockerfile and there is none. Java/JVM checks "
            "did not run either, but for a separate reason recorded in the "
            "coverage table: nothing in this chart indicates a JVM workload.",
        fix="Include the service Dockerfile in the analyzed directory."))
    _no_jvm_evidence(ctx, result)


def _jvm_env_file(ctx: ChartContext) -> str:
    """The template that made this chart look like a JVM workload.

    Findings raised with df=None have no Dockerfile to point at, and pointing
    at "" would put them in the report with a blank location - which is how a
    reader ends up unable to act on a CRITICAL. The honest anchor is the
    manifest whose container carries the evidence, since that is the file the
    reader has to edit to change the outcome.
    """
    for doc in ctx.workloads:
        for c in containers(doc):
            if is_sidecar(c.get("name", ""), c.get("image", "")):
                continue
            if container_jvm_evidence(c):
                return doc.file or ""
    return ""


def _no_jvm_evidence(ctx: ChartContext, result: AnalysisResult) -> None:
    """Record, in the coverage table, that the Java category did not apply.

    C2.6: an area that was not graded has to say it was not graded. A report
    that only prints failures makes "we checked and it was fine" and "we never
    looked" the same page. Pre-R8 this chart got the opposite treatment - a
    scored 'Java / JVM Container Fitness' category and a HIGH finding - so
    replacing that with nothing at all would be trading a false positive for a
    false negative and calling it progress.
    """
    for row in ctx.coverage:
        if row and row[0] == "Java / JVM checks":
            return
    # R15. If the operator passed --assume-java and this chart has no
    # Dockerfile, discovery._load_dockerfiles never runs and its "NOT applied"
    # note is never written - so the only thing the report said about the flag
    # was nothing at all. Silence about a discarded input is indistinguishable
    # from having honoured it, which is the whole fault this iteration is about.
    declined = ""
    if ctx.assume_java_requested:
        declined = (f" You passed --assume-java {ctx.assume_java_requested}; it "
                    f"was NOT applied. That flag states which Java version is "
                    f"in the image, not that there is one, and nothing here "
                    f"evidences a JVM for it to describe.")
    ctx.coverage.append([
        "Java / JVM checks",
        "NOT RUN - no JVM evidence in this chart." + declined
        + " Inputs examined: "
        + JVM_EVIDENCE_INPUTS +
        ". None of them mentions a JVM, so heap-vs-limit arithmetic, JDK "
        "container-awareness and flag checks were skipped and this chart is "
        "NOT scored on them. The absence of Java findings here is scope, not "
        "a pass. If this IS a Java workload, the tool is looking in the wrong "
        "place: set JAVA_TOOL_OPTIONS in the pod spec (which is where the "
        "flags belong anyway) or analyze the directory holding the "
        "Dockerfile."])


def _add(result, **kw):
    result.add(Finding(**kw))


# ---------------------------------------------------------------------------
# Base image
# ---------------------------------------------------------------------------

def _base_image(ctx, result, df: DockerfileInfo, jvm: bool = True):
    """`jvm` is whether anything in this chart indicates a JVM workload.

    DF001/DF002/DF004 are about the image and run either way. DF003 is not: it
    says "Java version undeterminable - JVM version checks degraded" and tells
    the reader to re-run with --assume-java, which presupposes there is a Java
    version to determine. Emitted on an nginx chart - which is what happened
    before R8, because `java_major is None` is true of every non-Java image -
    it is a MEDIUM finding reporting the absence of a thing that was never
    there, plus an instruction the reader cannot carry out.
    """
    fb = df.final_base
    if not fb:
        _add(result, rule_id="DF001", severity=Severity.HIGH, category=Category.DOCKERFILE,
             title="No FROM instruction found", file=df.path,
             detail="Could not identify a base image.",
             why="Unparseable Dockerfiles hide everything else.",
             fix="Ensure the Dockerfile begins with a valid FROM.")
        return

    image, tag = fb["image"], fb["tag"]
    if not tag or tag == "latest":
        _add(result, rule_id="DF002", severity=Severity.HIGH, category=Category.DOCKERFILE,
             title="Base image not pinned", file=df.path, line=fb["line"],
             detail=f"FROM {image}:{tag or 'latest (implicit)'}.",
             why="An unpinned base means every build may silently pick up a new "
                 "JDK - including major-version jumps that change GC defaults, "
                 "container awareness and memory ergonomics. Builds are not "
                 "reproducible and rollbacks do not roll back the runtime.",
             fix="Pin a full tag (better: a digest), e.g. "
                 "eclipse-temurin:17.0.11_9-jre.")

    if df.java_major is None and not jvm:
        return
    if df.java_major is None:
        _add(result, rule_id="DF003", severity=Severity.MEDIUM, category=Category.JAVA,
             title="Java version undeterminable - JVM version checks degraded",
             file=df.path,
             detail=f"FROM {image}:{tag} is not a recognizable Java "
                    f"distribution/tag (common for internal corporate base "
                    f"images).",
             why="The Java 8 update-level checks (container awareness, cgroup "
                 "v2 support, removed flags) depend on the exact version. They "
                 "DID NOT RUN for this image - absence of Java findings here "
                 "is missing coverage, not health. The memory/CPU budget "
                 "tables ran with conservative 'container-aware' assumptions "
                 "that may be wrong for an old internal JDK.",
             fix="Re-run with --assume-java <version> (e.g. --assume-java "
                 "8u151) matching what the base image actually ships, or use "
                 "a tag that embeds the version.")
        return

    if df.java_major == 8:
        upd = f" (update {df.java_update})" if df.java_update is not None else ""
        assumed = " [ASSUMED via --assume-java]" if ctx.assumed_java else ""
        _add(result, rule_id="JV001", severity=Severity.HIGH, category=Category.JAVA,
             title="Java 8 runtime", file=df.path,
             detail=f"Base image {image}:{tag} is Java 8{upd}{assumed}.",
             why="Java 8 (2014) predates containers: its container support is a "
                 "chain of backports with sharp edges (see the related findings), "
                 "it lacks modern collectors (G1 improvements, ZGC/Shenandoah), "
                 "compact strings (-10-20% heap for string-heavy apps), TLS 1.3 "
                 "defaults and years of JIT gains. Every JVM<->container problem "
                 "this report checks for is worse on 8.",
             fix="Plan a migration to 17 or 21 (LTS). Typical first step: run on "
                 "a current 8 update (8u392+) while testing 17.")
    elif df.java_major in (9, 10, 12, 13, 14, 15, 16, 18, 19, 20):
        _add(result, rule_id="JV002", severity=Severity.MEDIUM, category=Category.JAVA,
             title=f"Java {df.java_major} is a non-LTS release", file=df.path,
             detail=f"Base image is Java {df.java_major}.",
             why="Non-LTS feature releases stop receiving updates ~6 months "
                 "after GA; you are guaranteed to be running unpatched.",
             fix="Move to an LTS: 11, 17 or 21.")

    if df.java_flavor == "jdk" and not df.multistage:
        _add(result, rule_id="DF004", severity=Severity.LOW, category=Category.DOCKERFILE,
             title="Full JDK in final image (no multi-stage build)", file=df.path,
             detail=f"Final image {image}:{tag} is a JDK and the Dockerfile has a "
                    f"single stage.",
             why="A JDK ships compilers and tools the service never uses: bigger "
                 "attack surface, bigger pulls (slower cold starts - which "
                 "matters when the HPA is adding pods under load).",
             fix="Multi-stage: build with the JDK image, run on the matching "
                 "-jre (or distroless/java) image.")


# ---------------------------------------------------------------------------
# Container awareness by version
# ---------------------------------------------------------------------------

def _java_container_awareness(ctx, result, df: DockerfileInfo,
                              eff: List[str], annotate):
    if df.java_major is None:
        return
    raw = df.jvm_flags
    major, upd = df.java_major, df.java_update

    if major == 8:
        if upd is not None and upd < 131:
            _add(result, rule_id="JV010", severity=Severity.CRITICAL, category=Category.JAVA,
                 title=f"Java 8u{upd}: NO container awareness at all", file=df.path,
                 detail=f"JDK 8 update {upd} predates every cgroup backport.",
                 why="This JVM reads /proc for memory and CPU: it sizes its "
                     "default heap from the NODE's RAM and sees the NODE's cores. "
                     "Inside a small container it will happily try to grow the "
                     "heap far beyond the container limit and be OOM-killed "
                     "(exit 137) - no Java OutOfMemoryError, no heap dump, just "
                     "a killed pod.",
                 fix="Minimum fix: explicit -Xmx sized to the container limit. "
                     "Real fix: upgrade to 8u191+ (better: 17/21).",
                 math="Default MaxHeapSize = min(host_RAM/4, ...). On a 64 GiB "
                      "node: heap target 16 GiB vs container limit e.g. 512 MiB "
                      "=> kernel kills the cgroup at 512 MiB, ~3% of what the "
                      "JVM believes it may use.")
        elif upd is not None and upd < 191:
            applied = has_flag(eff, "UseCGroupMemoryLimitForHeap")
            present_inert = (not applied) and has_flag(raw, "UseCGroupMemoryLimitForHeap")
            if applied:
                state = "flags ARE present and applied."
            elif present_inert:
                state = ("flags exist only in an INERT variable - they are "
                         "NOT applied (see DF013).")
            else:
                state = "flags are ABSENT."
            sev = Severity.HIGH if applied else Severity.CRITICAL
            _add(result, rule_id="JV011", severity=sev, category=Category.JAVA,
                 title=f"Java 8u{upd}: only experimental cgroup support", file=df.path,
                 detail=f"8u131-8u190 need -XX:+UnlockExperimentalVMOptions "
                        f"-XX:+UseCGroupMemoryLimitForHeap; {state}",
                 why="Without the experimental flags applied, this JVM sizes its "
                     "heap from host RAM exactly like pre-8u131. Even with them, "
                     "CPU limits are ignored (GC/JIT thread pools sized for the "
                     "node) and MaxRAMPercentage does not exist.",
                 fix="Upgrade to 8u191+ where -XX:+UseContainerSupport is on by "
                     "default, then remove the experimental flags (they are "
                     "removed in Java 11 and abort startup there).")
        if upd is None and not ctx.assumed_java:
            _add(result, rule_id="JV012", severity=Severity.MEDIUM, category=Category.JAVA,
                 title="Java 8 update level unknown - container support unverifiable",
                 file=df.path,
                 detail="The image tag does not reveal the 8uNNN update.",
                 why="Container awareness on Java 8 depends entirely on the "
                     "update: <131 none, <191 experimental-only, >=191 backported "
                     "UseContainerSupport. An unpinned '8' tag can silently move "
                     "across those boundaries.",
                 fix="Pin a tag with an explicit update (e.g. 8u392-b08-jre) or "
                     "re-run with --assume-java 8uNNN.")
        if upd is not None and upd < 372:
            _add(result, rule_id="JV013", severity=Severity.HIGH, category=Category.JAVA,
                 title=f"Java 8u{upd}: blind to cgroup v2 nodes", file=df.path,
                 detail=f"cgroup v2 support reached Java 8 at 8u372.",
                 why="Modern node OSes (Ubuntu >= 22.04, EKS AL2023, GKE COS, "
                     "anything K8s ~1.25+) default to cgroup v2. On such nodes "
                     "this JVM finds no cgroup v1 files, concludes it is NOT in a "
                     "container, and reverts to host-RAM/host-CPU sizing - "
                     "re-introducing the OOM-kill behavior of pre-container-"
                     "aware JVMs even though UseContainerSupport is 'on'.",
                 fix="Upgrade to 8u372+ / 11.0.16+ / 17+, or pin explicit -Xmx "
                     "and -XX:ActiveProcessorCount as a stopgap.")
    elif major == 11 and upd is not None and upd < 16:
        _add(result, rule_id="JV013", severity=Severity.HIGH, category=Category.JAVA,
             title=f"Java 11.0.{upd}: blind to cgroup v2 nodes", file=df.path,
             detail="cgroup v2 support reached Java 11 at 11.0.16.",
             why="On cgroup-v2 nodes (default on modern distros) this JVM "
                 "cannot see container limits and sizes itself from the host.",
             fix="Update to a current 11.0.x (or 17/21).")
    elif major in (9, 10, 12, 13, 14):
        _add(result, rule_id="JV013", severity=Severity.HIGH, category=Category.JAVA,
             title=f"Java {major}: no cgroup v2 support (added in 15)", file=df.path,
             detail=f"Java {major} never received cgroup v2 detection.",
             why="On cgroup-v2 nodes the JVM sizes itself from host resources.",
             fix="Move to 17/21.")

    if has_flag(eff, "-XX:-UseContainerSupport"):
        _add(result, rule_id="JV014", severity=Severity.CRITICAL, category=Category.JAVA,
             title="Container support explicitly DISABLED", file=df.path,
             detail="-XX:-UseContainerSupport is applied.",
             why="The JVM is told to ignore cgroup limits entirely: heap "
                 "ergonomics, availableProcessors, GC threading all revert to "
                 "host values.",
             fix="Remove the flag.")

    if major >= 11 and has_flag(raw, "UseCGroupMemoryLimitForHeap"):
        applied = has_flag(eff, "UseCGroupMemoryLimitForHeap")
        sev = Severity.CRITICAL if applied else Severity.HIGH
        note = "" if applied else \
            " It is currently inert (see DF013) - the crash is armed and " \
            "waiting for whoever wires JAVA_OPTS up."
        _add(result, rule_id="JV015", severity=sev, category=Category.JAVA,
             title="Removed flag UseCGroupMemoryLimitForHeap on Java 11+", file=df.path,
             detail=f"Java {major} + -XX:+UseCGroupMemoryLimitForHeap.",
             why="This experimental flag was REMOVED in JDK 11. An unrecognized "
                 "-XX flag aborts JVM startup: the container exits immediately "
                 "and the pod CrashLoopBackOffs." + note,
             fix="Delete it; use -XX:MaxRAMPercentage instead.")

    if has_flag(raw, "UseConcMarkSweepGC") and major >= 14:
        applied = has_flag(eff, "UseConcMarkSweepGC")
        _add(result, rule_id="JV016",
             severity=Severity.CRITICAL if applied else Severity.HIGH,
             category=Category.JAVA,
             title="CMS collector flag on Java 14+", file=df.path,
             detail="-XX:+UseConcMarkSweepGC was removed in JDK 14."
                    + ("" if applied else " (currently inert - see DF013)"),
             why="Unrecognized VM option -> JVM refuses to start.",
             fix="Remove; use G1 (default) or ZGC.")

    for f in raw:
        if "PermSize" in f and major >= 8:
            _add(result, rule_id="JV017", severity=Severity.MEDIUM, category=Category.JAVA,
                 title="PermGen flag on Java 8+ (ignored)", file=df.path,
                 detail=f"{f} - PermGen was removed in Java 8.{annotate(f)}",
                 why="The flag is silently ignored (with a warning). Whoever set "
                     "it believes class metadata is capped; it is NOT - "
                     "Metaspace grows unbounded unless MaxMetaspaceSize is set, "
                     "eating into the container limit.",
                 fix="Replace with -XX:MaxMetaspaceSize=... if a cap is desired.")
            break


# ---------------------------------------------------------------------------
# Heap / flags - reality = applied flags; limit math lives in proofs.py
# ---------------------------------------------------------------------------

def _jvm_flags(ctx, result, df: Optional[DockerfileInfo], eff: List[str],
               annotate, env_flags: List[str] = (), file: str = ""):
    """Flag-reality checks. `df` is optional since R8.

    Every rule here judges the flags the JVM will ACTUALLY receive, and since
    F4 that set includes flags the pod spec supplies through JAVA_TOOL_OPTIONS
    - which the JVM reads with no help from the image. So none of these rules
    needs a Dockerfile to be answerable; the pre-R8 code required one only
    because the function happened to live in the module that parses Dockerfiles.
    With df=None the image-level half (the inert-vs-applied distinction, the
    JDK version) is simply unknown, and each rule below says so rather than
    filling it in.
    """
    # eff already includes env-applied flags; raw is image-level ("defined
    # somewhere, maybe inert") for the inert-vs-applied distinction.
    raw = df.jvm_flags if df is not None else []
    path = df.path if df is not None else file
    xmx = parse_jvm_size(flag_val(eff, "Xmx") or "")
    xms = parse_jvm_size(flag_val(eff, "Xms") or "")
    maxram_pct = flag_val(eff, "MaxRAMPercentage")
    maxram_frac = flag_val(eff, "MaxRAMFraction")
    major = (df.java_major or 0) if df is not None else 0

    if xmx is None and maxram_pct is None and maxram_frac is None:
        # distinguish "never configured" from "configured but inert"
        raw_has_sizing = (flag_val(raw, "Xmx") or flag_val(raw, "MaxRAMPercentage")
                          or flag_val(raw, "MaxRAMFraction"))
        modern = (major >= 10) or (major == 8 and ((df.java_update if df else 0) or 0) >= 191) \
                 or (major in (11, 17, 21))
        # With no Dockerfile the JDK version is unknown, so the HIGH variant -
        # which is justified by "an old JVM sizes the heap from NODE RAM" -
        # cannot be asserted. Report the finding at the severity the evidence
        # supports and name the gap, rather than picking the scarier branch
        # because a default happened to be 0.
        sev = (Severity.MEDIUM if (modern or df is None) else Severity.HIGH)
        detail = "Neither -Xmx nor -XX:MaxRAMPercentage/-XX:MaxRAMFraction is applied."
        if raw_has_sizing:
            detail += (" Heap sizing flags DO exist in an env var, but nothing "
                       "applies them (see DF013) - the JVM runs on pure "
                       "defaults.")
        if df is None:
            detail += (" No Dockerfile was in scope, so the JDK version is "
                       "unknown and image-baked sizing could not be ruled out; "
                       "severity is held at MEDIUM for that reason.")
        _add(result, rule_id="JV021", severity=sev, category=Category.JAVA,
             title="No JVM heap sizing is actually applied", file=path,
             detail=detail,
             why="Without an applied heap bound the JVM uses its ergonomic "
                 "default: 25% of the memory it can see. Two consequences: (a) "
                 "most of the container memory you pay for is never used for "
                 "heap, and (b) if the JVM cannot see the limit (old JDK, "
                 "cgroup v2 mismatch - see other findings) that 25% is 25% of "
                 "the NODE.",
             fix="Apply -XX:MaxRAMPercentage=50-75 (container-aware JDKs) or an "
                 "explicit -Xmx ~ 50-75% of limits.memory, via a mechanism that "
                 "actually reaches the JVM (JAVA_TOOL_OPTIONS, or exec-form "
                 "expansion).",
             math="Default heap = 0.25 x visible_RAM. Container limit 1 GiB "
                  "=> heap 256 MiB (why so small?). No visible limit on a "
                  "64 GiB node => heap 16 GiB (why so large?) -> OOMKill.")

    if maxram_pct is not None:
        try:
            pct = float(maxram_pct)
        except ValueError:
            pct = None
        if pct is not None and pct >= 85:
            _add(result, rule_id="JV022", severity=Severity.HIGH, category=Category.JAVA,
                 title=f"MaxRAMPercentage={maxram_pct} leaves too little non-heap room",
                 file=path,
                 detail=f"-XX:MaxRAMPercentage={maxram_pct} (applied).",
                 why="Container memory = heap + Metaspace + code cache + thread "
                     "stacks + direct buffers + GC bookkeeping + native. At "
                     f"{pct:.0f}% heap, only {100-pct:.0f}% remains for all of "
                     "that; on small containers that is tens of MiB. The kernel "
                     "kills the cgroup, not the JVM - you get exit 137 and no "
                     "OutOfMemoryError to debug.",
                 fix="50-75% is the safe band; leave >= 250-400 MiB absolute "
                     "non-heap headroom for typical Spring-class apps.",
                 math=f"limit L: non-heap budget = (100-{pct:.0f})% x L. "
                      f"L=512Mi => {(100-pct)*512/100:.0f} MiB for metaspace"
                      f"(~100)+stacks(~100)+code(~50)+direct+GC => negative "
                      f"balance => OOMKill.")
    if maxram_frac is not None:
        _add(result, rule_id="JV023", severity=Severity.LOW, category=Category.JAVA,
             title="Deprecated MaxRAMFraction", file=path,
             detail=f"-XX:MaxRAMFraction={maxram_frac} (deprecated since JDK 10).",
             why="Integer fractions are too coarse (1=100%, 2=50%, 3=33%, 4=25%) "
                 "- there is no way to say 60%. =1 is an OOM-kill guarantee.",
             fix="Use -XX:MaxRAMPercentage.")

    raw_xmx = parse_jvm_size(flag_val(raw, "Xmx") or "")
    raw_xms = parse_jvm_size(flag_val(raw, "Xms") or "")
    if raw_xmx is not None and raw_xms is not None and raw_xms != raw_xmx:
        _add(result, rule_id="JV024", severity=Severity.LOW, category=Category.JAVA,
             title="Xms != Xmx in a container", file=path,
             detail=f"-Xms {fmt_bytes(raw_xms)} vs -Xmx {fmt_bytes(raw_xmx)}."
                    + annotate(f"-Xmx{flag_val(raw, 'Xmx')}"),
             why="The pod's memory REQUEST must cover Xmx anyway (the heap will "
                 "get there under load and memory is rarely returned). Growing "
                 "the heap in steps just adds early GC cycles and page-fault "
                 "latency; you gain nothing you can bin-pack on.",
             fix="Set Xms = Xmx (or AlwaysPreTouch for latency-critical pods).")

    if xmx is not None and has_flag(eff, "MaxRAMPercentage"):
        _add(result, rule_id="JV025", severity=Severity.LOW, category=Category.JAVA,
             title="Both -Xmx and MaxRAMPercentage applied", file=path,
             detail="Explicit -Xmx overrides MaxRAMPercentage.",
             why="Redundant and confusing: -Xmx wins; the percentage silently "
                 "does nothing, so resizing the container limit no longer "
                 "resizes the heap.",
             fix="Keep exactly one mechanism (percentage scales with the limit).")

    if not has_flag(eff, "ExitOnOutOfMemoryError") and not \
            has_flag(eff, "CrashOnOutOfMemoryError"):
        extra = ""
        if has_flag(raw, "ExitOnOutOfMemoryError"):
            extra = (" The flag exists in an inert variable (see DF013) - "
                     "defined, never applied.")
        _add(result, rule_id="JV026", severity=Severity.MEDIUM, category=Category.JAVA,
             title="No applied -XX:+ExitOnOutOfMemoryError", file=path,
             detail="The flag is absent from the options the JVM will actually "
                    "receive." + extra,
             why="After a heap OutOfMemoryError a JVM often limps on with dead "
                 "threads and corrupted state - alive enough to pass a TCP "
                 "liveness probe, broken enough to fail every request. "
                 "Kubernetes can only heal what dies.",
             fix="Add -XX:+ExitOnOutOfMemoryError (and optionally "
                 "-XX:+HeapDumpOnOutOfMemoryError with a mounted dump path).")

    has_gc = any(has_flag(eff, g) for g in
                 ("UseG1GC", "UseParallelGC", "UseSerialGC", "UseZGC",
                  "UseShenandoahGC", "UseConcMarkSweepGC"))
    if not has_gc and major and major <= 11:
        _add(result, rule_id="JV027", severity=Severity.LOW, category=Category.JAVA,
             title="GC not pinned - ergonomics may pick SerialGC in-container",
             file=path,
             detail=f"Java {major} with no applied collector flag.",
             why="JVM ergonomics picks the collector from visible CPUs/RAM: with "
                 "<2 CPUs or <~1792 MiB visible, you get SerialGC - single-"
                 "threaded, long pauses - and a CPU limit of 1000m means "
                 "exactly that. Java 8's default (Parallel) also differs from "
                 "9+ (G1): upgrades silently change GC behavior.",
             fix="Pin the collector explicitly (-XX:+UseG1GC for most services).")


# ---------------------------------------------------------------------------
# Entrypoint / signals
# ---------------------------------------------------------------------------

_VAR_IN_EXEC_RE = re.compile(r'"\s*\$[{A-Za-z_]')


def _entrypoint(ctx, result, df: DockerfileInfo):
    ep = df.entrypoint or df.cmd
    if not ep:
        _add(result, rule_id="DF010", severity=Severity.MEDIUM, category=Category.DOCKERFILE,
             title="No ENTRYPOINT/CMD", file=df.path,
             detail="Dockerfile defines neither ENTRYPOINT nor CMD.",
             why="The image relies on the base image's default command or on the "
                 "chart overriding it - fragile and undocumented.",
             fix="Add an exec-form ENTRYPOINT.")
        return

    if ep["form"] == "shell":
        _add(result, rule_id="DF011", severity=Severity.HIGH, category=Category.DOCKERFILE,
             title="Shell-form ENTRYPOINT/CMD: JVM will not receive SIGTERM",
             file=df.path, line=ep["line"],
             detail=f"Line {ep['line']}: shell form ('{ep['args'][:60]}...' runs "
                    f"under /bin/sh -c).",
             why="PID 1 is the shell, not java, and sh does not forward SIGTERM. "
                 "On every pod stop (deploys, HPA scale-DOWN, drains) Kubernetes "
                 "sends SIGTERM, nothing happens, waits "
                 "terminationGracePeriodSeconds (30s), then SIGKILLs the JVM "
                 "mid-request: no graceful shutdown, no connection draining, no "
                 "shutdown hooks - and with an HPA this happens constantly, on "
                 "every scale-down.",
             fix='Use exec form: ENTRYPOINT ["java", ...]. If you need env '
                 'expansion: ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS ..."] '
                 "- the 'exec' makes java PID 1.")
    else:
        if _VAR_IN_EXEC_RE.search(ep["args"]) and '"sh"' not in ep["args"] \
                and '"bash"' not in ep["args"] and "'sh'" not in ep["args"]:
            _add(result, rule_id="DF012", severity=Severity.CRITICAL, category=Category.DOCKERFILE,
                 title="Exec-form ENTRYPOINT contains a $VARIABLE (never expanded)",
                 file=df.path, line=ep["line"],
                 detail=f"Line {ep['line']}: {ep['args'][:90]}",
                 why="Exec form bypasses the shell: $JAVA_OPTS is passed to java "
                     "as the LITERAL string '$JAVA_OPTS'. Either the JVM refuses "
                     "to start, or (if quoted oddly) your entire tuning is "
                     "silently ignored.",
                 fix='ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]')

    # applies to BOTH forms: even a shell only expands vars it references
    dead = inert_opt_vars(df)
    if dead:
        names = ", ".join(dead)
        inert_flags = sorted({f for v in dead
                              for f in extract_jvm_flags(df.java_opts[v])})
        flags_note = (f" Inert flags: {' '.join(inert_flags)}."
                      if inert_flags else "")
        _add(result, rule_id="DF013", severity=Severity.CRITICAL, category=Category.DOCKERFILE,
             title=f"{names} is defined but NEVER applied", file=df.path,
             detail=f"ENV sets {names}, but the container's launch command "
                    f"never references it and the JVM does not read it by "
                    f"itself." + flags_note,
             why="JAVA_OPTS is only a convention - nothing reads it "
                 "automatically. Every flag in it (heap sizing, GC, "
                 "container tuning) is silently NOT in effect; the JVM "
                 "runs on pure defaults while everyone believes it is "
                 "tuned. All other findings in this report judge the "
                 "options the JVM actually receives.",
             fix="Either switch to JAVA_TOOL_OPTIONS (the JVM itself "
                 "reads that env var) or expand it via "
                 '\'ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar app.jar"]\'.')


# ---------------------------------------------------------------------------
# General Dockerfile hygiene
# ---------------------------------------------------------------------------

_SECRET_ENV_RE = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)",
                            re.IGNORECASE)


def _hygiene(ctx, result, df: DockerfileInfo):
    if not df.user or df.user.strip() in ("root", "0"):
        _add(result, rule_id="DF020", severity=Severity.HIGH, category=Category.SECURITY,
             title="Container runs as root (no USER instruction)", file=df.path,
             detail="No non-root USER is set in the final stage."
                    if not df.user else f"USER {df.user} is root.",
             why="Defense in depth: a compromised JVM running as root can write "
                 "anywhere in the container and is one kernel bug from the node. "
                 "Pod Security 'Restricted' will refuse the pod unless "
                 "runAsNonRoot is satisfied - and an image built for root often "
                 "fails when forced non-root at deploy time.",
             fix="Create a user in the image and set USER (most Temurin images: "
                 "no default user - add one).")

    for ins in df.instructions:
        if ins["instr"] in ("ENV", "ARG") and _SECRET_ENV_RE.search(ins["args"]):
            _add(result, rule_id="DF021", severity=Severity.HIGH, category=Category.SECURITY,
                 title="Possible secret baked into image", file=df.path, line=ins["line"],
                 detail=f"Line {ins['line']}: {ins['instr']} {ins['args'][:70]}",
                 why="ENV/ARG values are stored in image layers and visible via "
                     "'docker history' to anyone who can pull the image.",
                 fix="Inject secrets at runtime (K8s Secrets -> env/volume), "
                     "never at build time.")
        if ins["instr"] == "ADD" and re.search(r"https?://", ins["args"]):
            _add(result, rule_id="DF022", severity=Severity.MEDIUM, category=Category.DOCKERFILE,
                 title="ADD from URL", file=df.path, line=ins["line"],
                 detail=f"Line {ins['line']}: ADD {ins['args'][:70]}",
                 why="ADD-from-URL is unverified (no checksum), uncached and "
                     "non-reproducible.",
                 fix="Use curl with checksum verification in a RUN, or COPY a "
                     "vendored artifact.")
        if ins["instr"] == "RUN" and "apt-get install" in ins["args"] \
                and "rm -rf /var/lib/apt/lists" not in ins["args"]:
            _add(result, rule_id="DF023", severity=Severity.LOW, category=Category.DOCKERFILE,
                 title="apt-get without cleaning lists", file=df.path, line=ins["line"],
                 detail=f"Line {ins['line']}: apt-get install without removing "
                        f"/var/lib/apt/lists in the same layer.",
                 why="Dead weight in every pulled image layer.",
                 fix="&& rm -rf /var/lib/apt/lists/* in the same RUN.")

    if df.healthcheck:
        _add(result, rule_id="DF024", severity=Severity.INFO, category=Category.DOCKERFILE,
             title="HEALTHCHECK is ignored by Kubernetes", file=df.path,
             detail="Dockerfile defines HEALTHCHECK.",
             why="Kubelet ignores Docker HEALTHCHECK; only liveness/readiness "
                 "probes count. Keeping both risks them drifting apart.",
             fix="Rely on chart probes; drop HEALTHCHECK or keep it consciously "
                 "for docker-run usage.")

    df_dir = os.path.dirname(os.path.join(ctx.root, df.path))
    if not os.path.isfile(os.path.join(df_dir, ".dockerignore")):
        _add(result, rule_id="DF025", severity=Severity.INFO, category=Category.DOCKERFILE,
             title="No .dockerignore", file=df.path,
             detail="No .dockerignore found beside the Dockerfile.",
             why="Build context ships .git, target/, node_modules - slow builds "
                 "and accidental secret inclusion.",
             fix="Add .dockerignore.")

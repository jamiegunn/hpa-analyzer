"""Turn the static-analysis boundary into action.

The tool cannot touch a cluster, but for every blind spot it DOES know
exactly which cluster fact it is missing - so it can hand the operator the
precise `kubectl`/`helm` command to close that gap, plus how to read the
result. Probes are emitted ONLY when relevant to this chart (an HPA must
exist before we suggest checking the metrics pipeline; a missing-requests
finding before we suggest looking for a LimitRange), and are populated with
the real object names and label selectors parsed from the chart.

Everything here is advisory text; nothing is executed.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .kube import containers, doc_name, jvm_evidence, pod_spec
from .models import AnalysisResult, ChartContext

NS = "<namespace>"          # the namespace you install the release into
REL = "<release>"           # your helm release name
CHART = "<chart-dir>"       # path to this chart


@dataclass
class ClusterProbe:
    key: str                # stable id, e.g. "metrics-pipeline"
    title: str              # short gap name
    gap: str                # one line: what static analysis cannot see
    commands: List[str]     # copy-pasteable kubectl/helm commands
    read: str               # how to interpret the output
    triggered_by: List[str] = field(default_factory=list)  # rule ids/reasons


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _is_placeholder(s: str) -> bool:
    s = str(s)
    return ("HELM" in s or "{" in s or s.startswith("<")
            or "RELEASE-NAME" in s or "CHART-NAME" in s)


def _selector(doc) -> Optional[str]:
    """`-l k=v,k2=v2` from a workload's spec.selector.matchLabels, skipping
    unresolved template values. None if nothing concrete is available."""
    data = doc.data if isinstance(doc.data, dict) else {}
    spec = data.get("spec") if isinstance(data, dict) else {}
    sel = spec.get("selector") if isinstance(spec, dict) else None
    ml = sel.get("matchLabels") if isinstance(sel, dict) else None
    if not isinstance(ml, dict):
        return None
    parts = [f"{k}={v}" for k, v in ml.items()
             if not _is_placeholder(k) and not _is_placeholder(v)]
    return ",".join(parts) if parts else None


def _first_selector(ctx: ChartContext) -> Optional[str]:
    for w in ctx.workloads:
        s = _selector(w)
        if s:
            return s
    return None


def _name(doc) -> str:
    n = doc_name(doc)
    return n if not _is_placeholder(n) else f"{REL}-<name>"


def _has_multi_container(ctx: ChartContext) -> bool:
    return any(len(containers(w)) > 1 for w in ctx.workloads)


def _has_native_sidecar(ctx: ChartContext) -> bool:
    for w in ctx.workloads:
        ps = pod_spec(w)
        if not isinstance(ps, dict):
            continue
        for ic in ps.get("initContainers") or []:
            if isinstance(ic, dict) and str(ic.get("restartPolicy", "")) == "Always":
                return True
    return False


def _uses_non_resource_metric(ctx: ChartContext) -> bool:
    for h in ctx.hpas:
        spec = h.data.get("spec") if isinstance(h.data, dict) else {}
        for m in (spec.get("metrics") or []) if isinstance(spec, dict) else []:
            if isinstance(m, dict) and str(m.get("type", "")).lower() not in (
                    "resource", "containerresource", ""):
                return True
    return False


# ---------------------------------------------------------------------------
# probe builder
# ---------------------------------------------------------------------------

def build_probes(result: AnalysisResult) -> List[ClusterProbe]:
    ctx = result.context
    ids = {f.rule_id for f in result.findings}
    probes: List[ClusterProbe] = []

    # nothing was actually analyzed as a workload -> nothing to verify live
    if ctx.ungradeable_reason and not ctx.workloads:
        return probes
    if not ctx.workloads and not ctx.hpas:
        return probes

    sel = _first_selector(ctx)
    sel_arg = f" -l {sel}" if sel else ""

    # 1. Metrics pipeline (only if an HPA exists) --------------------------
    if ctx.hpas:
        hpa_name = _name(ctx.hpas[0])
        cmds = [
            f"kubectl describe hpa {hpa_name} -n {NS}",
            f"kubectl top pods -n {NS}{sel_arg}",
        ]
        read = ("In `describe hpa`, the Conditions block must show "
                "`ScalingActive True`. `AbleToScale False` / "
                "`FailedGetResourceMetric` means the metrics API is not "
                "serving this HPA - install/repair metrics-server (CPU & "
                "memory targets).")
        if _uses_non_resource_metric(ctx):
            cmds.append(
                'kubectl get --raw "/apis/custom.metrics.k8s.io/v1beta1" '
                '| head -c 400; echo')
            cmds.append(
                'kubectl get --raw "/apis/external.metrics.k8s.io/v1beta1" '
                '| head -c 400; echo')
            read += (" This HPA uses a custom/external metric, which also "
                     "requires the Prometheus Adapter or KEDA - the two "
                     "`--raw` calls must return a metric list, not 404.")
        probes.append(ClusterProbe(
            "metrics-pipeline", "Will the HPA actually scale?",
            "Static files cannot show whether metrics-server / a custom-"
            "metrics adapter is installed, or the HPA's live status.",
            cmds, read, triggered_by=["HPA present"]))

    # 2. LimitRange defaulting (only if requests/limits look missing) ------
    if ids & {"RS001", "RS004", "RS005", "RS011"}:
        probes.append(ClusterProbe(
            "limitrange", "Are the 'missing' requests defaulted at admission?",
            "A namespace LimitRange can inject requests/limits this report "
            "flags as absent - changing the real QoS and scheduling.",
            [f"kubectl get limitrange -n {NS} -o yaml",
             f"kubectl get pods -n {NS}{sel_arg} "
             f"-o custom-columns=NAME:.metadata.name,QOS:.status.qosClass"],
            "A `LimitRange` with `defaultRequest`/`default` for "
            "`type: Container` supplies the values flagged missing - so the "
            "real `status.qosClass` (second command) may be Burstable/"
            "Guaranteed, not BestEffort. No LimitRange: the findings stand.",
            triggered_by=sorted(ids & {"RS001", "RS004", "RS005", "RS011"})))

    # 3. Deprecated/removed API vs actual server version ------------------
    if "TP010" in ids:
        probes.append(ClusterProbe(
            "api-removal", "Is the deprecated API fatal on YOUR cluster?",
            "Whether a removed-API object is rejected depends on the target "
            "cluster's version, which the files do not name.",
            [f"kubectl version -o json | grep -A3 serverVersion",
             "kubectl get --raw /metrics 2>/dev/null "
             "| grep apiserver_requested_deprecated_apis"],
            "If the server minor version is at or past the removal version "
            "named in the TP010 finding, `helm upgrade`/`kubectl apply` of "
            "that object WILL be rejected - migrate before the upgrade. The "
            "`/metrics` line shows whether anything on the live cluster is "
            "still calling the deprecated API.",
            triggered_by=["TP010"]))

    # 4. Native sidecars / multi-container pod QoS ------------------------
    if _has_multi_container(ctx) or _has_native_sidecar(ctx):
        # This text used to read "This report shows QoS per container;
        # Kubernetes assigns QoS per POD" - which was true of the tool before
        # R1 and false after it. A probe that tells the user the report is
        # wrong about something the report now gets right is its own kind of
        # misinformation, and it survived two iterations because nothing
        # tested the prose. The probe is still worth printing: the tool
        # computes QoS from the templates, and only the cluster can confirm
        # what was actually admitted.
        why = ("This report computes pod QoS from the templates by porting "
               "upstream ComputePodQOS; the cluster computes it from the pod "
               "that was actually admitted, after defaulting, LimitRange "
               "injection and any mutating webhook.")
        if _has_native_sidecar(ctx):
            why += (" Restartable init containers (native sidecars) count "
                    "toward both the pod's QoS and the node's allocation - "
                    "this report sums them, and the node view below is how "
                    "you check that against reality.")
        probes.append(ClusterProbe(
            "pod-qos", "What is the POD's real QoS and footprint?",
            why,
            [f"kubectl get pods -n {NS}{sel_arg} "
             f"-o jsonpath='{{range .items[*]}}{{.metadata.name}}{{\"  \"}}"
             f"{{.status.qosClass}}{{\"\\n\"}}{{end}}'",
             f"kubectl describe node <node>   # see 'Allocated resources'"],
            "`status.qosClass` is the authoritative pod QoS - it is what the "
            "kubelet wrote for the pod that exists. If it disagrees with the "
            "POD row in TABLE 1, something between the chart and the cluster "
            "changed the pod (a LimitRange default, an injected sidecar) and "
            "the difference is the finding. Sidecar requests appear in the "
            "node's Allocated resources; include them when sizing nodes.",
            triggered_by=["multi-container pod"]))

    # 5. ResourceQuota (any graded workload) ------------------------------
    if ctx.workloads:
        probes.append(ClusterProbe(
            "resourcequota", "Could a namespace quota reject this workload?",
            "A ResourceQuota can reject an otherwise-valid pod; quotas live "
            "in the cluster, not the chart.",
            [f"kubectl get resourcequota -n {NS} -o yaml"],
            "If `status.used` is near `status.hard` for cpu/memory/pods, the "
            "workload may be rejected at admission even though this chart is "
            "internally valid.",
            triggered_by=["workload present"]))

    # 6. Does the JVM actually see the container limit? -------------------
    #
    # R8, ninth site. This read `any(d.java_major or d.jvm_flags or
    # d.java_opts for d in ctx.dockerfiles)` - a JVM test that only ever
    # looked inside Dockerfiles. Measured on three charts:
    #
    #   pod spec sets JAVA_TOOL_OPTIONS=-Xmx1g, no Dockerfile  -> no probe
    #   the same, plus an unrelated `FROM nginx` file          -> no probe
    #   a pure nginx pod, chart ships a Java Dockerfile        -> PROBE
    #
    # Exactly inverted. And of all the probes here this is the worst one to
    # get wrong, because it is the one the operator cannot answer any other
    # way: whether the JVM sees the cgroup limit depends on the JDK build and
    # the node's cgroup version, neither of which is in any file. A container
    # that says `-Xmx1g` in its own pod spec is the clearest possible signal
    # that this question applies, and it was the case that got silence.
    #
    # The `ids &` clause below is not a safety net for that. It fires only
    # when a JVM finding was already raised - so it covers the chart whose
    # heap is visibly wrong and misses the chart whose files look fine, which
    # is precisely the chart whose only remaining risk is what the runtime
    # does with the limit.
    jvm_ev = jvm_evidence(ctx)
    if jvm_ev or (ids & {"JV010", "JV011", "JV013", "JV021", "XF001", "XF002", "XF003"}):
        example_pod = (f"$(kubectl get pod -n {NS}{sel_arg} "
                       f"-o name | head -1)" if sel else f"{REL}-<pod>")
        probes.append(ClusterProbe(
            "jvm-sees-limit", "Does the JVM actually see the cgroup limit?",
            "The heap the JVM chooses at runtime depends on whether it can "
            "read the container limit - which depends on the JDK build and "
            "the node's cgroup version, neither fully knowable from files.",
            [f"kubectl exec -n {NS} {example_pod} -- "
             f"java -XX:+PrintFlagsFinal -version 2>/dev/null "
             f"| grep -E 'MaxHeapSize|MaxRAMPercentage|UseContainerSupport|"
             f"ActiveProcessorCount'",
             f"kubectl exec -n {NS} {example_pod} -- "
             f"sh -c 'stat -fc %T /sys/fs/cgroup'   # cgroup2fs = cgroup v2"],
            "`MaxHeapSize` should be ~ (your memory LIMIT x the heap "
            "percentage), NOT ~1/4 of the node's RAM - the latter means the "
            "JVM is sizing from the host (old JDK or cgroup-v2 blindness). "
            "`cgroup2fs` confirms a v2 node; verify your JDK supports it "
            "(8u372+ / 11.0.16+ / 15+).",
            # Say WHY this probe is here. "JVM detected" is an assertion the
            # reader cannot check; the sentence that produced it is one they
            # can - and if the inference is wrong, quoting it is how they
            # find out.
            triggered_by=[f"JVM detected: {jvm_ev[0]}" if jvm_ev
                          else "a JVM finding was raised on this chart"]))

    # 7. Resolve template names for the commands above (static mode) ------
    names_are_placeholders = any(
        _is_placeholder(doc_name(d)) for d in (ctx.workloads + ctx.hpas))
    if ctx.render_mode != "helm" and names_are_placeholders:
        probes.append(ClusterProbe(
            "resolve-names", "Get the real object names for the commands above",
            "In static mode, object names shown are template placeholders "
            "(e.g. `<orders.fullname>`), not the deployed names.",
            [f"helm template {REL} {CHART} | grep -E '^kind:|^  name:'",
             f"# after install:  helm get manifest {REL} -n {NS}"],
            "Render the chart (or read the live release) to get the concrete "
            "Deployment/HPA names and drop them into the `kubectl` commands "
            "above.",
            triggered_by=["static mode + templated names"]))

    return probes

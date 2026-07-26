"""Shared Kubernetes helpers used by check modules."""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .models import ManifestDoc


@dataclass(frozen=True)
class ApiFact:
    """One row of the upstream deprecation guide, kept as DATA not prose.

    `removed_in` is a (major, minor) pair rather than the string "1.22"
    because R3 compares it against the chart's declared kubeVersion range.
    Storing it as a string was not a formatting choice; it was the reason the
    tool printed the same CRITICAL for a chart pinned below the removal and a
    chart pinned above it. A number you cannot compare is a comment.

    `replacement_since` is the other half of the same fact and was missing
    entirely: an API can also be too NEW for the cluster range a chart claims.
    """
    removed_in: Tuple[int, int]
    replacement: str
    replacement_since: Optional[Tuple[int, int]] = None
    note: str = ""


# (apiVersion, lowercase kind) -> ApiFact
#
# Source, transcribed row by row rather than recalled:
#   https://kubernetes.io/docs/reference/using-api/deprecation-guide/
#   ("Removed APIs by release", sections v1.16 / v1.22 / v1.25 / v1.26 /
#    v1.27 / v1.29 / v1.32), which is generated from
#   kubernetes/website content/en/docs/reference/using-api/deprecation-guide.md
#
# Completeness matters more here than anywhere else in the tool, because the
# output of a lookup miss is SILENCE, and silence from this table is
# indistinguishable from a clean bill of health. The pre-R3 table carried 22
# rows and was asymmetric in a way that showed: it listed
# rbac.../v1beta1 Role but not RoleBinding, so a chart with both got a
# finding on one and nothing on the other object three lines below it in the
# same file. It had no entry for apiextensions.k8s.io/v1beta1
# CustomResourceDefinition at all - an object charts ship in crds/.
DEPRECATED_APIS: Dict[Tuple[str, str], ApiFact] = {
    # -- removed in v1.16 ---------------------------------------------------
    ("extensions/v1beta1", "deployment"):        ApiFact((1, 16), "apps/v1", (1, 9)),
    ("extensions/v1beta1", "daemonset"):         ApiFact((1, 16), "apps/v1", (1, 9)),
    ("extensions/v1beta1", "replicaset"):        ApiFact((1, 16), "apps/v1", (1, 9)),
    ("extensions/v1beta1", "networkpolicy"):     ApiFact((1, 16), "networking.k8s.io/v1", (1, 8)),
    ("extensions/v1beta1", "podsecuritypolicy"): ApiFact(
        (1, 16), "policy/v1beta1", (1, 10),
        note="PodSecurityPolicy itself was removed in 1.25; the replacement "
             "is Pod Security Admission, not another apiVersion."),
    ("apps/v1beta1", "deployment"):              ApiFact((1, 16), "apps/v1", (1, 9)),
    ("apps/v1beta1", "statefulset"):             ApiFact((1, 16), "apps/v1", (1, 9)),
    ("apps/v1beta1", "replicaset"):              ApiFact((1, 16), "apps/v1", (1, 9)),
    ("apps/v1beta2", "deployment"):              ApiFact((1, 16), "apps/v1", (1, 9)),
    ("apps/v1beta2", "statefulset"):             ApiFact((1, 16), "apps/v1", (1, 9)),
    ("apps/v1beta2", "daemonset"):               ApiFact((1, 16), "apps/v1", (1, 9)),
    ("apps/v1beta2", "replicaset"):              ApiFact((1, 16), "apps/v1", (1, 9)),

    # -- removed in v1.22 ---------------------------------------------------
    ("admissionregistration.k8s.io/v1beta1", "mutatingwebhookconfiguration"): ApiFact(
        (1, 22), "admissionregistration.k8s.io/v1", (1, 16)),
    ("admissionregistration.k8s.io/v1beta1", "validatingwebhookconfiguration"): ApiFact(
        (1, 22), "admissionregistration.k8s.io/v1", (1, 16)),
    ("apiextensions.k8s.io/v1beta1", "customresourcedefinition"): ApiFact(
        (1, 22), "apiextensions.k8s.io/v1", (1, 16)),
    ("apiregistration.k8s.io/v1beta1", "apiservice"): ApiFact(
        (1, 22), "apiregistration.k8s.io/v1", (1, 10)),
    ("authentication.k8s.io/v1beta1", "tokenreview"): ApiFact(
        (1, 22), "authentication.k8s.io/v1", (1, 6)),
    ("authorization.k8s.io/v1beta1", "localsubjectaccessreview"): ApiFact(
        (1, 22), "authorization.k8s.io/v1", (1, 6)),
    ("authorization.k8s.io/v1beta1", "selfsubjectaccessreview"): ApiFact(
        (1, 22), "authorization.k8s.io/v1", (1, 6)),
    ("authorization.k8s.io/v1beta1", "subjectaccessreview"): ApiFact(
        (1, 22), "authorization.k8s.io/v1", (1, 6)),
    ("authorization.k8s.io/v1beta1", "selfsubjectrulesreview"): ApiFact(
        (1, 22), "authorization.k8s.io/v1", (1, 6)),
    ("certificates.k8s.io/v1beta1", "certificatesigningrequest"): ApiFact(
        (1, 22), "certificates.k8s.io/v1", (1, 19)),
    ("coordination.k8s.io/v1beta1", "lease"): ApiFact(
        (1, 22), "coordination.k8s.io/v1", (1, 14)),
    ("extensions/v1beta1", "ingress"): ApiFact(
        (1, 22), "networking.k8s.io/v1", (1, 19)),
    ("networking.k8s.io/v1beta1", "ingress"): ApiFact(
        (1, 22), "networking.k8s.io/v1", (1, 19)),
    ("networking.k8s.io/v1beta1", "ingressclass"): ApiFact(
        (1, 22), "networking.k8s.io/v1", (1, 19)),
    ("rbac.authorization.k8s.io/v1beta1", "clusterrole"): ApiFact(
        (1, 22), "rbac.authorization.k8s.io/v1", (1, 8)),
    ("rbac.authorization.k8s.io/v1beta1", "clusterrolebinding"): ApiFact(
        (1, 22), "rbac.authorization.k8s.io/v1", (1, 8)),
    ("rbac.authorization.k8s.io/v1beta1", "role"): ApiFact(
        (1, 22), "rbac.authorization.k8s.io/v1", (1, 8)),
    ("rbac.authorization.k8s.io/v1beta1", "rolebinding"): ApiFact(
        (1, 22), "rbac.authorization.k8s.io/v1", (1, 8)),
    ("scheduling.k8s.io/v1beta1", "priorityclass"): ApiFact(
        (1, 22), "scheduling.k8s.io/v1", (1, 14)),
    ("storage.k8s.io/v1beta1", "csidriver"): ApiFact(
        (1, 22), "storage.k8s.io/v1", (1, 19)),
    ("storage.k8s.io/v1beta1", "csinode"): ApiFact(
        (1, 22), "storage.k8s.io/v1", (1, 17)),
    ("storage.k8s.io/v1beta1", "storageclass"): ApiFact(
        (1, 22), "storage.k8s.io/v1", (1, 6)),
    ("storage.k8s.io/v1beta1", "volumeattachment"): ApiFact(
        (1, 22), "storage.k8s.io/v1", (1, 13)),

    # -- removed in v1.25 ---------------------------------------------------
    ("batch/v1beta1", "cronjob"): ApiFact((1, 25), "batch/v1", (1, 21)),
    ("discovery.k8s.io/v1beta1", "endpointslice"): ApiFact(
        (1, 25), "discovery.k8s.io/v1", (1, 21)),
    ("events.k8s.io/v1beta1", "event"): ApiFact(
        (1, 25), "events.k8s.io/v1", (1, 19)),
    ("autoscaling/v2beta1", "horizontalpodautoscaler"): ApiFact(
        (1, 25), "autoscaling/v2", (1, 23)),
    ("policy/v1beta1", "poddisruptionbudget"): ApiFact(
        (1, 25), "policy/v1", (1, 21)),
    ("policy/v1beta1", "podsecuritypolicy"): ApiFact(
        (1, 25), "Pod Security Admission", None,
        note="There is no replacement apiVersion: PodSecurityPolicy was "
             "removed outright in favour of Pod Security Standards."),
    ("node.k8s.io/v1beta1", "runtimeclass"): ApiFact(
        (1, 25), "node.k8s.io/v1", (1, 20)),

    # -- removed in v1.26 ---------------------------------------------------
    ("autoscaling/v2beta2", "horizontalpodautoscaler"): ApiFact(
        (1, 26), "autoscaling/v2", (1, 23)),
    ("flowcontrol.apiserver.k8s.io/v1beta1", "flowschema"): ApiFact(
        (1, 26), "flowcontrol.apiserver.k8s.io/v1beta2", (1, 26)),
    ("flowcontrol.apiserver.k8s.io/v1beta1", "prioritylevelconfiguration"): ApiFact(
        (1, 26), "flowcontrol.apiserver.k8s.io/v1beta2", (1, 26)),

    # -- removed in v1.27 ---------------------------------------------------
    ("storage.k8s.io/v1beta1", "csistoragecapacity"): ApiFact(
        (1, 27), "storage.k8s.io/v1", (1, 24)),

    # -- removed in v1.29 ---------------------------------------------------
    ("flowcontrol.apiserver.k8s.io/v1beta2", "flowschema"): ApiFact(
        (1, 29), "flowcontrol.apiserver.k8s.io/v1", (1, 29)),
    ("flowcontrol.apiserver.k8s.io/v1beta2", "prioritylevelconfiguration"): ApiFact(
        (1, 29), "flowcontrol.apiserver.k8s.io/v1", (1, 29)),

    # -- removed in v1.32 ---------------------------------------------------
    ("flowcontrol.apiserver.k8s.io/v1beta3", "flowschema"): ApiFact(
        (1, 32), "flowcontrol.apiserver.k8s.io/v1", (1, 29)),
    ("flowcontrol.apiserver.k8s.io/v1beta3", "prioritylevelconfiguration"): ApiFact(
        (1, 32), "flowcontrol.apiserver.k8s.io/v1", (1, 29)),
}


# (apiVersion, lowercase kind) -> the release the API BECAME AVAILABLE in.
#
# Derived from the "available since" column of the same upstream table, which
# states it for every replacement API it names. This is the axis the tool did
# not have at all, and its absence is conspicuous: CH010's own text tells the
# reader to set kubeVersion because "autoscaling/v2 requires Kubernetes >=
# 1.23" - advice about a failure mode the tool then never checked for.
#
# Only APIs upstream explicitly dates are listed. An apiVersion missing from
# here produces NO claim, rather than a guessed one.
API_AVAILABLE_SINCE: Dict[Tuple[str, str], Tuple[int, int]] = {
    ("apps/v1", "deployment"): (1, 9),
    ("apps/v1", "daemonset"): (1, 9),
    ("apps/v1", "statefulset"): (1, 9),
    ("apps/v1", "replicaset"): (1, 9),
    ("networking.k8s.io/v1", "networkpolicy"): (1, 8),
    ("networking.k8s.io/v1", "ingress"): (1, 19),
    ("networking.k8s.io/v1", "ingressclass"): (1, 19),
    ("policy/v1beta1", "podsecuritypolicy"): (1, 10),
    ("policy/v1", "poddisruptionbudget"): (1, 21),
    ("autoscaling/v2", "horizontalpodautoscaler"): (1, 23),
    ("batch/v1", "cronjob"): (1, 21),
    ("discovery.k8s.io/v1", "endpointslice"): (1, 21),
    ("events.k8s.io/v1", "event"): (1, 19),
    ("node.k8s.io/v1", "runtimeclass"): (1, 20),
    ("admissionregistration.k8s.io/v1", "mutatingwebhookconfiguration"): (1, 16),
    ("admissionregistration.k8s.io/v1", "validatingwebhookconfiguration"): (1, 16),
    ("apiextensions.k8s.io/v1", "customresourcedefinition"): (1, 16),
    ("apiregistration.k8s.io/v1", "apiservice"): (1, 10),
    ("authentication.k8s.io/v1", "tokenreview"): (1, 6),
    ("authorization.k8s.io/v1", "localsubjectaccessreview"): (1, 6),
    ("authorization.k8s.io/v1", "selfsubjectaccessreview"): (1, 6),
    ("authorization.k8s.io/v1", "subjectaccessreview"): (1, 6),
    ("authorization.k8s.io/v1", "selfsubjectrulesreview"): (1, 6),
    ("certificates.k8s.io/v1", "certificatesigningrequest"): (1, 19),
    ("coordination.k8s.io/v1", "lease"): (1, 14),
    ("rbac.authorization.k8s.io/v1", "clusterrole"): (1, 8),
    ("rbac.authorization.k8s.io/v1", "clusterrolebinding"): (1, 8),
    ("rbac.authorization.k8s.io/v1", "role"): (1, 8),
    ("rbac.authorization.k8s.io/v1", "rolebinding"): (1, 8),
    ("scheduling.k8s.io/v1", "priorityclass"): (1, 14),
    ("storage.k8s.io/v1", "csidriver"): (1, 19),
    ("storage.k8s.io/v1", "csinode"): (1, 17),
    ("storage.k8s.io/v1", "storageclass"): (1, 6),
    ("storage.k8s.io/v1", "volumeattachment"): (1, 13),
    ("storage.k8s.io/v1", "csistoragecapacity"): (1, 24),
    ("flowcontrol.apiserver.k8s.io/v1", "flowschema"): (1, 29),
    ("flowcontrol.apiserver.k8s.io/v1", "prioritylevelconfiguration"): (1, 29),
    ("flowcontrol.apiserver.k8s.io/v1beta2", "flowschema"): (1, 26),
    ("flowcontrol.apiserver.k8s.io/v1beta2", "prioritylevelconfiguration"): (1, 26),
}

RECOMMENDED_LABELS = (
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/version",
    "app.kubernetes.io/managed-by",
)


# containers that are NOT the JVM service - never given JVM budget/CPU tables
# nor JVM-specific workload findings.
SIDECAR_NAMES = {
    "istio-proxy", "envoy", "linkerd-proxy", "nginx", "oauth2-proxy",
    "cloud-sql-proxy", "cloudsql-proxy", "vault-agent", "fluent-bit",
    "fluentd", "promtail", "filebeat", "datadog", "dd-agent", "jaeger-agent",
    "otel-collector", "opentelemetry-collector", "haproxy",
}

# F5: the name set alone missed common cases (a container named 'log-shipper'
# running image 'fluent-bit-fork'). Match the IMAGE too, by substring, so a
# renamed sidecar is still recognised. "Never given a JVM budget" is a
# documented guarantee; a closed name list does not keep it.
_SIDECAR_IMAGE_HINTS = {
    "istio/proxyv2", "envoyproxy/", "linkerd/proxy", "fluent-bit", "fluentd",
    "fluent/fluent", "promtail", "filebeat", "datadog", "dd-agent",
    "jaeger", "otel", "opentelemetry-collector", "cloud-sql-proxy",
    "cloudsql-proxy", "vault", "oauth2-proxy", "haproxy", "nginx",
    "grafana/agent", "newrelic", "aws-otel",
}


def is_sidecar(name: str, image: str) -> bool:
    """True when a container is an infra sidecar, by name OR image substring -
    never a candidate for a JVM memory/CPU budget."""
    n, img = str(name).lower(), str(image).lower()
    return n in SIDECAR_NAMES or any(h in img for h in _SIDECAR_IMAGE_HINTS)


def pod_spec(doc: ManifestDoc) -> Optional[Dict[str, Any]]:
    """Return the pod spec of a workload document, whatever its kind."""
    data = doc.data if isinstance(doc.data, dict) else {}
    spec = data.get("spec")
    if not isinstance(spec, dict):
        return None
    kind = (doc.kind or "").lower()
    if kind == "cronjob":
        jt = spec.get("jobTemplate")
        if isinstance(jt, dict):
            spec = jt.get("spec") if isinstance(jt.get("spec"), dict) else {}
        else:
            return None
    tpl = spec.get("template")
    if isinstance(tpl, dict) and isinstance(tpl.get("spec"), dict):
        return tpl["spec"]
    if kind in ("pod",):
        return spec
    return None


def containers(doc: ManifestDoc, include_init: bool = False) -> List[Dict[str, Any]]:
    ps = pod_spec(doc)
    if not ps:
        return []
    out = []
    for key in (("containers", "initContainers") if include_init else ("containers",)):
        v = ps.get(key)
        if isinstance(v, list):
            out.extend(c for c in v if isinstance(c, dict))
    return out


# env vars the JVM reads from its environment BY ITSELF, no entrypoint help -
# so JVM flags set here in the pod spec are genuinely applied at runtime,
# however the container was built. (Mirrors dockerparse.AUTO_READ_VARS.)
_ENV_AUTO_READ_VARS = {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}


def as_int(v):
    """Coerce an int OR a quoted-integer string ('6') to int, else None.

    The `| quote` templating habit yields `minReplicas: "6"`, which is an
    integer semantically but fails server-side validation. Coercing here keeps
    N1 checks/proof tables alive; a companion finding flags the quoting itself.
    """
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v.strip())
    return None


def container_env(c: Dict[str, Any]) -> List[Dict[str, Any]]:
    ev = c.get("env")
    return [e for e in ev if isinstance(e, dict)] if isinstance(ev, list) else []


def container_jvm_env_flags(c: Dict[str, Any]) -> List[str]:
    """JVM flags set via the container's own env in the pod spec, for the env
    vars the JVM reads unaided (JAVA_TOOL_OPTIONS etc.). These apply regardless
    of how the image was built - the F4 blind spot the analyzer used to have."""
    from .dockerparse import extract_jvm_flags     # local: avoid import cycle
    flags: List[str] = []
    for e in container_env(c):
        name = str(e.get("name", ""))
        val = e.get("value")
        if name.upper() in _ENV_AUTO_READ_VARS and isinstance(val, str):
            flags.extend(extract_jvm_flags(val))
    return flags


def container_jvm_env_flag_source(c: Dict[str, Any], needle: str) -> Optional[str]:
    """Which pod-spec env var supplied this JVM flag to this container, or None.

    Provenance, not decoration. When the analyzer says "max heap 4 GiB" the
    next question is always "set where?" - and if the answer is an env var in
    a template rather than a line in a Dockerfile, saying so is the difference
    between a report the reader can act on and one they have to re-derive by
    hand. It is also the only way the human-readable report states the
    mechanism at all: the env vars are what make these flags reachable with no
    Dockerfile in sight.
    """
    from .dockerparse import extract_jvm_flags     # local: avoid import cycle
    want = needle.lstrip("-").lower()
    for e in container_env(c):
        name = str(e.get("name", ""))
        val = e.get("value")
        if name.upper() in _ENV_AUTO_READ_VARS and isinstance(val, str):
            for f in extract_jvm_flags(val):
                if want in f.lstrip("-").lower():
                    return name
    return None


def chart_jvm_env_flags(ctx) -> List[str]:
    """Union of JVM flags supplied via pod-spec env across every workload
    container in the chart - used to judge whether image-level JVM config is
    truly 'missing' before asserting it as fact."""
    flags: List[str] = []
    for doc in ctx.workloads:
        for c in containers(doc):
            flags.extend(container_jvm_env_flags(c))
    return flags


# ---------------------------------------------------------------------------
# R8: "does this run a JVM?" as a question about the workload, not about which
# files happen to be in the directory.
#
# Until R8 both JVM entry points asked `if ctx.dockerfiles:` - the presence of
# a file named Dockerfile - and treated the answer as if it meant "this is a
# Java workload". It does not mean that in either direction:
#
#   * A chart setting JAVA_TOOL_OPTIONS=-Xmx4g under a 2Gi limit, with no
#     Dockerfile beside it, is unambiguously a JVM heading for a kernel OOM
#     kill. The pre-R8 tool graded it A- and said nothing, because the flags
#     it needed were behind a gate keyed on an unrelated file.
#   * A chart whose every image is nginx, that happens to ship a Dockerfile,
#     was told at HIGH to set -XX:MaxRAMPercentage.
#
# The functions below replace the file test with the evidence test, and they
# return the evidence as TEXT rather than a bool on purpose. Every JVM finding
# the analyzer prints is downstream of this answer, so the first question a
# user asks when they dispute one is "what made you think this was Java?" - and
# a bool cannot be quoted back to them. These strings go into the report.
# ---------------------------------------------------------------------------

# Image names that are themselves a statement that a JVM is inside. This is
# the same signal dockerparse already accepts from a Dockerfile's FROM line;
# trusting it there and not here would mean the tool believed a fact about a
# workload only when it was written in whichever file it happened to prefer.
_JVM_IMAGE_RE = re.compile(
    # `java` is included as a whole delimited token: it matches
    # 'registry.corp/base/java:v9' but not 'javascript-runtime', because the
    # token has to end at a delimiter or the end of the string.
    r"(?:^|[/:._-])(?:java|openjdk|eclipse-temurin|temurin|adoptopenjdk|"
    r"amazoncorretto|corretto|azul|zulu|graalvm|semeru|liberica|sapmachine|"
    r"microsoft-jdk|ibmjava|jdk|jre|tomcat|jetty|wildfly|jboss|payara)"
    r"(?:$|[/:._-])", re.I)

# Env var names the JVM does NOT read unaided, so they contribute no flags -
# but whose presence is the chart author stating that this is a Java workload.
# JAVA_HOME is here for that reason and no other.
_JVM_HINT_ENV_RE = re.compile(
    r"^(?:JAVA|JDK|JVM|JRE|CATALINA|SPRING|GRADLE|MAVEN)(?:_[A-Z0-9_]*)?$")


def is_jvm_image(img: str) -> bool:
    """Does this image name itself say a JVM is inside?

    Exported so that no second module has to keep its own list. checks_hpa
    kept one until R8, and it had drifted: no tomcat, no jetty, no wildfly, so
    one report could call a Tomcat image a JVM in the scorecard and not a JVM
    in the HPA severity. One question, one answer, one place to correct it.
    """
    return bool(img) and bool(_JVM_IMAGE_RE.search(str(img)))


def container_jvm_evidence(c: Dict[str, Any]) -> Optional[str]:
    """Why THIS container is believed to run a JVM, in words, or None.

    Ordered strongest first: configuration the user wrote and the JVM reads
    unaided, then configuration the user wrote that only a Java app would
    have, then the image name. Only the first of these also supplies flags;
    the other two answer "is this Java" without answering "configured how",
    which is exactly the distinction the pre-R8 code collapsed.
    """
    name = str(c.get("name") or "?")
    for e in container_env(c):
        n = str(e.get("name", "")).upper()
        if n in _ENV_AUTO_READ_VARS:
            return (f"container '{name}' sets {n} in the pod spec, which the "
                    f"JVM reads unaided at startup regardless of how the image "
                    f"was built")
    for e in container_env(c):
        n = str(e.get("name", "")).upper()
        if _JVM_HINT_ENV_RE.match(n):
            return (f"container '{name}' sets {n} in the pod spec - a variable "
                    f"only a JVM workload has")
    img = str(c.get("image") or "")
    if img and _JVM_IMAGE_RE.search(img):
        return (f"container '{name}' runs image '{img}', a recognisable "
                f"JRE/JDK/Java-server image")
    return None


def chart_jvm_evidence(ctx) -> List[str]:
    """Per-container JVM evidence across the chart's workloads, sidecars aside.

    Sidecars are excluded for the same reason proofs.py excludes them from JVM
    modelling: an Envoy proxy is not the thing the chart is for, and letting
    one drag the whole chart into JVM grading would reintroduce the invention
    half of the R8 defect through a different door.
    """
    ev: List[str] = []
    for doc in ctx.workloads:
        for c in containers(doc):
            if is_sidecar(c.get("name", ""), c.get("image", "")):
                continue
            e = container_jvm_evidence(c)
            if e:
                ev.append(e)
    return ev


def dockerfile_jvm_evidence(df) -> Optional[str]:
    """Why a Dockerfile is believed to build a JVM image, in words, or None."""
    if df is None:
        return None
    if df.java_major is not None:
        return (f"{df.path}: FROM a Java {df.java_major} base image"
                + (f" (update {df.java_update})" if df.java_update else ""))
    if df.jvm_flags:
        return f"{df.path}: sets JVM flags ({' '.join(df.jvm_flags[:3])}...)"
    if df.java_opts:
        return (f"{df.path}: defines "
                f"{', '.join(sorted(df.java_opts)[:3])}")
    # A JRE base image whose tag the version parser cannot read is still a JRE
    # base image. Requiring java_major here would make "I could not determine
    # the version" mean "there is no JVM", which is C2.2 inverted: a limit of
    # the method reported as a fact about the target. `FROM corp/internal-jre`
    # is the exact case the report's "Java version unknown" label exists for,
    # and it has to reach the checks for that label to ever be printed.
    final = df.final_base or {}
    img = str(final.get("image") or "")
    if img and _JVM_IMAGE_RE.search(img):
        return f"{df.path}: FROM a JVM base image ({img}), version unreadable"
    # ENTRYPOINT/CMD args are stored as the RAW instruction text, in either
    # form - exec `["java","-jar","a.jar"]` or shell `java -jar a.jar`. An
    # earlier draft of this function iterated that string expecting a list,
    # which iterates CHARACTERS, so no entrypoint ever matched and a
    # `FROM .../java:v9` image with `ENTRYPOINT ["java",...]` came back as
    # "not a JVM". Tokenise instead of guessing the shape.
    for rec in (df.entrypoint, df.cmd):
        if not rec:
            continue
        for tok in re.findall(r"[\w./-]+", str(rec.get("args") or "")):
            if re.match(r"^(.*/)?java$", tok):
                return f"{df.path}: the image's entrypoint runs `java`"
    return None


def jvm_evidence(ctx) -> List[str]:
    """Everything in this chart that says a JVM is involved. Empty means none.

    Empty is not "probably not Java" - it is "nothing in the files you gave me
    mentions a JVM". The distinction matters because the caller must then say
    so in the coverage table rather than silently omitting a whole category:
    an unrun check and a passed check look identical in a report that only
    prints failures.
    """
    ev: List[str] = []
    for df in getattr(ctx, "dockerfiles", []):
        e = dockerfile_jvm_evidence(df)
        if e:
            ev.append(e)
    ev.extend(chart_jvm_evidence(ctx))
    return ev


def this_container_is_jvm(ctx, c: Dict[str, Any]) -> Optional[str]:
    """Why THIS container is believed to run a JVM, in words, or None.

    jvm_evidence(ctx) answers "is a JVM anywhere in this chart", which is the
    right question for a category denominator and the wrong one for a finding
    about one container: in a chart with a Java API and an nginx front end it
    is true for both. Findings whose PROSE claims JVM behaviour ("class
    loading and JIT make startup CPU-hungry") need the narrower question, or
    they hand a Java explanation to the operator of the nginx pod.

    A chart-level Java Dockerfile counts, because a chart that ships one
    usually builds the image its own workload runs - but the container's own
    env and image win, and a container the sidecar heuristic recognises is
    never claimed, since a Java app beside an Envoy proxy must not lend the
    proxy its startup profile.
    """
    if is_sidecar(str(c.get("name", "")), str(c.get("image", ""))):
        return None
    own = container_jvm_evidence(c)
    if own:
        return own
    for df in getattr(ctx, "dockerfiles", []):
        e = dockerfile_jvm_evidence(df)
        if e:
            return e
    return None


JVM_EVIDENCE_INPUTS = (
    "pod-spec env (JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS, _JAVA_OPTIONS, "
    "JAVA_HOME/JAVA_*, CATALINA_*, SPRING_*), container image names "
    "(openjdk/temurin/corretto/zulu/graalvm/*-jre/*-jdk, tomcat, jetty, "
    "wildfly), and any Dockerfile's FROM line, JVM flags and entrypoint")
"""The exact list of places jvm_evidence() looks, quoted verbatim into the
coverage table. A reader who thinks the tool got this wrong needs to be able
to point at the input it missed; 'no JVM detected' with no list is unfalsifiable
and therefore not worth printing."""


def doc_name(doc: ManifestDoc) -> str:
    data = doc.data if isinstance(doc.data, dict) else {}
    md = data.get("metadata")
    if isinstance(md, dict):
        n = md.get("name")
        if isinstance(n, str):
            if n.startswith("HELMINC@"):
                return f"<{n[len('HELMINC@'):]}>"     # e.g. <orders.fullname>
            return n.replace("HELMTPL", "<tpl>")
    return "(unnamed)"


# NOTE: a per-container `qos_class()` used to live here. It was removed, not
# fixed: QoS has no per-container meaning in Kubernetes, and a function with
# that name invites callers to print a container's class under a pod's label.
# Measured against upstream ComputePodQOS it was wrong on 5 of 8 cases,
# including two SINGLE-container cases (limits-without-requests, and zero
# quantities) - see docs/ITERATIONS.md R1. Use hpaanalyzer.qos.pod_qos().

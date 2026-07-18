"""Shared Kubernetes helpers used by check modules."""

from typing import Any, Dict, List, Optional, Tuple

from .models import ManifestDoc

# apiVersion -> (removed_in, replacement)  (deprecated/removed APIs)
DEPRECATED_APIS: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("extensions/v1beta1", "deployment"):            ("1.16", "apps/v1"),
    ("extensions/v1beta1", "daemonset"):             ("1.16", "apps/v1"),
    ("extensions/v1beta1", "replicaset"):            ("1.16", "apps/v1"),
    ("extensions/v1beta1", "ingress"):               ("1.22", "networking.k8s.io/v1"),
    ("extensions/v1beta1", "networkpolicy"):         ("1.16", "networking.k8s.io/v1"),
    ("extensions/v1beta1", "podsecuritypolicy"):     ("1.16", "policy/v1beta1 (PSP removed 1.25)"),
    ("apps/v1beta1", "deployment"):                  ("1.16", "apps/v1"),
    ("apps/v1beta2", "deployment"):                  ("1.16", "apps/v1"),
    ("apps/v1beta1", "statefulset"):                 ("1.16", "apps/v1"),
    ("apps/v1beta2", "statefulset"):                 ("1.16", "apps/v1"),
    ("apps/v1beta2", "daemonset"):                   ("1.16", "apps/v1"),
    ("autoscaling/v2beta1", "horizontalpodautoscaler"): ("1.25", "autoscaling/v2"),
    ("autoscaling/v2beta2", "horizontalpodautoscaler"): ("1.26", "autoscaling/v2"),
    ("policy/v1beta1", "poddisruptionbudget"):       ("1.25", "policy/v1"),
    ("policy/v1beta1", "podsecuritypolicy"):         ("1.25", "(removed - use Pod Security Standards)"),
    ("networking.k8s.io/v1beta1", "ingress"):        ("1.22", "networking.k8s.io/v1"),
    ("networking.k8s.io/v1beta1", "ingressclass"):   ("1.22", "networking.k8s.io/v1"),
    ("batch/v1beta1", "cronjob"):                    ("1.25", "batch/v1"),
    ("rbac.authorization.k8s.io/v1beta1", "clusterrole"): ("1.22", "rbac.authorization.k8s.io/v1"),
    ("rbac.authorization.k8s.io/v1beta1", "role"):   ("1.22", "rbac.authorization.k8s.io/v1"),
    ("storage.k8s.io/v1beta1", "csidriver"):         ("1.22", "storage.k8s.io/v1"),
    ("coordination.k8s.io/v1beta1", "lease"):        ("1.22", "coordination.k8s.io/v1"),
    ("discovery.k8s.io/v1beta1", "endpointslice"):   ("1.25", "discovery.k8s.io/v1"),
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


def chart_jvm_env_flags(ctx) -> List[str]:
    """Union of JVM flags supplied via pod-spec env across every workload
    container in the chart - used to judge whether image-level JVM config is
    truly 'missing' before asserting it as fact."""
    flags: List[str] = []
    for doc in ctx.workloads:
        for c in containers(doc):
            flags.extend(container_jvm_env_flags(c))
    return flags


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


def qos_class(requests_cpu, requests_mem, limits_cpu, limits_mem,
              has_requests: bool, has_limits: bool) -> str:
    """Kubernetes QoS class per the official algorithm (single-container view)."""
    if not has_requests and not has_limits:
        return "BestEffort"
    if (requests_cpu is not None and limits_cpu is not None and requests_cpu == limits_cpu
            and requests_mem is not None and limits_mem is not None
            and requests_mem == limits_mem):
        return "Guaranteed"
    return "Burstable"

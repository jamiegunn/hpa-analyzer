"""Pod QoS, computed the way Kubernetes computes it.

This module is a deliberate, line-by-line port of upstream. It exists because
the previous implementation classified QoS *per container* and reported the
result under a heading that says "Pod QoS" - a plausible wrong answer wearing
the right answer's name. Measured against upstream it was wrong on 5 of 8
cases, including two single-container cases (see docs/ITERATIONS.md, R1).

Ground truth, quoted so a reviewer can diff this file against it:

    pkg/apis/core/v1/helper/qos/qos.go   (ComputePodQOS)

      * iterate InitContainers, then Containers
      * containerQOS := requirementsQOS(&container.Resources)
      * if any container is Burstable          -> pod Burstable   (early out)
      * if classes differ between containers   -> pod Burstable
      * no containers at all                   -> BestEffort
      * when pod-level `spec.resources` is set (PodLevelResources: alpha 1.32,
        beta / on-by-default 1.34) the pod's own requirements decide, and the
        container loop is not reached.

    requirementsQOS: per resource in {cpu, memory}
    resourceQOS:
      * request != limit  -> Burstable
      * request == limit == 0 (or absent) -> BestEffort
      * request == limit != 0 -> Guaranteed

    pkg/apis/core/v1/defaults.go (SetDefaults_Pod)

      * "If limits are specified, but requests are not, default requests to
        limits" - applied to Containers AND InitContainers. So a container
        with only `limits` is Guaranteed, not Burstable.

Deviation from upstream, on purpose: upstream operates on a validated Pod where
every quantity parses. We operate on chart templates where a quantity may be an
unresolved `{{ }}` expression. Rather than invent a value (contract C2.2) an
undecidable resource yields UNKNOWN, which propagates to the pod - except where
upstream would already have short-circuited to Burstable on a *decided*
container, which stays Burstable.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .quantity import parse_cpu, parse_memory

_INC_PREFIX = "HELMINC@"
"""helmyaml.INC_PREFIX, duplicated to keep this port free of parser imports.

Only the include marker is special-cased. A leftover HELMVAL@ marker means the
.Values path is unset in every values file read, and helm would render the same
empty block, so the ordinary BestEffort arithmetic below is correct for it.
"""

GUARANTEED = "Guaranteed"
BURSTABLE = "Burstable"
BESTEFFORT = "BestEffort"
UNKNOWN = "Unknown"

_RESOURCES = ("cpu", "memory")


@dataclass
class ContainerQoS:
    name: str
    kind: str                    # "container" | "init" | "sidecar" (init w/ restartPolicy: Always)
    qos: str
    per_resource: Dict[str, str] = field(default_factory=dict)
    undetermined: List[str] = field(default_factory=list)   # raw values that would not parse
    defaulted: List[str] = field(default_factory=list)      # resources whose request came from limit


@dataclass
class PodQoS:
    qos: str
    reason: str                          # names the container/resource that decided it
    containers: List[ContainerQoS] = field(default_factory=list)
    pod_level: bool = False              # decided by spec.resources
    undetermined: bool = False

    @property
    def decided(self) -> bool:
        return self.qos != UNKNOWN


def _parse(resource: str, raw: Any) -> Tuple[Optional[int], bool]:
    """(value, parsed_ok). Absent -> (0, True): upstream reads a missing key as
    the zero Quantity. Present-but-unparseable -> (None, False)."""
    if raw is None:
        return 0, True
    v = parse_cpu(raw) if resource == "cpu" else parse_memory(raw)
    if v is None:
        return None, False
    return v, True


def _section(res: Any, name: str) -> Dict[str, Any]:
    if not isinstance(res, dict):
        return {}
    sec = res.get(name)
    return sec if isinstance(sec, dict) else {}


def requirements_qos(resources: Any) -> Tuple[str, Dict[str, str], List[str], List[str]]:
    """Port of requirementsQOS + resourceQOS, with SetDefaults_Pod applied.

    Returns (qos, per_resource, undetermined_raw_values, defaulted_resources).
    """
    # A helper-supplied block is a STRING marker, not a dict. _section() maps
    # any non-dict to {}, i.e. to "nothing was set", and every resource then
    # parses as the zero Quantity and lands on BESTEFFORT - the tool reporting
    # a QoS class it derived from a file it never opened. UNKNOWN is the only
    # answer the evidence supports; _qos() routes it to RS014, which already
    # exists to say "refuses to guess it from values it could not resolve".
    if isinstance(resources, str) and resources.startswith(_INC_PREFIX):
        name = resources[len(_INC_PREFIX):] or "(unnamed template)"
        return UNKNOWN, {}, [f'include "{name}"'], []

    requests = _section(resources, "requests")
    limits = _section(resources, "limits")

    per: Dict[str, str] = {}
    undetermined: List[str] = []
    defaulted: List[str] = []

    for res in _RESOURCES:
        lim_raw = limits.get(res)
        req_raw = requests.get(res)
        # SetDefaults_Pod: requests default to limits key-by-key.
        if req_raw is None and lim_raw is not None:
            req_raw = lim_raw
            defaulted.append(res)

        req, req_ok = _parse(res, req_raw)
        lim, lim_ok = _parse(res, lim_raw)
        if not req_ok or not lim_ok:
            per[res] = UNKNOWN
            undetermined.extend(str(r) for r, ok in
                                ((req_raw, req_ok), (lim_raw, lim_ok)) if not ok)
            continue

        if req != lim:
            per[res] = BURSTABLE
        elif req == 0:
            per[res] = BESTEFFORT
        else:
            per[res] = GUARANTEED

    # upstream: any Burstable resource decides immediately, even if the other
    # resource is undecidable - the answer cannot be anything else.
    if BURSTABLE in per.values():
        return BURSTABLE, per, undetermined, defaulted
    if UNKNOWN in per.values():
        return UNKNOWN, per, undetermined, defaulted
    # both resources agree, or one is BestEffort and the other Guaranteed
    classes = set(per.values())
    if len(classes) == 1:
        return classes.pop(), per, undetermined, defaulted
    return BURSTABLE, per, undetermined, defaulted


def _kind(c: Dict[str, Any], is_init: bool) -> str:
    if not is_init:
        return "container"
    return "sidecar" if str(c.get("restartPolicy", "")) == "Always" else "init"


def pod_qos(ps: Optional[Dict[str, Any]]) -> PodQoS:
    """Port of ComputePodQOS. `ps` is a pod spec (`.spec.template.spec`)."""
    if not isinstance(ps, dict):
        return PodQoS(UNKNOWN, "no pod spec found", undetermined=True)

    # C1.4: pod-level resources short-circuit the container loop.
    pod_res = ps.get("resources")
    if isinstance(pod_res, dict) and (pod_res.get("requests") or pod_res.get("limits")):
        q, per, undet, _ = requirements_qos(pod_res)
        return PodQoS(
            q,
            f"pod-level spec.resources decides QoS "
            f"(cpu={per.get('cpu', '-')}, memory={per.get('memory', '-')}); "
            f"container-level values do not change it on a cluster with the "
            f"PodLevelResources feature enabled (beta / default-on in 1.34+)",
            pod_level=True, undetermined=bool(undet))

    ordered: List[Tuple[Dict[str, Any], bool]] = []
    for c in ps.get("initContainers") or []:
        if isinstance(c, dict):
            ordered.append((c, True))
    for c in ps.get("containers") or []:
        if isinstance(c, dict):
            ordered.append((c, False))

    if not ordered:
        return PodQoS(BESTEFFORT, "pod declares no containers", undetermined=False)

    details: List[ContainerQoS] = []
    pod_class: Optional[str] = None
    reason = ""
    early: Optional[str] = None

    for c, is_init in ordered:
        q, per, undet, defaulted = requirements_qos(c.get("resources"))
        name = str(c.get("name", "?"))
        details.append(ContainerQoS(name, _kind(c, is_init), q, per, undet, defaulted))
        if early is not None:
            continue
        if q == BURSTABLE:
            which = [r for r, v in per.items() if v == BURSTABLE] or ["cpu/memory"]
            early = BURSTABLE
            reason = (f"container '{name}' is Burstable "
                      f"({', '.join(which)}: request != limit) - upstream returns "
                      f"Burstable for the whole pod as soon as one container is")
        elif pod_class is None:
            pod_class = q
            reason = f"all containers so far are {q} (deciding container: '{name}')"
        elif pod_class != q:
            # "A mix of classes is Burstable" holds only when both classes are
            # KNOWN. If either side is UNKNOWN the pod may still be uniform -
            # the unreadable container could match the readable one - so the
            # mix rule cannot fire on a value the tool never saw.
            if UNKNOWN in (q, pod_class):
                early = UNKNOWN
                reason = (f"container '{name}' is {q} and an earlier container "
                          f"is {pod_class}; with one class unreadable the pod "
                          f"class cannot be decided - it is uniform if the "
                          f"unread container matches, Burstable if it does not")
            else:
                early = BURSTABLE
                reason = (f"container '{name}' is {q} but an earlier container "
                          f"is {pod_class} - a mix of classes is Burstable")

    if early is not None:
        final = early
    elif pod_class is None:
        final = BESTEFFORT
        reason = "no containers"
    else:
        final = pod_class
        names = ", ".join(f"'{d.name}'" for d in details)
        reason = f"every container ({names}) is {final}"

    if final == UNKNOWN:
        bad = sorted({v for d in details for v in d.undetermined})
        # Separate the two reasons a quantity was not usable, because they
        # call for different actions: a helper body was never expanded (run
        # with helm, or move the values into values.yaml), versus a value that
        # was read and would not parse (fix the value).
        inc = [b for b in bad if b.startswith('include "')]
        rest = [b for b in bad if not b.startswith('include "')]
        parts = []
        if inc:
            parts.append("resources are supplied by " + ", ".join(inc)
                         + ", whose body was not expanded")
        if rest:
            parts.append(f"unresolved/unparseable quantities {rest}")
        reason = ("QoS cannot be determined: " + "; ".join(parts) if parts else
                  "QoS cannot be determined from the rendered values")

    return PodQoS(final, reason, details,
                  undetermined=any(d.undetermined for d in details))


def eviction_note(qos: str) -> str:
    return {
        BESTEFFORT: "evicted FIRST under node memory pressure",
        BURSTABLE: "evicted before Guaranteed (and first if over its request)",
        GUARANTEED: "evicted last",
    }.get(qos, "eviction order unknown until QoS is determined")

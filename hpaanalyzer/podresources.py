"""The pod's resource footprint, computed the way the scheduler computes it.

The scheduler does not place containers. It places pods, against a node's
allocatable capacity, using the pod's aggregate REQUESTS. Getting that total
right is what makes any statement about node capacity, bin-packing or cluster
cost true rather than merely arithmetic.

Ground truth, quoted so a reviewer can diff this file against it:

    kubernetes/staging/src/k8s.io/component-helpers/resource/helpers.go
        PodRequests / PodLimits -> aggregateContainerResourcesByFn

      result := v1.ResourceList{}
      for _, container := range pod.Spec.Containers {
          addResourceList(result, containerResources)
      }

      restartableInitContainerResources := v1.ResourceList{}
      initContainerResources := v1.ResourceList{}
      // init containers define the minimum of any resource
      //
      // Let's say `InitContainerUse(i)` is the resource requirements when the
      // i-th init container is initializing, then
      // `InitContainerUse(i) = sum(Resources of restartable init containers
      //  with index < i) + Resources of i-th init container`.
      for _, container := range pod.Spec.InitContainers {
          if isRestartableInitContainer(&container) {
              addResourceList(result, containerResources)
              addResourceList(restartableInitContainerResources, containerResources)
              containerResources = restartableInitContainerResources
          } else {
              combinedResources := v1.ResourceList{}
              addResourceList(combinedResources, containerResources)
              addResourceList(combinedResources, restartableInitContainerResources)
              containerResources = combinedResources
          }
          maxResourceList(initContainerResources, containerResources)
      }
      maxResourceList(result, initContainerResources)

    KEP-753 (sidecar containers), "Resources calculation for scheduling and
    pod admission".

Read in words, because the loop is easy to mis-skim:

  * A **regular container** is summed. Obvious.
  * A **native sidecar** - an init container with `restartPolicy: Always`,
    GA in 1.33 - is ALSO summed into the running total, because it keeps
    running for the pod's whole life. It is not an init container in any
    sense the scheduler cares about.
  * A **one-shot init container** is MAX'd, not summed, because it has exited
    before the regular containers start. But it is max'd against the sidecars
    running beside it at that moment - `restartableInitContainerResources`,
    the cumulative sum of every sidecar declared BEFORE it in the list. Order
    matters, which is why this module preserves it.
  * Finally the init peak is max'd against the steady-state total: a pod that
    needs 4 GiB for two seconds to migrate a database needs a node with 4 GiB
    free, even if it settles at 512 MiB.

Two further terms from PodRequests itself:

  * pod-level `spec.resources` (PodLevelResources; beta / default-on in 1.34)
    OVERRIDES the container aggregate for cpu and memory.
  * `spec.overhead` (RuntimeClass, e.g. Kata) is ADDED on top. It is charged
    against the node and is invisible in every container's spec.

Deviation from upstream, on purpose (contract C2.2): upstream operates on a
validated Pod. A chart template may carry an unresolved `{{ }}` quantity. A
container whose quantity will not parse makes the total UNDETERMINED rather
than silently contributing zero - a total that quietly omits a container is
exactly the failure this module exists to fix.

Note on limits: a container with no memory limit is not "0", it is unbounded.
`PodLimits` upstream simply sums what is declared; the aggregate is therefore
meaningful only when every container sets one. This module tracks that
explicitly (`limits_complete`) instead of printing a sum that reads like a cap
but is not one.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .quantity import parse_cpu, parse_memory

_RESOURCES = ("cpu", "memory")

REGULAR = "container"
SIDECAR = "sidecar"
INIT = "init"


@dataclass
class ContainerShare:
    """One container's contribution, and how it was applied."""
    name: str
    kind: str                     # REGULAR | SIDECAR | INIT
    requests: Dict[str, Optional[int]] = field(default_factory=dict)
    limits: Dict[str, Optional[int]] = field(default_factory=dict)
    counted: str = "summed"       # "summed" | "peak only" | "unparseable"
    # Whether the container declared a resources block at all. "No block" and
    # "a block that omits requests" are the same number to the scheduler but
    # not the same mistake to the author, and the report says so.
    declared: bool = True

    @property
    def summed(self) -> bool:
        return self.counted == "summed"


@dataclass
class PodResources:
    """The pod as the scheduler sees it."""
    requests: Dict[str, Optional[int]] = field(default_factory=dict)
    limits: Dict[str, Optional[int]] = field(default_factory=dict)
    steady: Dict[str, Optional[int]] = field(default_factory=dict)
    init_peak: Dict[str, Optional[int]] = field(default_factory=dict)
    shares: List[ContainerShare] = field(default_factory=list)
    pod_level: bool = False
    overhead: Dict[str, Optional[int]] = field(default_factory=dict)
    limits_complete: bool = True
    undetermined: List[str] = field(default_factory=list)

    @property
    def decided(self) -> bool:
        return not self.undetermined

    @property
    def init_dominates(self) -> bool:
        """True when an init container, not the steady state, sets the bar the
        node must clear."""
        return any(self.init_peak.get(r, 0) > (self.steady.get(r) or 0)
                   for r in _RESOURCES)

    def sidecars(self) -> List[ContainerShare]:
        return [s for s in self.shares if s.kind == SIDECAR]


def _parse(res: str, raw: Any) -> Optional[int]:
    if raw is None:
        return 0
    return parse_cpu(raw) if res == "cpu" else parse_memory(raw)


def _quantities(c: Dict[str, Any], section: str, bad: List[str]) -> Dict[str, Optional[int]]:
    res = c.get("resources") if isinstance(c.get("resources"), dict) else {}
    sec = res.get(section) if isinstance(res.get(section), dict) else {}
    out: Dict[str, Optional[int]] = {}
    for r in _RESOURCES:
        raw = sec.get(r)
        v = _parse(r, raw)
        if v is None:
            bad.append(f"{c.get('name', '?')}.{section}.{r}={raw!r}")
        out[r] = v
    return out


def _zero() -> Dict[str, int]:
    return {r: 0 for r in _RESOURCES}


def _add(acc: Dict[str, int], other: Dict[str, Optional[int]]) -> None:
    for r in _RESOURCES:
        acc[r] += other.get(r) or 0


def _maxinto(acc: Dict[str, int], other: Dict[str, Optional[int]]) -> None:
    for r in _RESOURCES:
        acc[r] = max(acc[r], other.get(r) or 0)


def _is_sidecar(c: Dict[str, Any]) -> bool:
    """A NATIVE sidecar in the Kubernetes sense - restartPolicy: Always on an
    init container. Deliberately unrelated to kube.is_sidecar(), which is a
    heuristic about whether a container runs a JVM. Conflating the two would
    make the scheduler arithmetic depend on a name list."""
    return str(c.get("restartPolicy", "")) == "Always"


def _section(c: Dict[str, Any], name: str) -> Dict[str, Any]:
    """`resources.<name>` if it is a mapping, else {}.

    Every reader of the resources block goes through here. The direct form,
    `(c.get("resources") or {}).get("limits")`, is correct for every chart
    that is well-formed and raises AttributeError on `resources: small` - a
    chart bug the tool exists to report, turned into a crash that reports
    nothing at all. tests/test_podresources.py pins the scalar case.
    """
    res = c.get("resources")
    if not isinstance(res, dict):
        return {}
    sec = res.get(name)
    return sec if isinstance(sec, dict) else {}


def _declared(c: Dict[str, Any]) -> bool:
    """Did this container declare a resources block with anything in it?"""
    return bool(_section(c, "requests") or _section(c, "limits"))


def _list(ps: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    v = ps.get(key)
    return [c for c in v if isinstance(c, dict)] if isinstance(v, list) else []


def pod_resources(ps: Optional[Dict[str, Any]]) -> PodResources:
    """Port of PodRequests / PodLimits. `ps` is a pod spec."""
    if not isinstance(ps, dict):
        return PodResources(undetermined=["no pod spec"])

    bad: List[str] = []
    shares: List[ContainerShare] = []

    req = _zero()
    lim = _zero()
    limits_complete = True

    for c in _list(ps, "containers"):
        r = _quantities(c, "requests", bad)
        l = _quantities(c, "limits", bad)
        if not _section(c, "limits"):
            limits_complete = False
        _add(req, r)
        _add(lim, l)
        shares.append(ContainerShare(str(c.get("name", "?")), REGULAR, r, l,
                                     declared=_declared(c)))

    # Steady state = regular containers + every native sidecar. Snapshot it
    # before the init max() so the report can show both numbers: what the pod
    # holds for its whole life, and what it briefly needs at startup.
    restartable = _zero()
    init_peak = _zero()

    for c in _list(ps, "initContainers"):
        r = _quantities(c, "requests", bad)
        l = _quantities(c, "limits", bad)
        name = str(c.get("name", "?"))
        if _is_sidecar(c):
            if not _section(c, "limits"):
                limits_complete = False
            _add(req, r)
            _add(lim, l)
            _add(restartable, r)
            candidate = dict(restartable)
            shares.append(ContainerShare(name, SIDECAR, r, l, "summed",
                                         declared=_declared(c)))
        else:
            candidate = {k: (r.get(k) or 0) + restartable[k] for k in _RESOURCES}
            shares.append(ContainerShare(name, INIT, r, l, "peak only",
                                         declared=_declared(c)))
        _maxinto(init_peak, candidate)

    steady = dict(req)
    _maxinto(req, init_peak)

    result = PodResources(
        requests=req, limits=lim, steady=steady, init_peak=init_peak,
        shares=shares, limits_complete=limits_complete, undetermined=bad)

    # spec.overhead (RuntimeClass) is charged to the node on top of everything.
    oh = ps.get("overhead")
    if isinstance(oh, dict):
        parsed = {r: _parse(r, oh.get(r)) for r in _RESOURCES}
        result.overhead = parsed
        for r in _RESOURCES:
            if parsed[r]:
                result.requests[r] = (result.requests[r] or 0) + parsed[r]
                result.limits[r] = (result.limits[r] or 0) + parsed[r]

    # Pod-level resources override the container aggregate entirely.
    pod_res = ps.get("resources")
    if isinstance(pod_res, dict) and (pod_res.get("requests") or pod_res.get("limits")):
        fake = {"name": "<pod>", "resources": pod_res}
        result.requests = _quantities(fake, "requests", bad)
        result.limits = _quantities(fake, "limits", bad)
        result.pod_level = True
        result.limits_complete = bool(pod_res.get("limits"))
        result.undetermined = bad

    return result


def pods_per_node(pod_request_bytes: Optional[int],
                  node_allocatable: int) -> Optional[int]:
    """How many of this pod fit on a node, by request. None when the pod's
    request is unknown or zero - a BestEffort pod is not limited by memory
    request, it is limited by the kubelet's pod cap, and pretending otherwise
    would be a made-up number."""
    if not pod_request_bytes:
        return None
    return node_allocatable // pod_request_bytes

"""Which Kubernetes version should `helm template` be told to pretend it is?

This module exists because of a fact that is easy to state and expensive to
miss: **`helm template` is not a function of the chart directory.** It is a
function of (chart, values, kubeVersion, apiVersions), and when the caller
supplies none of the last two, helm supplies them itself - from a constant
compiled into the binary.

    helm/pkg/chartutil/capabilities.go        (v3.16.4)

      const (
          k8sVersionMajor = "1"
          k8sVersionMinor = "20"
      )
      var DefaultCapabilities = &Capabilities{
          KubeVersion: KubeVersion{
              Version: fmt.Sprintf("v%s.%s.0", k8sVersionMajor, k8sVersionMinor),
              Major:   k8sVersionMajor,
              Minor:   k8sVersionMinor,
          },
          ...
      }

Kubernetes 1.20 went end-of-life in February 2022. Every `helm template` run
that does not pass `--kube-version` is therefore a render for a cluster that
has not existed for years, and it fails in two different ways:

  1. **It refuses outright.** `renderResources()` enforces the chart's own
     `kubeVersion` (see kubeversion.py for the quoted code), so any chart
     that declares a floor above 1.20 - which is to say, any chart written
     this decade - errors with

         Error: chart requires kubeVersion: >=1.23.0-0 which is
         incompatible with Kubernetes v1.20.0

     and the caller falls back to static scrubbing. Three of this tool's own
     five fixtures hit exactly that.

  2. **When it does render, it renders the wrong branch.** Charts routinely
     gate on the cluster version:

         {{- if semverCompare ">=1.23-0" .Capabilities.KubeVersion.Version }}

     `.Capabilities.KubeVersion` is exactly what `--kube-version` sets, so
     pinned at 1.20 helm takes the legacy arm of a chart the user will deploy
     on 1.31. That failure is silent: the render succeeds, the report says
     "rendered truth", and the truth is about a cluster nobody has.

     Verified against the binary rather than assumed - `.Capabilities`
     values probed out of a real render at three versions:

         --kube-version 1.16.0 -> KubeVersion.Version v1.16.0, Minor 16
         --kube-version 1.21.0 -> KubeVersion.Version v1.21.0, Minor 21
         --kube-version 1.32.0 -> KubeVersion.Version v1.32.0, Minor 32

**And one thing `--kube-version` does NOT fix, which was worth finding out
before claiming otherwise.** `.Capabilities.APIVersions` is not derived from
the Kubernetes version at all:

    DefaultVersionSet = allKnownVersions()   // capabilities.go

    func allKnownVersions() VersionSet {
        groups := scheme.Scheme.PrioritizedVersionsAllGroups()
        ...
    }

That is every group/version compiled into the helm binary's vendored
client-go - not the cluster's API surface, and not a function of
`--kube-version`. The same three probe renders above returned:

    APIVersions.Has "autoscaling/v2"       true   at 1.16, 1.21 and 1.32
    APIVersions.Has "autoscaling/v2beta1"  true   at 1.16, 1.21 and 1.32
    APIVersions.Has "policy/v1beta1"       true   at 1.16, 1.21 and 1.32

`autoscaling/v2` first exists in 1.23; `autoscaling/v2beta1` was removed in
1.26. No cluster has ever had both. So under `helm template` the
`APIVersions` set describes an impossible cluster, at every version, and a
chart that gates on it renders the same branch no matter what.

Nor can the caller correct it. `--api-versions` APPENDS:

    i.cfg.Capabilities.APIVersions =
        append(i.cfg.Capabilities.APIVersions, i.APIVersions...)
                                                  // pkg/action/install.go

Confirmed by running it: `--api-versions autoscaling/v2` at 1.32 still
answers true for `autoscaling/v2beta1`. There is no flag that removes an
entry, so `helm template` cannot be made to model a modern cluster's API
surface. This tool therefore does not pretend to: charts that branch on
`APIVersions.Has` get CH016, which WITHHOLDS confidence in the rendered
branch rather than asserting a branch it cannot verify.

So the version is a decision the tool has to make on purpose. The policy
below, in priority order:

  * `--kube-version` from the user always wins. They know their cluster; the
    tool does not. Nothing here second-guesses it.
  * Otherwise, if the chart declares a parseable `kubeVersion`, the chart has
    already answered the question and R3 taught the tool to read it. Use the
    top of the declared range - the newest cluster the chart claims to
    support - because that is where removed APIs bite and where a user
    upgrading will land. If the range is open-ended (`>=1.23.0-0` admits
    everything forever), the "top" is meaningless, so use the newest minor
    this tool has facts about, clamped up to the declared floor.
  * Otherwise pass nothing and let helm use its constant - but say so in the
    report instead of implying the render was authoritative. CH010 already
    tells that chart to declare a kubeVersion; this module does not invent
    one on its behalf.

Because the choice is a judgement, the tool also **checks its own choice**:
when the declared range spans more than one minor, the chart is rendered at
BOTH ends and the emitted object sets are compared. If they differ, the chart
produces different Kubernetes objects at different points inside its own
supported range, and no single-version analysis - including this one - covers
all of it. That is reported (CH015) rather than resolved, because there is no
correct single answer to report.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import kube
from .kubeversion import (DOMAIN_MAX_MINOR, AboveDomain, DeclaredRange, declared_range,
                          fmt_minor, parse_version)

# helm's compiled-in default, quoted above. Kept as data so the report can
# name the version the user would otherwise have silently got.
HELM_DEFAULT_MINOR: Tuple[int, int] = (1, 20)


def _known_latest_minor() -> Tuple[int, int]:
    """The newest minor this tool has any recorded fact about.

    Derived from the tables rather than typed as a literal, so it cannot
    drift away from them. This is deliberately NOT a claim about the newest
    released Kubernetes - it is a statement about the analyzer's own
    knowledge, and the report labels it that way.
    """
    minors = [f.removed_in for f in kube.DEPRECATED_APIS.values()]
    minors += list(kube.API_AVAILABLE_SINCE.values())
    return max(minors) if minors else HELM_DEFAULT_MINOR


KNOWN_LATEST_MINOR: Tuple[int, int] = _known_latest_minor()


@dataclass
class RenderPlan:
    """The decision, plus enough of the reasoning to print it."""

    version: Optional[str] = None      # passed to --kube-version; None = omit
    source: str = "helm-default"       # user | chart-ceiling | known-latest |
    #                                    helm-default | undeclared |
    #                                    unparseable | above-horizon
    reason: str = ""                   # one line, report-ready
    probe: Optional[str] = None        # second render version for divergence
    declared: DeclaredRange = field(default_factory=DeclaredRange)

    @property
    def explicit(self) -> bool:
        return self.version is not None

    @property
    def effective_minor(self) -> Tuple[int, int]:
        """What helm will actually believe, whether we chose it or it did."""
        if self.version:
            v = parse_version(self.version)
            if v:
                return (v.major, v.minor)
        return HELM_DEFAULT_MINOR


def _v(minor: Tuple[int, int]) -> str:
    return f"{minor[0]}.{minor[1]}.0"


# --- capability gates -------------------------------------------------------
# Both spellings helm accepts. `.Capabilities.APIVersions.Has "x"` is the
# documented one; `has "x" .Capabilities.APIVersions` works because
# APIVersions is a []string and sprig's `has` takes a list.
_CAPS_HAS_RE = re.compile(r"\.Capabilities\.APIVersions\.Has\s+\"([^\"]+)\"")
_CAPS_HAS_PIPE_RE = re.compile(
    r"\bhas\s+\"([^\"]+)\"\s+\.Capabilities\.APIVersions\b")
_CAPS_ANY_RE = re.compile(r"\.Capabilities\.APIVersions")

# `{{/* ... */}}` with any dash/whitespace variant, and whole-line YAML
# comments. Both are inert at render time, so a capability expression quoted
# inside one is documentation, not a branch.
_GO_COMMENT_RE = re.compile(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", re.DOTALL)
_YAML_COMMENT_RE = re.compile(r"(?m)^[ \t]*#.*$")


def _blank_out(m) -> str:
    """Replace a match with spaces, preserving every newline.

    Deleting the text would shift every subsequent line number; blanking it
    keeps `raw[:start].count('\\n')` honest, which is the only reason the
    reported line numbers can be trusted.
    """
    return "".join("\n" if ch == "\n" else " " for ch in m.group(0))


def strip_inert(raw: str) -> str:
    """Remove template and YAML comments without moving any other character.

    Found the hard way: this module's own fixture carries a Go-template
    comment EXPLAINING why `.Capabilities.APIVersions.Has` is untrustworthy,
    and the first version of the detector dutifully flagged the explanation as
    a branch. A rule that fires on prose about itself is not a rule.
    """
    return _YAML_COMMENT_RE.sub(_blank_out, _GO_COMMENT_RE.sub(_blank_out, raw))


def capability_gates(template_raw: Dict[str, str]
                     ) -> List[Tuple[str, int, Optional[str]]]:
    """Every `.Capabilities.APIVersions` test in the templates.

    Returns (file, line, queried-group/version-or-None), sorted by file. The
    None case is a reference the regex could not pin to a literal string -
    a variable, a `range`, a computed name. It still means the output depends
    on the capability set, which is the whole point, so it is reported rather
    than dropped: the alternative is a chart that silently escapes CH016 by
    being harder to parse.

    Lives here, next to the documentation of WHY the answer is untrustworthy,
    so the detector and the explanation cannot drift apart.
    """
    hits: List[Tuple[str, int, Optional[str]]] = []
    for path, raw in sorted(template_raw.items()):
        if path.endswith("NOTES.txt"):
            continue
        raw = strip_inert(raw)
        found = False
        for rx in (_CAPS_HAS_RE, _CAPS_HAS_PIPE_RE):
            for m in rx.finditer(raw):
                hits.append((path, raw[:m.start()].count("\n") + 1, m.group(1)))
                found = True
        if not found:
            m = _CAPS_ANY_RE.search(raw)
            if m:
                hits.append((path, raw[:m.start()].count("\n") + 1, None))
    return hits


def plan(raw_kube_version: Optional[str],
         override: Optional[str] = None) -> RenderPlan:
    """Decide the --kube-version for a chart declaring `raw_kube_version`."""
    dr = declared_range(raw_kube_version)

    if override:
        return RenderPlan(
            version=override, source="user",
            reason=f"--kube-version {override} (your value; not second-guessed)",
            declared=dr)

    if not dr.declared:
        return RenderPlan(
            version=None, source="undeclared",
            reason=(f"chart declares no kubeVersion, so helm's compiled-in "
                    f"default v{_v(HELM_DEFAULT_MINOR)} is in force - pass "
                    f"--kube-version to render for your cluster"),
            declared=dr)

    if dr.parsed and not dr.minors and dr.above_domain:
        # Distinct from "unparseable" on purpose. The constraint is fine; its
        # floor is simply above everything this module can enumerate, so
        # there is no version to choose - but saying "not usable" would be a
        # statement about the chart, when the honest statement is about the
        # analyzer's own reach. CH017 reports the chart-side consequence.
        admits = (f"only versions above 1.{DOMAIN_MAX_MINOR}, past this "
                  f"analyzer's sampling horizon and past every released "
                  f"Kubernetes")
        if dr.above_domain_edge == AboveDomain.MAJOR:
            admits = ("only Kubernetes 2.0 and later, a major version that "
                      "has never been released")
        return RenderPlan(
            version=None, source="above-horizon",
            reason=(f"chart's kubeVersion {dr.raw!r} admits {admits}; "
                    f"no render version can be chosen for it"),
            declared=dr)

    if not dr.parsed or not dr.minors:
        why = dr.error or "constraint matches no Kubernetes version"
        return RenderPlan(
            version=None, source="unparseable",
            reason=(f"chart's kubeVersion {dr.raw!r} is not usable ({why}); "
                    f"helm refuses this chart on every cluster, so no render "
                    f"version can help"),
            declared=dr)

    floor, ceiling = dr.floor, dr.ceiling
    if dr.truncated:
        chosen = max(floor, KNOWN_LATEST_MINOR)
        source = "known-latest"
        reason = (f"chart declares {dr.raw!r} (open-ended); rendering at "
                  f"{fmt_minor(chosen)} - the newest minor this analyzer has "
                  f"recorded API facts for, not necessarily the newest "
                  f"Kubernetes release")
    else:
        chosen = ceiling
        source = "chart-ceiling"
        reason = (f"chart declares {dr.raw!r}; rendering at {fmt_minor(chosen)}, "
                  f"the top of its own supported range")

    probe = _v(floor) if floor != chosen else None
    return RenderPlan(version=_v(chosen), source=source, reason=reason,
                      probe=probe, declared=dr)

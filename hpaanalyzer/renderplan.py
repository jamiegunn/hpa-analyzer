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

**The constant is a fact about the helm BINARY, not about helm.** helm 3
compiled in v1.20.0, a release that went end-of-life in February 2022; helm 4
ships a recent one instead (v4.2.1 answers v1.36.0, measured by probe render
on 2026-07-27), and it moves with every helm feature release as the vendored
client-go moves. This tool therefore does not table the constant per helm
version - it MEASURES it from the installed binary
(helmrender.helm_default_kube_version, one cached probe render) whenever the
default would be in force, and reports that measured value instead of
asserting 1.20.

Either way, a `helm template` run that does not pass `--kube-version` is a
render for a cluster the user chose by installing a binary, not by knowing
their cluster - and it fails in two different ways:

  1. **It refuses outright.** `renderResources()` enforces the chart's own
     `kubeVersion` (see kubeversion.py for the quoted code) against the
     default, so any chart whose declared range excludes it errors with

         Error: chart requires kubeVersion: >=1.23.0-0 which is
         incompatible with Kubernetes v1.20.0

     and the caller falls back to static scrubbing. Under helm 3's v1.20.0
     default that meant any chart written this decade - three of this tool's
     own five fixtures. Under helm 4's recent default the same enforcement
     bites from the other side: a chart PINNED to old clusters (a ceiling
     below the default, e.g. `>=1.20.0-0 <1.22.0-0`) is refused instead.

  2. **When it does render, it renders the wrong branch.** Charts routinely
     gate on the cluster version:

         {{- if semverCompare ">=1.23-0" .Capabilities.KubeVersion.Version }}

     `.Capabilities.KubeVersion` is exactly what `--kube-version` sets, so
     helm 3's 1.20 default takes the legacy arm of a chart the user will
     deploy on 1.31 - and helm 4's 1.36-era default takes the modern arm of
     a chart the user will deploy on 1.27. Too old and too new fail the same
     way, silently: the render succeeds, the report says "rendered truth",
     and the truth is about a cluster the user does not have.

     Verified against the binary rather than assumed - `.Capabilities`
     values probed out of a real render at three versions, identical under
     helm 3.16 and helm 4.2:

         --kube-version 1.16.0 -> KubeVersion.Version v1.16.0, Minor 16
         --kube-version 1.21.0 -> KubeVersion.Version v1.21.0, Minor 21
         --kube-version 1.32.0 -> KubeVersion.Version v1.32.0, Minor 32

**And one thing `--kube-version` does NOT fix, which was worth finding out
before claiming otherwise - and re-measuring before assuming helm 4 fixed
it (it did not).** `.Capabilities.APIVersions` is not derived from the
Kubernetes version at all:

    DefaultVersionSet = allKnownVersions()   // capabilities.go

    func allKnownVersions() VersionSet {
        groups := scheme.Scheme.PrioritizedVersionsAllGroups()
        ...
    }

That is every group/version compiled into the helm binary's vendored
client-go - not the cluster's API surface, and not a function of
`--kube-version`. The same three probe renders above returned:

    helm 3.16:
      APIVersions.Has "autoscaling/v2"       true   at 1.16, 1.21 and 1.32
      APIVersions.Has "autoscaling/v2beta1"  true   at 1.16, 1.21 and 1.32
      APIVersions.Has "policy/v1beta1"       true   at 1.16, 1.21 and 1.32
    helm 4.2:
      APIVersions.Has "autoscaling/v2"       true   at 1.16, 1.21 and 1.32
      APIVersions.Has "autoscaling/v2beta1"  false  at 1.16, 1.21 and 1.32
      APIVersions.Has "policy/v1beta1"       true   at 1.16, 1.21 and 1.32

`autoscaling/v2` first exists in 1.23; `autoscaling/v2beta1` was removed in
1.25. So helm 3's set describes a cluster that has never existed (both
present at 1.16). helm 4 swapped the constant for its newer client-go's -
and the new set is impossible in the OTHER direction: v2beta1 reads absent
at 1.16-1.24 where every real cluster had it, and policy/v1beta1 reads
present at 1.32 where it was removed seven minors earlier. The defect is
structural, not a stale constant: whatever set is compiled in, it is the
same at every `--kube-version` and matches no real cluster.

Nor can the caller correct it. `--api-versions` APPENDS:

    i.cfg.Capabilities.APIVersions =
        append(i.cfg.Capabilities.APIVersions, i.APIVersions...)
                                                  // pkg/action/install.go

Confirmed by running it - against helm 3.16 and again against helm 4.2:
`--api-versions autoscaling/v2beta1` at 1.32 makes v2beta1 answer true under
helm 4, and nothing makes anything answer false. There is no flag that
removes an entry, so `helm template` cannot be made to model a real
cluster's API surface. This tool therefore does not pretend to: charts that
branch on `APIVersions.Has` get CH016, which WITHHOLDS confidence in the
rendered branch rather than asserting a branch it cannot verify.

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

# helm 3's compiled-in default, quoted above. LAST-RESORT fallback only: the
# real in-force version is measured from the installed binary
# (helmrender.helm_default_kube_version) and threaded through plan(); this
# constant is used when that measurement is unavailable, and anything built
# on it is phrased as helm-3-specific rather than asserted for every helm.
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
    helm_default: Optional[str] = None  # measured from the binary; None if not

    @property
    def explicit(self) -> bool:
        return self.version is not None

    @property
    def effective_minor(self) -> Tuple[int, int]:
        """What helm will actually believe, whether we chose it or it did.

        When no version was chosen, prefer the default MEASURED from the
        installed binary; helm 3's compiled-in constant is only the fallback
        for when there was no binary to measure.
        """
        for candidate in (self.version, self.helm_default):
            if candidate:
                v = parse_version(candidate)
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
         override: Optional[str] = None,
         helm_default_version: Optional[str] = None) -> RenderPlan:
    """Decide the --kube-version for a chart declaring `raw_kube_version`.

    `helm_default_version` is the default MEASURED from the installed helm
    binary (helmrender.helm_default_kube_version), used to name what is in
    force whenever no version can be chosen. When it is None the messages
    say so per helm major instead of asserting helm 3's constant for every
    binary.
    """
    dr = declared_range(raw_kube_version)

    if override:
        return RenderPlan(
            version=override, source="user",
            reason=f"--kube-version {override} (your value; not second-guessed)",
            declared=dr, helm_default=helm_default_version)

    in_force = (f"helm's compiled-in default v{helm_default_version} "
                f"(measured from the installed binary) is in force"
                if helm_default_version else
                f"helm's compiled-in default is in force "
                f"(v{_v(HELM_DEFAULT_MINOR)} on helm 3, newer on helm 4)")

    if not dr.declared:
        return RenderPlan(
            version=None, source="undeclared",
            reason=(f"chart declares no kubeVersion, so {in_force} - pass "
                    f"--kube-version to render for your cluster"),
            declared=dr, helm_default=helm_default_version)

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
            declared=dr, helm_default=helm_default_version)

    if not dr.parsed or not dr.minors:
        why = dr.error or "constraint matches no Kubernetes version"
        return RenderPlan(
            version=None, source="unparseable",
            reason=(f"chart's kubeVersion {dr.raw!r} is not usable ({why}); "
                    f"helm refuses this chart on every cluster, so no render "
                    f"version can help"),
            declared=dr, helm_default=helm_default_version)

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
                      probe=probe, declared=dr,
                      helm_default=helm_default_version)

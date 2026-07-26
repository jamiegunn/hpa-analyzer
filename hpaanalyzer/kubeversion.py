"""What cluster versions does this chart actually claim to run on?

`Chart.yaml: kubeVersion` is not documentation. It is executable. Helm reads
it on every render and refuses to proceed when the cluster does not satisfy
it:

    helm/pkg/action/action.go, renderResources()          (v3.16.4)

      if ch.Metadata.KubeVersion != "" {
          if !chartutil.IsCompatibleRange(ch.Metadata.KubeVersion,
                                          caps.KubeVersion.String()) {
              return ..., errors.Errorf(
                  "chart requires kubeVersion: %s which is incompatible "
                  "with Kubernetes %s",
                  ch.Metadata.KubeVersion, caps.KubeVersion.String())
          }
      }

    helm/pkg/chartutil/compatible.go

      func IsCompatibleRange(constraint, ver string) bool {
          sv, err := semver.NewVersion(ver)
          if err != nil { return false }
          c, err := semver.NewConstraint(constraint)
          if err != nil { return false }
          return c.Check(sv)
      }

Three consequences follow, and this module exists so the checks can use them
instead of guessing:

  1. A chart that declares `>=1.20.0-0 <1.22.0-0` **cannot be installed** on a
     cluster that removed `networking.k8s.io/v1beta1` Ingress in 1.22. The
     deprecated API is still worth reporting - the chart cannot move forward -
     but it is not an outage, and calling it CRITICAL costs the top of the
     fix-first list.
  2. A chart that declares `>=1.26.0-0` and ships `batch/v1beta1` CronJob is
     broken on **every** cluster it claims to support. Same rule, opposite
     certainty. A tool that emits one severity for both has thrown away the
     distinction the reader needs.
  3. `IsCompatibleRange` returns **false when the constraint does not parse**.
     A typo in kubeVersion is not ignored; it makes the chart uninstallable
     everywhere. So "is this string a valid constraint" is itself a check.

Ground truth for the constraint language: helm depends on
`github.com/Masterminds/semver/v3 v3.3.0` (helm v3.16.4 go.mod). The parser
below is a deliberate line-by-line port of that library's `constraints.go`
and the `Compare` path of `version.go`, not an independent implementation of
"semver ranges" - the two differ, and the difference is the whole point. The
best known example: `>=1.29.0` does NOT match `1.29.0-gke.1`, because
Masterminds skips prerelease versions for constraints that carry no
prerelease comparator, and every managed distribution reports a gitVersion
that is a semver prerelease. `>=1.29.0-0` does match. That is why charts are
told to write the `-0`.

Because it is a port, it is checkable *as* a port: `proof/p3_oracle.py`
builds the real Go library from source and differential-tests this module
against it over several thousand (constraint, version) pairs, and freezes the
result into `tests/oracle_semver.json` so the test suite can assert
conformance without needing Go.

Deliberate non-goal: this module answers questions about MINOR versions,
because every API removal upstream publishes is minor-granular. It does that
by evaluating the ported constraint at concrete versions and collecting which
minors admit any version at all - enumeration over the domain that matters,
not interval algebra over one that does not. `DOMAIN_MAX_MINOR` bounds it,
and `DeclaredRange.truncated` says so out loud rather than letting an
open-ended `>=1.99` silently look like an empty range.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Port of Masterminds/semver v3.3.0 version.go
# ---------------------------------------------------------------------------

# semVerRegex, verbatim.
_SEMVER = (r"v?([0-9]+)(\.[0-9]+)?(\.[0-9]+)?"
           r"(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?"
           r"(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?")
_VERSION_RE = re.compile("^" + _SEMVER + "$")


@dataclass(frozen=True)
class Version:
    major: int = 0
    minor: int = 0
    patch: int = 0
    pre: str = ""
    metadata: str = ""

    def compare(self, o: "Version") -> int:
        """Port of Version.Compare. Note the release-beats-prerelease rule."""
        for a, b in ((self.major, o.major), (self.minor, o.minor),
                     (self.patch, o.patch)):
            if a != b:
                return -1 if a < b else 1
        if self.pre == "" and o.pre == "":
            return 0
        if self.pre == "":
            return 1
        if o.pre == "":
            return -1
        return _compare_prerelease(self.pre, o.pre)


def parse_version(text: str) -> Optional[Version]:
    """Port of semver.NewVersion - the LENIENT parser helm uses. `1.29` and
    `v1.29` are accepted and mean 1.29.0."""
    m = _VERSION_RE.match(text or "")
    if not m:
        return None
    return Version(
        major=int(m.group(1)),
        minor=int(m.group(2).lstrip(".")) if m.group(2) else 0,
        patch=int(m.group(3).lstrip(".")) if m.group(3) else 0,
        pre=m.group(5) or "",
        metadata=m.group(8) or "")


def _compare_prerelease(a: str, b: str) -> int:
    ap, bp = a.split("."), b.split(".")
    for i in range(max(len(ap), len(bp))):
        d = _compare_pre_part(ap[i] if i < len(ap) else "",
                              bp[i] if i < len(bp) else "")
        if d != 0:
            return d
    return 0


def _uint(s: str) -> Optional[int]:
    """Go's strconv.ParseUint(s, 10, 64): digits only, no sign, no spaces."""
    return int(s) if s.isdigit() else None


def _compare_pre_part(s: str, o: str) -> int:
    if s == o:
        return 0
    if s == "":
        return -1 if o != "" else 1
    if o == "":
        return 1
    si, oi = _uint(s), _uint(o)
    if si is None and oi is None:      # both strings
        return 1 if s > o else -1
    if oi is None:                     # o is a string, s is a number
        return -1
    if si is None:                     # s is a string, o is a number
        return 1
    return 1 if si > oi else -1


# ---------------------------------------------------------------------------
# Port of Masterminds/semver v3.3.0 constraints.go
# ---------------------------------------------------------------------------

# cvRegex, verbatim - note the '|' inside the character classes. That is a
# quirk of the upstream source (it reads as a literal pipe, not alternation);
# it is reproduced rather than tidied, because tidying it would be a silent
# behaviour change against the library helm actually runs.
_CV = (r"v?([0-9|x|X|\*]+)(\.[0-9|x|X|\*]+)?(\.[0-9|x|X|\*]+)?"
       r"(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?"
       r"(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?")
_OPS = r"=||!=|>|<|>=|=>|<=|=<|~|~>|\^"

_CONSTRAINT_RE = re.compile(r"^\s*(%s)\s*(%s)\s*$" % (_OPS, _CV))
_RANGE_RE = re.compile(r"\s*(%s)\s+-\s+(%s)\s*" % (_CV, _CV))
_FIND_RE = re.compile(r"(%s)\s*(%s)" % (_OPS, _CV))
_VALID_RE = re.compile(
    r"^(\s*(%s)\s*(%s)\s*)((?:\s+|,\s*)(%s)\s*(%s)\s*)*$" % (_OPS, _CV, _OPS, _CV))


class ConstraintError(ValueError):
    """The string is not a constraint Masterminds would accept - which means
    helm's IsCompatibleRange returns False for every cluster version."""


def _is_x(s: str) -> bool:
    return s in ("x", "*", "X")


@dataclass
class _Comparison:
    con: Version
    orig: str
    op: str
    minor_dirty: bool = False
    patch_dirty: bool = False
    dirty: bool = False

    def check(self, v: Version) -> bool:
        return _OP_FUNCS[self.op](v, self)


def _rewrite_range(text: str) -> str:
    """Port of rewriteRange: `1.2 - 1.4.5` becomes `>= 1.2, <= 1.4.5`."""
    out = text
    for m in _RANGE_RE.finditer(text):
        out = out.replace(m.group(0), ">= %s, <= %s " % (m.group(1), m.group(11)), 1)
    return out


def _parse_comparison(text: str) -> _Comparison:
    if not text:
        return _Comparison(Version(0, 0, 0), text, "", dirty=True)
    m = _CONSTRAINT_RE.match(text)
    if not m:
        raise ConstraintError("improper constraint: %s" % text)
    op, orig = m.group(1), m.group(2)
    g3, g4, g5, g6 = m.group(3), m.group(4), m.group(5), m.group(6) or ""
    minor_dirty = patch_dirty = dirty = False
    if _is_x(g3) or g3 == "":
        ver, dirty = "0.0.0%s" % g6, True
    elif _is_x((g4 or "").lstrip(".")) or not g4:
        ver, minor_dirty, dirty = "%s.0.0%s" % (g3, g6), True, True
    elif _is_x((g5 or "").lstrip(".")) or not g5:
        ver, patch_dirty, dirty = "%s%s.0%s" % (g3, g4, g6), True, True
    else:
        ver = orig
    con = parse_version(ver)
    if con is None:
        raise ConstraintError("constraint Parser Error")
    return _Comparison(con, orig, op, minor_dirty, patch_dirty, dirty)


@dataclass
class Constraint:
    """A parsed kubeVersion constraint. `check` is helm's `c.Check(sv)`."""
    raw: str
    ors: List[List[_Comparison]] = field(default_factory=list)

    def check(self, version: str) -> bool:
        """Exactly helm's IsCompatibleRange, given an already-parsed
        constraint: an unparseable *version* is False, not an exception."""
        v = parse_version(version)
        if v is None:
            return False
        for group in self.ors:
            if all(c.check(v) for c in group):
                return True
        return False


def parse_constraint(text: str) -> Constraint:
    """Port of semver.NewConstraint. Raises ConstraintError where the Go
    function returns an error - and that error is what makes helm refuse to
    install the chart anywhere at all."""
    rewritten = _rewrite_range(text)
    ors: List[List[_Comparison]] = []
    for segment in rewritten.split("||"):
        if not _VALID_RE.match(segment):
            raise ConstraintError("improper constraint: %s" % segment)
        found = [m.group(0) for m in _FIND_RE.finditer(segment)] or [segment]
        ors.append([_parse_comparison(s) for s in found])
    return Constraint(text, ors)


# -- the comparison functions, one per operator -----------------------------
#
# Every one of these opens with the same prerelease guard upstream. It is
# repeated here rather than hoisted, because hoisting it would hide the single
# most surprising behaviour in the file: `>=1.29.0` rejects `1.29.0-gke.1`.

def _pre_blocked(v: Version, c: _Comparison) -> bool:
    return v.pre != "" and c.con.pre == ""


def _gt(v: Version, c: _Comparison) -> bool:
    if _pre_blocked(v, c):
        return False
    if not c.dirty:
        return v.compare(c.con) == 1
    if v.major > c.con.major:
        return True
    if v.major < c.con.major:
        return False
    if c.minor_dirty:
        return False
    if c.patch_dirty:
        return v.minor > c.con.minor
    return v.compare(c.con) == 1


def _lt(v: Version, c: _Comparison) -> bool:
    if _pre_blocked(v, c):
        return False
    return v.compare(c.con) < 0


def _gte(v: Version, c: _Comparison) -> bool:
    if _pre_blocked(v, c):
        return False
    return v.compare(c.con) >= 0


def _lte(v: Version, c: _Comparison) -> bool:
    if _pre_blocked(v, c):
        return False
    if not c.dirty:
        return v.compare(c.con) <= 0
    if v.major > c.con.major:
        return False
    if v.major == c.con.major and v.minor > c.con.minor and not c.minor_dirty:
        return False
    return True


def _tilde(v: Version, c: _Comparison) -> bool:
    if _pre_blocked(v, c):
        return False
    if v.compare(c.con) < 0:
        return False
    if (c.con.major == 0 and c.con.minor == 0 and c.con.patch == 0
            and not c.minor_dirty and not c.patch_dirty):
        return True
    if v.major != c.con.major:
        return False
    if v.minor != c.con.minor and not c.minor_dirty:
        return False
    return True


def _tilde_or_equal(v: Version, c: _Comparison) -> bool:
    if _pre_blocked(v, c):
        return False
    if c.dirty:
        return _tilde(v, c)
    return v.compare(c.con) == 0


def _caret(v: Version, c: _Comparison) -> bool:
    if _pre_blocked(v, c):
        return False
    if v.compare(c.con) < 0:
        return False
    if c.con.major > 0 or c.minor_dirty:
        return v.major == c.con.major
    if c.con.major == 0 and v.major > 0:
        return False
    if c.con.minor > 0 or c.patch_dirty:
        return v.minor == c.con.minor
    if c.con.minor == 0 and v.minor > 0:
        return False
    return c.con.patch == v.patch


def _not_equal(v: Version, c: _Comparison) -> bool:
    if c.dirty:
        if _pre_blocked(v, c):
            return False
        if c.con.major != v.major:
            return True
        if c.con.minor != v.minor and not c.minor_dirty:
            return True
        if c.minor_dirty:
            return False
        if c.con.patch != v.patch and not c.patch_dirty:
            return True
        if c.patch_dirty:
            if v.pre != "" or c.con.pre != "":
                return _compare_prerelease(v.pre, c.con.pre) != 0
            return False
    return v.compare(c.con) != 0


_OP_FUNCS = {
    "": _tilde_or_equal, "=": _tilde_or_equal, "!=": _not_equal,
    ">": _gt, "<": _lt, ">=": _gte, "=>": _gte, "<=": _lte, "=<": _lte,
    "~": _tilde, "~>": _tilde, "^": _caret,
}


# ---------------------------------------------------------------------------
# The part the checks actually use
# ---------------------------------------------------------------------------

DOMAIN_MAX_MINOR = 60
"""Kubernetes 1.60 is roughly 2033 at three releases a year. Sampling stops
there; `DeclaredRange.truncated` records when the constraint was still
admitting versions at the edge, so an open-ended range is never mistaken for
a closed one."""

# Each minor is probed at both ends of its patch space. One sample is not
# enough: `>=1.21.3` admits 1.21 but not 1.21.0, and a single probe at
# `1.21.0` would drop a whole minor from the answer.
_PATCH_PROBES = (0, 999)

# Probes ABOVE the horizon, used only when the in-domain sampling found
# nothing. Without them an empty result has two very different causes wearing
# the same face:
#
#   `>=1.30.0-0 <1.20.0-0`   contradictory - satisfiable by nothing, ever
#   `>=1.61.0-0`             satisfiable, just not anywhere we looked
#
# Reporting the second as the first is contract C2.2 committed against our own
# sampling: "we stopped looking at 1.60" is not "there is nothing to find".
# One probe just past the horizon is not enough either - a floor of 1.99 would
# miss it - so the probes are spread out.
_ABOVE_DOMAIN_PROBES = (DOMAIN_MAX_MINOR + 1, DOMAIN_MAX_MINOR + 40, 200, 999)

# The domain has TWO edges, and the first version of this fix only guarded one.
# `majors` defaults to (1,) because Kubernetes has never shipped a 2.x, so
# `>=2.0.0-0` also produced an empty minor set - and fell into exactly the
# CH013 sentence this section exists to prevent, plus a render plan that called
# a well-formed constraint `unparseable`. "No 2.x exists" happens to make
# CH013's headline true today, which is precisely what made the hole easy to
# miss: a rule can be right by accident and still give wrong advice (it blames
# reversed bounds) and still make a false subsidiary claim (it parses fine).
_ABOVE_DOMAIN_MAJORS = (2, 3, 9)


class AboveDomain:
    """Which edge of the sampled domain a constraint sits past."""
    NO = ""
    MINOR = "minor"    # 1.x, x > DOMAIN_MAX_MINOR
    MAJOR = "major"    # 2.0 and later; no such release exists


@dataclass
class DeclaredRange:
    """The set of Kubernetes minors a chart says it supports.

    `parsed=False` is not "unknown, assume the worst quietly" - it is a fact
    with its own consequence (helm installs the chart nowhere) and callers are
    expected to branch on it rather than default through it.
    """
    raw: Optional[str] = None
    parsed: bool = False
    error: Optional[str] = None
    minors: Tuple[Tuple[int, int], ...] = ()
    truncated: bool = False
    accepts_prerelease: bool = True
    above_domain: bool = False
    """The constraint parsed, admits versions, and admits none of them at or
    below `DOMAIN_MAX_MINOR`. `minors` is empty for the same reason a search
    of the wrong shelf comes back empty - callers must not read it as
    'unsatisfiable'."""
    above_domain_edge: str = AboveDomain.NO
    """Which edge: `AboveDomain.MINOR` (1.61+, past our sampling horizon) or
    `AboveDomain.MAJOR` (2.0+, past every Kubernetes release ever made). The
    distinction is not pedantic - it changes what the user is told. The first
    may become a correct chart when the horizon is raised; the second is wrong
    today on every cluster and the advice differs accordingly."""

    @property
    def declared(self) -> bool:
        return bool(self.raw)

    @property
    def known(self) -> bool:
        """True when we can say something about which clusters are in scope."""
        return self.parsed and bool(self.minors)

    @property
    def floor(self) -> Optional[Tuple[int, int]]:
        return self.minors[0] if self.minors else None

    @property
    def ceiling(self) -> Optional[Tuple[int, int]]:
        return self.minors[-1] if self.minors else None

    def includes(self, major: int, minor: int) -> bool:
        return (major, minor) in self.minors

    def at_or_above(self, major: int, minor: int) -> List[Tuple[int, int]]:
        return [m for m in self.minors if m >= (major, minor)]

    def below(self, major: int, minor: int) -> List[Tuple[int, int]]:
        return [m for m in self.minors if m < (major, minor)]

    def describe(self) -> str:
        """A human-readable rendering of the sampled set, e.g. '1.20-1.21'."""
        if not self.minors:
            if self.above_domain_edge == AboveDomain.MAJOR:
                return "nothing in 1.x (only 2.0 and later)"
            if self.above_domain:
                return f"nothing at or below 1.{DOMAIN_MAX_MINOR}"
            return "no cluster version"
        lo, hi = self.floor, self.ceiling
        span = f"{lo[0]}.{lo[1]}" if lo == hi else f"{lo[0]}.{lo[1]}-{hi[0]}.{hi[1]}"
        return span + ("+" if self.truncated else "")


def fmt_minor(m: Tuple[int, int]) -> str:
    return f"{m[0]}.{m[1]}"


def declared_range(raw: Optional[str],
                   majors: Sequence[int] = (1,)) -> DeclaredRange:
    """Reconcile a Chart.yaml kubeVersion string into a set of minors.

    Returns a DeclaredRange in one of three honest states:
      * not declared           -> raw is None/empty; nothing is known
      * declared, unparseable  -> parsed=False with the error; helm rejects
                                  this chart on every cluster
      * declared and parsed    -> minors is the sampled satisfying set, which
                                  may legitimately be empty (e.g. `>=1.30 <1.20`)

    An empty `minors` has two causes and they are not interchangeable: the
    constraint is contradictory, or its floor is above `DOMAIN_MAX_MINOR` and
    the sampling never reached it. `above_domain` distinguishes them; a caller
    that reports the second as the first is asserting a fact it did not check.
    """
    if not raw or not str(raw).strip():
        return DeclaredRange(raw=None, parsed=False)
    text = str(raw).strip()
    try:
        con = parse_constraint(text)
    except ConstraintError as e:
        return DeclaredRange(raw=text, parsed=False, error=str(e))

    minors: List[Tuple[int, int]] = []
    for major in majors:
        for minor in range(0, DOMAIN_MAX_MINOR + 1):
            if any(con.check(f"{major}.{minor}.{p}") for p in _PATCH_PROBES):
                minors.append((major, minor))
    truncated = bool(minors) and minors[-1][1] == DOMAIN_MAX_MINOR

    # Empty in-domain result: ask whether the constraint is unsatisfiable or
    # merely out of range, instead of letting the caller guess (see
    # _ABOVE_DOMAIN_PROBES).
    above_minor = (not minors) and any(
        con.check(f"{major}.{m}.{p}")
        for major in majors
        for m in _ABOVE_DOMAIN_PROBES
        for p in _PATCH_PROBES)
    above_major = (not minors) and not above_minor and any(
        con.check(f"{maj}.{m}.{p}")
        for maj in _ABOVE_DOMAIN_MAJORS
        for m in (0, 1, 30, 999)
        for p in _PATCH_PROBES)
    edge = (AboveDomain.MINOR if above_minor else
            AboveDomain.MAJOR if above_major else AboveDomain.NO)
    above_domain = bool(edge)

    # Managed distributions report gitVersions like `v1.29.3-gke.1093000` and
    # `v1.30.0-eks-a5ec690`. Those are semver PRERELEASES, and Masterminds
    # refuses them for any constraint with no prerelease comparator - so
    # `>=1.29.0` matches no GKE or EKS cluster at all, at any version. This
    # probe asks the ported engine rather than pattern-matching for "-0".
    probe = minors[len(minors) // 2] if minors else (1, 30)
    accepts_pre = con.check(f"{probe[0]}.{probe[1]}.3-gke.1093000")

    return DeclaredRange(raw=text, parsed=True, minors=tuple(minors),
                         truncated=truncated, accepts_prerelease=accepts_pre,
                         above_domain=above_domain, above_domain_edge=edge)

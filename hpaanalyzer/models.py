"""Core data models: findings, severities, categories, parsed-file containers."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = ("CRITICAL", 5, 25)   # (label, rank, score deduction)
    HIGH     = ("HIGH",     4, 12)
    MEDIUM   = ("MEDIUM",   3, 6)
    LOW      = ("LOW",      2, 3)
    INFO     = ("INFO",     1, 0)

    @property
    def label(self) -> str:
        return self.value[0]

    @property
    def rank(self) -> int:
        return self.value[1]

    @property
    def deduction(self) -> int:
        return self.value[2]


class Basis(Enum):
    """Epistemic status of a finding - HOW the tool knows what it claims.

    The single most dangerous thing a static analyser can do is voice a guess
    in the same factual register as parsed evidence. Every finding therefore
    declares its basis, and the report renders each one differently:

      OBSERVED  the claim is read directly from the input (a value in the YAML,
                a flag in the Dockerfile, an object in the helm render). Stated
                as fact.
      DERIVED   the claim is arithmetic on observed values using a stated model
                with estimated constants (the JVM memory budget, CPU shares).
                The inputs are real; the projection is a model. Rendered with
                its assumptions visible.
      ASSUMED   the claim rests on a fallback the tool made *because it could
                not see the truth* (a single-workload pairing guess, a default
                heap ratio, an unknown Java version). Rendered with a mandatory
                'Assumes:' clause, flagged in fix-first, and - for CRITICALs -
                capped at HIGH's score weight so an assumption can never sink a
                grade the way an observed fact can.

    Deliberate design note: the field defaults to OBSERVED rather than being
    mandatory-with-no-default. OBSERVED is the correct value for the ~100 call
    sites that report parsed evidence; forcing each to restate it adds noise
    and edit risk without protection. Protection comes from the inverse
    discipline - every fallback/estimate path explicitly sets DERIVED/ASSUMED,
    and tests/test_regressions.py pins the basis of every such rule so a
    regression to OBSERVED fails the suite.
    """
    OBSERVED = "observed"
    DERIVED  = "derived"
    ASSUMED  = "assumed"

    @property
    def label(self) -> str:
        return self.value


class Category(Enum):
    CHART      = "Helm Chart Structure & Hygiene"
    TEMPLATES  = "Kubernetes Templates & API Versions"
    RESOURCES  = "Resource Requests & Limits"
    HPA        = "Horizontal Pod Autoscaling"
    AVAIL      = "Availability & Disruption Tolerance"
    PROBES     = "Health Probes & Lifecycle"
    DOCKERFILE = "Dockerfile Quality"
    JAVA       = "Java / JVM Container Fitness"
    SECURITY   = "Security Posture"
    CROSS      = "Cross-File Consistency (Chart <-> JVM)"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: Category
    title: str
    file: str                       # relative path of the offending file ('' if global)
    detail: str                     # what was found, with concrete values
    why: str                        # educational: why it matters
    fix: str                        # concrete remediation
    math: Optional[str] = None      # optional mathematical proof / worked example
    line: Optional[int] = None
    basis: Basis = Basis.OBSERVED   # epistemic status (see Basis); default is
                                    # correct for parsed evidence - fallbacks
                                    # and estimates MUST override it
    assumes: Optional[str] = None   # required for ASSUMED: the guess in one line

    def sort_key(self):
        return (-self.severity.rank, self.category.value, self.rule_id)

    def effective_deduction(self) -> int:
        """Score impact, with the ASSUMED-CRITICAL cap applied.

        An ASSUMED finding rests on a fallback the tool made because it could
        not see the truth; letting such a guess deduct a full CRITICAL (-25)
        would let the tool's own uncertainty sink a grade. ASSUMED findings
        deduct at most HIGH's weight.
        """
        d = self.severity.deduction
        if self.basis is Basis.ASSUMED:
            return min(d, Severity.HIGH.deduction)
        return d


@dataclass
class ProofTable:
    """A named mathematical proof table rendered in the report."""
    title: str
    intro: str                      # what the table proves
    headers: List[str]
    rows: List[List[str]]
    conclusion: str                 # verdict drawn from the numbers


@dataclass
class DockerfileInfo:
    path: str
    raw: str = ""
    instructions: List[Dict[str, Any]] = field(default_factory=list)  # {instr, args, line}
    base_images: List[Dict[str, Any]] = field(default_factory=list)   # {image, tag, stage, line}
    final_base: Optional[Dict[str, Any]] = None
    java_major: Optional[int] = None       # 8, 11, 17, 21 ...
    java_update: Optional[int] = None      # for java 8: 8uNNN
    java_flavor: str = ""                  # jdk / jre / distroless etc.
    java_opts: Dict[str, str] = field(default_factory=dict)  # env var name -> raw value
    jvm_flags: List[str] = field(default_factory=list)       # all parsed jvm flags
    entrypoint: Optional[Dict[str, Any]] = None  # {form: 'exec'|'shell', args, line}
    cmd: Optional[Dict[str, Any]] = None
    user: Optional[str] = None
    healthcheck: bool = False
    exposed_ports: List[str] = field(default_factory=list)
    multistage: bool = False
    launcher_script_text: str = ""   # text of an in-directory ENTRYPOINT/CMD
                                     # script (e.g. docker-entrypoint.sh), if
                                     # readable - lets DF013 see `exec java
                                     # $JAVA_OPTS` before calling a var inert


@dataclass
class ManifestDoc:
    """A single YAML document from a helm template.

    rendered=True  -> came from `helm template` output (real YAML) or, in
                      static mode, from the scrubbed parse (best effort).
    rendered=False -> template exists but did NOT render with the analyzed
                      values (e.g. gated behind a disabled flag); analyzed
                      anyway, findings are annotated as conditional.
    """
    file: str
    kind: Optional[str]
    api_version: Optional[str]
    data: Any
    raw: str = ""
    rendered: bool = True


@dataclass
class ChartContext:
    """Everything discovered in the target directory."""
    root: str = ""
    chart_yaml_path: Optional[str] = None
    chart: Dict[str, Any] = field(default_factory=dict)
    values_files: Dict[str, Any] = field(default_factory=dict)      # path -> parsed dict
    values_raw: Dict[str, str] = field(default_factory=dict)        # path -> raw text
    values: Dict[str, Any] = field(default_factory=dict)            # merged effective values
    template_files: List[str] = field(default_factory=list)
    template_raw: Dict[str, str] = field(default_factory=dict)      # path -> raw text
    docs: List[ManifestDoc] = field(default_factory=list)
    dockerfiles: List[DockerfileInfo] = field(default_factory=list)
    helpers_tpl: bool = False
    notes_txt: bool = False
    schema_json: bool = False
    helmignore: bool = False
    parse_errors: List[str] = field(default_factory=list)
    tests_dir: bool = False

    # --- coverage / confidence -------------------------------------------
    render_mode: str = "static"          # "helm" | "static" | "static (helm failed: ...)"
    helm_error: Optional[str] = None
    coverage: List[List[str]] = field(default_factory=list)   # [item, status]
    subcharts_present: bool = False
    assumed_java: Optional[str] = None   # from --assume-java
    overlay_values: List[str] = field(default_factory=list)   # non-base values files
    chart_dir_abs: Optional[str] = None  # for helm re-render of overlay variants
    foreign_charts: List[str] = field(default_factory=list)   # other Chart.yamls NOT analyzed
    templates_present: bool = False      # any chart templates existed at all
    ungradeable_reason: Optional[str] = None  # set -> force NOT GRADED

    # -- convenience selectors ------------------------------------------------
    def docs_of_kind(self, *kinds: str) -> List[ManifestDoc]:
        kl = {k.lower() for k in kinds}
        return [d for d in self.docs if (d.kind or "").lower() in kl]

    @property
    def workloads(self) -> List[ManifestDoc]:
        return self.docs_of_kind(
            "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
            "Job", "CronJob", "Rollout")

    @property
    def hpas(self) -> List[ManifestDoc]:
        return self.docs_of_kind("HorizontalPodAutoscaler")


@dataclass
class AnalysisResult:
    context: ChartContext
    findings: List[Finding] = field(default_factory=list)
    proofs: List[ProofTable] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def add_proof(self, proof: ProofTable):
        self.proofs.append(proof)

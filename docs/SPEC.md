# hpa-analyzer — specification of intent

This document states what the tool is *supposed* to do. It exists so that
"is it correct?" and "does it do its job?" are two different questions with
two different answers, and so that neither can be settled by opinion.

Everything below is a testable claim. Where a claim depends on Kubernetes or
JVM behaviour, the authoritative source is named. `docs/ITERATIONS.md` records
each place the implementation was measured against this document, what failed,
and what was done about it.

## 1. Purpose

Given **one directory** containing a Helm chart, its values file(s) and
(optionally) the Dockerfile for a **JVM service**, produce a report that lets
an engineer who is *not* a Kubernetes expert answer three questions before
they deploy:

1. **Will this schedule, admit and survive?** — requests/limits sanity, QoS,
   disruption budget, probes, API versions that the target cluster still has.
2. **Will the autoscaler do what the author thinks it does?** — HPA target
   arithmetic, metric availability, conflicts with `spec.replicas`.
3. **Will the JVM inside the container behave the way the chart assumes?** —
   cgroup awareness for the specific JDK build, whether the configured
   `JAVA_OPTS` are actually applied, and whether the heap plus its overheads
   fit inside `limits.memory`.

Non-goals, stated so absence is not read as failure: it is not a schema
validator (`kubeconform` is), not a policy engine (Kyverno/OPA are), not a
security scanner (Trivy is), not a load test, and it does not analyse
subcharts.

## 2. The contract

These are the properties the tool must hold. Each is numbered so tests and the
iteration log can cite it.

### C1 — Fidelity: model Kubernetes, not a plausible sketch of it

Where the tool restates a Kubernetes-computed value, it must implement the
algorithm Kubernetes actually uses, including the defaulting the API server
applies on the way in.

* **C1.1 Pod QoS.** QoS is a property of the **pod**, computed over init
  containers *and* regular containers, per-resource (cpu, memory), where any
  Burstable container makes the pod Burstable and a mix of BestEffort and
  Guaranteed also makes it Burstable.
  Source: `pkg/apis/core/v1/helper/qos/qos.go` — `ComputePodQOS` /
  `requirementsQOS` / `resourceQOS`.
* **C1.2 Request defaulting.** A container that sets `limits` and omits
  `requests` has requests defaulted to limits at pod creation, for regular
  **and** init containers. A tool that reports such a container as Burstable is
  wrong. Source: `pkg/apis/core/v1/defaults.go` — `SetDefaults_Pod`.
* **C1.3 Zero is not "set".** `cpu: 0` / `memory: 0` are BestEffort for that
  resource, not Guaranteed. Source: `resourceQOS`.
* **C1.4 Pod-level resources.** When `spec.resources` is present, QoS derives
  from it and container-level values do not decide the class.
  (`PodLevelResources`: alpha 1.32, **beta and on-by-default in 1.34**.)
* **C1.5 Sidecar accounting.** An init container with `restartPolicy: Always`
  (a *native sidecar*, GA 1.33) runs for the whole pod lifetime. It counts
  toward pod QoS, toward the pod's scheduling footprint, and toward what the
  container runtime lets the JVM's neighbours consume. Any total the tool
  prints must say which containers are in it.
* **C1.6 HPA arithmetic.** `desiredReplicas = ceil(currentReplicas ×
  currentMetricValue / desiredMetricValue)`, with no action inside the
  configured tolerance (default 10%).

### C2 — Epistemic honesty: never voice a guess in the register of a fact

* **C2.1** Every finding carries a `basis`: `OBSERVED` (read from the input),
  `DERIVED` (arithmetic on observed values through a stated model with stated
  constants), or `ASSUMED` (a fallback used *because the truth was not
  visible*).
* **C2.2** A value the tool cannot determine — an unresolved template, a
  quantity it cannot parse, a cluster fact — must be reported as
  *undetermined*, never defaulted into a confident answer. "Unknown" is a
  permitted output; a plausible wrong answer is not.
* **C2.3** A table headed "proof" proves only the arithmetic. Every estimated
  input must be labelled as an estimate **inside the table**, at the point of
  use, not in a caveat elsewhere in the document.
* **C2.4** Severity must reflect what the tool actually knows about the target.
  If the chart declares the cluster versions it targets (`kubeVersion`), a
  finding whose existence depends on the cluster version must be reconciled
  against that declaration.
* **C2.5** Absence of a finding is not a claim of correctness. Every input file
  and every skipped check appears in the coverage section.
* **C2.6** A category that could not be assessed must not silently contribute
  *nothing* either. C2.2 forbids defaulting the undetermined into a confident
  answer; the same reasoning forbids dropping it out of an average without
  saying so, because that silently changes the scale the answer is expressed
  on. Any surface that prints the score must print what the score was computed
  over, and must name the categories that were excluded and why.
* **C2.7** A predicate about the *workload* must be evaluated against evidence
  about the workload, and the evidence must be quotable. It is not enough that
  a proxy correlates: "is this a JVM?" answered by "is there a file named
  `Dockerfile`?" is a different question, and a proxy is wrong in **both**
  directions — it invents the property where the proxy is present and denies
  it where the proxy is absent. Consequently: (a) the predicate is computed in
  exactly one place, (b) it returns the sentences that justify it rather than a
  boolean, so that every surface which acts on it can print *why*, and (c)
  "the evidence was inconclusive" is a third state distinct from yes and no,
  reported under C2.2 with the inputs that were examined listed, so a reader
  who disagrees can name the one it missed. See *R8* in `ITERATIONS.md`, where
  this proxy had been substituted in thirteen places.
* **C2.8** C2.3 requires an estimate to be *labelled*; a label is not enough
  when the estimate decides the answer. A conclusion drawn from estimated
  inputs must be reported at the width of the evidence behind it, which means
  all of: **(a)** every estimated component carries a documented band, printed
  at the point of use, not only a point value; **(b)** any total derived from
  those components is reported as an interval, not as a number; **(c)** when
  the threshold the conclusion turns on (a memory limit, a quota) lies
  *inside* that interval, the verdict is a third state — undetermined — and
  the tool may not silently ship either endpoint's answer, because at that
  point the verdict is a property of the constants and not of the user's
  input; **(d)** the undetermined verdict must name the minimal set of
  estimates that decides it and how far they must move against how large the
  gap is, so the reader has something specific to check; **(e)** it must name
  the observation that would settle it and the flag that accepts that
  observation — *derived from the run, not written out as a sentence*, so
  that after a partial measurement it names what is still missing and not
  what the reader has already supplied, and says which is which — and
  supplying every component that way must remove the interval and say that
  it has; **(f)** because C2.5 forbids scoring the
  tool's own ignorance as the user's defect, the score does not move — and
  therefore *every* surface that prints the score must also print the
  undetermined verdict beside it, since a grade with an unqualified "no
  findings" under it is the same false confidence one screen further up; and
  **(g)** a cell that cites the user's own input as the provenance of a value
  must quote what they typed. Re-rendering the parsed number — as an integer,
  or through the tool's own formatter — puts a string the user never wrote
  into a sentence whose whole content is "this is here because you wrote
  that". See *R9* in `ITERATIONS.md`, where a 108 MiB margin was reported as
  a fit six rows below the tool's own printed 100 MiB band on one of its
  inputs; and where clause (e) was *satisfied* by a fixed sentence that told
  a reader to measure the two components they had just measured, which is
  why (e) now says "derived from the run".

### C3 — Determinism: same input, same output, everywhere

* **C3.1** Identical input directories produce byte-identical reports across
  operating systems and filesystem orderings. No result may depend on
  `os.walk`/`os.listdir` order, on dict iteration order, or on locale.
* **C3.2** Analysis performs no network I/O and mutates nothing in the target
  directory.

### C4 — Usability: the answer arrives without reading a file

* **C4.1** The terminal output alone states the grade, the count by severity,
  and the ranked list of what to fix first.
* **C4.2** A first-time user can discover the required directory layout from
  the tool itself (`--check`), not only from the README.
* **C4.3** Exit codes are stable and distinguish *tool failure* (2) from
  *quality gate failure* (1).
* **C4.4** A gate is a claim about the target, not about how much of it was
  read. Whatever the report says, the **exit code** is what CI acts on, so a
  threshold comparison made against a reduced scale (C2.6) must be visible on
  the CI surface — announced on stderr on every such run, and gateable
  (`--require-coverage`). It must not be possible to turn a failing gate green
  by removing an input file.

### C5 — Verifiability: claims are checkable by the reader

* **C5.1** For each cluster fact the tool cannot see, it emits the exact
  command that answers it, pre-filled with the user's object names.
* **C5.2** Where the ecosystem already has an authoritative tool (`helm lint`,
  `kubeconform`, `kube-score`, `polaris`), the tool can run it and reproduce
  its output verbatim and attributed, rather than reimplementing its opinion.
* **C5.3** Every capability claimed in the README is exercised by a test that
  runs the real code path. A capability verified only through mocks must be
  labelled as such, in the README, in the same sentence as the claim.

## 3. Inputs and outputs

**Input.** One directory. `Chart.yaml` identifies the chart. `values*.ya?ml`
are the base values plus overlays (each overlay is re-analysed as a variant).
`templates/` holds manifests. A `Dockerfile` may live anywhere beneath the
directory. `charts/` (subcharts) is recorded and skipped. Nothing is required
to be in a special place beyond Helm's own layout.

**Rendering.** When `helm` is on PATH the chart is rendered by the real
template engine and the analysis reads rendered truth. Otherwise the templates
are statically scrubbed, conditionals are analysed as taken, and the report
states which mode ran, in the report header and in coverage.

**Measured overrides.** `--measured metaspace=…,codecache=…,threads=…,
xss=…,direct=…,gc=…` replaces any estimated non-heap component with an
observed value (the report prints the `jcmd VM.native_memory summary` command
that produces them). Each supplied component drops out of the band arithmetic
of C2.8; supplying all of them removes the interval entirely and the report
says so rather than leaving the reader to notice that a range stopped being
printed.

**Output.** A plain-text report (any editor), optionally HTML, optionally JSON
for machines, plus the terminal summary of C4.1.

**The grade.** The score is defined as *a weighted count of the findings this
run produced*, expressed out of 100: ten categories carry fixed weights
summing to 100, each starts at 100, findings subtract. It is deliberately
**not** defined as an estimate of risk, of outage probability, or of
deployability, and the tool must not present it as one. Three properties
follow and must be stated wherever the number is:

1. It is a mean over the categories that could be assessed, so it is
   comparable across runs only when the coverage (C2.6) is the same.
2. Categories floor at 0, so it saturates: past some density of findings a
   worse chart scores the same.
3. It does not encode the evidence basis — a helm-rendered run and a static
   run print the same units, and may not even agree on whether the chart can
   be graded at all.

No value is imputed for an unassessed category. Imputing 100 would invent a
clean bill of health (a direct C2.2 violation), imputing 0 would invent
findings, and imputing the mean of the others asserts that the unseen
resembles the seen. There is no honest number for "not looked at", so the
tool prints the denominator instead of hiding it.

## 4. What "correct" means for this tool

Two distinct bars, both required:

**Bar 1 — arithmetic and model correctness.** Every value the tool derives
matches the upstream algorithm on a suite of cases including the degenerate
ones (zero quantities, limits-without-requests, multi-container pods, init and
native-sidecar containers, unparseable quantities).

**Bar 2 — fitness for purpose.** On a chart with a real defect of each class in
§1, the defect appears in the terminal output's fix-first list, with a fix an
engineer can apply without further research; and on a clean chart the tool
stays quiet. A tool that is arithmetically perfect and buries the one critical
finding under sixty lines of advice has failed Bar 2.

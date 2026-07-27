# Iteration log

Each entry follows the same discipline: state the defect, **prove** it against
an external authority rather than asserting it, explain the reasoning, fix it,
then evaluate against **both** bars in [SPEC.md](SPEC.md) §4 — Bar 1
(arithmetic and model correctness) and Bar 2 (fitness for purpose: does the
answer reach the user).

An entry is not finished when the code works. It is finished when the failure
mode that produced the defect has been named, so the same class of bug is
harder to reintroduce.

---

## R1 — Pod QoS was computed per container, and per container QoS does not exist

### The defect

`hpaanalyzer/kube.py` exposed `qos_class(container) -> str`, which inspected a
single container's `resources` block and returned `Guaranteed`, `Burstable` or
`BestEffort`. The proof table printed those values under the heading
**"QoS class and eviction order"**, and `checks_workload.py` raised RS011
("QoS class is BestEffort") once per container.

Kubernetes has no such concept. QoS is a property of the **pod**. It is what
the kubelet writes to `status.qosClass`, and it is the only value that decides
eviction order, OOM score adjustment, and eligibility for the static CPU
manager and memory manager policies. A per-container number printed under a
pod-level heading is not an approximation of the right answer; it is a
different quantity wearing the right answer's name.

### The authority

Not intuition, and not the Kubernetes website — the concepts page describes the
classes but does not state the algorithm precisely enough to port. The
authority used is the source:

    kubernetes/pkg/apis/core/v1/helper/qos/qos.go   ComputePodQOS
    kubernetes/pkg/apis/core/v1/defaults.go         SetDefaults_Pod

Fetching rather than remembering was decisive twice:

1. `ComputePodQOS` in current master has been **refactored** away from the
   older sum-of-requests-vs-sum-of-limits form into a per-container,
   per-resource form with an early return. A port written from memory of the
   older shape would have been wrong on mixed-class pods.
2. The container iterator is

   ```go
   containerIter := func(yield func(*v1.Container) bool) {
       for _, c := range pod.Spec.InitContainers { if !yield(&c) { return } }
       for _, c := range pod.Spec.Containers     { if !yield(&c) { return } }
   }
   ```

   There is **no `restartPolicy` filter**. A one-shot init container counts.
   That single fact carries most of R1's practical weight: a `wait-for-db`
   busybox that runs for two seconds costs the pod its Guaranteed class for
   the pod's entire lifetime, and nobody expects it.

The rules, quoted into the module docstring of `hpaanalyzer/qos.py` so a
reviewer can diff the port against the original:

* `resourceQOS`: `request != limit` → Burstable; `request == limit == 0` (or
  absent) → BestEffort; `request == limit != 0` → Guaranteed.
* `requirementsQOS`: over `{cpu, memory}` only — not ephemeral-storage, not
  hugepages.
* `ComputePodQOS`: any Burstable container returns Burstable immediately; a
  disagreement between containers returns Burstable; no containers →
  BestEffort.
* `SetDefaults_Pod`: "If limits are specified, but requests are not, default
  requests to limits" — applied key-by-key, to Containers **and**
  InitContainers. So `limits:` with no `requests:` is Guaranteed.
* Pod-level `spec.resources` (PodLevelResources, alpha 1.32, **beta and
  default-on in 1.34**) decides the pod's QoS and the container loop is never
  reached.

### The proof

`proof/p1_qos.py` runs eight pod specs through the old function and the new
port. The OLD column is the measured pre-fix output, captured before
`qos_class` was deleted.

    OLD: 5/8 wrong.   NEW: 0/8 wrong.

The five failures, and why each is not a rounding error:

| case | truth | old answer | why the old code got it wrong |
|---|---|---|---|
| `limits:` only, no `requests:` | Guaranteed | Burstable | never modelled `SetDefaults_Pod` |
| explicit `cpu: 0`, `memory: 0` | BestEffort | Guaranteed | treated `req == lim` as sufficient, ignoring the `IsZero` branch |
| Guaranteed app + Burstable `istio-proxy` | Burstable | "Guaranteed" for the app row | no pod-level computation existed |
| Guaranteed app + resource-less sidecar | Burstable | "Guaranteed" for the app row | same |
| Guaranteed app + BestEffort **init** container | Burstable | "Guaranteed" for the app row | init containers were not iterated at all |

Two of those five — limits-without-requests, and explicit zeros — are
**single-container pods**. That matters because the README defended the old
behaviour as "exact for single-container workloads." It was not. The defence
was false on its own terms, which is why the fix was a rewrite and not a patch.

### The reasoning

The bug is not arithmetic, it is a category error, and the category error was
reachable because a function existed with a name that made it sound sensible.
Anyone reading `qos_class(container)` at a call site has no reason to doubt it.
So the fix could not stop at making the function right — the function had to
stop existing, or the next contributor would call it again.

### The fix

* **New** `hpaanalyzer/qos.py`: a faithful port with the upstream algorithm
  quoted in the docstring. Returns a `PodQoS` carrying the pod class, a
  human-readable `reason` naming the container that decided it, and a
  `ContainerQoS` per container with its role (`container` / `init` /
  `sidecar`), its per-resource classes, which requests were defaulted from
  limits, and which quantities would not parse.
* **Deleted** `kube.qos_class`, replaced by a comment explaining why it was
  removed rather than fixed, so the deletion survives the next refactor.
* **One deliberate deviation from upstream**, documented in the docstring:
  upstream operates on a validated Pod where every quantity parses. This tool
  operates on chart templates where a quantity may be an unresolved `{{ }}`
  expression. An undecidable resource yields `Unknown` and propagates
  (contract C2.2) rather than inventing a value — except where upstream would
  already have short-circuited to Burstable on a *decided* container, which
  stays Burstable, because no value of the unknown could change that answer.
* **Rewrote the call sites**: RS011 (pod is BestEffort) now fires once per
  pod with the deciding reason; RS014 (INFO) reports an undeterminable QoS
  honestly instead of guessing; RS015 is new — see Bar 2 below.
* **Rewrote proof TABLE 4** to be pod-level: a row per container with a Role
  column, `= limit*` cells marking requests Kubernetes will default, a
  `=> POD` verdict row, and the `kubectl get pod -o
  jsonpath='{.items[*].status.qosClass}'` command to check the tool's answer
  against a live cluster.

### Evaluation — Bar 1 (arithmetic and model correctness)

`tests/test_qos.py` is a 16-case table (A–P), each case carrying the upstream
justification for its expected value as data, plus a meta-test that fails any
case whose justification is missing. Cases include the degenerate ones the old
code fell over: zero quantities, limits-without-requests, unit-equivalence
(`1000m == 1`, `1024Mi == 1Gi`), `request > limit`, native sidecars, pod-level
resources, and a pod with no containers.

Coverage before this iteration: **zero tests touched QoS at all.** That is the
real reason a category error survived — not that it was subtle.

Result: **157 tests pass** (140 before R1). Bar 1 met.

### Evaluation — Bar 2 (fitness for purpose)

Bar 1 passing is where this iteration nearly stopped, and stopping there would
have been a mistake. `proof/p1b_bar2.py` builds a chart whose *only* flaw is a
resource-less init container in a pod whose app container is Guaranteed, and
runs the real engine. With RS015 at its original MEDIUM severity, the terminal
printed:

    GRADE A  (94.0/100)   0 critical, 0 high, 4 medium, 6 low
    No critical or high findings.

The finding was computed correctly, written to the report file, and reported to
the user as *"no critical or high findings."* An actively reassuring wrong
answer is worse than silence. Bar 1 passed; Bar 2 failed.

**The fix, and why it is not severity inflation.** RS015 was raised to HIGH.
That is only legitimate because of the guard already in the rule: it fires only
when a regular container *already* has `request == limit` for both cpu and
memory. The author demonstrably intended Guaranteed and has paid its price —
pinned requests, no burst headroom, a harder pod to schedule — while receiving
none of its benefit. That configuration is strictly dominated: fixing the other
containers or relaxing this one is better on every axis. A pod that never asked
for Guaranteed is just Burstable, and RS015 stays silent;
`tests/test_fitness_qos.py::test_severity_is_justified_by_the_guard_not_by_the_bar`
pins that, so the severity cannot be quietly generalised later.

After:

    GRADE A-  (92.6/100)   0 critical, 1 high, 3 medium, 6 low
    Fix first:
      1. [RS015] Pod is Burstable although the app container is Guaranteed

`tests/test_fitness_qos.py` (5 tests, real engine, no mocks — contract C5.3)
now pins all of Bar 2: the defect reaches the *terminal*, the fix names the
offending container and is applicable without further research, a clean pod
stays quiet, and the proof table carries the `=> POD` verdict row.

End-to-end on `fixtures/sidecar-chart`, RS015 now sits second in the fix-first
list, and TABLE 4 renders `wait-for-db → init → BestEffort`,
`log-shipper → sidecar → Burstable`, `payments → container → Guaranteed`,
`istio-proxy → container → Burstable`, `=> POD → Burstable`.

### Bar 2 shortfall found and NOT fixed in this iteration

On `fixtures/sidecar-chart` the fix-first list is otherwise occupied entirely
by findings against `istio-proxy` — RS008, PB001, SC001 — each justified with
JVM-specific reasoning ("for a JVM with fixed `-Xmx` there is no benefit", "for
a JVM that means 503s during the whole warmup window") applied to an Envoy
proxy that contains no JVM. `kube.is_sidecar()` already knows `istio-proxy` is
a sidecar; it is used to withhold JVM budget tables but not to adjust the
rationale text of these findings.

This is a genuine Bar 2 defect — wrong reasoning attached to a real finding,
crowding the pod-level answer down the list — and it belongs to R2 (sidecar
accounting), where the sidecar model is being reworked anyway. Recording it
here rather than fixing it opportunistically keeps the iterations separable.

### Also discovered, queued

* The README claims `DEPRECATED_APIS` holds "14 entries". It holds 22. A
  claim that was true once and was never re-checked — the same failure mode as
  the QoS defence. Queued for R5 (README/SPEC reconciliation).
* Report table cells break container names mid-word (`wait-for / -db`,
  `log-ship / per`). Cosmetic, but it makes a table whose whole purpose is
  naming the offending container worse at naming it. Queued for R5.
* PB002 ("No livenessProbe") fires against `istio-proxy` — an instance of the
  R2 shortfall above.

---

## R2 — The tool answered pod questions with container numbers

### The defect

Three symptoms, one cause.

1. **RS008's node-fit sentence divided node allocatable by a single
   container's request** and called the result "such pods". On
   `fixtures/sidecar-chart` it printed *"node allocatable 8 GiB packs
   floor(8GiB/128 MiB) = 64 such pods by request"*. Upstream arithmetic says
   **3**. A 21.3x overstatement, in the one sentence in the report a capacity
   planner would actually copy into a spreadsheet.
2. **Nothing in the package computed a pod-level total at all.** Not a wrong
   total — no total. `git ls-tree HEAD hpaanalyzer/` lists 21 modules and none
   of them aggregates a pod.
3. **A native sidecar was invisible.** `kube.containers()` walks
   `spec.containers` unless asked otherwise, so an init container with
   `restartPolicy: Always` — a real, always-running process, GA since 1.33 —
   passed through every resource check the tool had without being looked at
   once.

The cause is the same category error as R1, one level up: a container is not a
schedulable thing. The scheduler places **pods** against node allocatable. Any
sentence about how many fit, what a replica costs, or whether a node has room
is a pod sentence, and answering it with a container number is not an
approximation — it is a different quantity wearing the right answer's name.

### The authority

    kubernetes/staging/src/k8s.io/component-helpers/resource/helpers.go
        PodRequests / PodLimits -> aggregateContainerResourcesByFn
    KEP-753 (sidecar containers), "Resources calculation for scheduling
        and pod admission"

The Go loop is quoted in full at the top of `hpaanalyzer/podresources.py` and
again in `proof/p2_sidecar.py`, so a reviewer can diff the port against the
original without leaving the repo. Fetching rather than recalling mattered in
two places that a from-memory port gets wrong:

* A one-shot init container is max'd **against the cumulative requests of the
  restartable init containers declared before it**
  (`InitContainerUse(i) = sum(restartable init containers with index < i) +
  resources of the i-th`). Declaration **order** therefore changes the pod's
  request. Moving a sidecar above or below a migration container in the YAML
  changes what the node reserves, and nothing in the chart makes that visible.
* `PodRequests` has two terms that live nowhere near a container: pod-level
  `spec.resources` (PodLevelResources, beta and default-on in 1.34)
  **overrides** the container aggregate, and `spec.overhead` (RuntimeClass,
  e.g. Kata) is **added** to it.

### The proof

Every claim above is produced by running code, and the "before" column is not
a description of the old behaviour — it is the old behaviour. `git archive
<baseline>` extracts the pre-fix commit into a temporary directory, the
fixture is copied in, and it runs in a subprocess. Both columns are real
program output and the only variable is the fix.

> Corrected in R3: this originally read `git archive HEAD`, which was true
> only while nothing had been committed. See *The proof* under R3 — the
> revision is now pinned in `proof/baseline.py`.

* `proof/p2_sidecar.py` — the 21.3x claim, before and after, plus a
  hand-transcribed reference port of the Go that imports nothing from
  `hpaanalyzer`. When the tool and the reference agree that is two independent
  derivations agreeing; a tool agreeing with itself is not evidence.
  Before: `= 64 such pods`. After: `= 3 of these pods`. Reference: 3.
* `proof/p2d_bar2.py` — the fitness half, on `fixtures/initheavy-chart`.
* `proof/p2b_rationale.py` — the R1-deferred rationale defect (below).
* `proof/p2c_label.py` — the label-wrapping defect (below).

`proof/` now lives inside the repository. It was outside it until this
iteration, which meant `docs/ITERATIONS.md` cited scripts a reader could not
run — a documentation claim that could not be checked, in a document whose
entire argument is that claims should be checkable.

### The reasoning

Why a new module rather than a helper next to the existing checks: the
aggregate is not a convenience, it is a *model*. It has to carry the steady
state and the init peak separately (a pod that needs 6 GiB for forty seconds
needs a node with 6 GiB free, and the number it settles at is not the number
that has to fit), it has to preserve declaration order, it has to know that
`limits` summed across containers where one container has none is not a
ceiling, and it has to refuse to answer when a quantity will not parse. Those
constraints are the module. Scattering them across call sites is how the
21.3x sentence happened in the first place.

Why the totals are shown and not just used: contract C1.5 says any total the
tool prints must say which containers are in it. A pod request is a number the
reader cannot re-derive by looking at the YAML — `summed` versus `peak only`
is the entire difference between a native sidecar and an init container, and
it hangs on one `restartPolicy: Always` line. A total the reader cannot check
is a total the reader has to trust, and this tool has already been wrong.

### The fix

* **New** `hpaanalyzer/podresources.py`: `pod_resources(pod_spec)` returning
  `requests`, `limits`, `steady`, `init_peak`, a `ContainerShare` per
  container (name, kind, quantities, how it counted, whether a `resources`
  block was declared at all), `pod_level`, `overhead`, `limits_complete` and
  `undetermined`.
* **Rewrote RS008's math** to state the pod total, name every container in it,
  and divide by that: *"Node fit is a POD question, so it uses the pod's
  request (payments 2 GiB, istio-proxy 128 MiB, log-shipper 128 MiB) = 2.2
  GiB: an 8 GiB node packs floor(8 GiB / 2.2 GiB) = 3 of these pods."*
* **New RS016** — an init container that sets the pod's reservation. Fires
  when `init_peak > steady` by ≥1.25x, HIGH at ≥2x. It reports both numbers
  and the multiplier, per resource.
* **New RS017** — a native sidecar with no requests. **CRITICAL** when it
  declares no `resources` block at all, HIGH when it declares limits and omits
  requests.
* **New proof TABLE**, "Pod scheduling footprint (what the node reserves)": a
  row per container with how it counts, then `steady state`, `init peak` and
  `=> POD REQUEST` rows, and a verdict naming pods-per-node by both memory and
  CPU.
* **RS015's rationale de-assumed**: it asserted the pod's Burstable class cost
  "the JVM" its Guaranteed eviction priority. It now names the container that
  is configured correctly instead of guessing what runs inside it.

**Why RS017 is CRITICAL, argued rather than chosen.** RS001 ("container has no
resource requests/limits") is CRITICAL. To the scheduler and to
`ComputePodQOS`, a native sidecar *is* a regular container: KEP-753 sums it,
and the QoS classifier iterates it. So this is not a defect similar to RS001's
— it is RS001's defect, in a container the tool never looked at. A separate
rule exists only because `kube.containers()` defaults to `spec.containers`;
grading the same failure lower because the tool found it in a different list
would encode a blind spot in the tool as a judgement about Kubernetes, and
that kind of mistake outlives the blind spot. The one gradation that is about
the author rather than the tool: no block at all was never sized (CRITICAL); a
block with limits and no requests is a sizing mistake with a bounded blast
radius (HIGH). `tests/test_fitness_podresources.py` pins both.

### Evaluation — Bar 1 (arithmetic and model correctness)

`tests/test_podresources.py`, 26 cases against the upstream algorithm:
summing, native sidecars summed and not max'd, one-shot inits max'd, the
per-resource (not whole-vector) max, an init max'd against the sidecars
declared *before* it, **declaration order changing the answer**, two one-shot
inits not summing with each other, pod-level `spec.resources` overriding,
`spec.overhead` adding, incomplete limits flagged rather than summed,
unresolved templates making a total undetermined, and `pods_per_node(0)`
returning `None` rather than infinity.

Result: **202 tests pass** (157 after R1). Bar 1 met.

**A bug this iteration introduced, and how it was caught.** The `declared`
conformance tests include `resources: small` — a scalar where a mapping
belongs, which a chart can render. Two readers in the new module used
`(c.get("resources") or {}).get("limits")`, correct for every well-formed
chart and an `AttributeError` for that one. Verified end-to-end: the analyzer
died on the whole chart, reporting nothing about any of it — the worst
possible response to precisely the input it exists to catch. Fixed by routing
every read through one `_section()` helper. Recorded here because the lesson
is not "be careful": it is that the conformance test found a defect the
feature tests could not, because it asked about a shape rather than a value.

### Evaluation — Bar 2 (fitness for purpose)

`fixtures/initheavy-chart` is the subject: an application container beyond
reproach — Guaranteed, three probes, non-root, read-only root filesystem, all
capabilities dropped, `preStop` hook — and a pod aggregate that is a capacity
accident. Steady state 500m / 1 GiB, init peak 2 cores / 6 GiB, so every
replica reserves 6 GiB for its whole life and uses 1 GiB after the first few
seconds. At `replicaCount: 4`, 20 GiB of cluster memory held open for nothing.

`proof/p2d_bar2.py`, both columns real program output:

    BEFORE   GRADE A+  (97.1/100)   0 critical, 0 high, 2 medium, 3 low
             No critical or high findings.

    AFTER    GRADE B-  (82.8/100)   1 critical, 3 high, 2 medium, 3 low
             Fix first:
               1. [RS017] Native sidecar runs for the pod's whole life with
                  no resource requests
               2. [RS015] Pod is Burstable although the app container is
                  Guaranteed
               3. [RS016] Init container sets the pod's memory reservation
                  (6.0x the steady state)
               4. [RS016] Init container sets the pod's cpu reservation
                  (4.0x the steady state)

The strings `6 GiB`, `metrics-agent` and `init peak` appear nowhere in the
before-summary. The pre-fix tool did not merely miss this chart's defects; it
graded it at the top of the scale and told the user there was nothing urgent
to do. No rule was lost in the change — the three that appear are new.

The grade fell from A+ to B- on a chart nobody edited. That is the tool
correcting itself rather than the chart getting worse, and it is the whole
argument for having a second bar: the A+ was the bug.

`tests/test_fitness_podresources.py` (19 tests, real engine over real
directories on disk, contract C5.3) pins every part of that: the finding
reaches the *terminal* fix-first list and not just the report file; the fix
names `db-migrate` and shows `6 GiB`, `1 GiB` and `4 x`; both numbers are
reported, not just the larger; a proportionate init container stays quiet and
the 1.25x threshold is pinned so nobody later widens RS016 into noise on every
chart that has an init container; a sized sidecar stays quiet; a one-shot init
container is never accused of being a sidecar; and a malformed `resources`
block does not kill the run.

### The R1-deferred defect, closed here

R1 recorded that on `fixtures/sidecar-chart` the fix-first list was occupied
almost entirely by findings against `istio-proxy`, each justified with
JVM-specific reasoning — `-Xmx`, class loading, `/actuator/health`,
`MaxRAMPercentage`, "add a USER to the Dockerfile" — applied to an Envoy proxy
that contains no JVM and whose image the user does not build.

`proof/p2b_rationale.py` measures it by monkeypatching the new `_pick` helper
back to its pre-fix behaviour, so both columns come from the same engine on
the same fixture: **8 false premises before, 0 after**, with the finding
count, the rule/severity multiset and the fix-first list provably unchanged.
All four fix-first entries had been against `istio-proxy`, and all four
prescribed something impossible.

A finding's `why` and `fix` are the product; the rule id and severity are
packaging. When the prose describes a workload the container is not, both
available outcomes are bad: the reader acts on advice that does not apply, or
learns the prose is decorative and stops reading it — which discards the
findings that were right.

**The asymmetry that makes this safe.** `kube.is_sidecar()` is a heuristic
over container names and image substrings — ASSUMED, never OBSERVED. It is
sound to consult it here, and *only* here, because it withholds a **claim**
and never a **finding**. Misclassifying the app as infrastructure costs the
reader one JVM-specific sentence they did not need; it hides no defect. Using
the same heuristic to suppress a finding would not be safe.
`tests/test_fitness_podresources.py::TestTheHeuristicNeverHidesAFinding` runs
the whole engine with the heuristic forced off and requires an identical
rule/severity multiset — and requires the app container to *keep* its JVM
advice, because withholding the JVM sentence from the JVM would be the same
defect, mirrored.

### The third defect, found by this iteration's own Bar 2 test

The new footprint table labelled its answer row `Deployment/payments  => POD
REQUEST`. At `WIDTH=100` a five-column table leaves 84 characters of content;
the natural widths came to 86, the renderer shrank the first column to 31, and
the label is 35. It printed as `=> POD` on one line and `REQUEST` on the next,
under a container-shaped cell. A reader scanning the left column for the pod
total does not find it. Neither does grep — which is how it was caught: the
Bar 2 assertion `assertIn("=> POD REQUEST", text)` failed against a report
containing every character of that string.

Fixed by merging `Role` into `How it counts`. That is not tidying: the role
*is* how it counts — a sidecar is summed *because* it is a sidecar — so the
two columns carried one fact twice. Four columns leave 87 against naturals of
79 and every label fits whole. `proof/p2c_label.py` shows the before and
after through the real renderer, and the regression test checks **every**
label in the table rather than the one that failed, because the next column
someone adds will break a different one.

### Also discovered, queued

* The R5 note about mid-word cell breaking (`wait-for / -db`) is the same
  renderer behaviour seen from a different angle. R2 relieved the pressure on
  this table by removing a column; it did not fix `_table`, which will still
  break a long token mid-word when the budget genuinely does not fit. Still
  queued for R5.
* PB003's `math` and several `detail` strings still describe pod behaviour
  using a single container's numbers. Lower stakes than RS008 because they do
  not produce a capacity figure, but the same category error. Queued for R5.

---

## R3 — Kubernetes version numbers were decoration, not data

### The defect

One cause, three symptoms, all demonstrable on a chart of forty lines.

1. **Severity was a constant.** Every `TP010` (removed apiVersion) finding was
   `CRITICAL`, on every chart, regardless of what the chart said about where
   it runs. A chart pinned to `>=1.20.0-0 <1.22.0-0` shipping a
   `networking.k8s.io/v1beta1` Ingress — an API removed in 1.22, i.e. *above
   the chart's own ceiling* — was reported as an outage. It is not one. Helm
   will not install that chart on 1.22 at all.
2. **The availability axis did not exist.** The tool checked whether an API
   had been *removed* below the cluster version and never whether it had been
   *introduced* above it. `autoscaling/v2` on a chart declaring 1.20–1.21 is a
   half-applied release — helm's gate passes, the API server rejects the one
   object — and the tool said nothing. The sharpest evidence that this was an
   oversight rather than a scope decision is that the pre-fix `CH010` finding
   *named this exact failure mode as the reason to set a kubeVersion*:

   > *"…the chart will happily install onto clusters whose APIs it does not
   > support (e.g. autoscaling/v2 requires Kubernetes >= 1.23), failing at
   > apply time…"*

   It asked the user to set the field, explained why in terms of a check, and
   did not perform the check.
3. **The removal table was incomplete, asymmetrically.** 23 rows. `Role` was
   present; `RoleBinding` — same apiVersion, same removal release, same file —
   was absent. A subset of the truth that a reader cannot predict the shape of
   reads as completeness.

The cause underneath all three: `kubeVersion` was treated as a string to
print, not a constraint to evaluate. The chart carried the answer, the tool
had already parsed the file, and nothing in the package could turn
`">=1.20.0-0 <1.22.0-0"` into the set `{1.20, 1.21}`.

### The authority

    helm/pkg/action/action.go        renderResources()  — the enforcement site
    helm/pkg/chartutil/compatible.go IsCompatibleRange() — the five lines
    github.com/Masterminds/semver/v3 v3.3.0             — what helm pins

Two facts were fetched rather than recalled, and both changed the design.

**helm enforces `kubeVersion` at render time.** It is executable, not
documentation. That is the entire licence for letting severity depend on it:
an author who narrows `kubeVersion` until a removed API is out of scope has
not silenced the tool, they have made helm refuse the install that would have
failed. The caveat is stated in the findings themselves — `helm template |
kubectl apply` bypasses the gate.

**`IsCompatibleRange` returns `false`, not an error, when the constraint fails
to parse.** So a typo'd `kubeVersion` does not mean "unchecked"; it means the
chart is installable on *no cluster at all*, and the failure arrives as a
render error the author will read as a bug in helm. That is `CH013`, and it is
`CRITICAL` for a reason that only fetching the source would have revealed.

**Masterminds excludes prereleases from constraints with no prerelease
comparator.** `>=1.29.0` does not match `1.29.3-gke.1093000`. Managed
distributions report gitVersions that are semver prereleases, so the obvious
constraint excludes every GKE, EKS and AKS cluster in existence. That is
`CH014`.

### The proof

`proof/p3_oracle.py` builds Masterminds/semver v3.3.0 in Go, wraps it in
helm's exact five lines, and compares 47 constraints × 56 versions =
**2632 pairs** against the Python port. It freezes the answers to
`tests/oracle_semver.json`, and refuses to write unless the live comparison
passes first — so CI replays the real library's verdicts without needing a Go
toolchain.

`proof/p3_severity.py` shows the defect as a matrix: four materially different
charts, BEFORE yielding **one** distinct severity (`['CRITICAL']`), AFTER
yielding `['CRITICAL', 'LOW', 'HIGH', 'CRITICAL']`. The chart pinned *above*
the removal is unchanged across the fix, which is what makes this a
reconciliation rather than a blanket downgrade.

`proof/p3b_bar2.py` runs the whole tool, before and after, on
`fixtures/legacy-chart` and prints the summary an SRE actually reads.

**A correction to the method itself.** The before/after scripts extracted the
pre-fix tree with `git archive HEAD`. That was correct exactly as long as
nothing had been committed — and the first commit of this series would have
silently re-pointed every proof at its own fix, turning *"here is what
changed"* into *"nothing changed"*, with no failure and no warning. The
revision is now pinned to a literal SHA in `proof/baseline.py`, and the
scripts abort rather than fall back if that commit is missing. Every proof
script in the repo was re-run against the pinned baseline.

### The reasoning

Why severity may depend on the chart and not only on the object: because the
severity scale is a claim about *consequence*, and consequence is a function
of where the thing runs. Calling an unreachable removal `CRITICAL` is not
caution, it is a false statement about impact, and it costs the reader the
same evening as a true one. The scale only means something if the levels are
distinguishable.

Why the demoted findings are not deleted: they are real — the cluster will
reach 1.22 before the chart can, and the chart is an upgrade blocker. `LOW`
with a `why` that says so is the accurate report. Suppression would be the
same error in the other direction.

The four-state severity policy for `TP010`, and the reason each state is what
it is:

| Declared range | Severity | Because |
|---|---|---|
| undetermined | `CRITICAL` | no basis to demote; conservative, and says so in the text |
| entirely at/above removal | `CRITICAL` | certainty, not risk — worded accordingly |
| straddling removal | `HIGH` | fails on part of the supported set |
| entirely below removal | `LOW` | portability and upgrade blocker, not an outage |

The undetermined case is the load-bearing one. It would have been easy to make
"no kubeVersion" mean "no finding", which would have rewarded deleting the
field. It escalates instead.

`TP013` (API newer than the declared floor) is `CRITICAL` when *every*
declared minor lacks the API, `HIGH` on partial overlap, and **silent** when
the range is unknown — there is no claim to contradict, and inventing one
would violate C2.2.

### The fix

* `hpaanalyzer/kubeversion.py` — a port of Masterminds/semver v3.3.0 under
  helm's `IsCompatibleRange` shape, plus `DeclaredRange`, which turns a
  constraint into a sampled set of minors and keeps three states honestly
  apart: undeclared, unparseable, parsed-but-empty. Sampling probes patch 0
  and 999 per minor, because `>=1.21.3` excludes `1.21.0` but includes
  `1.21.9` — probing only `x.y.0` would drop the whole minor. Open-ended
  ranges are marked `truncated` rather than reporting `DOMAIN_MAX_MINOR` as if
  it were the chart's own ceiling.
* `hpaanalyzer/kube.py` — `DEPRECATED_APIS` 23 → **50** rows, each carrying
  its replacement and the release the replacement arrived in; new
  `API_AVAILABLE_SINCE` with **39** rows.
* `hpaanalyzer/checks_chart.py` — `TP010` re-graded against the range,
  `TP013` added, `CH013` (constraint that installs nowhere) and `CH014`
  (constraint that excludes all managed clusters) added, and `CH010`'s `fix`
  string **derived from the chart's own apiVersions** instead of being a
  constant example.
* `hpaanalyzer/models.py` / `discovery.py` — `chart_yaml_raw` retained so
  findings can cite a line number.

The `CH010` change is small and worth naming. It read:

    Add e.g. kubeVersion: ">=1.23.0-0".

It now reads:

    Add kubeVersion: "<1.25.0-0", because batch/v1beta1 CronJob is gone
    from 1.25 onward…

Same rule, same severity. The difference is that the second sentence could
only have been written by something that read the chart.

### Evaluation — Bar 1 (correctness)

`tests/test_kubeversion.py`, 21 tests. The bulk of it asserts nothing of my
own devising: it replays all 2632 frozen oracle pairs. Three guards keep that
from degrading into theatre — it asserts the pinned versions (`v3.3.0`,
`v3.16.4`), asserts the table has not shrunk below 2000 cases, and asserts
that **both** `True` and `False` appear among the frozen answers, so a port
that returned `False` unconditionally cannot pass. The hand-written cases
after the replay cover the layer *above* semver: `declared_range`'s three
states and the boundary rule that an API removed in 1.25 is gone **as of**
1.25, since putting that minor on the wrong side is an off-by-one that
downgrades an outage to a note.

### Evaluation — Bar 2 (fitness for purpose)

`tests/test_fitness_kubeversion.py`, 30 tests, all running the real engine
over real directories per C5.3. `proof/p3b_bar2.py` is the argument in one
screen, on `fixtures/legacy-chart` (`kubeVersion: ">=1.20.0-0 <1.22.0-0"`;
three v1beta1 objects removed in 1.22; one `autoscaling/v2` HPA):

    BEFORE  Fix first:  HP050, TP010, TP010, SC001
    AFTER   Fix first:  HP050, TP013, SC001

Before the fix the list was topped by two removals that cannot fire on any
cluster the chart can be installed on; the string `autoscaling/v2` appeared
nowhere in the full report, so an SRE who read every line still had no way to
learn the release would half-apply. After, the outage is second and the three
upgrade blockers are `LOW` — still in the report, with a `why` that cites
`IsCompatibleRange` and names what remains. No rule was lost.

### The thing this iteration proves about the grade

The grade went **up**: B (84.5) → B (85.7), on a chart nobody changed, while
what the report *says* reversed. That is not a defence of the grade, it is
evidence against it. A single number that cannot distinguish "three
unreachable schema migrations" from "this release will half-apply" is not
carrying information — and R2's own Bar 2 proof leaned on a grade *drop* as
though the drop were the result. The value is in the order and the reasoning,
not the score.

Queued for R5: state plainly in the README that the grade is a weighted
finding count, not a risk estimate.

### Also discovered, queued

* `README.md` and `docs/SPEC.md` still say `DEPRECATED_APIS` has 14 entries.
  It has 50. Stale documentation about the size of a table is a small lie of
  the same family as the ones this iteration fixed — R5.
* The sampling ceiling `DOMAIN_MAX_MINOR = 60` is an arbitrary horizon. It is
  surfaced honestly today (`truncated`, and `describe()` ends in `+`), but a
  chart declaring `>=2.0.0-0` would be reported as an empty set rather than as
  out-of-domain. No 2.x exists, so this is queued rather than fixed — R5.

---

## R4 — The mode the tool calls ground truth was unreachable on modern charts

### The defect

`helmrender.py` says, in its own module docstring and unchanged since before
this iteration:

> *"`helm template` is ground truth: real Go-template evaluation, real
> conditionals, real values merging. The static scrubber in helmyaml.py is the
> fallback, and the report says loudly which mode produced its facts."*

That is a contract: install helm, get rendered truth. Five defects sat between
the contract and the behaviour.

1. **D1 — the helm path was unreachable on any chart written this decade.**
   `render_chart()` passed no `--kube-version`, so helm applied its
   compiled-in default, and helm *enforces* the chart's own `kubeVersion`
   against that default at render time. Every chart declaring a floor above
   1.20 was refused and fell back to the scrubber. Measured, not estimated:
   **3 of the tool's own 5 fixtures**, and the two that rendered were the one
   pinned to 1.20–1.21 and the one declaring nothing at all. The feature
   worked precisely on the charts nobody writes.
2. **D2 — the advice printed in that state was the one action that could not
   help.** The fallback text said *"Install helm on PATH and re-run for
   rendered-truth analysis."* helm was on PATH. It had run. It had refused.
   A reader who followed that advice installed helm a second time and got a
   byte-identical report.
3. **D3 — even on success, it rendered for the wrong cluster.** Charts branch
   on `.Capabilities.KubeVersion`; pinned at 1.20 helm takes the legacy arm of
   a chart the user deploys on 1.31. Silent: the render succeeds, the report
   says "rendered truth", and the truth is about a cluster nobody has.
4. **D4 — the external cross-check reported "could not determine" as
   "invalid".** kubeconform exits 1 both when manifests fail validation and
   when it cannot reach a schema. The tool read the exit code and printed
   FAIL. This is contract C2.2 — undetermined must not be reported as bad —
   violated against another program's output rather than its own input.
5. **D5 — the failure was cosmetically invisible.** A multi-line subprocess
   error was spliced into single-line report fields, and `good-chart` was
   graded **A+ (100.0/100)** while in the fallback state, in the same format
   as a grade earned from a real render.

### The authority

    helm/pkg/chartutil/capabilities.go   k8sVersionMajor/"1", k8sVersionMinor/"20"
    helm/pkg/chartutil/capabilities.go   DefaultVersionSet = allKnownVersions()
    helm/pkg/action/install.go:276       APIVersions = append(APIVersions, ...)
    helm/pkg/action/action.go            renderResources() — the enforcement site

Kubernetes 1.20 reached end of life in February 2022.

**The assumption this iteration falsified, and the reason the instruction said
not to make them.** The design started from "pass `--kube-version` and the
capabilities are correct". That is false, and the source says so. `--kube-version`
sets `.Capabilities.KubeVersion` and nothing else. `.Capabilities.APIVersions`
is `allKnownVersions()` — every group/version compiled into the helm binary's
vendored client-go, not a function of the version flag. Probed out of three
real renders rather than reasoned about:

    --kube-version 1.16.0 / 1.21.0 / 1.32.0
      KubeVersion.Version          v1.16.0 / v1.21.0 / v1.32.0   (flag works)
      APIVersions.Has "autoscaling/v2"       true / true / true
      APIVersions.Has "autoscaling/v2beta1"  true / true / true
      APIVersions.Has "policy/v1beta1"       true / true / true
      APIVersions.Has "monitoring.coreos.com/v1"  false / false / false

`autoscaling/v2` first exists in 1.23; `autoscaling/v2beta1` was removed in
1.26. **No cluster has ever had both.** So under `helm template` the
APIVersions set describes an impossible cluster at every version, and it fails
in both directions: built-in groups answer true on clusters that never had
them, and CRD groups answer false on clusters that do. Nor can the caller
correct it — `--api-versions` *appends*, and confirmed by running it,
`--api-versions autoscaling/v2` at 1.32 still answers true for
`autoscaling/v2beta1`. There is no flag that removes an entry.

Had that assumption shipped, the tool would have printed a stronger claim than
before ("rendered for your cluster") over the same defect. The fixture built
to demonstrate divergence, `fixtures/capability-chart`, was written on the
false model and **did not diverge** when run — which is how the assumption was
caught. The fixture was rewritten to gate on `semverCompare` over
`.Capabilities.KubeVersion.Version`, and verified against the binary at both
ends before being trusted.

### The proof

`proof/p4_render.py` — Bar 1, before/after against the pinned baseline
`ea95681`, every number from a subprocess:

| fixture | declared kubeVersion | BEFORE | AFTER |
|---|---|---|---|
| good-chart | `>=1.23.0-0` | static (helm refused) | helm @ 1.32.0 |
| sidecar-chart | `>=1.29.0-0` | static (helm refused) | helm @ 1.32.0 |
| initheavy-chart | `>=1.33.0-0` | static (helm refused) | helm @ 1.33.0 |
| legacy-chart | `>=1.20.0-0 <1.22.0-0` | helm | helm @ 1.21.0 |
| bad-chart | (none) | helm | helm |

Every chart that fell back declares a floor above 1.20; the ones that rendered
declare nothing, or nothing the 1.20 constant violates. CLAIM 0 establishes
helm's default by running the binary twice on the same bytes with and without
the flag. Nothing lost: no rule fired BEFORE stops firing AFTER, on any
fixture, and the four rules gained are absent from the baseline *source*
entirely — asked of the baseline tree with `grep`, not assumed.

`proof/p4b_bar2.py` — Bar 2, the two-fixture distinction, premise asserted
against real helm so it cannot rot:

    capability-chart  @1.21 Deployment + PDB(policy/v1beta1)
                      @1.32 Deployment + HPA(autoscaling/v2)     -> differ
    apiversion-chart  @1.21 Deployment + HPA(autoscaling/v2)
                      @1.32 Deployment + HPA(autoscaling/v2)     -> identical

The second is the outage. Rendered for a 1.21 cluster it emits an
`autoscaling/v2` HPA — an API that does not exist before 1.23 — while the
chart's own `{{- else }}` arm, holding the correct `autoscaling/v2beta1`
object, is never taken. Install it and the Deployment lands and the HPA is
rejected with "no matches for kind". A half-applied release, from a chart
whose author did the right thing.

### The reasoning

The two cases need two different answers, and conflating them is what a lesser
fix would do.

Where the gap is **measurable**, measure it. If a chart declares a range
spanning more than one minor, render both ends and compare the object sets.
Different objects means no single-version analysis covers the range —
including this one. Report it (`CH015`, MEDIUM) rather than resolve it: there
is no correct single version to report for a chart that legitimately emits
different objects at different points of a range it legitimately declares.

Where the gap is **not measurable**, say so and score nothing. A chart gating
on `.Capabilities.APIVersions` renders identically at both ends, so CH015 has
nothing to compare — this is not an implementation weakness, it is arithmetic.
`CH016` therefore fires at `INFO` with a grade contribution of exactly **0**,
permanently. This is the withhold-asymmetry the whole report rests on: a
heuristic may withhold confidence, never manufacture a defect. CH016 knows the
branch is unverifiable; it does not know the branch is wrong, and if it
deducted points every chart using the commonest capability idiom in the
ecosystem would be marked down for a helm limitation.

The version itself is a judgement, so it is made on purpose and printed: user
`--kube-version` wins; else the top of the chart's declared range (where
removed APIs bite and where an upgrading user lands); else the newest minor
this analyzer has *recorded facts about* — labelled as such, because it is a
statement about the tool's knowledge, not about Kubernetes.

### The fix

* `renderplan.py` — the version decision, the policy, and the source
  quotations that justify it, in one module so the rule and its explanation
  cannot drift apart. `capability_gates()` lives here for the same reason.
* `checks_chart.py` — `CH015` (divergence across the declared range),
  `CH016` (unverifiable APIVersions branch), and `_gv_exists_at()`, which
  returns `True`/`False`/**`None`** where `None` means "this tool has no
  recorded fact", per C2.2 — an unknown group/version is not a false one.
* `external.py` — `ExternalResult.verdict` gains `UNKNOWN`, read from
  kubeconform's own machine-readable tally (`Invalid: 0, Errors: 3` is "not
  checked", not "invalid") rather than from its exit code. Asymmetric on
  purpose: it can only downgrade FAIL to UNKNOWN, never upgrade to PASS.
  `Invalid > 0` stays FAIL.
* `report.py` — `_flatten` for subprocess errors, the render version stated in
  the Mode line, and the qualification placed **in the mode paragraph**, three
  lines from the word "rendered", not 200 lines below it.

### Two self-inflicted defects, recorded because they are the point

**CH016 fired on its own documentation.** The first run of the new rule
flagged `fixtures/capability-chart` — matching `.Capabilities.APIVersions.Has`
inside the Go-template *comment* written moments earlier to explain why that
idiom is untrustworthy. A rule that fires on prose about itself is not a rule.
Fixed with `strip_inert()`, which blanks `{{/* */}}` and whole-line YAML
comments **to spaces rather than deleting them**, so every subsequent line
number stays honest.

**The report contained the exact overclaim CH016 exists to prevent.** The mode
paragraph asserted that `.Capabilities.KubeVersion` *and*
`.Capabilities.APIVersions.Has` "were answered for that version and no other."
The second half was false, and was written by me, in this iteration, while
implementing the rule that says it is false. Deleted; replaced with an explicit
withholding paragraph.

**And the proof harness itself produced a false proof.** `p4_render.py`
originally ran the pre-fix tool on `<baseline-tree>/fixtures/<name>` — pre-fix
tool *and* pre-fix fixture bytes, which sounds like the stricter control. But
three of those five fixtures were written during R1–R3 and do not exist at the
baseline commit. The tool was handed a path that was not there, did not crash,
reported "No Chart.yaml found" and mode "static", and the proof scored that as
"the helm path was unreachable". Three fifths of CLAIM 1 was measuring an empty
directory, and it said `d1: True`. The guard is now `_chart_dir()`, which
raises: **a missing input must be a stop, not a data point.** With the control
corrected (chart held constant, tool varied — the same control the other
proofs use) the real number is 3 of 5, not 4 of 5.

### Evaluation — Bar 1 (correctness)

293 tests, all green, no skips. The mocked helm/kubeconform cross-check tests
were **deleted**, not extended: they asserted against invented output
(`"1 chart(s) linted, 0 failed"`, which real helm does not print — it prints
`1 chart(s) linted, 0 chart(s) failed`) and so tested the mock. Replaced with
tests that build a real `PATH` directory containing only the binaries under
test and run them, per C5.3, including a regex pinned to real kubeconform
output. `proof/p4_render.py` exits 0 on all five claims.

### Evaluation — Bar 2 (fitness for purpose)

`proof/p4b_bar2.py` exits 0. On `apiversion-chart` at `--kube-version 1.21.0`:
CH015 is silent (correctly — nothing to compare), CH016 fires naming
`autoscaling/v2` and stating it "does not exist on a real 1.21.0 cluster",
TP013 (an R3 rule) catches the concrete object, and the mode paragraph carries
the qualification. The two rules are complementary and the proof shows why
neither substitutes for the other.

Stated in the proof's own verdict rather than left for a user to discover:
this does **not** prove the arm helm did not take would pass these checks — it
was never rendered; CH015 renders the two ends and would miss a chart that
changes only in the interior of its range; and nothing here helps with
CRD-provided group/versions, which helm answers `false` for at every version
even on clusters that have them. Only a live cluster answers those.

### Also discovered, queued

* **The grade is the worst thing in the report.** `A+ (100.0/100)` was printed
  for a chart the tool could not render, in the same format as a grade earned
  from a real render — while the same pre-fix code printed `NOT GRADED` for
  the two capability fixtures. It knew how to withhold a grade and did not do
  it in the case where the reader would be misled. R5.
* `DOMAIN_MAX_MINOR = 60` caps minor enumeration, so `>=1.61.0-0` is reported
  as `unparseable` rather than out-of-domain. Pinned by a test that names it
  as a horizon, fixed in R5.
* `README.md` and `docs/SPEC.md` remain stale (still "14 entries"), now also
  missing CH015/CH016 and the UNKNOWN verdict. R5.

## R5 — The headline number moved when you deleted a file

### The defect

The grade is the first thing the tool prints, the only thing most readers
will look at, and the thing CI compares against a threshold. It was computed
like this, and had been since the beginning:

```python
for cat, score, _ in category_scores(result):
    if score is None:
        continue          # <- the entire defect is on this line
    num += WEIGHTS[cat] * score
    den += WEIGHTS[cat]
return num / den
```

A category that could not be assessed leaves the **numerator and the
denominator**. The remaining categories are renormalised over a smaller
weight, and nothing anywhere in the output said so. Every surface printed
`GRADE F  (51.8/100)` in a format byte-identical to a grade computed over all
ten categories.

So the score is not a property of the chart. It is a property of the chart
*and of which input files happened to be present*. Measured on this repo's own
fixtures — copy the fixture, delete only `Dockerfile`, change **no Kubernetes
manifest whatsoever** (asserted file-by-file with `filecmp` in
`proof/p5_grade.py`, CLAIM 0), `--helm off` both sides:

    good-chart     100.0 A+  ->  100.0 A+   +0.0
    sidecar-chart   88.7 B+  ->   83.7 B    -5.0
    bad-chart        45.5 F  ->   51.8 F    +6.3

The last line is the one that matters. **The worst chart in the repo got
better by 6.3 points because a file was deleted.** Its Dockerfile, JVM and
cross-file categories were where it was failing hardest; removing them from
the average removed the evidence of that. The direction is not even
consistent — `sidecar-chart` moved down by 5.0 for the same operation —
so a reader cannot correct for it with a rule of thumb either.

> **Re-measured at R8 — this table no longer reproduces, and the reason is
> the point.** Running the same experiment on the R8 tree gives:
>
>     good-chart     100.0 A+  ->  100.0 A+   +0.0   (unchanged)
>     sidecar-chart   88.7 B+  ->   87.7 B+   -1.0   (was -5.0)
>     bad-chart        45.5 F  ->   49.9 F    +4.4   (was +6.3)
>
> Both moves shrank, for two different reasons, and neither is R5 being
> walked back. `sidecar-chart` shrank because R8 stopped gating the JVM
> analysis on the *presence of a Dockerfile*: that chart sets
> `JAVA_TOOL_OPTIONS` in its own pod spec, so with the file gone the
> heap-vs-limit analysis still has everything it needs and only the
> image-level DOCKERFILE category leaves the mean — four of the five points
> were never a renormalisation artefact at all, they were R8's defect
> showing up inside R5's measurement. `bad-chart` shrank because PB004
> (liveness with no startupProbe) was *also* gated on `ctx.dockerfiles`, so
> deleting the file used to delete a HIGH from a category that stayed in the
> denominator; that finding now survives the deletion and the gap narrows by
> 1.9. What is left — `+4.4` — is the honest residue R5 describes: with no
> image evidence anywhere, DOCKERFILE and JAVA genuinely cannot be assessed,
> and the remedy is still to print the denominator rather than to invent a
> number for them. The prose above is preserved as written because the
> R5 argument does not depend on the magnitude; `hpaanalyzer/scoring.py`
> carries the current table, and every rendered surface quotes `4.4`.
>
> One consequence worth recording: `proof/p5b_bar2.py` had `--min-score
> 50.0` written into it, chosen at R5 to sit between `45.5` and `51.8`. When
> `51.8` became `49.9` the proof failed — its argument was still sound, its
> constant had gone stale underneath it. It now calibrates the threshold
> from the two scores it measures at run time. A proof that hardcodes the
> number it is supposed to be measuring is the same category of mistake as a
> report that prints a mean without its denominator.

And the score moves in the direction that rewards deleting evidence, which is
exactly the direction a defect must never move.

### The authority

There is no upstream source for this one; it is not a Kubernetes question. The
authority is this project's own contract, C2.2:

> *A value the tool cannot determine must be reported as undetermined, never
> defaulted into a confident answer. "Unknown" is a permitted output; a
> plausible wrong answer is not.*

C2.2 was written about individual values and the implementation honoured it
there — an unassessed category prints `not assessed`, not `0`. The reasoning
extends one step further than the text did, and R5 extends the text to match
(the new **C2.6**): silently dropping the undetermined out of an average is
the same offence as silently defaulting it. Both take "we do not know" and
turn it into a number the reader will read as knowledge. The first changes the
value; the second changes the *scale*, invisibly, which is worse, because a
wrong value can at least be argued with.

C4.4 is the second half, added for the same reason and discovered by this
iteration's own Bar 2 test — see below.

### The proof

`proof/p5_grade.py` (exit 0). Both trees are real: BEFORE is `git archive` at
the pinned baseline SHA from `proof/baseline.py`, not `HEAD`; the CLI runs are
real subprocesses.

* **CLAIM 0** — the two directories differ by exactly one file. Without this
  the deltas prove nothing, so it is asserted with `filecmp.dircmp` plus a
  byte comparison of every remaining file, not by inspection.
* **CLAIM 1** — the pre-fix score moves, and on `bad-chart` it moves **up**.
* **CLAIM 2** — no pre-fix surface mentions the denominator. It goes further
  and shows the pre-fix scorecard actively *reassured* the reader, with the
  words `not free points`, that exclusion was harmless.
* **CLAIM 3** — the arithmetic is unchanged by the fix: the printed score
  equals the weighted mean recomputed from the tool's own category table to
  1e-9, on three fixtures in both their with- and without-Dockerfile forms
  (six runs).
* **CLAIM 4** — all five surfaces carry the coverage (stdout summary, text
  report, HTML badge, `--quiet`, `--json`), CLI paths run as subprocesses.
* **CLAIM 5** — no rule was lost, and the fully-assessed case says
  `all 10 categories` and prints no comparability warning.

### The reasoning

The obvious fix is to impute a value for the unassessed categories, and every
version of it is a lie:

* **Impute 100.** The tool asserts a clean bill of health for a Dockerfile it
  never opened. This is precisely the C2.2 violation, promoted to the headline
  number.
* **Impute 0.** The tool asserts findings it did not find. `good-chart` would
  drop to 64.0 for shipping no Dockerfile — punishing a chart-only repo for
  being a chart-only repo.
* **Impute the mean of the assessed categories.** This asserts that the unseen
  resembles the seen, which is unfalsifiable and, on `bad-chart`, is the
  claim that the Dockerfile is as bad as the templates. Nothing supports it.

There is no honest number for "not looked at". The arithmetic was already the
only defensible arithmetic available — `overall_score()` is byte-for-byte
unchanged by this iteration. **The defect was never the mean; it was printing
a mean without its denominator.** So the fix exposes the denominator and
refuses to invent the missing terms:

    GRADE F  (51.8/100)   6 critical, 5 high, 11 medium, 13 low
    Scored over 7 of 10 categories (64 of 100 weight); NOT assessed: DOCKERFILE, JAVA, CROSS.
    Evidence: static template parsing, NOT a helm render (static) - see the coverage section.

The second line is C2.6. The third is R4's mode qualification finally attached
to the number it qualifies, rather than living in a section further down that
the reader who only wants the grade never reaches.

### The fix

* **`scoring.py`** — rewritten around `unassessed_reason(cat, ctx)`, which
  returns *why* a category cannot be scored (`"no Dockerfile was found under
  the target"`, `"no Kubernetes objects were parsed from the templates"`, …)
  or `None`. A frozen `Coverage` dataclass carries the assessed list, the
  unassessed list *with reasons*, and the assessed weight, and renders the
  one-line form every surface uses. `category_scores()` now derives
  applicability from that single function instead of repeating the conditions.
  The module docstring states what the score is, why the denominator is part
  of the answer, and why nothing is imputed — with the three measured deltas
  in it, so the next reader does not have to take it on faith.
* **`report.py`** — `score_qualifier_lines()` returns everything that must be
  printed *next to* the number or not at all. The executive summary gains a
  "What this number is" paragraph, the per-category reasons, and the
  comparability warning. The scorecard's `N/A` becomes `not assessed`, and the
  `not free points` reassurance is replaced by the explanation of what
  renormalisation actually does.
* **`html_report.py`** — the badge itself carries `51/100 · 7/10 cats`.
* **`__main__.py`** — `--quiet` appends `over 7/10 categories`; `--json` gains
  `score_coverage`; and see Bar 2 for `--require-coverage`.
* **`tests/test_score_coverage.py`** — 15 new tests, every one running the
  real engine over a real directory, CLI paths through the real `main()`.
  Suite at that point: **308 tests, OK**; **318** after the second defect
  below, **322** after the third.

### Three self-inflicted defects, recorded because they are the point

The instruction was "don't make assumptions". Three claims written into these
proofs were refuted by running them, and each is corrected in the text rather
than softened.

1. **`p5_grade.py` CLAIM 3, first draft** asserted the before/after delta
   would be *equal* across tool versions. The run refuted it on
   `sidecar-chart`: −4.0 before, −5.0 after. The assertion was wrong, not the
   code — R1–R4 added rules (RS015, RS016, RS017, TP013…) that change that
   chart's per-category scores, so cross-version delta equality was never a
   valid expectation. Replaced with what R5 must actually preserve: the score
   equals the weighted mean of the tool's own table, the count of categories
   entering the mean equals `coverage.n_assessed`, and the direction of
   movement is unchanged.
2. **`p5b_bar2.py` CLAIM 5(1), first draft** asserted that `bad-chart` had
   categories already floored at 0.0. The measurement printed `none`.
   Saturation is real but needed an experiment that produces it: duplicating
   the Deployment template 0/3/20/40× over real temp directories gives
   `45.51 / 18.12 / 10.18 / 10.18` — **x20 and x40 score identically with 460
   vs 860 findings.** The measurement also corrected the shape of the claim:
   saturation is per-category, and the overall keeps moving until the last
   category bottoms out.
3. **`p5b_bar2.py` CLAIM 5(2), first draft** compared helm-rendered against
   static scores on `bad-chart` expecting a difference. Measured: **45.5 both
   ways.** Replaced with the pair where the evidence basis changes the answer
   categorically — `capability-chart` and `apiversion-chart` grade 86.4 and
   87.2 under helm and are **NOT GRADED** under `--helm off`, while printing
   the *identical* `7 of 10 categories` coverage line. That is the sharper
   claim anyway: it proves the denominator is necessary and **not sufficient**.

A fourth, smaller one: the duplication helper first rewrote a hardcoded
`name: bad-app` in each copy "so the workloads are distinct". The fixture's
name is `{{ .Release.Name }}-payments`, the substitution matched nothing, and
the guard around it aborted the proof — which is what a guard is for. The
copies never needed renaming; the helper now verifies the workload count
scaled (1 / 4 / 21 / 41) instead of assuming the mechanism.

### The second defect — the tool reported its own horizon as a fact about Kubernetes

R4 closed with a forward commitment: "`DOMAIN_MAX_MINOR = 60` caps minor
enumeration, so `>=1.61.0-0` is reported as `unparseable` rather than
out-of-domain. Pinned by a test that names it as a horizon, fixed in R5."
This is that fix, and it belongs in R5's iteration rather than a footnote,
because it is the *same defect as the headline one* wearing different
clothes: a number computed over part of the domain, presented as if it were
computed over all of it.

`declared_range()` enumerates minors 1.0 … 1.60. A chart declaring
`>=1.61.0-0` therefore produced an empty minor set, and the empty set fell
into CH013, whose text reads *"no Kubernetes 1.x release satisfies it"* and
whose stated usual cause is *"a reversed or overlapping pair of bounds"*.
Both halves are false about that chart. Nothing is reversed, and the tool had
not established that nothing satisfies the constraint — it had stopped
looking at 1.60. Contract C2.2, violated by the tool that exists to catch
C2.2 violations in other people's charts. The user-visible cost is not
cosmetic: CH013 sends the reader hunting a bound conflict that does not
exist, when the actual bug in `>=1.61.0-0` is one transposed digit.

**The fix.** `DeclaredRange.above_domain` (probed at minors 61 / 100 / 200 /
999 × patches 0 / 999) separates "unsatisfiable" from "satisfiable outside
the sampled domain". A new rule **CH017** (CRITICAL) reports the second case
in its own words, names the horizon as *this analyzer's* limit in both the
detail and the fix, and explicitly disowns the contradiction reading by rule
id. `RenderPlan.source` gains `above-horizon`, distinct from `unparseable`.

**And then the same mistake, one axis over.** The first cut of that fix
probed *minors* only — but `declared_range(majors=(1,))` samples one major
too, so `>=2.0.0-0` still produced an empty set, still landed in CH013, and
still got a render plan reading `unparseable`. It survived my own review
because **CH013's headline is true for it**: no 2.x has ever shipped, so
nothing does satisfy it. Worse — and this is the part worth sitting with —
R2's own "also discovered" list had already written the case down, in these
words: *"a chart declaring `>=2.0.0-0` would be reported as an empty set
rather than as out-of-domain"*. I had the defect in my own notes, three
iterations old, and still shipped a first cut of the fix that missed it,
because I fixed the example I was looking at (`>=1.61.0-0`) rather than the
class the note described. A queued-defect list is worth nothing if the fix is
written from the symptom instead of from the list. That is the most dangerous shape a wrong answer
takes — accidentally right in the summary, wrong in the diagnosis (it blames
reversed bounds), and flatly false in a subsidiary claim (`unparseable`
about a string that parses cleanly). Being right for the wrong reason is not
being right, and it is exactly what a passing test suite fails to notice.
`_ABOVE_DOMAIN_MAJORS` and `above_domain_edge` (`AboveDomain.MINOR` /
`MAJOR` / `NO`) split the two edges, and CH017 now emits a different
sentence and different advice for each — telling a `>=2.0.0-0` author their
floor is "above 1.60" would have been a precise-sounding falsehood, which is
the genre of statement CH017 was created to stop emitting.

**The proof, and an honest weakness in it.** `proof/p5c_horizon.py`, 20
checks, exit 0. Its BEFORE column is the only one in `proof/` that is *not*
`git archive` at the pinned baseline, and the script says so in its own
output before printing a number: the defective revision was introduced in R3
and fixed in R5, both after the baseline commit, so there is no object to
archive. BEFORE is instead the current tree with `above_domain` forced
`False` — the exact state of that field before R5 added it. The script also
flags that the CH013 text it prints under BEFORE is current wording, whose
"and probed above that horizon too" clause makes the BEFORE read *worse*
than R3 actually was, and therefore asserts only on the sentence R3 wrote
and R5 left alone. That is weaker evidence than the other thirteen proofs
and is labelled as weaker rather than dressed up.

**Coverage.** Nine tests in `tests/test_fitness_kubeversion.py` under
`TestAFloorAboveEveryReleaseIsNotCalledAContradiction`, including the
precision half — a reversed range and a `<1.0.0-0` ceiling must still be
CH013 and must **not** be CH017, or the fix has traded one misdiagnosis for
another. `NEW_RULES` in `TestNoFabricationOnHealthyCharts` gains CH017, so
the clean fixtures are held silent under it too.

### The third defect — the tool describing its own old behaviour

**The defect.** Looking for stale claims in the README turned up a worse one
in the code. `clusterprobes.py` printed, inside the report, next to the table
it was talking about:

    This report shows QoS per container; Kubernetes assigns QoS per POD.

That sentence was true of this tool until R1. R1 replaced the per-container
guess with a port of upstream `ComputePodQOS` and gave TABLE 1 a `=> POD`
verdict row. The probe kept telling users the report was wrong about the one
thing R1 had just made right, for **two further iterations**. The same probe
also said native sidecar requests were "not yet counted" in the budget math;
R2 counted them.

Three README bullets under *known weaknesses* were stale in exactly the same
way, and named the same three fixes: per-container QoS (R1), uncounted
sidecars (R2), removed-API severity ignoring `kubeVersion` (R3).

**Why this is not a documentation nit.** Every previous defect in this
document was the tool being wrong about *the world*. This one is the tool
being wrong about *itself*, in its own output, and it fails worse: a user who
reads that line either distrusts a correct number or goes and recomputes pod
QoS by hand — the exact work the tool exists to remove. A weakness note is a
claim, and an unverified claim in the honesty section is the one place a
project like this cannot afford one. C2.2 says never report a limit of the
method as a finding about the target; the mirror-image sin is reporting a
limit the method no longer has.

**Why it survived.** 318 tests passed the entire time, because not one of
them read a sentence. The suite asserted on rule IDs, severities, scores and
table values — every machine-readable surface — and the prose rendered beside
them was unguarded. Stale prose is silent by construction: nothing fails, no
diff appears, and the only way it surfaces is a human rereading text they
wrote and believing it.

**The measurement before the rewrite.** Each stale claim was re-run rather
than reasoned about, because "I fixed that in R1" is precisely the kind of
memory that produced the defect. The `networking.k8s.io/v1beta1` Ingress,
same chart, three declared ranges:

    (no kubeVersion)       TP010  CRITICAL  (deduction 25)
    >=1.19.0-0 <1.21.0-0   TP010  LOW       (deduction  3)
    >=1.29.0-0             TP010  CRITICAL  (deduction 25)

R3's reconciliation is live: below the 1.22 removal it is a note, at or past
it a blocker. TABLE 1 was confirmed to carry a `=> POD` row, and the sidecar
fixture's requests were confirmed summed into the footprint.

**The fix.** The probe now states the gap that actually remains — the tool
computes QoS from the *templates*, the cluster computes it from the pod that
was *admitted*, after defaulting, LimitRange injection and mutating webhooks —
and its `read` line tells the user that a disagreement between
`status.qosClass` and the POD row **is** the finding. The three README
bullets are not deleted but replaced by one bullet that says they were there,
were false, and for how long; deleting them would have hidden the failure
this section exists to record.

**Coverage.** Four tests in `tests/test_regressions.py` under
`TestTheToolDoesNotDescribeItsOwnOldBehaviour`, which render a real report and
read it: the two retired sentences must be absent, the `=> POD` row must be
present (so the two `assertNotIn`s cannot pass vacuously on an empty report),
and the TP010 severity spread above is pinned as behaviour so the README can
be checked against a measurement instead of against memory. Suite: **322**.

### Evaluation — Bar 1 (correctness)

`proof/p5_grade.py` exits 0 on all six claims. The arithmetic is unchanged and
is verified against a recomputation from the tool's own category table on
three fixtures in both forms (six runs); the denominator appears on all five
surfaces; the fully-assessed
case is not polluted with warnings that do not apply to it. `proof/p5c_horizon.py`
exits 0 on all 20 checks. 322 tests pass, and all 14 proofs exit 0 with no
`[FAIL]` line.

### Evaluation — Bar 2 (fitness for purpose)

Bar 2 asked what the grade is *for*, and the answer includes gating a deploy.
That found a second defect the report fix provably cannot close, because **CI
reads the exit code, not the report**:

    bad-chart            --min-score 50   ->  exit 1
    same chart, no Dockerfile  --min-score 50   ->  exit 0, stderr silent

A red build turns green for deleting a file, and the honest coverage block R5
had just added sits in a text file nobody's pipeline reads. `p5b_bar2.py`
CLAIM 2 asserts exactly this against the report-only fix and shows it still
returns 0. That is the whole justification for R5 touching `__main__.py`:

* every `--min-score` run over a reduced scale now names it on **stderr**,
  and names the lever rather than just complaining;
* `--require-coverage` makes it a gate — the Dockerfile-less run exits 1;
* the intact fixture with `--require-coverage` alone still exits 0, so a
  chart-only repo that never had a Dockerfile is not punished.

This adds a flag, and "flag sprawl" is on this project's own defect list. The
trade is written into the proof's output rather than left implicit: a stderr
line in a green build's log is read by nobody, and there was no other way for
a CI author to gate on the scale their threshold is compared against.

What `p5b_bar2.py` CLAIM 5 states rather than hides — the denominator is
necessary for comparability and **not sufficient**. Categories floor at 0 so
the score cannot order two already-bad charts (x20 vs x40 above); the number
does not encode its evidence basis (`capability-chart`: 86.4 vs NOT GRADED,
identical coverage line); and the weights are a judgement with nothing in this
repo evidencing that requests/limits matter ~4× chart hygiene. All three are
now in the README as well, under *What the grade is — and the three ways it
will mislead you*.

### Also discovered, queued

* **C2.3 is still not fully honoured inside the proof tables.** Estimated
  inputs are labelled in the surrounding text, not at the point of use in
  every table row.
* `DOMAIN_MAX_MINOR = 60` **remains a horizon, but no longer a lie** — see
  *The second defect* above. The sampling ceiling is unchanged; what changed
  is that the tool now says "I stopped looking here" instead of "there is
  nothing to find". If Kubernetes ships 1.61 this analyzer will call a
  correct chart CRITICAL until the constant is raised. That wrong answer is
  now bounded and printed; it is not gone.
* **The prose surface is still almost entirely untested.** Four tests now read
  rendered sentences; the report prints hundreds more — every `fix=` string,
  every probe, every teach block — and each one is a claim that can go stale
  the next time the code beneath it changes. R5 found two such sentences by
  hand. There is no reason to believe hand-reading found them all, and no
  mechanism yet that would fail when the next one goes stale.
* `_table` still breaks mid-word on narrow columns; PB003 reports container
  numbers for a pod-level behaviour; the flag and output surface keeps
  growing (this iteration added one more).

---

## R6 — Two of the four validators it offers to run had never been run by its own tests

### The defect

`--cross-check` runs four other people's programs and folds their verdicts
into the report: `helm lint`, `kubeconform`, `kube-score`, `polaris`. R4
replaced the mocked tests for the first two with real-binary ones. It did not
touch the other two, and nothing else ever had either. `kube-score` and
`polaris` were not mocked — mocks would at least have been a statement of
what the author expected. They were simply never executed by any test in any
iteration, while the tool went on printing a PASS/FAIL column derived from
them.

Both columns were wrong, in opposite directions, for the same reason: the
code read an exit status as if it were a verdict.

* **polaris always exits 0.** It exits 0 on a clean chart. It exits 0 having
  found danger-severity failures. It exits 0 on a file that is not YAML,
  printing `Final score: 100` over `Controllers: 0` — a perfect score for
  having read nothing. `ok = (rc == 0)` therefore made *every* polaris run a
  PASS, including runs where polaris itself said the chart was dangerous.
* **kube-score exits 1 for two unrelated things**: "I found a CRITICAL" and
  "Failed to score files: failed to parse files". Read as an exit code, an
  unparseable file becomes an invalid chart. That is C2.2 — reporting a limit
  of the method as a finding about the target — committed about another
  program's output.

And the summary line the reader actually sees for polaris was
`_last_summary_line`, which returns the last non-empty line of the output.
polaris's last line is its own argv:

```
| polaris | PASS | > polaris audit --audit-path
|         |      | /tmp/hpa-xcheck-2bb6gmmw/rendered.yaml --format
|         |      | pretty --upload-insights --cluster-name=my-cluster
```

An advertisement for a hosted product, quoting a scratch directory that no
longer exists by the time anyone reads the report, presented as a validator's
finding — under the word PASS, on a chart polaris scored 79/100 with two
danger-severity failures.

### The authority

This module's own docstring, unchanged since it was written:

> Discipline: this tool did not write these validators and does not vouch for
> their results — it runs them and reports exit status + output verbatim,
> clearly attributed.

"Reports exit status verbatim" is exactly the mistake. For two of these four
tools the exit status is not a verdict, so transcribing it faithfully still
misinforms the reader. The discipline the docstring is reaching for is
*report their finding verbatim*, and their finding is in their output.

C2.2 and C5.3 supply the rest: a capability verified only through mocks must
be marked unverified, and a capability verified through nothing at all is
worse than one verified through mocks, because nobody wrote down what they
expected.

### The proof

`proof/p6_external.py`, against the pinned baseline `ea95681`, 31 checks.

The control matters and is stated in the file: **both trees are handed the
same rendered bytes**, produced once by the current helm at 1.32.0 and passed
via `rendered_text`. Re-rendering inside the baseline tree would have measured
R4's defect (helm's compiled-in v1.20.0 refusing modern fixtures) rather than
this one.

Measured, BEFORE:

```
good-chart  polaris     PASS  | > polaris audit --audit-path <tmp> ...
good-chart  kube-score  FAIL  | (exit 1)
garbage     polaris     PASS  | Final score: 100  over Controllers: 0
garbage     kube-score  FAIL  | (exit 1 — "failed to parse files")
```

AFTER:

```
good-chart  kube-score  FAIL  | 5 object(s) scored: 12 critical, 1 warning
good-chart  polaris     FAIL  | score 79/100 over 2 controller(s): 2 danger, 18 warning
garbage     kube-score  UNKNOWN
garbage     polaris     UNKNOWN
```

polaris's exit code is measured directly rather than assumed: 0 on the good
chart *and* 0 on the garbage file, in the same run in which its own output
contains `❌ Danger`. That single measurement is the whole case for ignoring
it.

### The fix

Each tool gets a reader that parses its own output into a tally, and the
verdict comes from the tally. `ExternalResult` gains two fields the report and
`--json` now expose:

* `tally` — the counts the verdict was computed from
  (`{'controllers': 2, 'score': 79, 'danger': 2, 'warning': 18, ...}`).
* `verdict_basis` — the sentence naming which signal was read, printed under
  each tool: *"polaris's own danger tally and controller count; its exit code
  is always 0 and carries no verdict."*

Both are there for the same reason: a verdict a reader cannot audit is
indistinguishable from this project's opinion, and this project has no opinion
about anyone else's chart standards. Unreadable input now returns `ok=None`
(UNKNOWN) from both readers, with the reason printed — the same three-state
discipline R4 established for kubeconform, applied to the two tools that never
got it. ANSI escapes and the scratch path are stripped, so polaris's colour
codes stop being pasted into a plain-text file.

`NEEDS_RENDER` moved to module level so the tests can invoke the *exact* argv
the tool invokes. That was not tidiness: the first draft of the test rebuilt
polaris's command line from memory, dropped `--format pretty`, got JSON back,
counted zero danger markers in output containing two, and passed judgement on
a command this tool never runs. The mocked-test failure mode, one layer down.

### The defect this iteration's own test found

The tally is counted over a validator's whole output. The block printed
underneath it is cut at 1500 bytes, and the cut was marked `... (truncated)`.
So the first test that ever compared the two failed:

```
AssertionError: 12 != 5
```

Both numbers were correct. kube-score really did emit 12 `[CRITICAL]`, and the
excerpt really did contain 5. The report was still misleading, and newly so —
because R6 had just added a paragraph inviting the reader to *check this
tool's transcription against the raw output printed below it*, and then handed
them a fragment that admitted nothing about being one. A reader who counts
what is in front of them gets 5 under a summary saying 12 and concludes the
summary is wrong.

`_trunc` now states the drop, and the report's invitation is qualified to
match:

```
... (149 more line(s), 4589 more byte(s) not shown; the tally and verdict
above were computed over the FULL output, not this excerpt)
```

Recorded because of how it was found. It was not found by reading the code —
it was found by a test that put two numbers from different scopes next to
each other for the first time. Every previous iteration had both numbers
available and nothing compared them.

### Evaluation — Bar 1 (correctness)

`python3 proof/p6_external.py` exits 0 on all 31 checks. **336 tests** pass,
and all **15 proofs** exit 0 with no `[FAIL]` line.

Eleven new tests run `kube-score` and `polaris` for real, skip-guarded on
`shutil.which` (polaris is not shipped with this project and will be absent in
a clean container — the tests say so instead of pretending). Each verdict is
checked against the binary's **full** output, obtained through the module's
own argv builder, never against the truncated detail block.

### Evaluation — Bar 2 (fitness for purpose)

The purpose of `--cross-check` is to let a reader who does not trust this
analyzer hear from tools that are not this analyzer. It failed at that twice
over: it told them polaris approved of a chart polaris had flagged, and it
told them kube-score had condemned a chart kube-score had never managed to
read.

Fitness here is *not* agreement. `good-chart` grades A+ in this report and is
criticised by both external tools on the same bytes; that disagreement is the
feature, and the report now carries it intact instead of flattening it into a
PASS. What the reader gains is the ability to check: the status, the signal it
came from, the counts, and the raw output are all on the page together, and
where the raw output is cut it says so.

What this does not buy: it does not make those tools correct, and it pins two
more parsers to two more output formats. When those formats change these tests
fail loudly — which is the only property being purchased.

### Also discovered, queued

* **The remaining two validators' verdicts are now audited; nothing audits
  the four tools' *selection*.** A reader could reasonably ask why these four
  and not Kyverno, OPA or Datree. The answer is "they were what the author
  reached for", and that is not written down anywhere the reader can see.
* **`_last_summary_line` is still in use for `helm lint`.** helm lint's exit
  code genuinely is its verdict, so it is not wrong there — but it is the same
  function that produced the polaris advertisement, and its heuristic ("the
  last line is the summary") is a guess about output formats that happens to
  hold for one tool.
* The prose surface remains largely untested; R6 added two more prose tests
  and several hundred more sentences remain unread by any test.

---

## R7 — "Out of scope" was being spent as evidence

### The defect

Subcharts are declared out of scope. That is a defensible decision: a vendored
chart is someone else's code, and folding its findings into *your* grade
misrepresents what you are responsible for. The tool even recorded the
omission in the coverage table, which is more than most linters do.

The omission was not contained. `helm template` renders subcharts — that is
what an umbrella chart *is* — and `discovery.py` dropped those objects on the
floor before anything else looked at them:

```python
if src.startswith("charts/"):
    skipped_subchart += 1
    continue
```

Every later check therefore reasoned over a world in which those objects did
not exist. HP041 asks "does any workload in this chart match the HPA's
`scaleTargetRef`?", found none, and reported:

```
[HP041] HPA target does not match any workload in the chart      HIGH
    Basis : OBSERVED - read directly from your files (stated as fact).
    Found : HPA 'umbrella-worker' targets Deployment/umbrella-worker,
            which matches no Deployment/StatefulSet template here
    Fix   : Make the ref use the same fullname helper as the Deployment.
```

`Deployment/umbrella-worker` exists. helm rendered it, in the same run, from
`charts/worker`. The analyzer threw it away and then reported its own
blindness as a HIGH-severity fact about the user's chart.

### The authority

> **C2.2** A value the tool cannot determine must be reported as undetermined.
> Never report a limit of the method as a finding about the target.

and the report's own basis vocabulary: `OBSERVED — read directly from your
files (stated as fact)`. Nothing was read. The finding was an artefact of a
`continue` statement.

This is the C2.2 conflation in its purest form and worse than R6's. R6
mis-transcribed another program's verdict; this one invented a defect.

### The proof

`proof/p7_subcharts.py`, 16 checks, all green. `fixtures/umbrella-chart` is a
real umbrella chart — parent `Deployment/umbrella-api`, an HPA targeting
`umbrella-worker`, and `charts/worker` providing exactly that Deployment. The
BEFORE column is the committed pre-fix tool, extracted with `git archive` at
the SHA pinned in `proof/baseline.py`, run as a subprocess against the same
fixture bytes.

CLAIM 0 confirms helm really does render the "missing" object before anything
is claimed about the analyzer. CLAIM 4 is the guard that matters most: point
the HPA at `umbrella-typo`, a name nothing in the chart or its subcharts
provides, and HP041 must still fire at HIGH. The cheap way to make a false
positive disappear is to stop firing the rule, and that trades it for a false
negative — the worse bug, because nobody notices a finding that is absent.

### The fix

Three edits.

`discovery.py` now parks subchart output instead of discarding it.
`_record_subchart_chunk` parses each `charts/…` document into
`ctx.subchart_docs` and records the subchart's name in `ctx.subchart_names`;
the names are also read straight off the filesystem at discovery time, so they
are known in static mode where nothing renders at all. Parse failures there
are deliberately swallowed rather than pushed into `ctx.parse_errors` — a
parse error is reported as a gap in the analysis of *your* chart, and this
document was never part of that analysis. Surfacing it would be the mirror
image of the bug being fixed.

`checks_hpa._target_is_out_of_scope` is consulted before HP041 fires, and
distinguishes three situations. If a subchart provides the target, the
reference resolves and no finding is raised. If subcharts exist but none of
their objects were visible — static mode renders nothing, and a subchart gated
off by a condition emits nothing — the tool cannot tell "missing" from
"somewhere I did not read", so it records the question as UNDETERMINED. A
chart with no `charts/` directory reaches neither branch and behaves exactly
as before.

The coverage row changed from a count to an inventory. `N object(s) SKIPPED`
cannot be acted on: it does not tell a reader whether the thing they are
looking for is behind the boundary. It now names the subchart, the kinds and
the object names, caps the list at eight and says when it capped, and each
suppressed HP041 leaves its own row naming the HPA, the target and the file
the target actually came from.

### The honest loss

The static-mode branch is conservative: a genuinely dangling reference in an
umbrella chart analysed without helm now goes unreported. That is the right
direction to err — a false HIGH sends someone to edit correct code, while this
leaves an itemised coverage row saying exactly which claim was not checked and
how to settle it by hand — but it is a loss, and it is stated in the code, in
the report and here rather than left for someone to find.

### Evaluation — Bar 1 (correctness)

`proof/p7_subcharts.py` — 16/16, exit 0. **346 tests** pass, and all **17
proofs** exit 0. Ten new regression tests pin both halves: a ref a subchart
satisfies raises nothing and leaves an auditable coverage row; a ref nothing
satisfies still fires; kind must match, not just name; a chart with no
subcharts is untouched; unrendered subcharts are UNDETERMINED rather than a
finding. Two of them run the real pipeline over the real fixture, because the
unit tests alone could pass while the wiring was wrong — which is precisely
how R6's two validators went four iterations without ever being executed.

### Evaluation — Bar 2 (does it do what it is for)

`proof/p7b_bar2.py`, all checks green. A static analyser is not a scoreboard.
Every finding ends with a `Fix:` line and the entire value proposition is that
somebody reads it and edits their chart, so the Bar 2 question is not "was the
finding wrong" but "what happened to the person who believed it".

The proof performs the edit. The only Deployment the pre-fix tool could see
was `umbrella-api`, so "make the ref use the same fullname helper as the
Deployment" has exactly one referent for a reader who trusts the tool about
which Deployments exist. Applying it retargets a correct HPA onto the wrong
workload — and the pre-fix tool then reports the broken chart as clean. The
false positive is self-confirming: follow the advice and the complaint stops,
which reads as confirmation that the advice was right.

Measured on byte-identical input, the non-defect cost 2.8 points (90.5 → 93.3)
and the post-fix score is not a whitewash — the same run still raises 21
findings. The replacement is checkable by hand: the report names the target,
the file it came from, and states unambiguously that it was `NOT graded`. The
pre-fix report named none of it.

CLAIM 4 executes the remedy the new coverage row recommends, because advice a
proof does not run is advice nobody has checked — the R6 lesson applied to
prose. Running the analyzer directly against `charts/worker` produces a real
graded report of 22 findings.

CLAIM 5 measures what is still missed rather than asserting it. That
subchart's container sets `JAVA_TOOL_OPTIONS=-Xmx4g` under a 2Gi memory limit:
a guaranteed kernel OOM kill, and the single class of defect this tool exists
to catch. Neither the parent run nor the direct run finds it. The parent's
silence is now itemised by name and kind instead of being a bare count, but
the direct run's silence is a different defect entirely, and it is the largest
one currently known.

### Also discovered, queued

* **JVM checks are gated on a Dockerfile.** `checks_docker.run` opens with
  `if not ctx.dockerfiles: … return`, so a pod-spec `JAVA_TOOL_OPTIONS=-Xmx4g`
  under a 2Gi limit is never compared against anything. The flags reach the
  JVM regardless of how the image was built; the gate is an artefact of where
  the parser happens to live.

  *Corrected in R8.* The description above is wrong in two ways and both
  matter. It reads as a **gap** — something the tool declines to do — and it
  reads as **one site**. R8 measured it: the same substitution also fires in
  the other direction, inventing a JVM on a chart that has none, which is a
  C2.2 violation and not a gap at all; and the substitution is made in
  **thirteen** places, four of them outside the check layer entirely. See
  `## R8`.
* **HP041 was the demonstrable case, not the only one.** Any check that
  concludes "absent" from "not in `ctx.docs`" reasons the same way. The fix is
  deliberately narrow — one rule, one proof — and the class stays open until
  someone shows another member doing harm.
* **Subchart values are still not merged.** `ctx.subchart_docs` records what
  helm rendered; it says nothing about whether the parent's `values.yaml`
  overrode the subchart's defaults, which is the usual reason an umbrella
  chart surprises its author.

---

## R8 — A question about a runtime, answered by a directory listing

### The defect

The tool's reason to exist is one sum. A JVM that is not told about its
cgroup will size its heap from the machine's memory, the kernel will kill the
container, and the HPA will replace it with another container that does the
same thing. Computing `heap + metaspace + code cache + threads×Xss + direct`
against `limits.memory` is the thing this program is *for*.

Before it can compute that sum it has to decide whether the workload is a
JVM at all. It decided by asking whether the chart directory contained a file
named `Dockerfile`:

```python
if not ctx.dockerfiles:
    ...
    return
```

That is not a cheap approximation of the right question. It is a different
question, and it is wrong in **both** directions:

**FACE A — silence.** `fixtures/umbrella-chart/charts/worker` sets
`JAVA_TOOL_OPTIONS=-Xmx4g` in its pod spec under `limits.memory: 2Gi`. Those
flags reach the JVM through the environment; the image build has nothing to
do with it. The chart ships no Dockerfile, so the sum was never attempted.
Measured on the pinned baseline:

```
GRADE A-  (90.9/100), 22 findings
  critical : 0
  high     : 2   (PB001 No readinessProbe; SC001 Container may run as root)
```

Not one finding about memory, heap or the limit, at any severity. A
guaranteed OOMKill, graded A-.

**FACE B — invention.** `fixtures/nojvm-chart` is a pure nginx chart that
happens to own a file called `Dockerfile`. The baseline reported:

```
HIGH     JV021  No JVM heap sizing is actually applied
         file=Dockerfile  basis=observed
         fix: Apply -XX:MaxRAMPercentage=50-75 …
MEDIUM   JV026  No applied -XX:+ExitOnOutOfMemoryError
MEDIUM   DF003  Java version undeterminable - JVM version checks degraded
         fix: Re-run with --assume-java <version> …
```

plus a scored "Java / JVM Container Fitness" category. `basis=observed`
means *read directly from your files, stated as fact*. Nothing was read. The
tool asserted, at HIGH and as fact, the configuration state of a runtime that
is not in the container.

FACE B is the more expensive of the two and the one a rule count cannot see.
Those three findings did not print alone. They printed in the same list as
PB004, SC001 and SC002, which are true of that chart and worth acting on. An
operator who checks the loudest claim first — and JV021 is trivially
checkable, they need only read their own Dockerfile — discovers it is
nonsense about software they do not run, and applies that discount to
everything printed beside it. Silence loses one finding; invention discounts
the whole page.

### The authority

> **C2.2** A value the tool cannot determine must be reported as undetermined.
> Never report a limit of the method as a finding about the target.

> **C2.6** An ungraded area must say it was ungraded.

FACE B violates C2.2 outright, in the same shape as R6 and R7: a limit of the
method — "I only know how to find JVM flags in Dockerfiles" — printed as a
finding about the target. FACE A is not a C2.2 violation, because the tool did
announce the skip (DF000), and that distinction is why the R7 queued note
filed this as a gap. That note was wrong, and the correction is above: R8 is
both faces, and the invention half is a contract breach.

C2.6 is what stops the fix from being `del`. Deleting the JV021 line replaces
a false HIGH with a false clean bill of health, because an unrun check and a
passed check look identical in a report that only prints failures.

Neither contract, though, forbids the *substitution itself* — they only
describe what to do once you notice you do not know. So R8 adds one, because
a defect that reaches thirteen sites is a missing rule and not thirteen
mistakes:

> **C2.7** A predicate about the workload must be evaluated against evidence
> about the workload, and the evidence must be quotable. Computed in exactly
> one place; returns the sentences that justify it, not a boolean; and
> "inconclusive" is a third state distinct from yes and no.

The boolean is the part worth dwelling on. `has_dockerfile` could only ever be
printed as a decision, never as a reason, which is precisely why the wrong
answer propagated to a preflight line, a probe title, an inventory row, an
appendix and two security rationales without anyone noticing: none of those
surfaces was in a position to show its working.

### The trap: two gates, arranged so that finding it would not have mattered

`ctx.dockerfiles` decided whether the check ran. `scoring.unassessed_reason`
used the *identical test* to decide whether the category counted toward the
score. So on a chart with no Dockerfile, the CROSS category was removed from
the denominator by the same condition that stopped anything being put into
it.

`proof/p8b_bar2.py` CLAIM 2 measures what that costs, by scoring the fixed
tool's findings over both denominators:

```
pre-fix denominator (7 categories)   with XF001 89.5   without 89.5   delta 0.0
fixed  denominator (9 categories)    with XF001 87.9   without 91.8   delta 3.9
```

The CRITICAL was worth **exactly zero points** under the pre-fix scale.
Fixing only the check would have produced a tool that finds a guaranteed
OOMKill and prints the same number it printed before — which is the reason R8
could not be a patch at one site.

### The proof

`proof/p8_jvm_gate.py` — 27 checks, exit 0 — is Bar 1. BEFORE is the
committed pre-fix tool, extracted with `git archive` at the SHA pinned in
`proof/baseline.py`, run as a subprocess against the same fixture bytes.
CLAIM 6 is the guard: `bad-chart` and `sidecar-chart` genuinely exercise the
JVM path (57 rules / 10 JVM-family, and 22 / 1), and their rule sets and
scores are byte-identical before and after. Widening a gate is only a fix if
the cases that already worked are untouched.

`proof/p8b_bar2.py` — 24 checks, exit 0 — is Bar 2, and asks what the wrong
gate cost the two people who read the output.

Three things in that proof were wrong on first run, and all three are worth
recording because each is a way a proof can lie:

1. **A check that could not fail.** The JSON emits `"severity": "HIGH"`; the
   Python enum's value is lowercase. The severity helper compared against
   lowercase literals, so it returned `[]` on every chart and CLAIM 1 passed
   on inputs that are full of CRITICALs. The comparison is now normalised at
   the single place it is made.
2. **An instrument that reproduced the bug it was built to detect.** The
   surface test asked `"JVM detected" in text` — which matches inside the
   string *"no JVM detected"*, and so reported the pure-nginx chart as
   asserting a JVM. Now `asserts_jvm()` strips the negated forms first and
   matches the evidence sentence itself.
3. **A claim whose prose the measurement refuted.** CLAIM 1 was drafted as
   "no finding above MEDIUM". The run shows two HIGHs. The rule is that the
   text is corrected from the measurement and never the assertion softened,
   so the claim was re-made on the axis the data supports and which is also
   sharper: **zero findings about memory at any severity**. The correction is
   narrated in the proof's own output rather than quietly edited away.

### The fix — one question, thirteen sites

`kube.py` now holds the question itself, as a question about the workload:

```python
jvm_evidence(ctx) -> List[str]          # quotable sentences, not a boolean
this_container_is_jvm(ctx, c) -> Optional[str]
```

It returns *evidence text* rather than a flag, because every caller has to be
able to print why. It reads pod-spec env (`JAVA_TOOL_OPTIONS`,
`JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `JAVA_HOME`, `CATALINA_*`, `SPRING_*`),
container image names (`openjdk`/`temurin`/`corretto`/`zulu`/`graalvm`,
`*-jre`, `*-jdk`, `tomcat`, `jetty`, `wildfly` — the last three had drifted
out of the one image list that did exist), and any Dockerfile's `FROM` line
and flags.

The substitution was made in thirteen places. Four were in the check layer
and were found by reading the code; four are not checks at all; the last
three were found by `p8b`'s surface table rather than by reading anything.

| # | site | what it did |
|---|------|-------------|
| 1 | `checks_docker.run` | returned early with no Dockerfile |
| 2 | `proofs.run` / `_pairs` | paired containers with a Dockerfile, not with a JVM |
| 3 | `scoring.unassessed_reason` | the second gate — removed the category from the denominator |
| 4 | `discovery.py:592` | coverage row |
| 5 | `report.py` file inventory | `Java version unknown` on line 1 of an nginx report |
| 6 | `checks_workload` PB004 | "Liveness can kill a still-starting JVM" |
| 7 | `checks_workload` RS010 | |
| 8 | `checks_hpa._target_is_jvm` | |
| 9 | `clusterprobes` cgroup probe | withheld from the chart that needed it |
| 10 | `preflight` | demanded `--assume-java` — the first thing the user reads |
| 11 | `checks_workload` SC003/SC004 | rationale prose assumed a JVM without gating on one |
| 12 | `report._education` | printed a JVM primer on every chart |
| 13 | `report.py` inventory `jvm :` row | said nothing about a JVM on the chart that has one |

Sites 11–13 are the smallest and none of them is a rule, which is exactly why
they survived the first ten. They are the page telling the reader something
about a runtime. A reader does not experience modules; they experience one
page, and the page has to agree with itself.

Site 12 is the only one where the remedy was **not** to remove the JVM
material. §6.2–6.4 of the appendix explain container-aware heap sizing, and
the reader who most needs that explanation is the one whose Java service this
tool *cannot detect* — flags baked into an opaque `corp.registry/payments-api:4.2`.
Deleting the primer would convert an admitted blind spot into a withheld
answer. So it is **labelled** instead:

```
[reference only - nothing in this chart indicates a JVM, so 6.2-6.4
describe a runtime that was NOT detected here and no finding in this
report rests on them. …]
```

and on a chart with evidence, `[applies to this chart - <the evidence>]`.
`p8b` proves that exclusion legitimate rather than assuming it: section 6 is
byte-identical between the two charts apart from that one bracketed note.

### The honest loss

None, in the sense of a check that stopped running — `p8_jvm_gate` CLAIM 6
holds the previously-working charts byte-identical. But the widened question
is a **heuristic over names and environment variables**, and it has a floor
that R8 does not raise: a Java service whose flags are baked into an opaque
image, with nothing Java-shaped in its name or pod spec, is invisible to it.
That is the single most common real-world shape.

R8 does not solve that case. R8 stops the tool **guessing** about it.
`p8b` CLAIM 6 measures it, and the tool now says:

```
JAVA assessed: False
reason: nothing in this chart indicates a JVM workload; examined pod-spec env
(JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS, _JAVA_OPTIONS, JAVA_HOME/JAVA_*,
CATALINA_*, SPRING_*), container image names (openjdk/temurin/corretto/zulu/
graalvm/*-jre/*-jdk, tomcat, jetty, wildfly), and any Dockerfile's FROM line…
```

That is C2.2 doing its job rather than being violated: *I could not determine
this* is reported in the place the answer would have gone, with the inputs it
examined listed, so a reader who disagrees can point at the one it missed and
close the gap by adding it. The pre-fix tool had no vocabulary for this state
at all — it had a filename, and a filename is always either there or not.

### Evaluation — Bar 1 (correctness)

`proof/p8_jvm_gate.py` — 27/27, exit 0. **369 tests** pass; all **19 proofs**
exit 0. The regression tests pin both directions and, importantly, the three
non-rule surfaces: that nginx SC003/SC004 prose contains no "JVM" while still
naming `/tmp`; that the inventory states the JVM verdict on a chart with no
Dockerfile; that the primer says whether it applies to this chart.

Scores move as measured, not as hoped: FACE A `90.9 → 87.9` (a CRITICAL
appears), FACE B `90.0 → 90.7` over 8 categories instead of 10 (two false
findings and two fabricated denominators leave). The good/sidecar/bad control
table is unchanged.

### Evaluation — Bar 2 (does it do what it is for)

`proof/p8b_bar2.py` — 24/24, exit 0.

The Java operator is now told, at CRITICAL, on OBSERVED basis, with the
arithmetic shown:

```
Deployment 'umbrella-worker' / container 'app': effective max heap 4 GiB
(-Xmx (4 GiB) via pod-spec env JAVA_TOOL_OPTIONS) vs limits.memory 2 GiB.
```

and — because of site 3 — the grade moves with it. Under the old denominator
that finding was worth 0.0 points; a reader who gates on the number would have
shipped anyway.

The nginx operator is told nothing about JVMs, and is told *that* explicitly
rather than by omission: the JAVA category reads NOT ASSESSED, the reason
names every input examined, and the remedy names the **input** ("set
`JAVA_TOOL_OPTIONS` in the pod spec") rather than the rule. The five true
findings that JV021 was discrediting now print on their own credit.

### Also discovered, queued

* **`--assume-java` is asking the wrong actor.** The version is usually
  recoverable from `pom.xml`, `build.gradle`, `.java-version` or a
  `maven.compiler.release` property. Demanding a flag for a fact sitting in
  the repo is the same shape of defect as R8, one layer up: the tool has the
  evidence and asks the human anyway.
* **The evidence heuristic has no confidence axis.** `JAVA_TOOL_OPTIONS` in a
  pod spec is proof; an image tagged `*-jre` is strong; `SPRING_PROFILES_ACTIVE`
  alone is suggestive and could be a sidecar's. All three currently produce
  the same unqualified "JVM evidenced" sentence.
* **The prose surface is still largely untested.** Sites 11–13 were found by
  a Bar 2 proof, not by the 369 unit tests, and only because that proof
  enumerated every reader-visible surface by hand. There is no mechanism that
  would catch a fourteenth.

---

## R9 — A guess with a comment beside it, carried into a categorical verdict

### The defect

`fixtures/good-chart` is the flagship clean fixture. Before this iteration the
tool said, of a JVM that had never run:

```
| Metaspace (est.)            | 128 MiB  | typical framework app 80-180 MiB   |
| ...                                                                         |
| ESTIMATED PEAK RSS (T)      | 916 MiB  | T = H + non-heap components        |
| Margin (limit - T)          | +108 MiB | +11% of limit                      |

  VERDICT: Fits with 108 MiB headroom (11% of limit).
```

The margin is 108 MiB. Six content rows above it, in the same table, the tool
prints a 100 MiB span of uncertainty on *one* of the five components feeding
that margin. Both numbers were on the page; the subtraction was left to the
reader, who ran a program precisely so as not to have to do it.

Five constants — metaspace, JIT code cache, thread count, direct buffers, GC
and JVM internal — were bare `int`s with a comment beside them, and the
comment was the only place the width existed:

```python
EST_METASPACE = 128 * MiB   # typical Spring/framework app: 80-180 MiB
```

The comment was even *printed*, in the Basis cell, next to the single value it
did not use. That single value then decided a categorical verdict and the
grade.

### The authority

Not Kubernetes this time; the tool's own contract. **C2.3** already required
every estimated input to be labelled as an estimate inside the table, at the
point of use — and it *was*. The row says `(est.)`. The label was satisfied
and the defect was still there, which is the finding: a label tells you a
number is uncertain, and says nothing about whether that uncertainty is large
enough to change the answer. Here it was more than large enough, and the
verdict was voiced in the register C2.2 reserves for facts.

The technical authority for the widths is upstream and cited in the code:
metaspace is uncapped by default and grows with loaded classes; Spring Boot's
embedded Tomcat defaults to `server.tomcat.threads.max=200`, so 100 threads is
one guess among the shipped defaults; `-XX:ReservedCodeCacheSize` reserves 240
MiB and commits far less; with no `-XX:MaxDirectMemorySize` the JVM's own
direct-buffer limit defaults to max heap, so the high end is not a cap at all.
An interval invented as freely as the point estimate would be the same defect
with error bars painted on, so each band carries its source.

### The proof

`proof/p9b_bar2.py` CLAIM 1. Same fixture, files proved byte-identical by
sha256 over every file in the tree, two constants moved to the ends of the
bands **the pre-fix report prints in its own Basis column** — metaspace 128 →
180 MiB, threads 100 → 200:

```
typical constants : GRADE A+ (100.0/100)   XF=[]
    Fits with 108 MiB headroom (11% of limit).
band-end constants: GRADE A+ (98.3/100)   XF=['XF002']
    T exceeds the limit by 44 MiB: expect kernel OOM kills (exit 137)…
```

Same program, same bytes, two answers in different categories, one of which
the user was shown with nothing marking that the other existed. That is the
defect stated as a cost. Not that 128 MiB is a bad guess — it is a good guess
— but that a guess was rendered in the grammar of a measurement, and the
reader's decision (ship this limit, or raise it) was made on the difference.

CLAIM 3 measures the reach: the false confidence was not confined to the
table. It arrived in the eleven-line terminal block a CI job prints, as
`GRADE A+ (100.0/100) 0 critical, 0 high` and `No critical or high findings.`
Every individual sentence there is true. The report is wrong at a level the
sentences cannot show.

### The fix

`Est(lo, point, hi, source)` replaces the five bare ints, and the width is
carried everywhere the number goes instead of being discarded at the first
arithmetic. `point` remains what every existing finding fires on, so findings
and the grade keep meaning exactly what they meant — now labelled as claims
about typical values rather than about the user's chart. `lo`/`hi` decide only
whether the *answer* is determined.

The verdict becomes three-state, and the undetermined case is not a shrug:

```
UNDETERMINED: the limit 1 GiB falls INSIDE the range this model can produce
(722 MiB - 1.2 GiB), so whether the JVM fits is decided by the estimates and
not by your chart. At typical values it fits (+108 MiB); that number is
reported, and findings are raised from it, as a claim about typical values
only. No single estimate crosses the limit on its own inside its documented
band; the smallest set that does is Thread stacks at its high end (200 MiB),
JIT code cache at its high end (128 MiB), which moves T by 164 MiB against a
gap of 108 MiB. To settle it, measure and re-run: `kubectl exec POD -- jcmd 1
VM.native_memory summary` (needs -XX:NativeMemoryTracking=summary), then pass
the numbers back with --measured
metaspace=...,codecache=...,threads=...,direct=...,gc=...
```

(That last line is quoted as it ships *after* the third defect below. The
first draft ended it with a hand-written `metaspace=...,threads=...,direct=...`
that was the same on every run, and the section after next is what running the
README's own example did to it.)

The test of a Bar 2 fix is not that the tone got humbler; it is whether the
reader can now *do* something. Before: nothing to check, nothing to measure,
no way to discover the sentence was fragile. After: a named deciding set, the
movement required against the gap available, and one command that replaces
both with observations — `--measured`, which drops each supplied component out
of the band arithmetic and, when all are supplied, removes the interval and
says that it has, on both the fits and the over-limit branch.

A thin margin is still a **finding**, not an uncertainty: `-Xmx3364m` against a
4 GiB limit puts `t_hi` exactly on the limit, and that reads "worst case 0 B
spare" with XF004 raised, never UNDETERMINED. Undetermined is reserved for the
threshold falling strictly *inside* the interval. This distinction was a bug in
R9's own first draft, and it is pinned by a test.

This is now **C2.8** in `SPEC.md`.

### The defect this iteration's own proof found

Writing `p9b_bar2.py` CLAIM 5 produced the counterfactual by disabling the new
summary qualifier in the current tree and re-rendering. It showed that the
first version of the fix — table only — left the terminal block reading:

```
GRADE A+  (100.0/100)   0 critical, 0 high, 0 medium, 0 low
No critical or high findings.
```

on a chart whose report says UNDETERMINED on page 3. C2.5 forbids scoring the
tool's ignorance as the user's defect, so *not moving the number was correct*;
letting the summary imply a pass was not. That is the pre-fix defect exactly,
moved one screen up — and R8 spent thirteen sites learning that a reader does
not experience modules. What ships instead:

```
GRADE A+  (100.0/100)   0 critical, 0 high, 0 medium, 0 low
JVM fit UNDETERMINED (limit 1 GiB vs model range 722 MiB-1.2 GiB) for
Deployment 'release-name-orders-service' / container 'orders' - not scored,
and NOT a pass. Settle it with
`--measured metaspace=...,codecache=...,threads=...,direct=...,gc=...`.
No critical or high findings - but see the UNDETERMINED item above.
```

sourced from the coverage rows rather than recomputed, so the summary cannot
disagree with the table it summarises, and repeated on all six surfaces the
proof enumerates (terminal block, full-report exec summary, coverage table,
budget verdict, HTML, JSON). The range is echoed because "UNDETERMINED" alone
invites the reader to assume a small doubt; `722 MiB - 1.2 GiB` against a 1 GiB
limit tells them the doubt spans the answer.

### The third defect, found by running the README's own example

C2.8(e) requires the verdict to name "the observation that would settle it and
the flag that accepts that observation". The first implementation satisfied
that as written — every undetermined verdict ended with the same sentence. The
README, one commit later, printed this as its example invocation:

```
python3 hpa-analyzer.py ./svc --measured metaspace=210Mi,threads=180
```

Running it is what exposed the defect. The verdict still said
`--measured metaspace=...,threads=...,direct=...` — two components the reader
had *just supplied*, and it omitted `codecache` and `gc`, two of the three
that were still deciding the answer. The terminal block said `Settle it with
--measured.` to somebody who had used `--measured`. The tool was telling a
user to go and do the thing they had done while staying silent about the thing
that would have worked.

This is not a wording bug, and the honest reading of it is uncomfortable:
C2.8(e) was **satisfied** and the tool was **useless at the moment of use** —
the same shape as C2.3 being satisfied while R9's original defect stood, one
level further in. A canned remedy cannot be right after a partial measurement,
because *which* observation settles the question is a property of the run. So
the list is derived from the same `Comp` records the table prints — `estimated`
is the property the row's `(est.)` label is computed from — and `report.py`
reads it back out of the coverage row rather than recomputing it, so there is
one place for it to be wrong instead of two. What ships:

```
default : --measured metaspace=...,codecache=...,threads=...,direct=...,gc=...
partial : --measured codecache=...,direct=...,gc=...
          "You have already measured metaspace, threads; what is left
           undetermined is decided by the components you have not:
           codecache, direct, gc."
```

The credit sentence is not decoration: a reader who passed two flags and is
handed three different ones has to be told why the list changed, or the tool
looks like it ignored the measurement. Seven tests pin it, on all three
surfaces, in both directions — that the remainder is named, and that what was
supplied is *not*, since a test of only the first would be satisfied by
reverting to the canned string, which named `metaspace`. CLAIM 7 measures it
against the real CLI, with the BEFORE produced by rebinding the derivation to
the old constant and re-rendering rather than quoted from memory.

**The spec was the accomplice, so the spec changed.** A clause that a
defective implementation satisfies is an underspecified clause, and "name the
flag that accepts that observation" was one: a fixed sentence names a flag.
C2.8(e) now reads *derived from the run, not written out as a sentence*, and
requires the report to distinguish what is still missing from what the reader
already supplied. Tightening the authority rather than only the code is the
difference between fixing this defect and fixing this instance of it.

Writing those tests then surfaced a smaller sibling with the same shape.
`MEASURED: --measured metaspace=...` is a claim about provenance — it says
*this number is here because you passed that* — and it was rendering the
value back from the parsed integer, citing `metaspace=220200960` at somebody
who wrote `210Mi`. Re-rendering through the tool's own formatter would only
move it (`256M` would come back as `244.1Mi`, a string they also did not
type, and one that reads as the tool disagreeing with them), so the literal
is carried through parsing and the defensive copy in `discovery` — which is
where the first attempt at the fix silently died, because `dict(measured)`
returns a plain dict and drops it. The value cell shows the tool's reading
and the source cell shows the user's words, which is what lets the *reader*
catch a misunderstanding instead of only the tool catching it. This is now
**C2.8(g)**, and CLAIM 8 measures it.

CLAIM 8 also cost this proof one more correction of the kind R9 keeps
producing: its first draft typed the BEFORE string by hand as
`metaspace=268435456`, and that was **wrong** — `256M` is 256 × 10⁶ in
Kubernetes quantity notation, not 2²⁸. A remembered number, asserted inside
a proof whose entire subject is not doing that. It is now rendered by the
tool with the citation rebound to the superseded form, and a check asserts
the counterfactual really is the same value cited differently.

### Evaluation — Bar 1 (correctness)

`proof/p9_estimates.py` — 79 checks, exit 0, including CLAIM 0, which proves
the arithmetic under test is byte-identical between the two baseline pins
before any measurement is taken (R9 is the first iteration to need a second
pin: its subject is not reached on several fixtures at the original baseline,
and `proof/baseline.py` records why).

**412 tests** pass; all **21 proofs** exit 0. The 43 new regression tests are
proved non-vacuous by measurement rather than by assertion: `git archive
f806890` into a scratch tree, copy this one file in, and run the seven R9
classes against it — **37 of the 43 fail** (20 failures, 17 errors). Five of
the six that pass are preservation claims: that `-Xmx4g` against a 2 GiB limit
stays CRITICAL and never becomes a maybe, that a fully `--measured` verdict
says the estimates had no part in it, that a range which fits *entirely*
inside the limit is a fit, that a clean chart acquires no new warning, and
that the score does not move. A guard test that *failed* before the fix would
mean R9 invented the guarantee rather than kept it, which is a different and
worse claim than the one being made.

The sixth passer corrected the rule. This measurement was first taken at 32
tests, and the note left in the file said a test passing at `f806890` is
"either a preservation claim or vacuous". Re-running it after the third defect
above refuted that: `test_a_run_with_nothing_measured_does_not_credit_a_
measurement` asserts the "you have already measured …" sentence is **absent**
when nothing was measured, and it passes at `f806890` for the degenerate
reason that the sentence did not exist there. It is not a preservation claim —
nothing was preserved — and it is not vacuous, because it is what stops the
sentence becoming decoration that prints either way. It is the negative face
of a paired claim, and it carries content only alongside the partner that
fails. The rule in the file is corrected from the measurement rather than the
measurement excused, which is the same discipline four of `p9b_bar2.py`'s own
claims were rewritten under.

### Evaluation — Bar 2 (does it do what it is for)

`proof/p9b_bar2.py` — 47 checks, exit 0.

CLAIM 6 is the guard, because epistemic honesty bought with true findings is
not honesty, it is a quieter tool — and R7 is the recorded case of that trade
being made by accident. All ten fixtures, both trees, score and finding set:

```
apiversion 87.2 B+ · bad 45.5 F [XF001,XF003] · capability 86.4 B ·
good 100.0 A+ · initheavy 85.3 B [XF002] · legacy 83.8 B · nojvm 90.7 A- ·
sidecar 88.7 B+ · umbrella 91.5 A- · worker 87.9 B+ [XF001]
```

Zero movement. R9 added a state the tool did not have and took nothing away
from the cases it could already decide.

### The honest loss

CLAIM 9, measured rather than footnoted: R9 makes the **width** of the answer
honest; it does not make the width **right**. `EST_METASPACE = 80-180 MiB` is
sourced to "typical Spring/framework app". An application with a large
dependency graph, an ORM generating proxies, or any bytecode-weaving agent
sits outside it — and `--measured metaspace=400Mi` produces a different
verdict category, while every metaspace quantity the default report prints
tops out at 180 MiB. For that application the tool is confidently wrong in
exactly the pre-R9 way; it merely states a range while being wrong.

And the escape hatch has a precondition the main use case cannot meet.
`jcmd VM.native_memory` needs a running pod, and the person choosing
`limits.memory` for a first deploy does not have one. For them the band *is*
the answer, and its endpoints are two more numbers nobody measured.

### Also discovered, queued

* **The bands have no confidence axis.** They should be narrow where the chart
  supplies evidence (a declared `-Xss`, a pinned thread pool, a framework the
  image name identifies) and wide where it does not. Today one band serves
  every workload, which is the R8 defect one level up: the tool has evidence
  available and does not let it move the answer.
* **`--measured` asks the wrong actor at the wrong time.** Some of these
  numbers are recoverable statically — `-XX:MaxMetaspaceSize`,
  `server.tomcat.threads.max` in a bundled `application.yaml`,
  `-XX:MaxDirectMemorySize` — and demanding a flag for a fact sitting in the
  repo is the shape of defect R8 named.
* **Six surfaces were enumerated by hand.** CLAIM 5 checks that all six agree,
  but nothing generates that list; a seventh surface would not be caught.
* ~~A measured row echoes bytes, not the flag.~~ **Fixed in this iteration**
  — noticed while writing the tests above, and small enough that queuing it
  would have been the wrong call: it is the same category as everything else
  here, a sentence in the grammar of provenance that was not quite
  provenance. `--measured metaspace=210Mi` was cited back as
  `MEASURED: --measured metaspace=220200960`, a string the user never typed.
  It is now **C2.8(g)** in `SPEC.md`, and CLAIM 8 measures it.

---

## R10 — A tool whose answer depends on `PATH`, shipped as if it did not

### The defect

R6 established, by measurement, that this tool's report is a function of what
is on `PATH`. Remove `helm` and the same chart's report changes its
`Analysis mode` from `helm (rendered truth)` to `static`, rewrites every row of
the coverage table from `rendered by helm` to `statically parsed`, and rewords
a finding — HP050 loses the word "Rendered". Remove `kubeconform`, `kube-score`
or `polaris` and `--cross-check` loses whole verdicts, correctly declaring them
"not checkable".

Nothing in that behaviour is dishonest. The report says what it did and did not
look at, which is exactly what R6 and R8 were about. The defect is one level
up: the project's central claim is that a report is an artifact you can hand to
somebody else and diff against last week's, and **it shipped no way to pin the
thing the report most depends on**. Two engineers on the same commit of the
same chart could exchange reports that disagree, with both reports accurate and
neither of them wrong about anything. `README` said "Recommended: `helm` on
PATH". It did not say *which* helm, and the answer moves with the version.

There is a second, sharper version of the same defect. `kubeconform` fetches
JSON schemas over HTTPS. On a machine with no CA bundle it reports
`x509: certificate signed by unknown authority`; the analyzer records that
correctly as "not checkable"; and a chart that validates cleanly on one machine
reads as `0 valid, 0 invalid, 3 not checkable` on another. Nobody lies at any
step and the answer still changes. This was not reasoned about — it was
measured, in the first stand-in image built for the proof, which had no
`/etc/ssl/certs`.

### The authority

The user's request, and the tool's own contract.

The request was specific: run it as a Docker image, but drive that image from a
shell harness so that to the user it still looks like a shell script and *all
the flags still work*; ask once, on first run, where output should go, and
remember it as an environment variable.

The contract is what makes that hard. C10.1, written for this iteration, is the
bar: `hpa-analyzer FLAGS DIR` must produce the **same bytes and the same exit
code** as `python3 -m hpaanalyzer FLAGS DIR`. Not the same findings — the same
bytes. That is a deliberately unforgiving standard, and it is the right one,
because the report prints `Target directory : <path>` and the terminal prints
`Full report: <path>`. A wrapper that mounts the chart at `/work` produces a
report whose own text is wrong the moment somebody pastes a path out of it into
another command. "Same findings, different paths" is not transparency; it is a
translation layer the user did not ask for and will not be told about.

One part of the request cannot be honoured literally, and saying so was part of
the work: **a child process cannot export a variable into its parent shell.**
That is `execve`, not a shortcoming of bash. Any tool that appears to do it is
writing to a dotfile without saying so. So "remember it as an environment
variable" is implemented as a config file at
`${XDG_CONFIG_HOME:-~/.config}/hpa-analyzer/config` which the wrapper **parses**
— never sources — and re-exposes under exactly the name the user expected,
`$HPA_ANALYZER_OUTPUT_DIR`, with an actually-exported variable taking
precedence over it.

### The proof

`proof/p10_harness.py`, 88 checks. Three of them are worth naming because they
are where a wrapper of this kind actually fails.

**The wrapper is a second argument parser, and it was checked against the first
one.** To know where to mount, the shell has to work out which token is the
positional directory — which means it has to agree with `argparse` about which
tokens are flag *values*. Checking that against my reading of `__main__.py`
would prove nothing, so the proof monkey-patches
`argparse.ArgumentParser.parse_args`, dumps the resulting namespace to stderr,
and compares it with what the shell decided, over a 19-row matrix. That is what
catches `--kube-version 1.31.0 chart/` mounting `1.31.0` as if it were a
directory, and the nastier one: `--html` takes an **optional** argument
(`nargs='?'`), so `--html --summary chart/` must not swallow `--summary` and
lose the chart.

**The config file is parsed, not sourced — proven by planting code in it.** The
proof writes a config containing a `touch <canary>` line, runs the wrapper, and
asserts the canary was never created. Sourcing a file you own is the kind of
convenience that turns a typo in a dotfile into arbitrary code execution.

**The report is byte-identical, native versus containerised** — 62704 bytes
either way, terminal summary and absolute paths included. That is the whole
claim, and it is only available because every host path is mounted at its own
path with the container's working directory set to the host's `$PWD`.

The first-run prompt is driven over a real controlling terminal with
`pty.fork()`; the second run is proven silent; and the no-TTY path is proven to
complete in 0.01s with two stderr notes and no config file written, because a
wrapper that blocks on a question in CI has broken every gate the tool exists
to provide.

### The fix

`bin/hpa-analyzer` and `docker/Dockerfile`, documented in
[DOCKER.md](DOCKER.md). Four binaries pinned by `ARG` — helm 3.16.4,
kubeconform 0.6.7, kube-score 1.20.0, polaris 9.6.4 — each one **executed** in
the build stage before being copied forward, because a binary that downloaded
but cannot run does not announce itself at run time; it surfaces as a quiet
coverage downgrade in a report that still looks complete.

The wrapper touches the user's command line in exactly one way: it appends
`-o <dir>/hpa_analysis_report.txt` when, and only when, no `-o`/`--output` was
given. It replaces the tool's **default**, never a path the user typed. That is
what makes "all the flags still work" literally true rather than approximately
true, and it is the answer to the design question this iteration had to settle
first — the saved directory could have been made to win over an explicit flag,
and that would have been a wrapper quietly redirecting output away from where
the command said to put it.

### Three defects this iteration's own proof found

**A wrapper being helpful is a wrapper diverging.** The first draft validated
the chart directory in the shell and exited 1 with a tidier message. The
analyzer already reports both failures precisely — `error: <abspath> is not a
directory`, exit **2** — so the tidier message substituted the script's wording
and the script's exit code for the tool's. Caught by CLAIM 8's rows "a
directory that is not there" and "a file where a directory was expected", both
of which now read native=2 harness=2.

**`[ "$#" -eq 0 ] && set -- --help` turns a red build green.** `python3 -m
hpaanalyzer` with an empty argv is an argparse usage error that exits 2. A
wrapper answering the same input with help text and exit 0 has converted a
failing command into a passing one, out of pure friendliness. The Dockerfile
had the identical bug from the identical instinct — `CMD ["--help"]` — and both
were removed. There is now a comment in each file explaining why the obvious
convenience is absent, because otherwise somebody will helpfully add it back.

**macOS ships bash 3.2, where `"${arr[@]}"` on an EMPTY array aborts under
`set -u`.** Every array in the script starts empty, and `add_mount`'s very
first call is made in exactly that state. This one is handled by construction —
indexed arrays with hand-maintained counters throughout — and it is stated here
as *handled*, not as *proven*, because it could not be measured: `ftp.gnu.org`
returned 403 from this sandbox and no bash 3.2 could be built to test against.
That is a weaker claim than every other claim in this file and it is labelled
as one.

### Evaluation — Bar 1 (correctness)

427 tests pass (412 before this iteration, plus the 15 in
`tests/test_harness.py`) and all 22 `proof/p*.py` scripts exit 0 after the
change, which
is the point: this iteration was required to change **nothing** about the
analyzer, and the evidence that it did not is that every prior iteration's
proof still reproduces its own measurement. Not one line of `hpaanalyzer/` was
touched.

### Evaluation — Bar 2 (does it do what it is for)

Yes for the harness, with one honest gap in what was proven.

The image the byte-identity check ran against **is not the image in the
Dockerfile**. No container registry — and not even `get.helm.sh` — is reachable
from this sandbox, so the image was assembled with `docker import` from this
machine's own filesystem. Its four binaries are therefore the *same builds* the
native run uses. CLAIM 7a therefore proves the **harness** transparent and
proves nothing whatsoever about whether helm 3.16.4 agrees with this machine's
helm v3.16. The proof says this in its own output rather than in a comment, and
`docs/DOCKER.md` repeats it: build the real Dockerfile on a networked machine
and re-run `proof/p10_harness.py`. If byte-identity then fails, the difference
**is** the pinned toolchain — which is a fact about the report worth publishing,
not a bug in the wrapper.

### The honest loss

Pinning the toolchain makes a report reproducible *given the image*. It does
not make the image's answer the right one. helm 3.16.4 renders what helm 3.16.4
renders; if the cluster the chart is bound for runs a different Helm, the
pinned answer is reproducibly the wrong one, and the tool has no way to know.
The image converts a silent, per-machine variable into an explicit, versioned
decision. That is strictly better and it is not the same as being correct.

### Also discovered, queued

* **R11 — `--cross-check` output is not reproducible run to run, natively.**
  Found by accident while trying to prove something else. kube-score printed
  six distinct md5s over six runs of one chart; polaris two over three;
  kubeconform varies with what the network answered that second. Four
  consecutive native runs over `fixtures/bad-chart` produced four distinct
  md5s with pairwise diffs of 51, 55 and 65 lines. The cause is Go map
  iteration order inside the tools being quoted. No **verdict** moves — the
  tallies are computed from counts and are order-independent — but the evidence
  a reader would use to audit that verdict does, and the whole premise of this
  project is a report a human can diff against last week's. It is logged rather
  than fixed because fixing it means reordering another tool's output, and
  `external.py`'s stated discipline is to reproduce it verbatim. That tension
  deserves its own iteration.
* **The external tools' versions are still not recorded in the report.** This
  iteration pinned them and then did not print them, which leaves the
  provenance grammar R8 built one field short of complete: a report says it was
  rendered by helm, and still not which helm. Inside the image the answer is
  knowable exactly, so the excuse is gone.
* ~~Nothing drives the shell harness from the Python test suite.~~ **Fixed in
  this iteration**, because queuing it was the wrong call: the wrapper's
  argument scan is a parser duplicating `argparse`, and that is precisely the
  code that drifts silently when a flag is added — add a value-taking flag to
  `__main__.py`, forget `VALUE_FLAGS` in the wrapper, and `--new-flag foo ./svc`
  mounts `foo` and analyzes it. `tests/test_harness.py` adds 15 tests that run
  entirely under `HPA_ANALYZER_DRY_RUN=1`, so they need no daemon, no image and
  no network, and every claim about the positional is checked against the real
  `argparse` namespace rather than against a reading of it.

  Six deliberate mutations of `bin/hpa-analyzer` confirm the tests can fail,
  which is not a formality here — R8's `p8b` shipped a check that compared
  against the wrong case and could not fail on any input. Dropping
  `--kube-version` from `VALUE_FLAGS` fails 2; appending `-o` even when the
  user typed one fails 3; restoring `[ "$#" -eq 0 ] && set -- --help` fails 1;
  mounting the chart at `/work` fails 1; sourcing the config instead of parsing
  it fails 1 (the canary test); and validating the chart directory in the shell
  fails 1.

---

## Documentation site — not an iteration of the analyzer

`docs/` gained a six-page static site (`index`, `usage`, `reading-the-report`,
`container`, `reference`, `limits`) served by GitHub Pages from `main` /
`/docs`, with a `.nojekyll` file so the HTML is served verbatim and no build
step stands between the repository and the page. Nothing in `hpaanalyzer/`
changed, so it is recorded here without a number of its own. (An earlier
version of this sentence said "rather than numbered as R12", written when R12
did not exist yet. It does now — it is the container-only round below — so the
sentence has been corrected to claim nothing about a number it does not own.)

It is listed in this log for one reason. A documentation site is a set of
claims about a program, and claims decay silently: a flag gets renamed, an
exit code changes, a fixture's score moves, and the page keeps saying what it
said. This project's standing discipline is that a claim is proved by running
it, so the site gets the same treatment as a fix — `proof/p11_docsite.py`, 171
checks, re-derives every checkable claim from the running program: both
directions of the flag round-trip against `--help` (a reference page that
documents a removed flag is as wrong as one that misses a new flag), every
`$ ...` transcript re-executed and compared line by line, every quoted figure
recomputed (the four verbosity line counts, the ten category weights and their
sum, the twelve JSON keys, the six exit-code rows, the byte-identity figure),
every internal link and `#anchor` resolved, every `github.com/blob/main/...`
link checked against a path that exists, and a check that the site never
mentions the unpublished `trial/` directory.

Four checks failed on its first run and all four were the *checker* being
wrong, which is worth naming because the reflex is to edit the page:
`src.count("<head")` also counts every `<header>`; `html.escape` with
`quote=True` demanded `&#x27;` where a raw apostrophe is correct HTML text;
a fragment comparison was case-sensitive across a sentence boundary; and the
byte-identity check looked for `62704` as a literal in `p10_harness.py`, which
measures that number at runtime rather than storing it. The last was replaced
with a live re-measurement — 62704 bytes, timestamp normalised — so the page
is held to the measurement rather than to another file's source text.

The fifth failure was real, and it was the site's. `limits.html` quoted the
R11 non-determinism as *51 to 65 lines*, itself already a correction of an
earlier *45 to 57*. The proof script re-runs that measurement instead of
repeating it, and its batches returned 43–55, then 25–59, then 49–61, then
38–59. The 51 floor was refuted by measurement. Both pages now state an
envelope of roughly **25 to 70 lines**, name both superseded ranges, and say
plainly that any narrow figure quoted for unbounded reshuffling is a sampling
artefact waiting to be refuted. The check was tightened at the same time,
because the version that passed was a containment test written as an overlap
test: it accepted a quoted 51–65 on a run that observed 25. A check that
cannot fail is not a check.

### The second machine found what one machine could not

Syncing the site to a second machine and running `p11_docsite.py` there
produced eight failures, and every one of them had the same cause: that host
has no `helm` on `PATH`. The analyzer correctly fell back to static parsing,
and static mode is a *longer* report — 170 / 919 / 1031 / 1251 lines against
the 167 / 906 / 1018 / 1238 the site quoted, and 63410 bytes against 62704 —
because it adds a parse-problem warning and rewrites every coverage row from
*rendered by helm* to *statically parsed*.

Nothing was broken. The site was quoting helm-mode figures without saying they
were helm-mode figures, which is a documentation defect that no amount of
re-running on the machine the docs were written on could ever surface. Both
pages now label the figures, publish the helm-less numbers beside them, and
say what does and does not change: for `fixtures/bad-chart` the verdict did
not move — GRADE F, 45.5/100, the same 60 findings, the same top five — which
is a property of that fixture rather than a guarantee, so the note says that
too and points at the mode banner as the thing to compare first.

The script was fixed in the same spirit. The obvious repair is to skip the
mode-dependent checks when `helm` is absent, and it is the wrong one: a gate
that only skips lets the site drift unchecked on exactly the machines that
would notice. It now branches instead — with `helm` it checks the helm-mode
figures, without `helm` it checks the static-mode figures the site publishes
for that case — so both hosts have something that can fail. 172 checks pass
here, 160 on the machine without the four external validators, and the twelve
that differ are the ones those validators gate.

---

## R11 — An accusation of absence, made without opening the file

### The defect

Helm charts share blocks through `templates/_helpers.tpl` and pull them in with
`include`. It is the idiom `helm create` itself generates, and `resources:` is
one of the most commonly shared blocks:

```yaml
resources:
  {{- include "orders.resources" . | nindent 12 }}
```

Without `helm` on `PATH` this program scrubs Go template actions into markers
and parses the YAML that is left. `.tpl` files are never parsed as documents on
that path — `discovery.py` records only that helpers exist — so the block above
collapses to a single leaf string, `HELMINC@orders.resources`. Three checks read
that string, found no `requests` key inside it, and said so at the severity of a
fact:

```
[RS001] CRITICAL  Container has no resource requests/limits
[HP022] CRITICAL  HPA scales on CPU but target workload has no CPU request
[RS011] HIGH      Pod QoS class is BestEffort
```

and a fourth read `resources: {}` in a values file that no template consumes:

```
[VA004] HIGH      Empty resources block in values
```

Every one of those is a claim of **absence**, and not one of them was supported
by absence. The tool had not opened the file the values live in. The RS001 entry
carried the line

```
Basis : OBSERVED - read directly from your files (stated as fact)
```

which is the one thing it was not. A chart written with a helper was graded four
findings worse than the byte-for-byte equivalent chart written longhand, and the
difference was entirely a property of the analyzer's reading, presented as a
property of the user's chart. R8 built the `Basis` grammar precisely so that a
guess could not wear the word OBSERVED; this was a guess wearing it.

### The authority

`docs/SPEC.md` §2 and the `Basis` doctrine established in R8. A finding stamped
OBSERVED asserts that the analyzer read the fact directly. `helmyaml.is_unresolved()`
is true for two markers that mean opposite things, and the checks fired on the
union of them:

| Marker | What it means | Is "no resources" true? |
|---|---|---|
| `HELMVAL@resources` | `.Values.resources` is unset in every values file read | **Yes.** helm renders an empty block from the same inputs. RS001 is correct and must keep firing at CRITICAL. |
| `HELMINC@x` | the body is in a file this run did not open | **Unknown.** Nothing is established either way. |

The fix therefore had to be narrower than `is_unresolved`, and deliberately so:
`kube.helper_resources_ref()` matches `HELMINC@` and nothing else, and tests pin
that narrowness so that a later "simplification" back to `is_unresolved` breaks
rather than silently restores the bug.

### The fix

The four accusations are **replaced, not deleted**. Silence would read as a
pass, and a chart that was never examined is not a chart that came back clean —
the same rule R8 wrote for the JVM gate. RS018, RS014 and HP032 (INFO) and
VA011 (LOW) name the helper that was not read, list the verdicts withheld
because of it, and say how to get them back (install `helm`, or run the
container, which pins one).

Scoring follows the module's own rule — there is no honest number for "not
looked at" — and drops RESOURCES from the denominator when **every** container
is helper-supplied, printing the reason in the coverage table. One legible
container keeps the category scored, so this does not reintroduce the
PB004/Dockerfile gate that R8 removed: a category with something real in it
stays in the mean.

### The proof

`proof/p12_helpers.py`, 7 claims, real subprocesses against the pinned baseline.
CLAIM 7's control was narrowed during the round: as first written it compared
against the immediate parent over the whole report, which passed while being
incapable of failing, because no fixture in the repository produces any of the
four rules it was watching. It now compares only the four rules it can actually
observe move. 455 tests pass.

### A number this log promised and then spent elsewhere

R10's queued list opens with "**R11 — `--cross-check` output is not reproducible
run to run, natively**". That item is still queued and still unfixed; the number
went to this round instead. It is left standing rather than renumbered, because
the useful record here is that a queued item was labelled with a round it did
not get, which is what queues do. The cross-check non-determinism is listed
again below.

---

## R12 — A reproducibility mechanism nobody was required to use

### The defect

R10 measured that this tool's answer is a function of `PATH`. `p10_harness.py`
CLAIM 3 diffs the same chart's report with `helm` present and absent and finds
the `Analysis mode` line, every row of the coverage table, the set of scored
categories, the denominator, the grade and the wording of HP050 all different.
Both runs are honest. Neither is comparable to the other.

R10 built a container image to close that — four pinned binaries, one build, the
same report everywhere. It closed nothing. `python3 -m hpaanalyzer ./svc` stayed
in the README as an equally valid command, and it is the one people reach for:
no build, no daemon, no 400 MB pull. The image was optional, so in practice it
was unused, so the grades stayed incomparable.

That is the defect, and it is not a code defect. **A reproducibility mechanism
that nobody is required to use is decoration.** Shipping it and then leaving the
unpinned path in the documentation as a peer is the same as not shipping it,
with the added cost that the project now believes the problem is solved.

### The authority

The user's instruction, verbatim: "Let's remove any instructions that allow
someone to use python to run the code on bare metal — let's force them to use
the docker image." Clarified to *docs plus a guarded runtime*: strip the native
instructions **and** make the module refuse, because documentation alone is a
convention and conventions are what the last round already tried.

### The fix

`__main__._require_image()` refuses unless `/etc/hpa-analyzer-image` is present
(written by the runtime stage of the Dockerfile) or `HPA_ANALYZER_ALLOW_NATIVE=1`
is set. Five decisions inside that sentence, each of which could have gone the
other way:

**Exit 2, never 1.** 1 means "your chart failed a gate". A CI job that reads
"you ran this wrong" as "your chart is bad" has been given a false verdict by a
tool whose entire purpose is not giving false verdicts.

**No carve-outs for `--help`, `--version` or `--check`.** A carve-out teaches
that native mode half-works, which is exactly the belief being removed.

**The guard is inside `if __name__ == "__main__"`, so it gates the *command*.**
`main([...])` in process is untouched: 20 tests and any embedder depend on it,
and breaking embedders to prevent a mistake embedders are not making is a bad
trade.

**A file marker, not an environment variable.** One `export` in a shell profile
would disable an env marker machine-wide and nobody would notice it happen. The
marker is explicitly **not** a security boundary and `IMAGE_MARKER`'s docstring
says so — it is aimed at habit, and habit is what the defect is made of.

**The refusal does not print the override.** A bypass shown in every terminal
becomes the folk-standard invocation within a week. It is documented in
`docs/DEVELOPING.md` and set by `proof/nativeoverride.py`, which is how the
evidence layer still spawns the CLI.

Documentation: README install/usage/fixtures blocks, `index.html`, `usage.html`,
`reference.html`, `container.html` and `DOCKER.md` now teach one command. Where
the module form survives it is prose explaining the refusal, never a copy-paste
block — `p11_docsite.py` scans `<pre><code>` specifically and fails on any native
invocation offered as a thing to run, while leaving the explanations alone.
`hpa-analyzer.py` is kept as a refusing shim, so an old CI line gets a sentence
instead of `No such file or directory`.

The Dockerfile's version ARGs moved to global scope in the same commit.
Redeclared per stage they are invisible to stage 2, and the provenance marker
would have recorded `helm=` on any build without `--build-arg` while the image
actually contained 3.16.4 — a provenance record that is blank exactly when it is
most needed.

### The proof

`proof/p13_guard.py`, 7 claims. CLAIM 6 was first written as a substring test
over the Dockerfile and **passed on a comment** — the file names the marker path
in three comments as well as in the `RUN` that creates it — so it now strips
comment lines before asserting. That is the third time in this log a check has
passed on something other than the thing it meant to check, which is why the
convention here is to record it rather than quietly fix it.

455 tests; p10, p11, p12 and p13 all pass.

---

## R13 — A category that cannot deduct, scored 100

### How it was found

Not by reading the code. The user asked for ten to fifteen random charts with
various Java configurations, run "using just the defaults (cuz that is how most
people will use this)". `proof/corpus_charts.py` builds fifteen; `proof/p14_corpus.py`
runs each one through `python3 -m hpaanalyzer <dir>` with no other flags. One row
of the resulting table did not make sense:

```
c12-no-mem-limit      B+   88.2   1C 3H 4M 10L
```

c12's image sets `-XX:MaxRAMPercentage=75` and its pod spec sets no
`limits.memory` at all. A container-aware JVM with no cgroup memory limit reads
the **node's** memory as its budget, so that chart asks for 75% of the node's RAM
in every replica: a 12 GiB heap target per pod on a 16 GiB node, 48 GiB on a
64 GiB node. It is the most dangerous chart in the corpus. The tool gave it a B+
and printed this:

```
| Java / JVM Container Fitness           |  94.0 | A  | 14 |  1M  |
| Cross-File Consistency (Chart <-> JVM) | 100.0 | A+ | 14 |  -   |
| Max heap (H)   | UNBOUNDED | no limit and no explicit sizing - unbounded |
```

### The defect

Four defects, in increasing order of seriousness.

**"no explicit sizing" is false.** The chart sizes the heap explicitly. What the
tool means is "I could not turn that sizing into a number", and it reports its
own arithmetic's limit as a property of the user's chart. A reader who acts on
that sentence sets `-Xmx` and does not set the limit, which is the wrong half.

**The peak-RSS row said "all measured, no estimates"** while every component row
above it was labelled `(est.)`. The wording is chosen by `banded`, whose comment
asserts it "is false only when the user has measured EVERY non-heap component".
That was true when it was written and became false once `total` could be `None`
— a comment that was correct at the time and was not re-read when the thing it
described changed.

**Cross-File Consistency scored 100.0 / A+** — fourteen of a hundred weight
points of clean bill of health. It is not a passing grade, it is an empty
category. XF001 through XF005 are every rule in it and all five are gated on
`if lim ...`; with no memory limit the category cannot deduct a single point, by
construction. `c03` shows the same fault without the first one: `-Xmx512m`, no
limit, heap therefore known and bounded, and Cross-File Consistency still
100.0 / A+ over zero findings. **This is the third time this project has shipped
this exact fault** — PB004/Dockerfile in R8, helper-supplied resources in R11 —
and `scoring.py`'s own docstring names it: "Score an unassessed category 100:
invents a clean bill of health for something never looked at."

**No finding at any severity says "you asked for a percentage of a limit you did
not set."** The tool holds every fact needed; it prints "MaxRAMPercentage is
computed FROM it" in its own prose, and draws no conclusion.

### The authority

`docs/SPEC.md` §3 (the budget model) for the first two, and `scoring.py`'s own
forbidden-fabrication list for the third. The fourth is Bar 2: a tool that holds
the facts and does not reach the conclusion has not done what it is for.

### The fix

XF006 fires when a percentage-based heap sizing meets an absent memory limit,
and says what will happen rather than what is missing. The budget table stops
claiming the user failed to size the heap when the truth is that the analyzer
could not resolve the number, and `banded` no longer promises "all measured"
once any component is unknown. `proofs.cross_no_limit_reason()` gates the CROSS
category out of the denominator when no JVM container sets `limits.memory`,
printing the reason — the same treatment R11 gave RESOURCES.

### The proof

`proof/p15_nolimit.py`, with a negative control for each of the four defects, so
that a later simplification that reintroduces any of them fails there rather
than in somebody's cluster. c12 moves from `B+ 88.2` to `C 86.5, 2C` — one new
critical, and the grade change is R14's, below.

---

## R14 — A report that says the container will be OOM-killed, above the letter B+

### The defect

`c07-xmx-over-limit` sets `-Xmx3g` inside a `limits.memory: 2Gi`. The tool gets
this completely right. It files XF001 at CRITICAL with basis OBSERVED, and says
in its own prose that the container will be OOM-killed under first real load.
Then the front page of that same report said:

```
  OVERALL QUALITY SCORE :  87.8 / 100   GRADE: B+
```

Both statements are outputs of the same program about the same chart in the same
run. One of them says the workload cannot start successfully under load; the
other is a letter that a reader, a manager, or a CI gate will read as *fine*.
Whichever one is right, shipping both is the defect — and the letter is the one
almost everybody reads, because it is the only part of the report small enough
to quote.

Nothing is wrong with the arithmetic. The score is a weighted mean over ten
categories. c07 is mediocre-in-nine-and-fatal-in-one, and a weighted mean of
that really is 87.8. **The mean is behaving correctly and that is precisely the
problem**: a mean is a summary of a distribution, and a certain failure is not a
point in a distribution. Dilution across nine healthy categories is exactly the
mechanism by which one fatal fact disappears.

### The authority

The corpus, run on defaults, which is how the user asked for it to be tested and
how nearly everybody will use it. `p14_corpus.py`'s CLAIM 3 is where this
surfaced, and the history of that claim is worth recording because the same
mistake was made twice:

*First draft:* `spread > 20`. It failed at 19.9. An arbitrary threshold is not a
claim; it is a number chosen so today's output passes, and the only thing 19.9
disproved was the 20.

*Second draft:* c01 beats c03 by at least 15 points. A comparison between two
named charts rather than a threshold on an aggregate, so it was an improvement —
but it failed at 8.2, and chasing *why* showed the 15 to be as arbitrary as the
20 had been. It was demanding that the mean stop behaving like a mean.

What the corpus actually exposed was never about gaps between charts. It was
c07.

### The fix, and the two things it deliberately does not do

`scoring.overall_grade()` caps the **OVERALL grade** at C when the result carries
any non-ASSUMED CRITICAL. `CRITICAL_GRADE_CAP = "C"`, applied over
`_GRADE_ORDER`.

**It does not touch the number.** Re-weighting the mean so that a critical drags
the arithmetic down was considered and rejected: the score is a measurement of
how many findings of what severity landed in which categories, and bending it so
the label comes out right would corrupt a measurement to fix a label. The label
is what is wrong, so the label is what gets corrected. The 87.8 stays, and the
cap reason says so out loud.

**It does not cap on ASSUMED criticals.** `models.effective_deduction()` already
limits an ASSUMED finding to `Severity.HIGH.deduction`, on the grounds that the
tool's own uncertainty must not sink somebody's grade. A cap firing where the
deduction does not would make one finding weigh two different amounts in two
places. `c04`'s HP025 is exactly this case — CRITICAL, but ASSUMED because the
HPA's target was not resolvable by name — and it keeps its A- 90.6.

**Per-category grades stay uncapped.** The cap is a statement about the chart as
a whole; a category grade is a statement about that category, and capping it
would blur which category the fatal fact is in.

### The cap is never silent, on any of the four surfaces

A grade a reader cannot reconcile with the number printed beside it is worse
than the uncapped grade was. So the reason is printed by the text report, the
HTML report (where the badge colour follows the cap rather than the score, since
a green badge carrying the letter C is its own contradiction), the stdout
summary, and `--quiet`. `--quiet` matters most: it is one line, and one line is
where a silent cap would do the most damage, because it is the line that gets
pasted into a ticket with nothing around it. It reads `grade C CAPPED`.

The JSON emits `grade` (capped — it is what the reports print and what a CI gate
will branch on), `grade_uncapped`, and `grade_cap_reason`. A consumer gating on
an uncapped B+ while the human report said C would be the same lie in a new
place.

The reason text for c07, measured rather than quoted from a draft:

```
capped at C from B+: 1 CRITICAL finding (XF001) asserts a failure this chart
will hit, and a grade above C would contradict it. The 87.8 is unchanged - it is
a weighted count of findings across 10 scored categories, only 1 of which carries
a critical, and that dilution is exactly why the mean cannot see this
```

### A sentence explaining a cap is the last place that can afford an invented number

The first version of that string hardcoded "across ten categories, and nine of
them being clean". On any chart with an unassessed category that sentence is
simply false, and c03 and c09 both have one. The counts are now read off the
result being explained — `cov.n_assessed`, and the number of distinct categories
actually carrying a hard critical — rather than written into the prose.

### The proof

`proof/p16_gradecap.py`, 8 claims, all passing. The cap fires exactly where a
non-ASSUMED CRITICAL exists **and** the uncapped band is above C, per chart;
charts already at or below C report no cap (c02, c11); `good-chart` is untouched
and its report contains no "capped at" text anywhere; the score is identical in
the report and the JSON and the reason quotes that same number; the disclosure
reaches all four surfaces; and no corpus chart shows a grade above the cap while
asserting a certain failure.

Two things about that script are deliberate. It builds its own
`assumed_only_chart()` fixture rather than borrowing one from the corpus,
because every corpus chart that raises an ASSUMED critical also raises an
observed one, so the corpus cannot isolate the exemption — and **a claim that
cannot be isolated is a claim that cannot fail**. And its first run produced ten
failures which were all the *script's* fault: `report.py` wraps at 100 columns,
so a verbatim substring search for the reason was, in effect, asserting that the
report does not wrap. That is not the claim and is not even desirable. A
whitespace-collapsing helper fixed it, and the reasoning lives in that helper's
docstring so the next person does not "fix" the wrapping instead.

`p14_corpus.py` gained a matching claim in the other direction: a chart whose
only CRITICAL is a guess keeps its earned grade. The exemption is now asserted
rather than merely relied upon.

### The corpus, on defaults

```
c01-temurin21-pct-cpu       A-  92.9   0C 3H 3M 10L   10 categories (100 weight)
c02-8u131-inert-javaopts     C  73.8   5C 5H 4M 11L   already at C, no cap
c03-openjdk8-shellcmd        B  84.7   0C 6H 6M  9L   9 of 10 (86 weight)
c04-17-noflags-memhpa       A-  90.6   1C 2H 5M 11L   HP025 ASSUMED -> not capped
c05-11-removed-flags         C  87.3   1C 3H 5M 11L   CAPPED from B+ (JV015)
c06-helper-resources        A-  92.1   0C 3H 4M  9L
c07-xmx-over-limit           C  87.8   1C 3H 5M  9L   CAPPED from B+ (XF001)
c08-corporate-base          A-  92.0   0C 2H 6M 10L
c09-no-dockerfile           A-  92.2   0C 2H 5M 10L   9 of 10 (92 weight)
c10-statefulset-distroless  A-  92.6   0C 3H 5M  8L
c11-pct-on-java8             C  75.4   5C 4H 5M 11L   already at C, no cap
c12-no-mem-limit             C  86.5   2C 3H 4M 10L   CAPPED from B (HP050)
c13-unsized-sidecar          C  83.8   1C 5H 7M 12L   CAPPED from B (RS001)
c14-resources-in-overlay     C  80.9   3C 4H 4M 10L   CAPPED from B- (HP022, RS001)
c15-tiny-heap-big-limit      A  93.7   0C 2H 4M 10L
```

### The honest loss

The cap is coarse. It says "not above C" and nothing finer; a chart with one
critical and a chart with five both land at C on the letter, and only the number
beside it separates them. That is a deliberate trade — the alternative is a
second scale that would need its own justification — but a reader who wants to
rank two failing charts must read the score, not the grade, which is the inverse
of the usual advice.

### Also discovered, queued

* **HPA scores 94.0 / A at weight 15 on charts with no HPA at all.** The
  category is not empty — HP002 fires and deducts — so R11's and R13's remedy
  (drop it from the denominator) would delete a real deduction, which is the R8
  fault pointing the other way. It needs a different answer from the two this
  project has already used, and it did not get one this round.
* **AV010, SC001, SC002, PB004 and PB005 fire on nearly every corpus chart**,
  which makes them close to a constant offset rather than a discriminator. They
  are true on c01 as well, so part of this is a corpus-design artefact and not a
  calibration fault; separating the two requires charts written to pass them,
  which the corpus was not built to do.
* Everything still queued from R10 and earlier: `--cross-check`
  non-determinism, the external tools' versions still absent from the report,
  cluster-facts ingestion, Java version detection from `pom.xml` / `build.gradle`,
  R9's bands having no confidence axis, `--measured` asking the wrong actor, R7's
  unmerged subchart values, `_table`'s mid-word breaking, PB003, and
  `_last_summary_line` being used for helm lint.

---

## R14b — A gate that deleted real deductions, and the check that let it

### The defect

R13 added a coverage gate: if no JVM container sets `limits.memory`, the CROSS
category cannot deduct, so drop it from the denominator. That is right, and the
implementation reads only the **base** context.

`engine.analyze()` does not stop at the base context. `_overlay_variants()` runs
the workload checks, the HPA checks and the proofs against every values overlay
and merges the new findings back in. `fixtures/bad-chart` sets no memory limit in
`values.yaml` and a 4 GiB one in `values-prod.yaml`, where XF001 and XF003 both
fire at CRITICAL.

So the gate declared "not assessable" about a category holding two criticals,
and removed fourteen weight points of **real deductions** from the denominator
those points had already been subtracted from. The score of a chart with two
critical cross-file faults went **up**. This is the R8 fault inverted: not a
clean category scored 100, but a dirty category scored nothing at all.

It was found by three unit tests failing after R13 and R14 went in — that is,
by a fixture's score moving for no reason anybody could name, which is exactly
how the next one will be found if the backstop below is not there.

### The authority

`scoring.py`'s own framing, sharpened. A gate answers "*could* this category
have deducted?" — a prediction. The findings answer "*did* it?" — a measurement.
Where they disagree, the measurement wins.

### The fix, in two layers

**The gate learns about overlays.** `proofs._overlay_sets_mem_limit()` scans each
overlay's raw values for anything shaped like `{"limits": {"memory": ...}}`. It
is a structural walk rather than a path lookup, because `resources` is not at a
fixed key — charts nest it under the component name, under `global`, under a
list of sidecars. Re-rendering each overlay here would duplicate the engine and
cost a helm invocation per overlay. A false positive only keeps a category *in*
the score, which is the direction that cannot invent a clean bill of health.

**`coverage()` carries a backstop.** A category that lost points was assessed,
whatever any gate believes, so no category with a nonzero deduction may be
dropped from the mean those points were subtracted from. It is a backstop over
`unassessed_reason()`, not a substitute for it, and it exists because the gates
keep getting this wrong in one specific direction — three rounds running.

### The disagreement is never silent, and never charged to the user

When the backstop overrides a gate, `_warn_gate_contradiction()` prints to
stderr, once per distinct contradiction per process, so a sweep over fifteen
charts does not print the same tool bug fifteen times.

It goes to stderr and it does **not** become a `Finding`. Deducting points from
somebody's score because the tool contradicted itself would be the tool charging
the user for its own bug. stderr is visible to whoever runs the tool and invisible
in the report they hand to somebody else, which is exactly the right audience for
"hpa-analyzer has an internal inconsistency, please report it".

Silence was the alternative and is worse: a silent backstop papers over gate
bugs forever, and the next one gets found the way this one did.

### The first draft of the backstop was wrong, in the way this log always records

It keyed on "the category produced a finding". Five more tests broke. DF000 is an
INFO worth zero points whose entire job is to report that no Dockerfile was
found — a coverage statement, firing precisely on the charts where DOCKERFILE
genuinely cannot be assessed. Keying on findings kept DOCKERFILE in the
denominator at **100.0 / A+ on a chart with no Dockerfile**, which is the exact
fabrication `scoring.py` forbids, reintroduced by the fix for its inverse.

The invariant is narrower and exactly right: **deducted from**, not "has a
finding". `f.effective_deduction() > 0`.

### The proof

`tests/test_score_coverage.py` gains `TestGateCannotDeleteDeductions`, three
tests: bad-chart keeps CROSS because an overlay deducts from it; a gate that
lies about RESOURCES is overridden *and* announced, with stderr captured and
asserted to name the rule id; and a zero-point finding does not force a category
back in, which pins the DF000 mistake so it cannot return as a simplification.

458 tests and 40 subtests pass. All 28 proof scripts, p1 through p16, exit 0
with no `[FAIL]` line; p14, p15 and p16 each report ALL CLAIMS PASS.

---

## R15 — Six flags the tool accepted and four of them it then ignored

### How it was found

By the only method that has ever worked here: running the thing. The corpus grew
from fifteen charts to thirty (`proof/corpus_charts.py`), and
`proof/p17_flagmatrix.py` was written to run all thirty plus both fixtures across
the whole flag surface — `--kube-version`, `--assume-java`, `--measured`,
`--values`, `--json`, `--html`, `--quiet`, `--check`, `--cross-check` — and
compare the outputs to each other rather than to a stored expectation. Comparing
runs to each other is the part that mattered. Four of the six defects below are
invisible in any single report, because a single report of a flag that did
nothing looks exactly like a report of a flag that worked.

### D1 — `--kube-version` never reached the ranking it exists to inform

`c16` and `c17` carry the same deprecated `apiVersion`s. Run at
`--kube-version 1.20` and at `--kube-version 1.31`, the two runs of c17 were
byte-identical in outcome:

```
--kube-version 1.20.0 ->  91.7 / 100  A-   TP010 LOW, TP010 LOW
--kube-version 1.31.0 ->  91.7 / 100  A-   TP010 LOW, TP010 LOW  ("Nothing breaks today")
```

`extensions/v1beta1 Ingress` was removed in 1.22. On a 1.31 cluster this chart
does not install. The tool said "Nothing breaks today" because it ranked the
finding against the chart's own `kubeVersion: >=1.19.0-0 <1.21.0-0` and never
looked at the flag — in the same report where helm had *already refused the
chart* against 1.31 and said so twelve lines further up.

The mistake underneath is a category error about what the two numbers are. A
chart's `kubeVersion` is a **claim the chart makes about itself**. `--kube-version`
is a **statement about the world**, made by the person who can see the cluster.
When they disagree the chart is the thing that is wrong, and the tool was
resolving the disagreement in favour of the file.

`_Scope` in `checks_chart.py` resolves it the other way and says so rather than
switching silently:

```
The chart's own kubeVersion (>=1.19.0-0 <1.21.0-0) does not admit 1.31, so helm
will refuse to install it there until that constraint is corrected - but the
constraint is the chart's opinion of your cluster, and you have stated
otherwise, so this finding is ranked against the cluster.
```

```
--kube-version 1.31.0 ->  89.5 / 100  C    TP010 CRITICAL, TP010 CRITICAL
```

### D2 — `--assume-java` manufactured a JVM

`c24-not-java` is nginx. Run with `--assume-java 17` it moved JAVA and CROSS
**out** of the unassessed list, filed JV021 and JV026 against nginx, and the
score went **up**, from 85.4 to 87.8, because two categories full of nothing
joined the mean at their starting 100.

`--assume-java 17` states a version. It does not state the existence of a
runtime, and the tool read it as both. `discovery.py` now applies the assumption
only where a JVM is evidenced — by the Dockerfile, or anywhere in the chart's
containers — and where it is not, records in coverage why the flag was declined
rather than obeying it:

```
--assume-java 17 NOT applied: no JVM is evidenced anywhere in this chart ...
The flag states a version, not the existence of a runtime - Java checks stay
unassessed rather than being scored against a JVM that is not there
```

c24 with the flag is now identical to c24 without it: `85.4 C`, `unassessed =
['JAVA', 'CROSS']`, zero JV and zero XF findings. This is the R8/R11/R13/R14b
fault family again, arriving from a new direction: not a gate that scored an
empty category, but a flag that filled one.

**The first fix was half a fix, and the test found the other half.** The "NOT
applied, and here is why" note is written by `discovery._load_dockerfiles`,
which does not run on a chart with no Dockerfile — so a chart whose JVM-ness is
decided entirely from the pod spec printed `Java / JVM checks: NOT RUN` and said
*nothing whatever* about the flag the operator had just passed. Silence about a
discarded input is indistinguishable from having honoured it, which is the
sentence this whole iteration is about. `ChartContext` now records what the
operator **typed** separately from what was **applied** — two different facts,
only one of which was being stored — and `checks_docker._no_jvm_evidence` names
the declined flag.

### D3 — the HTML headline rounded across a grade boundary

```html
<div class=grade>A-<span>93/100</span></div>
```

for a chart the text report scored 92.9. 93 is exactly the A threshold, so the
first thing a reader saw was a document disagreeing with itself about which
grade it had just awarded. `{score:.0f}` — and the per-category cells directly
below that badge had always rendered one decimal, so the rounding was not even
internally consistent. A grade boundary is a cliff and no display convention
gets to round a number across one.

### D4 — a workload-kind filter doing coverage's job

`proofs._pairs()` only considered Deployment, StatefulSet and DaemonSet. Any
chart whose workload is a Job, CronJob or Argo Rollout got no JVM footprint
proof, no heap-versus-limit arithmetic — and Cross-File Consistency still scored
100.0 / A+ at fourteen weight points, because a category with no findings looks
identical to a category with nothing wrong.

```
c22-cronjob-hpa    A   95.9    Cross-File Consistency | 100.0 | A+ | 14
                                Scored over all 10 categories (100 of 100 weight)
```

c22 sets `-Xmx6g` under a `4Gi` limit. It is a guaranteed OOM kill and the tool
gave it an A.

This is **the fourth time** this project has shipped this exact fault — R8
(Dockerfile), R11 (helper-supplied resources), R13 (CROSS with no limit), and
now a kind filter. It keeps arriving because a filter and a gate are the same
line of code from the inside; the difference is only whether anything downstream
knows the skip happened. The filter now admits every kind that can carry
containers, and `c22` grades `C 88.6` with XF001 CRITICAL.

### D5 — `scaleTargetRef.kind` was never compared to anything

c22's HPA targets a `batch/v1` CronJob. A CronJob has no `scale` subresource; the
controller reports `FailedGetScale` and never scales anything, ever. The tool
resolved the target **by name**, found it, and printed a full scaling table
describing behaviour that cannot occur.

The gap was never parsing — HP041 already proves name resolution works, and
catches c27's case mismatch. The `kind` was simply never looked at. HP042 fires
CRITICAL for the four kinds that provably cannot scale, and the scaling table
stops pretending:

```
[INERT: target CronJob cannot be scaled]
NONE OF THIS HAPPENS. The scaleTargetRef names a CronJob, which has no `scale`
subresource, so the controller reports FailedGetScale and never acts on any row
above (see HP042). The table is retained to show what the declared thresholds
WOULD have meant, and for no other purpose.
```

An unrecognised kind still gets no finding. Argo Rollouts, KEDA ScaledObjects and
any number of CRDs implement `scale` correctly, and withholding a claim never
becomes asserting one.

### D6 — remediation advice written without reading argv

The helm-refusal paragraph had one canned sentence, and it was wrong in two
different ways at once. It explained every refusal as a `kubeVersion` problem,
including c20's, which fails on `image.tag must be set for this chart`. And it
interpolated the run's own `--kube-version` into its example, so a run invoked
with `--kube-version 1.31.0` ended by advising its operator to re-run with
`--kube-version 1.31.0`.

Advice that does not read the arguments it is advising about is not advice. The
paragraph now branches on the actual helm message and on whether the flag was
supplied:

```
That is not a kubeVersion problem - the message above names the actual cause.
Reproduce it directly with `helm template release-name <chart>` and fix what it
names; no flag of this analyzer will change it.
```

### The authority

Bar 2 throughout — a tool that holds the facts and does not reach the conclusion
has not done what it is for — plus one addition this round makes explicit: **a
flag the tool accepts is a promise it will act on it.** Accepting `--kube-version`
and ranking against the file, or accepting `--assume-java` and inventing a
runtime, is worse than rejecting the flag, because the operator has no way to
tell from the output that their input was discarded.

### The proof

`proof/p17_flagmatrix.py`: 69 claims over 32 charts and the full flag surface,
0 failures. Three of those claims were themselves wrong first and are recorded in
the script rather than quietly repaired — a conflict check that passed because
the tool echoed the flag back ("a check that passes because the tool repeated my
own argument to me is not a check"), an advice-loop check that could not match
because the report hard-wraps at 100 columns and the wrap fell mid-sentence, and
a coverage claim that demanded a heap finding from a chart that sizes its heap
correctly.

`proof/p14_corpus.py` was repaired the same way. Its `len(made) == 15` was a check
testing the author's memory; two more demanded a score line from every report,
which c21 — an umbrella chart with no renderable workload — correctly declines to
produce. Demanding a number there would have been demanding the one behaviour
`scoring.py` exists to forbid. The claims now read "either scores or says NOT
GRADED, and says why".

`tests/test_r15_flags.py` pins all six as unit tests — eighteen of them, each
comparing two runs that differ only in the flag, because that is the only shape
that catches a flag doing nothing. Three are negative controls: no flag still
believes the chart's `kubeVersion`; `--assume-java` still works where a JVM *is*
evidenced; and an unrecognised `scaleTargetRef.kind` still gets no finding.
Writing them found the half-fix recorded under D2 above.

476 tests and 40 subtests pass. All 29 proof scripts exit 0.

## R16 — Fifteen weight points of A+ for a question the tool never asked

### How it was found

Not by reading the code, and not by looking for this. The round opened on a
different complaint, and one that is still arguable: `Horizontal Pod Autoscaling`
carries weight 15, and a chart with **no autoscaler at all** scores that category
94.0, an A, because HP002 is a single MEDIUM. Measured over the thirty-five-chart
corpus:

```
100.0  x1   (fixtures/good-chart, and it was written to)
 97.0  x12  (HP030 - no behavior block - fires on 25 of the 26 charts with an HPA)
 94.0  x6   (every chart with no HPA object at all)
 85.0  x2      72.0  x9      41.0  x1      20.0  x1
```

Absence of the entire feature outranks fourteen of the twenty-six charts that
implement it. That is a calibration argument, it is arguable in both directions,
and it was deliberately **not** changed — see "What was left alone" below.

Underneath it was something not arguable. `checks_hpa._no_hpa()` opened:

```python
scalable = [w for w in workloads
            if (w.kind or "").lower() in ("deployment", "statefulset")]
if not scalable:
    return
```

A bare `return`: no finding, and — because nothing else in the tool asks the
question — no coverage note either. `scoring.unassessed_reason()` drops HPA only
when **no** Kubernetes objects were parsed at all. Objects were parsed. So the
category counted as assessed, held zero findings, and a category with zero
findings scores 100.0.

One chart per workload kind, differing only in `kind:`, the apiVersion that kind
requires, and the spec fields that apiVersion makes mandatory:

```
kind                    HPA cat   HPA findings   assessed weight
Deployment                 94.0   ['HP002']              64
StatefulSet                94.0   ['HP002']              64
ReplicaSet                100.0   []                     64
ReplicationController     100.0   []                     64
DaemonSet                 100.0   []                     64
CronJob                   100.0   []                     64
Pod                       100.0   []                     64
Rollout                   100.0   []                     64
```

and on six of those eight the scorecard printed:

```
| Horizontal Pod Autoscaling             | 100.0        | A+    | 15   |
```

which is the first entry on `scoring.py`'s own list of forbidden fixes, arrived
at from the other end: *"Score an unassessed category 100: invents a clean bill
of health for something never looked at."* The tool had been writing the fixes it
forbids, in the one number people read first, for fifteen rounds.

This is the same fault as R8, R11, R13, R14b and R15's D4 — one `if` deciding
both which findings to emit **and** whether the category was assessed. Sixth
instance. That is no longer a bug, it is a shape, and it is the shape to grep for
in any tool that both scores and explains.

### Three defects, not one, and they need three different fixes

The eight rows above do not all fail for the same reason, and the first draft of
this round treated them as if they did.

**(a) ReplicaSet, ReplicationController — a copy of a list, and the list rotted.**
Both implement `/scale`. Both are in `kube.SCALABLE_KINDS`, which is the tool's
own written statement of exactly that. `_no_hpa()` re-typed two of the four
inline and dropped the other two. HP002 is precisely the finding for these charts
and they got silence.

The correction that matters here, because the first fix was not enough:
swapping in `SCALABLE_KINDS` recovered ReplicaSet and **not**
ReplicationController.

```
kind                    HPA findings   HPA score
ReplicaSet              ['HP002']           94.0
ReplicationController   []                 100.0
```

The list `_no_hpa` was handed is `ChartContext.workloads`, whose own literal has
never mentioned ReplicationController — so the document was filtered out one
level **above** the bug being fixed, and fixing the copy inside the function
could not reach it. Two copies of the same wrong list, in series. The input is
now `kube.scale_candidates(ctx.docs)`, which reads the level below both.

**(b) DaemonSet, Job, CronJob, Pod — the only new idea in the round.** These
genuinely cannot be autoscaled, and `kube.UNSCALABLE_KINDS` already held a
written reason for each. Silence on the **findings** axis is correct and always
was: telling an operator to put an HPA on a DaemonSet is worse than saying
nothing. Silence on the **scoring** axis is not, because fifteen weighted points
of A+ were being awarded for it. Filing it as unassessed would also be false —
the tool was not blind, it read the object and holds the answer.

So there is now a third coverage state, **NOT APPLICABLE**, arithmetically
identical to NOT ASSESSED (the category leaves the mean, numerator and
denominator together) and semantically its opposite. The discriminator, written
into `scoring.not_applicable_reason`:

> Can the tool state, from evidence it HOLDS, that the category's subject cannot
> exist for this chart? Then NOT APPLICABLE. Did it merely fail to FIND evidence?
> Then NOT ASSESSED.

The difference is not decorative — it is the difference between an instruction
and a fact. NOT ASSESSED tells the reader to go find an input. NOT APPLICABLE
tells them not to bother, and the reason string says so in as many words: *"no
change to the chart would create one."*

**(c) Rollout — the answer neither of the above supplies.** An Argo `Rollout`
**does** expose `/scale`, so HP002's subject exists — but this tool's kind lists
have never heard of it, and concluding "that CRD cannot autoscale" from a set
that does not mention it invents the answer just as surely as scoring it 100 did.
What the tool actually has here is ignorance of a specific, nameable kind. That
is NOT ASSESSED, and the reason string names the kind so the reader can settle it
in the ten seconds it takes:

```
this chart deploys no built-in scalable workload, and whether Rollout implements
the scale subresource is not something this tool knows; it is not scored either
way
```

The fact underneath all three was never two-valued. `kube.scale_class` now
returns `scalable` / `unscalable` / `unknown`, and each of the three routes
somewhere different.

### The negative control, which is the whole reason condition 1 exists

The failure mode of a fix like this is not that it stops working — it is that it
starts working everywhere. A predicate keyed on workload kind alone would drop
HPA from the mean on `c22-cronjob-hpa`, a corpus chart that ships a CronJob
**and** an HPA pointed at it and deducts a CRITICAL 25 points for it. Dropping a
category that has just deducted twenty-five points is **the R14b bug, re-committed
one round after it was fixed**, and the R14b backstop would have caught it and
printed an internal-inconsistency warning — which is not the same as not writing
it. Relying on a backstop to cover a bug you can see from where you are standing
is not engineering.

`not_applicable_reason` therefore refuses to fire at all when the chart contains
an HPA object, before it looks at a single workload kind. The new gate is
nonetheless routed through the same R14b backstop as the old one, and the comment
says why: *a backstop that only guards the gates you already distrust is not a
backstop.*

### Two properties where there was one

`Coverage` gained a third field rather than a flag on the entries of
`unassessed`, because every consumer reading that list today is enumerating the
tool's **blind spots**, and quietly widening it would have filed a category the
tool answered completely under a heading it had just disproved. New meaning, new
field; the old field keeps its old meaning exactly.

`complete` likewise keeps meaning "no blind spots", and `--require-coverage`
still gates on it. This is deliberate and it is the point of the round: a build
that failed on a DaemonSet chart would be the gate demanding the user add an
autoscaler to a DaemonSet, which is the advice this entire round exists to stop
the tool giving. `all_scored` is the new, narrower claim — that the mean really
did run over all ten categories — and it is what the reports and the badge use.

### What was left alone, on purpose

The 94.0 for a chart with no HPA. It is a calibration argument with two sides,
this round produced no measurement that settles it, and changing a weight because
a distribution looked wrong is how a scoring model stops meaning anything.

Three further inline copies of `("deployment", "statefulset")` in
`checks_hpa.py`. They are copies of the same rotted list — but unlike the one in
`_no_hpa` they decide which **findings** are emitted rather than whether the
category counts, so widening them moves scores on charts nobody has measured.
They are annotated in place so the next round measures them rather than
discovering them.

`SCALE_CANDIDATE_KINDS` deliberately does **not** match `ChartContext.workloads`.
It adds `replicationcontroller` and `pod`, which are exactly the subject of the
scale question and which that property does not return. Widening `workloads`
itself would change the input set of every pod-level rule in the tool — probes,
resources, security, the lot — and this round measured none of that.

### The proof

`proof/p18_notapplicable.py`: seven claims over nine charts that differ only in
workload kind, with the expectations written as data **before** the runs so they
are a specification and not a transcription. All pass. The state table it now
produces:

```
kind                    HPA state         scorecard cell  rules
Deployment              scored                      94.0  ['HP002']
StatefulSet             scored                      94.0  ['HP002']
ReplicaSet              scored                      94.0  ['HP002']
ReplicationController   scored                      94.0  ['HP002']
DaemonSet               not_applicable    not applicable  []
Job                     not_applicable    not applicable  []
CronJob                 not_applicable    not applicable  []
Pod                     not_applicable    not applicable  []
Rollout                 unassessed          not assessed  []
```

Two of that script's own checks were wrong first and are recorded in it rather
than repaired quietly. Its score column read `data["categories"]`, a JSON key
that does not exist, and printed `None` for all nine rows without failing — the
assertion beside the table did not depend on it. A column that silently prints
None for every input is indistinguishable from a fix that works. It now reads the
rendered scorecard cell, which is both real and better evidence, since the string
`| Horizontal Pod Autoscaling | 100.0 | A+ |` is the thing being disproved. And a
check reading `complete is False or True` — true of every input, asserting
nothing — was deleted rather than fixed, because a green line reading "nothing
was skipped" is worse than no line: it would have gone on passing through a
regression that failed `--require-coverage` on every DaemonSet chart.

**Blast radius, measured rather than argued.** Thirty-five corpus charts plus
fixtures, run against `git archive HEAD` and against the working tree with the
same chart generator on both sides: **0 of 44 targets moved.** Not one score,
grade, weight, per-category value or rule-id set changed anywhere. That proves
the fix is surgical, and it proves something less comfortable — the corpus
contains no chart whose only workload is unscalable, which is exactly why this
survived fifteen rounds of a tool built to find things like it. A corpus is a
sampling method, and a sampling method has blind spots that no amount of running
it will reveal.

`tests/test_r16_notapplicable.py` pins twenty-five cases: the three answers of
`scale_class`; each kind's resulting state; that the two exclusion reasons make
different claims; the four negative controls (unscalable **with** an HPA stays
scored and the deduction reaches the score; predicate and gate agree so the
backstop is unnecessary rather than merely unfired; one scalable object among
four unscalable ones keeps the category real; a chart with no objects at all is
blindness, not inapplicability); and the rendered artefacts, because an exclusion
that were true only inside the data structure would have fixed nothing.

One of those tests caught a bad **fixture** while asserting correct behaviour of
the code, which is the only way round that is worth anything. `only_hpa_excluded`
was first built by dropping a Dockerfile beside the DaemonSet chart, on the
reasoning that DOCKERFILE was the missing input; running it printed
`unassessed: ['JAVA', 'CROSS']`, so `complete` was False for two reasons that
predate R16 and every assertion built on it was measuring something other than
what its name said. Recorded in the file rather than corrected in silence.

**Eight documentation figures moved and none of them is a regression.** Every
report grew by exactly four lines and 388 bytes, because the scoring-model footer
gained a paragraph explaining the new state and that footer documents the model,
not the run. `diff` between the pre-R16 and post-R16 report of `fixtures/bad-chart`
is those four lines and nothing else. `docs/usage.html`, `docs/reference.html`,
`docs/container.html`, `docs/DOCKER.md` and `README.md` were re-measured — the
helm-less set on a `PATH` with no helm binary, which is a different thing from
`--helm off` — and `proof/p11_docsite.py` is green again at 179 checks.

501 tests and 40 subtests pass. All 30 proof scripts exit 0.

---

## R17 — One list, re-typed eight times, and the copies stopped agreeing

### How it was found

By keeping a promise. R16 fixed one inline `("deployment", "statefulset")` and
wrote next to the others: *"they are annotated in place so the next round
measures them rather than discovering them."* That is a defensible place to stop
a round and a terrible place to leave a codebase, because an annotated defect and
an unknown one score the same on every chart anybody runs.

So R17's first act was not a fix. It was one chart per workload kind — identical
in every byte but the `kind:` line, the apiVersion that kind requires, and the
fields that apiVersion makes mandatory — each carrying `replicas: 3` in the
template and an HPA whose `scaleTargetRef` names that same object. Every one of
them is the same mistake: helm and an HPA both writing `spec.replicas`, which is
`HP050`, a `CRITICAL`.

```
kind                    before R17          after R17
Deployment              85.5  C  HP050      85.5  C  HP050
StatefulSet             85.5  C  HP050      85.5  C  HP050
ReplicaSet              92.5  A- (silent)   85.5  C  HP050
Rollout                 92.1  A- (silent)   85.5  C  HP050
ReplicationController   NOT GRADED          85.5  C  HP050
```

Seven points and four grade bands between two spellings of one mistake. And the
`A-` is worse than the seven points make it look. `HP050` is `CRITICAL`, and
since R14 a non-`ASSUMED` critical caps the **overall** grade at `C` — so what
`ReplicaSet` and `Rollout` escaped was not primarily a deduction, it was the cap.
The tool's loudest signal, the one deliberately built to be un-diluteable by a
weighted mean, switched off by a missing word in a tuple.

`ReplicationController`'s row is a different failure again, and a more
interesting one. It was not scored high and it was not scored low — it was not
scored. `ChartContext.workloads` filters **first**, and its literal had never
contained `"ReplicationController"`, so the document was gone before any rule
saw it. `discovery`'s F9 then observed templates present and zero workloads, set
`ungradeable_reason`, and the report printed `NOT GRADED`.

That output is not dishonest. The tool did not claim a pass. But the reader
cannot tell *"this chart has no workload"* from *"this chart has a workload of a
kind I do not recognise"*, and those two call for opposite responses — the first
means fix your chart, the second means fix the tool. Meanwhile
`kube.SCALABLE_KINDS` has listed `ReplicationController` as a first-class
scalable workload since R16 and `scoring` scored its HPA category the whole time,
so the tool held two contradictory opinions about whether the object existed and
never noticed, because nothing in it compares the two lists.

### Eight sites, and they do not all want the same answer

The seventh instance of this fault family — after R8's `DOCKERFILE`, R11's
`RESOURCES`, R13's `CROSS` gate, R14b's gate that deleted real deductions, R15's
`proofs._pairs()` filter and R16's `_no_hpa` — is not one bug with eight copies.
The first draft of this round assumed it was, and the correct move was to stop
and ask each site what question it was actually asking. There turned out to be
three questions, and collapsing them would have re-introduced the exact advice
R16 spent a round removing.

**Can an HPA target this?** That is `/scale`, and it is `SCALABLE_KINDS`.
`Rollout` is out (the tool does not know whether that CRD implements the
subresource, which is why R16 built the `unknown` answer).

**Is the scale question even meaningful here?** That is `SCALE_CANDIDATE_KINDS`,
and it deliberately **includes** `DaemonSet` — precisely so R16 can answer "not
applicable" instead of scoring silence 100.

**Does this object carry a replica count the chart author chose?** Nothing named
this, and it is the question all five inline pairs were actually asking:

```
HP050/HP051   helm and an HPA fighting over spec.replicas
AV001         replicas: 1 with no HPA is zero redundancy
AV002/AV003   rollout strategy and pod spreading
AV010         a PDB protects a replica set from voluntary disruption
```

That is `kube.REPLICA_MANAGED_KINDS`, new this round. `Rollout` is **in** it and
in neither of the others: an Argo `Rollout` has `spec.replicas`, is routinely
paired with an HPA, and `helm upgrade` resets that field on it at exactly the
moment it does on a `Deployment`. `DaemonSet`, `Job`, `CronJob` and `Pod` are
**out** and it is not an oversight — a DaemonSet's count is a property of the
cluster, a Job's parallelism is fixed at creation, and a bare Pod is one pod.
Telling any of them to raise their replica count or add a PDB is the
DaemonSet-autoscaler advice R16 removed, wearing a different rule ID.

Three sets, three memberships, no two identical. `kube.py` says so at the
definition, because the next person to see three overlapping sets will want to
tidy them into one.

### The eighth copy was R15's own fix

The last site was not on R16's list of five, and finding it is the part of this
round worth generalising from. `proofs._pairs()` — the function R15 fixed, for
exactly this fault — contained:

```python
if (doc.kind or "").lower() not in (
        "deployment", "statefulset", "daemonset",
        "replicaset", "job", "cronjob", "rollout"):
    continue
```

Read the literal. It is precisely the contents of `ctx.workloads` at the moment
R15 was written, retyped by hand. R17 added `ReplicationController` to
`ctx.workloads`, and this line went stale **the same day**, silently, in exactly
the manner its own comment above it describes. A fix for a class of bug,
implemented as another instance of that bug, broken within one round by the round
that was hunting it.

Measured on two charts identical but for `kind:`, each a `temurin:21-jre` asking
for `-Xmx6g` under a `4Gi` limit:

```
Deployment              C   88.9   XF001
ReplicaSet              C   88.9   XF001
ReplicationController   A-  92.7   (none)
```

The tuple is **gone** rather than corrected. A filter whose only effect is to
re-state its own input, minus whatever the author forgot, is not a filter.
`ctx.workloads` *is* the set of kinds that run containers, `kube.pod_spec()`
already unwraps every one of them, and there is nothing left at that line to
decide. A copy that does not exist cannot rot.

### The site that was left alone, and why that is a result

One of the eight is still there, and this is the part that is easy to fix and
wrong to. `_replicas_conflict`'s nested `_single_obvious_target` helper contains
the same pair, and **two constructed attempts failed to reach it**.

The first used a `scaleTargetRef` of `{{ .Release.Name }}-x`, which survives
static parsing as a resolvable literal, so `any_literal_mismatch` returned False
three lines earlier. The second named a `_helpers.tpl` include, which the static
parser rewrites to `HELM_TPL_n` — and the loop above matches anything starting
with `HELM` and returns True before the branch is consulted. Five charts
differing only in a second workload's kind emitted identical `HP050` under both
probes. The branch is reachable only when the ref name contains `<` and does not
begin with `HELM`, a parser state neither probe produced.

Changing an unreached predicate is not a fix. It is a guess with a diff attached,
and this entire fault family exists because somebody once made exactly that edit.
So the line stays, with the failed measurements written at the site — and with
the one thing the measurement *did* establish: this site is a **count used as a
confidence test**, not a filter, so widening it would make `HP050` fire **less**.
That is the opposite direction from the site forty lines below it, which is the
concrete reason "replace all eight with one set" would have been wrong.

`proof/p19_replicamanaged.py`'s CLAIM 5 backs this with a line tracer rather than
an argument: fourteen targets traced, `checks_hpa.py:751` executed **0 times**.

### Two strings that were quietly lying

`HP050`'s title was the fixed noun `"Rendered Deployment sets spec.replicas
while an HPA manages it"`, sitting above a detail line that already interpolated
`w.kind`. The moment the loop reached `ReplicaSet` and `Rollout`, that title
would have printed `Deployment` over a finding whose own next sentence said
`Rollout` — and a reader who greps their templates for a Deployment, finds none,
and concludes the tool is broken has been failed by a formatting decision, not a
rule.

`AV010`'s detail was `"Chart ships Deployments/StatefulSets but no PDB."`, naming
two kinds the chart might contain neither of. It now names what is actually
there: on a two-kind chart, `"Chart ships Deployment, StatefulSet but no PDB."`

Neither is scored. Both are the report claiming to have seen something it did
not, which is the same species of defect as the rest of this round in the only
place the user actually reads.

### The blast radius, measured

Fifty targets — the thirty-five-chart corpus, both fixtures, and six synthetic
one-workload charts differing only in `kind:` — run against `git archive HEAD`
and against the working tree, same machine, same chart generator feeding both
sides:

```
identical in every measured field       9
AV010 detail string changed, nothing else   38
score / grade / rules moved             3
```

The three that moved are the synthetic `ReplicaSet`, `ReplicationController` and
`Rollout` charts, which is precisely what the round set out to fix.
`ReplicaSet` gained `HP050` + `AV003` + `AV010`; `Rollout` gained only `HP050` +
`AV010`, because `_availability` had already been individually patched for
`Rollout` at some point while `_pdb` had not — the divergence of the copies,
visible in the diff of a sweep; and `ReplicationController` gained ten rules,
because it was not being looked at at all. `DaemonSet` did **not** move, which is
the negative control: the fix reaches the kinds that manage replicas and stops at
the kinds R16 taught the tool to leave alone.

**Zero corpus charts moved in score.** That is the fix being surgical, and it is
also the corpus admitting something: the `proofs._pairs()` deletion moved nothing
across all fifty targets, because not one of the fifty is both a
`ReplicationController` *and* a JVM chart. The two-chart probe above is the only
thing that measures that edit. A corpus is a sampling method, and this is the
second consecutive round where the thing being fixed was invisible to it.

### Two of this round's own checks were wrong, and one of them could not fail

**A documented figure had rotted by 344 bytes, and the check on it was green the
whole time.** `docs/container.html` quotes two byte figures — the helm-mode one
(`N bytes either way`) and the helm-less one (`(N bytes)`) — and
`proof/p11_docsite.py` checked whichever one matched the host it happened to run
on, an `if/else` on `HAVE_HELM`. Every machine this project has run on except one
has helm. So the helm-less figure was checked exactly once, on the second machine
that ever produced it, and never again; the page said `63410` while the real
helm-less report had grown to `63754`.

A check that only runs on a machine nobody uses is the same species of defect as
R16's unasked question: the tool was not wrong, it just never looked. Both
figures are now measured on **every** host. Helm-mode still needs helm and there
is no honest way to synthesise it without one. Helm-less needs the opposite, and
that *is* synthesisable exactly — build a `PATH` of symlinks to every executable
currently on `PATH` except `helm`. Notably **not** `--helm off`, which produces a
different report (`63570` here, 184 bytes short) because it says "helm is
installed but was not used" where the absent-helm run says "helm is not on PATH".
The page's claim is about the second one, so the second one is what gets built.

**The other three figures moved for a reason that is not a bug, and it took
arithmetic to establish that.** The helm-mode figure went `63092` → `63078`, and
`63092` was suspiciously exactly the old number. The report's `Generated :`
line is normalised before measuring, from 38 characters to 24 — a fixed 14-byte
reduction, fixed because the timestamp is fixed-width. `63092` was the R16-era
*normalised* figure recorded in the wrong column, and R17's `AV010` change
happened to remove exactly 14 bytes as well. Two 14s, one a constant of the
measurement and one a coincidence of the diff. Confirming that rather than
accepting the tidy-looking equality is the only reason it is written down here.

**Expectation E4 in the blast-radius sweep was refuted by its own run — and
contradicted E5 three lines below it.** E4 said "no target gains or loses a
finding ID"; E5 explicitly predicted the synthetic kind charts would gain
findings. Both were written before the first run, in the same sitting. That is
not the measurement finding something surprising, it is the expectations being
internally inconsistent, and it is recorded as an error in writing them rather
than narrowed after the fact into something the run happened to satisfy.

**And one check in `p19` could not fail.** CLAIM 5 proves the parked site is
unreached by tracing it, which requires locating the line. The first version
located it by grepping for the literal — which matched **two** lines: the code at
751, and line 73, a *docstring* quoting the old code in prose. The tracer
faithfully traced line 73, a line never executed by construction, reported zero
hits, and printed `PASS`. The underlying claim was true and the evidence for it
was worthless, and the only thing that caught it was a structural assertion
beside it that looked redundant. The site is now located with `ast`, which sees
expressions and not prose, and the failure is written at the site: *a check that
cannot fail is not a check* — which is the argument for keeping assertions that
look redundant.

### The shipped sample reports were nine months of rounds behind

Grepping for the old `AV010` string to see where else it had been published
found it in `sample_reports/`, and pulling that thread found something larger:
the four shipped samples were generated on 2026-07-19 and had not been
regenerated since, so they were missing the explanatory text added by R2, R3,
R9, R13, R14, R16 **and** R17. A prospective user's first look at this tool's
output was a report that no version of the tool would produce.

They are regenerated — deliberately on a `PATH` with no `helm` binary, because
their header carries the absent-helm wording rather than the `--helm off`
wording, and regenerating in the other mode would have made the diff about the
mode instead of about the rounds. The result is the reassuring half of this
round: **no score, grade or finding count moved in either sample.** `bad-chart`
is still `45.5 / F` with `11 critical, 11 high, 14 medium, 16 low`. Everything
in a 400-line diff is the tool explaining itself better. The samples were stale
in their prose and current in their verdict, which is the failure mode you want
if you have to have one.

One thing was noticed while doing it and is **not** fixed here: `-o report.html`
writes the *text* report to that filename. The HTML report is a separate
`--html [PATH]` flag, which `--help` does say, but a user who names their output
`.html` and opens it in a browser gets a wall of monospace. That is a real papercut,
it is unrelated to this round's fault family, and inventing a format-from-extension
rule at the end of an unrelated round is how flags acquire behaviour nobody
specified. Recorded for a round that can measure it.

### What was left alone, on purpose

Bare `Pod` is still excluded from `ctx.workloads`. A Pod has no controller, so
`AV001`'s "replicas: 1 is zero redundancy" and `AV010`'s PDB advice have no field
to point at, and every rule that reaches through `spec.template` would need a
second code path. It is a real gap. It is recorded in `models.py` rather than
half-fixed, because adding the kind and letting the pod-level rules mostly-work
is precisely the failure mode this round exists to document.

`checks_hpa.py:751`, above — unreached by two probes, annotated with both.

### Verification

`proof/p19_replicamanaged.py`: six claims, twenty-five checks, expectations
written as data above every run. All pass. CLAIM 2 is the anti-over-correction
guard — `DaemonSet`, `Job` and `CronJob` must receive **none** of
`{HP050, HP051, AV001, AV002, AV003, AV010}` — and it is the check that would
fail first if a future round tidied the three kind sets into one.

`tests/test_r17_replicamanaged.py`: fifteen tests across six classes, written as
**equality between kinds** rather than as absolute numbers, so they pin the
property (one defect, one verdict) and not this week's arithmetic.

516 tests pass. All 31 proof scripts exit 0. `proof/p11_docsite.py` is green at
180 checks with both byte figures now measurable on any host.

## R18 — Thirty-five charts, thirty-three of them the same shape

### The round did not start with a defect

R17 ended with eight sites closed and a sentence that should have been
uncomfortable: both R16's defect and R17's had been found by hand-built one-off
charts, written after someone had already guessed where to look. The
thirty-five-chart corpus — the instrument this project points at as evidence —
had been silent through both.

So R18's first act was to measure the instrument instead of the tool. Across
all thirty-five charts:

```
Deployment             33
StatefulSet             1
CronJob                 1
ReplicaSet              0
ReplicationController   0
Rollout                 0
DaemonSet               0
Job                     0
```

A Deployment monoculture. Every round that has ever claimed "thirty-five charts
agree" was claiming that thirty-three copies of one shape agree. That is not a
corpus, it is a fixture with variations in the values file, and no amount of
growing it — fifteen to thirty-two to thirty-five — changes the axis it does not
vary.

### The fix is a generator, not a chart

`proof/chartgen.py` writes charts over a space rather than one at a time:

* **Tier A** — eight kinds, one shape, nothing else varying. Every difference
  between the eight files is forced by the Kubernetes API (a CronJob's
  `schedule`, a StatefulSet's `serviceName`, a Job's `restartPolicy`), and each
  forced difference is printed next to any divergence it could explain, so
  "the CronJob scored differently" is never reported without the reason it
  might legitimately have.
* **Tier B** — a deterministic greedy pairwise covering array over six axes
  (kind × replicas × resources × heap × hpa × probes) → 45 charts, every pair of
  values from every pair of axes covered at least once. No RNG.

`proof/p20_kindsweep.py` is the instrument that runs it, and the thing that
makes it an instrument rather than a second opinion is what it is **not**
allowed to know. Two oracles:

* **O1** — a verdict field (score, grade, graded) differs from the Deployment
  variant, or a rule fires on some kinds and not others.
* **O2** — a chart was generated and the tool graded nothing, or a whole rule
  family the Deployment raised went silent, or fewer than half its findings
  appeared.

Neither contains a Kubernetes kind name, a rule ID, or a threshold copied from
`kube.py`. A test (`AT5a`) tokenizes the oracle and fails if one appears. The
oracles do not find defects; they raise **questions**, and a question is not a
defect until it is either argued away in `proof/kindsweep_expect.txt` with a
written reason or reproduced with a standalone chart and fixed.

### Two things this round got wrong, kept rather than erased

**The acceptance test was built to fail first.** Its whole claim is that the
instrument would have found the last two rounds unaided, so it runs against
`713774c` — the commit before R16 — with an **empty** expectations file, and
requires that R16's and R17's defects both reappear. The first version used one
baseline shape and `AT4` (R16's defect: a DaemonSet with no HPA scoring a free
100) did not appear, because R16's defect only exists on a chart with **no**
HPA and that baseline had one. A second baseline was added. The design changed
and the test did not, and both are recorded in `chartgen.BASELINES`.

**`AT5b` fails on every run and is supposed to.** The design fixed the
no-answer-key property over *the oracle*; the first implementation checked the
oracle **and the generator**, and the generator failed it — its prose cites
`HP050` while explaining why the `replicas` axis has a `conditional` value. A
tokenize pass proved that no forbidden name appears in generator *code*
(`AT5b-exec`, which passes). The honest reading is that the axes were chosen
with the silent-rule list in view, which makes Tier B **targeted** coverage, not
blind coverage. The response was disclosure, not deletion: `AT5a` and
`AT5b-exec` assert the property the design actually fixed, and `AT5b` is
reported `FAIL` on every run so the weaker claim cannot be quietly forgotten.
Deleting the sentence would have made the test pass by removing the admission.

### The ninth site

With an empty expectations file the sweep raised 21 questions on HEAD. Most
decomposed into rules R16 and R17 had already argued. One did not.

Two charts, container blocks **byte-identical** — a liveness probe with
`initialDelaySeconds: 5`, a readiness probe, no `startupProbe`, a JVM image with
`-Xmx6g` — differing only in `kind` and the `restartPolicy: Never` the Job
schema forces:

```
                  score  grade   PB findings      Health Probes & Lifecycle
Deployment         92.2  A-      PB004 PB005       82.0  B-
Job                94.8  A       (none)           100.0  A+
```

The Job is **strictly worse** than the Deployment — its `restartPolicy` makes a
liveness kill permanent rather than a restart — and it scored two points higher
with a perfect probe category. And the same report file contradicted itself:
line 106 printed `Health Probes & Lifecycle | 100.0 | A+`, and line 308 drew
`TABLE 3: Probe budget vs JVM startup` showing `startupProbe window: none |
liveness starts immediately`. The tool measured the problem, printed the
measurement, and scored the category as if it had not.

Cause, at `checks_workload.py:591`:

```python
if kind in ("job", "cronjob"):
    return
```

The ninth copy of the inline kind list R17 closed at eight sites — this one
uncommented, so R17's sweep of annotated sites never reached it — and the second
instance of R16's defect: **a filter written to choose findings was also,
silently, choosing the denominator.**

### Five rules, and they do not want the same answer

The wrong fix is "run the probe rules on Jobs", which replaces a false pass with
a false finding. Asked one at a time:

| rule | | for a Job or CronJob |
|---|---|---|
| `PB001` | missing readiness probe | **SKIPPED** — nothing routes traffic to a Job's pods, so readiness has no subscriber |
| `PB002` | missing liveness probe | **SKIPPED** — a wedged Job's real control is `activeDeadlineSeconds` |
| `PB003` | liveness and readiness identical | **SKIPPED** — follows from the two above |
| `PB004` | startup budget vs JVM warm-up | **RUNS** — a Job's container still starts a JVM |
| `PB005` | liveness with no `startupProbe` | **RUNS** — same, and the `restartPolicy` makes it worse |

The set that turns the first three off is `kube.BATCH_KINDS`, and it is a
**fifth** kind set because it answers a fifth question: *does this object run to
completion rather than serving traffic indefinitely?* It matches none of the
existing four — `SCALABLE_KINDS` and `UNSCALABLE_KINDS` and
`SCALE_CANDIDATE_KINDS` are about the `/scale` subresource,
`REPLICA_MANAGED_KINDS` is about `spec.replicas`, and every one of them puts
`daemonset` on the wrong side of this question: a DaemonSet is unscalable, is
not replica-managed, and **serves traffic all day**, so it needs its readiness
probe checked. Each entry carries a written reason, and a test asserts they are
non-empty, so a future kind cannot be added by someone who cannot say why.

### After

```
                  score  grade   PB findings      Health Probes & Lifecycle
Deployment         92.2  A-      PB004 PB005       82.0  B-     (unchanged)
Job                92.7  A-      PB004 PB005       82.0  B-
```

The Deployment does not move — the guard is on `batch`, so any movement there
would be a regression, not a fix.

### Blast radius, and the corpus failing to notice

All thirty-five corpus charts plus the nine fixtures, run against `HEAD` and
against the working tree:

```
MOVED:      0
UNCHANGED: 44
```

The expectation written before that run said at least one chart would move,
because the census had found a CronJob. **It was refuted, and the refutation is
the more interesting result.** `c22-cronjob-hpa` declares no probes at all — its
container has an image, an env var and resources — so the only rules that could
ever have fired on it are the three that are still, correctly, skipped. The
corpus did not merely fail to find this defect; it could not have observed the
fix either. Generated charts with probes were used to close the check instead,
and exactly the two batch kinds moved:

```
gen/Deployment  94.8/A -> 94.8/A   +-
gen/Job         96.4/A -> 95.7/A   +PB005
gen/CronJob     96.4/A -> 95.7/A   +PB005
gen/DaemonSet   95.7/A -> 95.7/A   +-
```

One more check in that script was wrong in a way worth recording: the helper
that read a category score from the JSON payload assumed
`score_coverage["assessed"]` held dicts with a `score` key. It holds bare
strings — the per-category number exists **only** in the text report. So the
check that was meant to catch "a category scored 100 while findings existed"
compared `None` to `100.0` and passed vacuously. It is left in the script,
still reported, with the replacement beside it that reads the number from the
text report where the number actually lives.

### What was dispositioned, and what was refused

Every Tier A divergence decomposes with no residue into five rules:

```
hpa-absent   CronJob/DaemonSet/Job  95.7 vs 94.8   missing AV003 AV010 HP001
             Rollout                94.9 vs 94.8   missing HP001
hpa-present  CronJob/DaemonSet/Job  92.0 vs 91.3   missing AV003 AV010 HP050
                                                   extra   HP042
```

`HP001`, `HP050`, `HP042` and both Rollout keys are argued in
`proof/kindsweep_expect.txt` and closed. `AV003` and `AV010` are **not**, and
neither is anything that sums them, which is why `O1a:DaemonSet`, `O1a:Job`,
`O1a:CronJob` and their `O2` twins are absent from that file. Both rules are
gated on `REPLICA_MANAGED_KINDS`, which is documented and deliberate — and
deliberate is not the same as correct. `AV003` asks about **pod spread**, and
for a DaemonSet the silence is definitionally right, but for a `Job` with
`parallelism > 1` the rule's own stated reason still applies and it is being
answered by a set named after `spec.replicas`. `AV010`'s eviction API honours a
PDB for any pod its selector matches, Job pods included. Neither has been
measured. Signing them off would be exactly the move this method exists to
prevent, so they stay OPEN and the sweep keeps reporting them: **16 open
questions** at the end of the round, by choice.

### Recorded, not fixed

* No rule for `activeDeadlineSeconds`, which is a Job's actual hang control and
  the reason `PB002` can be skipped honestly.
* A Job that *declares* a readiness probe deserves a "delete this" finding. It
  does not exist.
* `AVAIL` is scored 100 at weight 8 on a Job with no `AV` rule applicable. That
  is a coverage gap rather than a fabrication — a Job **can** have availability
  concerns the tool does not check — but it is the same shape as R16's defect
  and it should be answered by `not_applicable_reason`, which is still
  HPA-only.
* `kube.py` says in one comment that a Rollout "DOES expose /scale" and in
  another that the tool cannot know. Both cannot be true.
* 69 of 138 declared rule IDs fired nowhere in this sweep. Tier B did fire five
  the hand-written corpus has never reached — `HP001 JV022 JV025 PA001 RS004`.

### Verification

`proof/p20_kindsweep.py` — 6.7s, 45 Tier B charts, 8/8 kinds and every axis
value covered. `--acceptance` — 2.4s, `AT1`–`AT7`, `AT5b` failing by design.
`tests/test_r18_batchprobes.py` — 13 tests, written as **equality between a
batch kind and its non-batch twin** where the answer must not depend on the
kind, and as an explicit set difference where it must. One of them is a control
that proves the tokenizer in the test above it can still see a real regression.

529 tests pass. All 32 proof scripts exit 0. `proof/p11_docsite.py` green.

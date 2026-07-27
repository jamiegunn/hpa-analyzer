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
changed, so this is recorded here rather than numbered as R12.

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

# hpa-analyzer

A static analyzer for a directory containing a **Helm chart**, its **values
file(s)**, and — optionally — a **Dockerfile**, for a **JVM service** (any JDK
from Java 8 up). The Dockerfile is optional as of *R8*: a JVM declared only in
the pod spec (`JAVA_TOOL_OPTIONS`, a `temurin`/`corretto` image) is analyzed
just as fully, and a chart that ships a Dockerfile but runs no JVM is no
longer told about heap flags.
It writes a plain-text (and optional HTML) report scoring the chart on
HPA correctness, resource requests/limits, and — the part no other tool
does — how the JVM will actually behave inside the container's cgroup.

```bash
python3 hpa-analyzer.py ./my-service
#   GRADE F  (45.5/100)   11 critical, 11 high, 14 medium, 16 low
#   Fix first:
#     1. [HP004] HPA minReplicas > maxReplicas (invalid)  (templates/hpa.yaml)
#     2. [HP050] Deployment sets spec.replicas while an HPA manages it
#     ...
```

---

## Honest assessment — read this first

This tool was built iteratively with AI assistance and put through repeated
adversarial code review. It is genuinely useful in a narrow lane, and it is
**not** a substitute for the tools you already run. Here is the unvarnished
version.

### What it is genuinely good at

* **JVM-in-container fitness — nothing else checks this.** Applied-vs-inert
  `JAVA_OPTS` (with correct Docker exec/shell/CMD-form semantics; reads
  pod-spec `env` and an in-directory entrypoint script before calling a flag
  "missing"), Java 8 update-level cgroup awareness (the 8u131 / 8u191 / 8u372
  and 11.0.16 boundaries are encoded correctly), removed flags that abort
  startup, heap-vs-limit budget math.
* **It decides whether a workload is a JVM by looking for a JVM.** Until *R8*
  it looked for a file named `Dockerfile`, which is a different question and
  was wrong in both directions: a chart setting `JAVA_TOOL_OPTIONS=-Xmx4g`
  under a 2Gi limit — a guaranteed OOMKill — was graded `A-` with **no
  finding about memory at any severity**, while a pure nginx chart that
  happened to own a `Dockerfile` was told at HIGH, on `OBSERVED` basis, to
  set `-XX:MaxRAMPercentage` on a container with no JVM in it. The question
  is now asked once, in `kube.jvm_evidence()`, over pod-spec env, image names
  and any Dockerfile, and it returns **quotable evidence rather than a
  boolean** so every surface can print why. It was substituted in thirteen
  places, four of them outside the check layer; see *R8* in
  `docs/ITERATIONS.md`.
* **HPA correctness.** The scaling arithmetic (`ceil(current × util / target)`
  with the ±10% tolerance dead-band) is correct; it catches the
  `spec.replicas`-fights-the-HPA-on-upgrade bug, memory-metric-on-a-JVM
  ratchet, dangling `scaleTargetRef`, and quoted-string numerics.
* **Accurate reference data.** The deprecated/removed-API table (50 entries)
  matches the official Kubernetes migration guide; the `512m` milli-byte and
  bare-integer byte-scale typos are caught.
* **It knows when its own render was not evidence.** With `helm` present it
  renders at **both ends of the chart's declared `kubeVersion` range** and
  diffs the emitted `(kind, name)` sets — if a PDB or an HPA exists at one end
  and not the other, the chart is two different charts and `CH015` says so
  instead of silently picking one. Its companion `CH016` covers the case that
  probe provably cannot catch: `helm`'s `.Capabilities.APIVersions` is the set
  compiled into the *binary*, not your cluster's (verified by running helm
  v3.16 at 1.16/1.21/1.32 — it answers `true` for both `autoscaling/v2` and
  `autoscaling/v2beta1`, a combination no cluster has ever had), so a branch
  gated on it is reported as *not evidence* rather than analyzed as taken.
* **It tells you what it does not know.** Every finding carries an epistemic
  basis — `OBSERVED` (read from your files), `DERIVED` (arithmetic on your
  values with a stated model), or `ASSUMED` (a fallback because it couldn't
  see the truth). `ASSUMED` findings say `Assumes:` and can't sink your grade.
  A coverage section lists every input and what happened to it, so silence is
  never mistaken for a clean bill of health.
* **Honest about the cluster boundary.** For each cluster fact it can't see,
  it prints the exact `kubectl`/`helm` command to check it yourself.

### What it does NOT do / known weaknesses (verified)

* **These three entries used to be here and are no longer true — they were
  the first three defects fixed, and the README went on claiming them for
  three more iterations.** QoS was per-container (fixed R1: it is now a port
  of upstream `ComputePodQOS`, pod-level, with a `=> POD` verdict row); native
  sidecars were uncounted (fixed R2: `restartPolicy: Always` init containers
  are summed into the footprint and decide pod QoS); removed-API severity
  ignored `kubeVersion` (fixed R3: measured just now — the same
  `networking.k8s.io/v1beta1` Ingress is `CRITICAL` with no declared range or
  a modern one, and `LOW` under `>=1.19.0-0 <1.21.0-0`, a range where the API
  still exists). They are listed here rather than deleted because a README
  that overstates weaknesses is still a README nobody can trust, and the same
  stale sentence was also being printed *inside the report* by
  `clusterprobes.py` until this iteration caught it.
* **JVM detection is a heuristic, and it has a floor *R8* does not raise.**
  It reads pod-spec env (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`,
  `_JAVA_OPTIONS`, `JAVA_HOME`, `CATALINA_*`, `SPRING_*`), image names
  (`openjdk`/`temurin`/`corretto`/`zulu`/`graalvm`, `*-jre`, `*-jdk`,
  `tomcat`, `jetty`, `wildfly`) and any Dockerfile's `FROM` line and flags.
  A Java service whose flags are baked into an opaque
  `corp.registry/payments-api:4.2`, with nothing Java-shaped in its name or
  pod spec, is **invisible** to it — and that is the most common real-world
  shape. What changed at R8 is not that this case is solved but that the tool
  stops guessing at it: the JAVA category reads `NOT ASSESSED`, and the
  reason lists every input it examined, so you can see which one to add.
  `proof/p8b_bar2.py` CLAIM 6 measures exactly this failure.
* **It cannot see the cluster.** LimitRange defaulting (which can turn a
  "no requests" finding into a false positive), ResourceQuota, whether
  metrics-server / a custom-metrics adapter is installed, and the real node
  shape are all invisible. The "Verify on your cluster" report section gives
  you the commands; run them.
* **Static mode approximates Helm.** Without `helm` on PATH, `tpl`, `printf`,
  `required`, and subcharts cannot be resolved and conditionals are analyzed
  as taken. Install `helm` for rendered-truth analysis; the report always
  states which mode ran.
* **Estimates are estimates — and since *R9* the tool says when they, and
  not your chart, are what decides the answer.** The JVM memory-budget
  components (metaspace, JIT code cache, thread count, direct buffers,
  GC/internal) are `DERIVED` guesses. Each now carries a documented band with
  a cited source, the peak-RSS total is reported as an interval, and when your
  `limits.memory` falls *inside* that interval the verdict is `UNDETERMINED`
  rather than either endpoint's answer — it names the smallest set of
  estimates that would flip it, how far they must move against the gap
  available, and the `jcmd VM.native_memory` command that settles it. Feed the
  result back with `--measured` and the estimates drop out. What this does
  **not** fix: the bands themselves are constants somebody chose. An app with
  a large dependency graph or a bytecode-weaving agent can sit outside them,
  and there the tool is confidently wrong in the old way — it merely states a
  range while being wrong. `proof/p9b_bar2.py` CLAIM 9 measures that case.
* **The grade is a weighted count of what this run found — not a risk
  estimate, and not comparable across runs by default.** See *What the grade
  is* below; it has its own failure modes and they are measured, not
  hand-waved.
* **Verification of the ecosystem paths is uneven, and here is exactly how.**
  All four external validators — `helm lint`, `kubeconform`, `kube-score` and
  `polaris` — are now exercised against the **real binaries** over real
  directories (`tests/test_renderplan.py`, `tests/test_preflight_external.py`),
  and those tests skip rather than mock when the binary is absent. Each
  verdict is checked against the tool's *full* output, obtained through the
  same argv builder the tool itself uses, so a test cannot pass judgement on a
  command line that is never run. Until R6 `kube-score` and `polaris` had
  never been run by any test in any iteration and **both were misreported** —
  see *R6* in `docs/ITERATIONS.md`; the fix is why the report now prints a
  "status derived from:" line under each tool. `tests/test_helm_mode.py` still
  substitutes a canned render on purpose: it tests mode *selection* logic, not
  helm. Tool versions differ;
  confirm against your own installed versions before relying on them in CI.
* **Scope is deliberately narrow.** One chart per run; it is a JVM/HPA/
  resources linter, not a general Kubernetes validator, schema checker, or
  security scanner. Subcharts are **not graded** — a vendored chart is
  someone else's code and folding its findings into your score would
  misrepresent what you are responsible for. What changed in *R7* is that the
  boundary no longer functions as evidence: until then the objects `helm
  template` rendered from `charts/` were *discarded*, so HP041 could not see
  a Deployment helm had just produced from `charts/worker` and reported the
  user's correct HPA as dangling at HIGH, labelled `OBSERVED`. Followed, its
  `Fix:` line retargeted a working HPA onto the wrong workload — and the tool
  then called the broken chart clean. Those objects are now recorded but
  never scored, the coverage table names the subchart, its kinds and its
  object names instead of counting them, and each reference that resolves
  into a subchart gets its own row saying so. A reference that matches
  nothing still fires at HIGH. **Where subcharts exist but did not render**
  (static mode, or a subchart gated off by a condition) a target the tool
  cannot find is reported as UNDETERMINED rather than as a finding — which
  means a genuinely dangling reference in an umbrella chart analysed without
  helm will *not* be flagged. That is a real loss, taken deliberately, and
  the coverage row says which claim went unchecked and how to settle it.

### Do not assume

* **A high grade does not mean "deployable."** An `A+` is a statement about
  the *files*, by static analysis. It is **not** a promise the workload will
  schedule, scale, or even be admitted on *your* cluster.
* **It does not replace your existing tools.** Run it *alongside*
  `kubeconform` (schema), a policy engine (Kyverno / OPA / ValidatingAdmission
  Policy) for org rules, and a real load test. Use `--fail-on high` as a
  warning gate, not the sole merge blocker.
* **Absence of a finding is not proof of correctness.** It can mean "not
  covered." Read the coverage section.
* **The proof-table numbers are arithmetic on estimates, not measurements.**
* **A finding's severity accounts for the cluster version *your chart
  declares*, and nothing else about your cluster.** Deprecated-API severity is
  reconciled against `kubeVersion` (R3). Namespace LimitRange/quota and
  metrics setup are invisible and are not in any severity, so a "no requests"
  finding may be defaulted away by a LimitRange the tool cannot see.
* **The external-validator output is not ours.** `--cross-check` runs those
  tools and reports their output verbatim; we do not vouch for it.
* **It doesn't know a Java version the base-image tag hides.** Pass
  `--assume-java <ver>` for internal/corporate base images. Since *R8* this
  no longer skips the JVM checks wholesale — heap-vs-limit arithmetic needs
  only the flags and the limit, and runs without it. What degrades is the
  version-dependent subset (8u131 / 8u191 / 8u372 / 11.0.16 cgroup
  behaviour), and the report says which. Note also that this flag asks *you*
  for something usually sitting in your repo (`pom.xml`, `build.gradle`,
  `.java-version`); reading it instead is queued, not done.
* **A `NOT ASSESSED` category is not a pass, and a missing finding is not
  either.** After R8 the tool deliberately prints "the JVM checks did not
  apply, and here is what would make them apply" rather than going quiet,
  because in a report that only lists failures, an unrun check and a passed
  check look identical.

If any of the above matters to you, the tool is designed to help you check it
rather than take its word — that is what the basis labels, the coverage
section, and the "Verify on your cluster" commands are for.

---

## Requirements

* Python 3.8+ and PyYAML (`pip install -r requirements.txt`)
* **Recommended:** `helm` on PATH → the chart is rendered by the real
  template engine (`helm template`) instead of statically scrubbed.

## Getting started

1. Install the one dependency (add `--break-system-packages` on Debian/Ubuntu
   if pip refuses):

   ```bash
   pip install -r requirements.txt
   ```

2. Run it against the directory that holds your chart (and, ideally, the
   service Dockerfile). You do **not** place files anywhere special — you pass
   **one directory** and the tool walks it:

   ```bash
   python3 hpa-analyzer.py /path/to/your/service
   ```

3. **Read the answer in your terminal.** The run prints the grade, the counts,
   and the ranked *fix-first* list to stdout — the full report is written to
   `hpa_analysis_report.txt` (`-o` to change) for the deep dive; add `--html`
   for a browsable version.

First time? Run `python3 hpa-analyzer.py <dir> --check` to confirm the tool
found your chart/values/Dockerfile before analyzing.

### How much detail? (verbosity)

| Mode | Command | Contains |
|---|---|---|
| Terminal | *(always)* | grade + counts + top fixes on stdout (`--quiet` → one line) |
| Summary | `--summary` | score, scorecard, CRITICAL/HIGH only (~150 lines) |
| Default | *(none)* | findings + proofs + cluster-verify; LOW/INFO collapsed; no education |
| Expanded | `--all` | as default, LOW/INFO expanded |
| Teach | `--teach` | default **plus** the education appendix |
| Full | `--full` | everything (implies `--all --teach`) |
| Browsable | `--html [PATH]` | self-contained HTML: filter, collapsible cards, TOC, dark-mode |

Orthogonal to verbosity: `--measured metaspace=…,codecache=…,threads=…,
xss=…,direct=…,gc=…` replaces any of the JVM non-heap **estimates** with
numbers you measured (`kubectl exec POD -- jcmd 1 VM.native_memory summary`,
with `-XX:NativeMemoryTracking=summary` set). Each value you supply narrows
the reported interval; supply all of them and the interval disappears and the
verdict says the estimates had no part in it.

The remedy the report prints is derived from *your* run, not canned: after a
partial measurement it names only the components still deciding the answer,
says which ones you already supplied, and each measured row quotes the flag
text you typed rather than the integer it parsed to. (Both were defects,
found by running the example command above; `proof/p9b_bar2.py` CLAIMs 7 and
8 measure them, and they are C2.8(e) and C2.8(g) in `docs/SPEC.md`.)

## What it looks for (project layout)

Point the tool at a directory containing a Helm chart and, ideally, the
service Dockerfile — **pass `my-service/`**:

```
my-service/                <-- pass THIS directory
├── Chart.yaml             required: identifies the chart
├── values.yaml            base configuration
├── values-prod.yaml       optional overlay(s) — analyzed as variants
├── templates/
│   ├── deployment.yaml
│   ├── hpa.yaml
│   └── _helpers.tpl
└── Dockerfile             optional; adds image-level checks and the Java
                           version. The JVM analysis no longer depends on it
                           (may live anywhere under the dir)
```

Discovered by name (case-insensitive) anywhere under the directory: `Chart.yaml`,
`values*.ya?ml`, `templates/*.{yaml,yml,tpl}`, `Dockerfile` / `*.dockerfile`,
`values.schema.json`, `.helmignore`. `.git`, `node_modules`, `.idea`,
`__pycache__`, `.helm` are skipped. `charts/` is skipped for *grading*: its
templates are not read as yours, but the objects helm renders from it are
recorded so a reference into a subchart is not mistaken for a dangling one
(*R7*), and the coverage table names what went ungraded. Point at the
chart root, not a parent holding many charts (it analyzes one and records the
rest). No Dockerfile → the **Dockerfile** category is not assessed (there is
no file to assess). Since *R8* the **Java/JVM** and **cross-file** categories
are decided separately, by whether anything indicates a JVM: a chart with no
Dockerfile but `JAVA_TOOL_OPTIONS` in its pod spec is fully graded on both,
and a chart with a Dockerfile but no JVM is graded on neither. A category
that is not assessed changes the scale the grade is computed over; the report
says so on every surface (see *What the grade is*).

## Usage

```bash
python3 hpa-analyzer.py ./svc --assume-java 8u151          # base-image tag hides the JDK
python3 hpa-analyzer.py ./svc --fail-on high --json out.json   # CI gate
python3 hpa-analyzer.py ./svc --min-score 70 --require-coverage  # score gate that can't be dodged by deleting an input
python3 hpa-analyzer.py ./svc --helm on|off                # force / forbid helm rendering
python3 hpa-analyzer.py ./svc --check                      # guided input check, no analysis
python3 hpa-analyzer.py ./svc --cross-check                # also run helm lint / kubeconform / kube-score / polaris
python3 hpa-analyzer.py ./svc --html                       # + browsable HTML report
python3 hpa-analyzer.py ./svc --measured metaspace=210Mi,threads=180  # settle an UNDETERMINED JVM fit with real NMT numbers
```

Exit codes: `0` ok · `1` a gate failed (`--fail-on` / `--min-score` /
`--require-coverage`) · `2` usage/IO error. A `--min-score` run whose score
was computed over fewer than 10 categories always warns on stderr, whether or
not it passed.

Try the fixtures:

```bash
python3 hpa-analyzer.py fixtures/bad-chart  -o bad.txt    # scores F
python3 hpa-analyzer.py fixtures/good-chart -o good.txt   # scores A+
```

## What the grade is — and the three ways it will mislead you

The grade is **a weighted count of what this tool found, expressed out of
100**. It is not an estimate of risk, not a probability of an outage, and not
a measurement of anything. Ten categories carry fixed weights that add to 100
(`RESOURCES` 15, `CHART` 4, …); each category starts at 100 and findings
subtract from it; the overall score is the weighted mean.

Three consequences, all of them measured against the fixtures in this repo
(`proof/p5_grade.py`, `proof/p5b_bar2.py` — run them):

**1. The denominator moves, so two scores are not automatically comparable.**
A category that cannot be assessed — no Dockerfile, no parseable workload —
leaves *both* the numerator and the denominator, renormalising the rest.
Deleting `fixtures/bad-chart/Dockerfile` and changing **no Kubernetes
manifest at all** moves the grade from `45.5` to `49.9` — **up 4.4 points**.
The tool refuses to impute a value for what it did not look at (scoring 100
would invent a clean bill of health; scoring 0 would invent findings), so
instead it always prints the denominator:

```
  GRADE F  (49.9/100)   6 critical, 6 high, 11 medium, 13 low
  Scored over 7 of 10 categories (64 of 100 weight); NOT assessed: DOCKERFILE, JAVA, CROSS.
  Evidence: static template parsing, NOT a helm render (static) - see the coverage section.
```

on stdout, in the text report, on the HTML badge, in `--quiet`, and as
`score_coverage` in `--json`. **In CI this matters more than in the report,
because CI reads the exit code, not the report** — a `--min-score` set
anywhere in that 4.4-point band (`proof/p5b_bar2.py` calibrates one from the
measurement rather than hardcoding it) passes the Dockerfile-less copy that
the intact chart failed. Use
**`--require-coverage`** with `--min-score` to fail when the scale moved.

**2. Per-category scores floor at 0, so badness saturates.** Duplicating
`bad-chart`'s Deployment template 20× vs 40× gives **10.18 both times** —
with 460 findings in one and 860 in the other. The score cannot order two
already-bad charts.

**3. The number does not encode the evidence behind it.** `capability-chart`
grades `86.4` under `helm` rendering and is **NOT GRADED** under `--helm off`
— same chart, same `7 of 10` coverage line. The render mode is printed next
to the score; the *number* does not carry it, so `/100` values diffed across
modes are not the same comparison.

The weights themselves are a judgement, not a finding — nothing in this repo
evidences that requests/limits matter ~4× chart hygiene. Read the categories,
not the total.

## What it checks (10 categories)

Helm chart structure · Kubernetes templates & deprecated API versions ·
resource requests/limits & QoS · **HPA correctness** · availability & PDB
math · probes & lifecycle · **Dockerfile quality** · **Java/JVM container
fitness** · security posture · **cross-file JVM-vs-chart consistency**. See
the report's scorecard for the full per-category breakdown.

## Verify on your cluster · Cross-check the standard stack

* The report's **"Verify on your cluster"** section emits the exact
  `kubectl`/`helm` commands (pre-filled with your object names) for the
  cluster facts static analysis can't see — only the ones relevant to your
  chart, plus how to read each result. Also in `--json` as `cluster_probes`.
* `--cross-check` detects and runs whichever of `helm lint`, `kubeconform`,
  `kube-score` and `polaris` are on your PATH, folding their **verbatim,
  attributed** output into the report (absent tools show an install command).
  Verdicts are `PASS` / `FAIL` / **`UNKNOWN`** / `not run`, and **none of them
  is a re-reading of an exit code** — each is derived from the tool's own
  printed tally, with a `status derived from:` line naming the signal and a
  machine-readable `tally` in `--json`. This matters because the exit codes
  lie: `kubeconform` exits non-zero both for a chart that failed validation
  and for a schema it could not fetch (`Invalid: 0, Errors: 3` is `UNKNOWN`
  with the reason, never `FAIL`); `kube-score` exits 1 both for "I found a
  CRITICAL" and for "I could not parse your files"; and `polaris` exits **0
  unconditionally** — on a clean chart, on one it scores 66/100 with
  danger-severity failures, and on a file that is not YAML at all. Unreadable
  input is `UNKNOWN` from every tool, never a verdict about your chart. The
  raw output is printed under each verdict so you can check the
  transcription; where it is cut, the excerpt states how many lines were
  dropped.

## Development

```bash
python3 -m unittest discover -s tests -t .     # 412 tests
python3 proof/p5_grade.py                      # each proof/p*.py exits 0 or explains why not
```

133 distinct rule IDs are emitted. 128 of them live in
`hpaanalyzer/checks_*.py` (AV 6, CH 24, DF 15, HP 23, JV 17, LC 1, PA 1,
PB 5, RS 16, SC 6, TP 8, VA 6); the remaining 5 are the `XF` cross-check
findings, which live in `proofs.py` because they are raised by comparing this
tool against an external one rather than by reading the chart. Earlier
revisions of this file said "127 rules in `checks_*.py`", which undercounted
by one and put the `XF` five in the wrong file. Every rule emits a `Finding`
(`models.py`); scoring and rendering pick new rules up automatically.
`tests/test_regressions.py` pins every bug found in adversarial review so it
can't return. Several of those tests assert on the *sentences* the report
prints, not just its numbers — the first four were added in R5 after a probe
was found telling users the report was wrong about something it had gotten
right since R1. Every test passed the whole time, because until then no test
read the prose. R8 added three more, and needed them: three of its thirteen
sites are not rules at all but prose — two security findings whose rationale
explained itself in terms of a JVM, an appendix that printed a JVM primer on
every chart, and a file inventory that said nothing about a JVM on the chart
that has one. They were found by a Bar 2 proof enumerating every
reader-visible surface by hand, not by the test suite, and nothing would yet
catch a fourteenth.

`proof/` holds 21 standalone scripts, one per defect fixed in the nine
documented iterations. Each extracts the pre-fix tree at a **pinned** commit
(`proof/baseline.py`, not `HEAD`), runs both versions as real subprocesses
over real fixture directories, and prints the before/after measurement rather
than asserting the claim. One exception is labelled as such in its own output:
`p5c_horizon.py` fixes a defect that was introduced *and* fixed after the
baseline commit, so there is no old tree to archive; its BEFORE column is
reconstructed by disabling one field, and the script says so before printing a
number. Several of them record where the first draft of a claim was **refuted
by its own run** and corrected from the measurement — that history is in
`docs/ITERATIONS.md` and is deliberately not tidied away.

Two failure modes of the proofs themselves are recorded there for the same
reason. A check can be **unable to fail**: `p8b`'s severity helper compared
against lowercase strings while the JSON emits `"HIGH"`, so it returned no
findings on any chart and its claim passed on inputs full of CRITICALs. And a
claim about what the tool *cannot* do has **no natural failure signal**:
`p7b`'s "the OOMKill is still missed" went on passing after R8 fixed exactly
that, because the rule that now fires was not in the id set it searched. Both
are fixed, and every "what is still missed" claim is now written to assert the
current state in **both** directions.

## License

MIT (see `LICENSE`).

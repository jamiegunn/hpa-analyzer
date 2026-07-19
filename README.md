# hpa-analyzer

Quality analysis for a directory containing a **Helm chart**, **values
file(s)** and a **Dockerfile** (any JDK from Java 8 upward). Point it at the
directory; it writes a plain-text report you can open in any editor, with a
weighted score, per-finding explanations (*what / why / math / fix*) and
mathematical proof tables that derive every verdict from arithmetic on the
values found in your files.

No assumptions are made about file correctness: broken YAML, duplicate keys,
Helm-template syntax, deprecated APIs, contradictory HPA/replica settings and
JVM flags that are defined but never applied are all treated as findings, not
as fatal errors.

**Every finding declares its epistemic basis** — `OBSERVED` (read from your
files), `DERIVED` (arithmetic on your values with a stated model), or
`ASSUMED` (a fallback the tool made because it could not see the truth).
`ASSUMED` findings print an `Assumes:` line, are flagged in the fix-first
list, and — if `CRITICAL` — are capped at `HIGH`'s score weight, so the
tool's own guesses can never sink your grade or read like measurements.

## Requirements

* Python 3.8+ and PyYAML (`pip install -r requirements.txt`)
* **Recommended:** `helm` on PATH. When present, the chart is rendered with
  the real template engine (`helm template`) and the analysis works on
  rendered truth — conditionals, loops and helpers evaluated exactly as a
  deploy would. Without helm the tool falls back to static template
  scrubbing and says so, loudly, in the report's coverage section.

## Getting started

1. From the project directory (the folder containing `hpa-analyzer.py`),
   install the one dependency:

   ```bash
   pip install -r requirements.txt   # PyYAML
   #   on Debian/Ubuntu, if pip refuses: add --break-system-packages
   ```

   Optional but recommended: install `helm` and put it on your `PATH` for
   rendered-truth analysis.

2. Run it against the directory that holds your chart (and, ideally, the
   service Dockerfile):

   ```bash
   python3 hpa-analyzer.py /path/to/your/service
   ```

   You do **not** place files anywhere special. You pass **one directory**
   and the tool walks it to find the chart, values, templates and Dockerfile
   itself.

3. **Read the answer in your terminal.** By default the run prints the grade,
   the finding counts, and the ranked *fix-first* list right to stdout — you
   don't have to open a file to know what to do. The full report is written to
   `hpa_analysis_report.txt` (or the `-o` path) for the deep dive; add
   `--html` for a browsable version.

```text
$ python3 hpa-analyzer.py ./my-service
  GRADE F  (45.5/100)   11 critical, 11 high, 14 medium, 16 low
  Fix first:
    1. [HP004] HPA minReplicas > maxReplicas (invalid)  (templates/hpa.yaml)
    2. [HP050] Deployment sets spec.replicas while an HPA manages it
    3. [RS002] Memory quantity uses 'm' (MILLI-bytes)  (values.yaml)
    ... +17 more critical/high (see report)
  Full report: hpa_analysis_report.txt
```

### How much detail? (verbosity)

| Mode | Command | Contains |
|---|---|---|
| Terminal | *(always)* | grade + counts + top fixes on stdout (`--quiet` → one line) |
| Summary | `--summary` | score, scorecard, CRITICAL/HIGH only (~150 lines) |
| Default | *(none)* | findings + proofs + cluster-verify; LOW/INFO collapsed; **no** education |
| Expanded | `--all` | as default, LOW/INFO expanded to full detail |
| Teach | `--teach` | default **plus** the education appendix |
| Full | `--full` | everything (implies `--all --teach`) |
| Browsable | `--html [PATH]` | self-contained HTML: filter box, collapsible cards, TOC, dark-mode |

## What it looks for (project layout)

Point the tool at any directory that contains a Helm chart and, ideally, the
service Dockerfile. A typical service repo looks like this — **point the
tool at `my-service/`**:

```
my-service/                <-- pass THIS directory
├── Chart.yaml             required: identifies the chart
├── values.yaml            base configuration
├── values-prod.yaml       optional overlay(s) — analyzed as variants
├── values.schema.json     optional
├── templates/
│   ├── deployment.yaml
│   ├── hpa.yaml
│   ├── service.yaml
│   └── _helpers.tpl
└── Dockerfile             the JVM image (may live anywhere under the dir)
```

Files are discovered by name (case-insensitive) anywhere under the directory
you pass:

| Piece | Matched names |
|---|---|
| Chart | `Chart.yaml` / `Chart.yml` (outermost wins; other charts are recorded, never merged) |
| Values | `values.yaml`, `values-prod.yaml`, `values_staging.yml`, … (`values*.ya?ml`) |
| Templates | every `*.yaml` / `*.yml` / `*.tpl` / `NOTES.txt` under a `templates/` dir |
| Dockerfile | `Dockerfile`, `Dockerfile.jre`, `service.dockerfile`, … |
| Schema / ignore | `values.schema.json`, `.helmignore` |

* The **Dockerfile does not have to be inside the chart** — anywhere under
  the directory you pass is fine; it is matched by filename.
* `charts/` (vendored subcharts), `.git`, `node_modules`, `.idea`,
  `__pycache__` and `.helm` are skipped.
* Point at the **chart root**, not a parent holding many charts: given
  several `Chart.yaml`s the tool analyzes the outermost one and lists the
  rest as separate (it never blends them).
* **No Dockerfile?** The chart is still analyzed; the Java/JVM and cross-file
  categories are marked `N/A` in the scorecard rather than guessed.

## Usage

```bash
python3 hpa-analyzer.py /path/to/chart-directory
# report written to hpa_analysis_report.txt

# corporate base image whose tag hides the JDK version:
python3 hpa-analyzer.py ./svc --assume-java 8u151

# CI gate: fail the pipeline on real problems
python3 hpa-analyzer.py ./svc --fail-on high --min-score 70 --json findings.json

# force or forbid helm rendering
python3 hpa-analyzer.py ./svc --helm on
python3 hpa-analyzer.py ./svc --helm off

# guided input check: what did it find, what looks misplaced? (no analysis)
python3 hpa-analyzer.py ./svc --check

# also run the standard stack (helm lint / kubeconform / kube-score / polaris)
python3 hpa-analyzer.py ./svc --cross-check
```

**Guided input check (`--check`).** Before analyzing anything, prints what it
discovered (chart, values, templates, workloads, Dockerfile + Java version)
and flags what looks off — no Dockerfile, undeterminable Java (suggests
`--assume-java`), several charts in one directory, parse failures — with a
one-line fix for each. Exits `0` if it is a usable chart directory, `2` if
it is not. Every normal run also prints this discovery banner first, so you
always see what the tool saw; `--quiet` collapses the whole terminal output
(banner + fix-first summary) to a single machine-readable line.

**Cross-check against the standard stack (`--cross-check`).** Detects and
runs whichever of `helm lint`, `kubeconform`, `kube-score` and `polaris` are
on your `PATH`, and folds their **verbatim** output into the report (section
"External validators"). hpa-analyzer did not write these tools and does not
vouch for them — it reports their exit status and output as-is, clearly
attributed. Absent tools are listed with an install command; tools that need
rendered manifests are skipped with a reason when `helm` isn't available to
render. Results also appear in `--json` under `cross_check`.

Exit codes: `0` ok · `1` a gate failed (`--fail-on` / `--min-score`) ·
`2` usage/IO error.

Try the fixtures:

```bash
python3 hpa-analyzer.py fixtures/bad-chart  -o bad.txt    # scores F, ~60 findings
python3 hpa-analyzer.py fixtures/good-chart -o good.txt   # scores A+
```

## What it checks (10 categories)

| Category | Examples |
|---|---|
| Helm chart structure | Chart.yaml hygiene, SemVer, schema/helpers/NOTES, duplicate YAML keys, template syntax in values |
| Templates & API versions | removed/deprecated apiVersions (incl. `autoscaling/v2beta1`), hardcoded namespaces, `:latest`, labels |
| Requests & limits | missing requests/limits, the `512m` **milli-bytes** typo AND the bare-integer `512` **byte-scale** typo, limit<request, overcommit ratios, QoS class |
| HPA | replicas-vs-HPA fight on `helm upgrade` (rendered-truth in helm mode; control-flow-aware gate analysis in static mode), min/max sanity (incl. **quoted-string** numerics), dangling `scaleTargetRef` (no false pairing), CPU target vs request math, **memory-metric-on-JVM ratchet scoped to the actual target**, missing requests breaking utilization, behavior windows |
| Availability | single replica, `Recreate`, PDB math (`minAvailable >= replicas` blocks drains), anti-affinity/spread |
| Probes & lifecycle | missing readiness, liveness==readiness, probe time-to-kill vs JVM startup, `terminationGracePeriodSeconds` |
| Dockerfile | unpinned bases, shell-form ENTRYPOINT (PID 1 / SIGTERM), `$JAVA_OPTS` in exec form (never expanded), **JAVA_OPTS defined but never applied** (checked against an in-directory entrypoint script before calling it inert), secrets in ENV, ADD-from-URL, JDK-vs-JRE; multi-stage aware (builder-stage ENV/ENTRYPOINT/USER never count as runtime facts); **BuildKit heredoc (`RUN <<EOT`) bodies are data, not instructions** |
| Java / JVM | Java 8 update-level forensics (<8u131 / <8u191 / <8u372), **cgroup v2 blindness matrix**, removed flags that abort startup, MaxRAMPercentage sanity, missing heap bounds, `ExitOnOutOfMemoryError`, GC ergonomics on small CPU — all judged against the flags the JVM **actually receives** |
| Security | root containers, privilege escalation, capabilities, read-only rootfs, host namespaces, SA tokens |
| Cross-file | **JVM memory budget vs container limit** (heap+metaspace+stacks+buffers), CPU quota vs `availableProcessors`, HPA arithmetic tables, probe-vs-startup budget, availability math |

## Values overlays

`values-prod.yaml` (and any `values-*.yaml`) is analyzed as a separate
variant: the overlay is merged over the base (helm mode: re-rendered with
`-f`) and the resource/HPA/JVM checks re-run. Regressions that exist only
in the overlay — a prod-only `minReplicas > maxReplicas`, a dropped limit —
are reported and labeled with the overlay file.

## Honesty guarantees

* **Epistemic basis on every finding** (`OBSERVED` / `DERIVED` / `ASSUMED`),
  rendered in the report and the `--json` output. A guess never reads like a
  measurement, and an `ASSUMED` critical is capped at `HIGH`'s deduction.
* **Coverage section**: *every* input is listed with what happened to it —
  rendered, statically parsed, parse-failed (no checks ran!), a values file
  that loaded but was not a mapping (primary analysis ran with EMPTY values),
  Java version detected/assumed/unknown, oversized templates skipped,
  subcharts skipped. Silence is never a clean bill of health.
* **Not graded** beats a fake grade: an empty/unrelated directory *and* a
  chart whose entire workload surface went unanalyzed (e.g. a library chart
  whose `{{ include }}` renders zero objects) score `NOT GRADED`, not 100.
* **One chart at a time**: pointed at a directory holding several charts, the
  tool analyzes the outermost and records the rest as separate — it never
  merges one chart's values onto another's templates (which would fabricate
  cross-chart criticals).
* **The flags the JVM actually receives**: JVM options set via pod-spec env
  (`JAVA_TOOL_OPTIONS`, ...) and applied by an in-directory entrypoint script
  are read before declaring image-level config "missing" or "inert".
* Proof-table verdicts feed the score: a <10% memory margin is a finding
  (XF004), not just prose.
* Estimates are labeled (`DERIVED`), and conclusions that rest on them say so.
* Sidecar containers are never given JVM budgets — recognised by name **or
  image** (a `log-shipper` running `fluent-bit-fork` is still a sidecar).

## Report layout

1. Executive summary (score 0–100 or NOT GRADED, fix-first list)
2. Analysis coverage — what was and was NOT checked
3. Scorecard by category (inapplicable categories are N/A, not free points)
4. Findings with *Found / Why / Math / Fix*, grouped by severity (INFO
   compacted to one line each)
5. Mathematical proof tables
6. Education appendix — HPA control loop, JVM-in-container memory model, Java
   container-awareness timeline, baseline config, the requests-vs-limits
   "relativity trap", compressible-vs-incompressible resources, the
   unready-pod dampening outage, thrashing / stabilization / HPA+VPA spiral,
   demand metrics (RPS / queue depth / p99, KEDA), predictive scaling and the
   scaling-invariant aggregate, the workload→scaler decision framework, how to
   read the `basis` line, and golden rules
7. **Verify on your cluster** — for each cluster fact static analysis can't
   see (metrics pipeline, LimitRange defaulting, deprecated-API vs server
   version, pod-level QoS / native-sidecar footprint, ResourceQuota, whether
   the JVM sees its cgroup limit), the exact `kubectl`/`helm` command to run
   and how to read it. Only the checks relevant to your chart appear; also in
   `--json` as `cluster_probes`.
8. Methodology & limitations

## Development

```bash
python3 -m unittest discover -s tests -t .     # 140 tests
```

Each rule lives in one of the `hpaanalyzer/checks_*.py` modules and emits a
`Finding` (see `models.py`); scoring and rendering pick new rules up
automatically. Proof tables live in `proofs.py`. `tests/test_regressions.py`
pins every bug found in adversarial review.

## Where this fits (and where it does not)

This is **one advisory stage**, not an admission/policy gate and not a
standalone "is this prod-ready?" oracle. An `A+` means the chart is
internally consistent and JVM-container-fit *by static analysis of the
files you gave it* — it is **not** a promise the workload will schedule,
scale, or even admit on your specific cluster. Pair it with:

* `kubeconform` / `kubeval` for API-schema validation,
* a policy engine (Kyverno / OPA-Gatekeeper / ValidatingAdmissionPolicy)
  for your org's admission rules,
* a real load test with GC logs (`-Xlog:gc*`) and `kubectl top` / VPA
  recommendations for how the HPA and heap *actually* behave.

Run it as a warning gate (`--fail-on high`), not the sole merge blocker.

## Known limitations

### Deliberate scope

* Subcharts (`charts/`) are out of scope — run the analyzer against the
  subchart directly. The coverage section notes when they exist.
* One chart per run: pointed at a directory with several charts, it analyzes
  the outermost and records the rest as separate (never merged).
* In static mode (no helm), complex template expressions (`tpl`, `printf`,
  `required`) cannot be resolved and conditionals are analyzed as taken. The
  report labels the mode and its consequences. Install `helm` for
  rendered-truth analysis.
* JVM memory components (metaspace, threads, direct buffers) are `DERIVED`
  estimates with stated values — replace with measured numbers for final
  sizing.

### Cluster context it cannot see (the static-analysis boundary)

The tool reads files, not a cluster. The following are real Kubernetes
behaviours it does **not** model. It does not stay silent about them: the
report's **"Verify on your cluster"** section (and the `cluster_probes`
array in `--json`) prints the exact `kubectl`/`helm` command to close each
gap that is relevant to your chart — pre-filled with the object names and
label selectors it parsed — plus how to read the result. Where they apply,
run the command and weigh the finding accordingly:

* **LimitRange defaulting.** A container with no `requests`/`limits` may be
  defaulted at admission by a namespace `LimitRange` — so it is not
  necessarily `BestEffort`/unbounded. The tool flags the missing values
  regardless; if your chart or namespace ships a `LimitRange`, read
  `RS001`/QoS findings in that light.
* **Deprecated-API severity vs `kubeVersion`.** A removed-API finding
  (`TP010`) assumes a cluster at or past the removal version. It does **not**
  down-rank based on a chart's declared `kubeVersion` window, so a chart
  pinned below the removal version still gets the finding at full severity.
* **Native sidecars** (`restartPolicy: Always` init containers, GA in 1.33).
  Only `spec.containers` are analyzed; a restartable init container's
  requests count toward real pod QoS and scheduling footprint but are not
  yet included in the budget math.
* **Metrics pipeline.** A correct CPU HPA still does nothing without
  metrics-server; custom/external metrics need the Prometheus Adapter or
  KEDA. The tool cannot verify any of it is installed.
* **ResourceQuota.** A namespace quota can reject an otherwise-valid pod;
  that is invisible to file-level analysis.

### Correctness scoping

* **QoS is shown per container.** Kubernetes QoS is a *pod-level* property
  (a pod is `Guaranteed` only if **every** container has `requests==limits`
  for both resources). For single-container workloads — the common JVM
  service — the per-container view is exact; for multi-container pods, read
  the per-container rows as inputs, not as the pod's class.

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
```

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
7. Methodology & limitations

## Development

```bash
python3 -m unittest discover -s tests -t .     # 102 tests
```

Each rule lives in one of the `hpaanalyzer/checks_*.py` modules and emits a
`Finding` (see `models.py`); scoring and rendering pick new rules up
automatically. Proof tables live in `proofs.py`. `tests/test_regressions.py`
pins every bug found in adversarial review.

## Known limitations (deliberate)

* Subcharts (`charts/`) are out of scope — run the analyzer against the
  subchart directly. The coverage section notes when they exist.
* In static mode (no helm), complex template expressions (`tpl`, `printf`,
  `required`) cannot be resolved; conditionals are analyzed as taken. The
  report labels the mode and its consequences.
* JVM memory components (metaspace, threads, direct buffers) are estimates
  with stated values — replace with measured numbers for final sizing.

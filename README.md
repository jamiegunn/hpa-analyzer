# hpa-analyzer

A static analyzer for a directory containing a **Helm chart**, its **values
file(s)**, and a **Dockerfile** for a **JVM service** (any JDK from Java 8
up). It writes a plain-text (and optional HTML) report scoring the chart on
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
* **HPA correctness.** The scaling arithmetic (`ceil(current × util / target)`
  with the ±10% tolerance dead-band) is correct; it catches the
  `spec.replicas`-fights-the-HPA-on-upgrade bug, memory-metric-on-a-JVM
  ratchet, dangling `scaleTargetRef`, and quoted-string numerics.
* **Accurate reference data.** The deprecated/removed-API table (14 entries)
  matches the official Kubernetes migration guide; the `512m` milli-byte and
  bare-integer byte-scale typos are caught.
* **It tells you what it does not know.** Every finding carries an epistemic
  basis — `OBSERVED` (read from your files), `DERIVED` (arithmetic on your
  values with a stated model), or `ASSUMED` (a fallback because it couldn't
  see the truth). `ASSUMED` findings say `Assumes:` and can't sink your grade.
  A coverage section lists every input and what happened to it, so silence is
  never mistaken for a clean bill of health.
* **Honest about the cluster boundary.** For each cluster fact it can't see,
  it prints the exact `kubectl`/`helm` command to check it yourself.

### What it does NOT do / known weaknesses (verified)

* **QoS is shown per-container; Kubernetes assigns QoS per-pod.** For a
  single-container workload (the common JVM service) this is exact. For a
  **multi-container pod the per-container label can be wrong** — trust
  `kubectl get pod -o jsonpath='{.status.qosClass}'`, not the report's row.
* **Native sidecars are not counted.** `restartPolicy: Always` init
  containers (GA in Kubernetes 1.33) contribute to pod QoS and scheduling
  footprint; the budget math ignores them.
* **Deprecated-API severity ignores your `kubeVersion`.** A removed-API
  finding is reported at full severity even if the chart pins a cluster
  version where that API still exists.
* **It cannot see the cluster.** LimitRange defaulting (which can turn a
  "no requests" finding into a false positive), ResourceQuota, whether
  metrics-server / a custom-metrics adapter is installed, and the real node
  shape are all invisible. The "Verify on your cluster" report section gives
  you the commands; run them.
* **Static mode approximates Helm.** Without `helm` on PATH, `tpl`, `printf`,
  `required`, and subcharts cannot be resolved and conditionals are analyzed
  as taken. Install `helm` for rendered-truth analysis; the report always
  states which mode ran.
* **Estimates are estimates.** The JVM memory-budget components (metaspace,
  thread stacks, direct buffers, assumed node RAM) are `DERIVED` guesses with
  stated values. Substitute measured RSS/CPU for real sizing decisions.
* **Some capabilities are only lightly verified here.** In this project's own
  test suite, the `helm`-rendered path and the external validators
  (`kubeconform` / `kube-score` / `polaris`) are exercised largely through
  mocks and against specific tool versions. Confirm them against your own
  installed versions before relying on them in CI.
* **Scope is deliberately narrow.** One chart per run (subcharts are out of
  scope and recorded, never analyzed); it is a JVM/HPA/resources linter, not
  a general Kubernetes validator, schema checker, or security scanner.

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
* **A finding's severity does not account for your cluster version, namespace
  LimitRange/quota, or metrics setup** — it can't see them.
* **The external-validator output is not ours.** `--cross-check` runs those
  tools and reports their output verbatim; we do not vouch for it.
* **It doesn't know a Java version the base-image tag hides.** Pass
  `--assume-java <ver>` for internal/corporate base images, or the JVM checks
  are skipped (and the report says so).

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
└── Dockerfile             the JVM image (may live anywhere under the dir)
```

Discovered by name (case-insensitive) anywhere under the directory: `Chart.yaml`,
`values*.ya?ml`, `templates/*.{yaml,yml,tpl}`, `Dockerfile` / `*.dockerfile`,
`values.schema.json`, `.helmignore`. `charts/` (subcharts), `.git`,
`node_modules`, `.idea`, `__pycache__`, `.helm` are skipped. Point at the
chart root, not a parent holding many charts (it analyzes one and records the
rest). No Dockerfile → the Java/JVM and cross-file categories are `N/A`.

## Usage

```bash
python3 hpa-analyzer.py ./svc --assume-java 8u151          # base-image tag hides the JDK
python3 hpa-analyzer.py ./svc --fail-on high --json out.json   # CI gate
python3 hpa-analyzer.py ./svc --helm on|off                # force / forbid helm rendering
python3 hpa-analyzer.py ./svc --check                      # guided input check, no analysis
python3 hpa-analyzer.py ./svc --cross-check                # also run helm lint / kubeconform / kube-score / polaris
python3 hpa-analyzer.py ./svc --html                       # + browsable HTML report
```

Exit codes: `0` ok · `1` a gate failed (`--fail-on` / `--min-score`) ·
`2` usage/IO error.

Try the fixtures:

```bash
python3 hpa-analyzer.py fixtures/bad-chart  -o bad.txt    # scores F
python3 hpa-analyzer.py fixtures/good-chart -o good.txt   # scores A+
```

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

## Development

```bash
python3 -m unittest discover -s tests -t .     # 140 tests
```

Each rule lives in `hpaanalyzer/checks_*.py` and emits a `Finding`
(`models.py`); scoring and rendering pick new rules up automatically. Proof
tables live in `proofs.py`; `tests/test_regressions.py` pins every bug found
in adversarial review so it can't return.

## License

MIT (see `LICENSE`).

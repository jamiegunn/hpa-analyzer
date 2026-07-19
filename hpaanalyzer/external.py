"""Run the complementary ecosystem tools and report their output verbatim.

hpa-analyzer covers a niche (HPA + resources + JVM-in-container). The
standard stack covers other ground: `helm lint` (chart mechanics),
`kubeconform` (API-schema validation), `kube-score` / `polaris` (generic
best practices). This module DETECTS which of them are installed and, when
`--cross-check` is given, RUNS them and folds a summary into the report.

Discipline: this tool did not write these validators and does not vouch for
their results - it runs them and reports exit status + output verbatim,
clearly attributed. Absent tools are listed with an install command, never
silently skipped. Tools that need rendered manifests are skipped with a
reason when `helm` is unavailable to render.

Nothing is run unless the caller opts in.
"""

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from .helmrender import find_helm, render_chart


@dataclass
class ExternalResult:
    name: str
    installed: bool
    ran: bool
    ok: Optional[bool]            # None = did not run / indeterminate
    summary: str                  # one line
    manual_cmd: str               # how to run it yourself
    install_hint: str = ""
    detail: str = ""              # captured output (truncated)


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _run(cmd: List[str], timeout: int = 90, stdin: Optional[str] = None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=stdin)
        return p.returncode, (p.stdout or ""), (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, "", str(e)


def _trunc(s: str, n: int = 1500) -> str:
    s = s.strip()
    return s if len(s) <= n else s[:n] + "\n... (truncated)"


def run_cross_check(chart_dir: Optional[str],
                    rendered_text: Optional[str] = None) -> List[ExternalResult]:
    """Detect and run the ecosystem validators. `rendered_text` is the
    `helm template` output if the main run already produced it; otherwise we
    render here when helm is available."""
    results: List[ExternalResult] = []
    helm = find_helm()

    # ensure we have rendered manifests for the tools that need them
    rendered_path = None
    tmpdir = None
    if rendered_text is None and helm and chart_dir:
        out, _err = render_chart(chart_dir, helm_bin=helm)
        rendered_text = out
    if rendered_text:
        tmpdir = tempfile.mkdtemp(prefix="hpa-xcheck-")
        rendered_path = os.path.join(tmpdir, "rendered.yaml")
        with open(rendered_path, "w", encoding="utf-8") as f:
            f.write(rendered_text)

    # --- helm lint (chart mechanics) -------------------------------------
    if not helm:
        results.append(ExternalResult(
            "helm lint", installed=False, ran=False, ok=None,
            summary="helm not on PATH",
            manual_cmd=f"helm lint {chart_dir or '<chart-dir>'}",
            install_hint="https://helm.sh/docs/intro/install/"))
    elif not chart_dir:
        results.append(ExternalResult(
            "helm lint", installed=True, ran=False, ok=None,
            summary="no chart directory to lint",
            manual_cmd="helm lint <chart-dir>"))
    else:
        rc, out, err = _run([helm, "lint", chart_dir])
        blob = (out + "\n" + err).strip()
        results.append(ExternalResult(
            "helm lint", installed=True, ran=rc is not None,
            ok=(rc == 0) if rc is not None else None,
            summary=(_last_summary_line(blob) if rc is not None
                     else f"failed to run: {err}"),
            manual_cmd=f"helm lint {chart_dir}",
            detail=_trunc(blob)))

    # --- schema + best-practice tools needing rendered manifests ---------
    needs_render = [
        ("kubeconform",
         lambda p: [_which("kubeconform"), "-strict", "-summary", p],
         "kubeconform -strict -summary <(helm template <chart>)",
         "go install github.com/yannh/kubeconform/cmd/kubeconform@latest"),
        ("kube-score",
         lambda p: [_which("kube-score"), "score", p],
         "kube-score score <(helm template <chart>)",
         "https://github.com/zegl/kube-score#installation"),
        ("polaris",
         lambda p: [_which("polaris"), "audit", "--audit-path", p,
                    "--format", "pretty"],
         "polaris audit --audit-path <(helm template <chart>)",
         "https://polaris.docs.fairwinds.com/infrastructure-as-code/"),
    ]
    for name, argv_fn, manual, install in needs_render:
        binp = _which(name)
        if not binp:
            results.append(ExternalResult(
                name, installed=False, ran=False, ok=None,
                summary="not installed",
                manual_cmd=manual, install_hint=install))
            continue
        if not rendered_path:
            results.append(ExternalResult(
                name, installed=True, ran=False, ok=None,
                summary="needs rendered manifests; install helm so the chart "
                        "can be rendered first",
                manual_cmd=manual))
            continue
        rc, out, err = _run(argv_fn(rendered_path))
        blob = (out + "\n" + err).strip()
        results.append(ExternalResult(
            name, installed=True, ran=rc is not None,
            ok=(rc == 0) if rc is not None else None,
            summary=(_last_summary_line(blob) if rc is not None
                     else f"failed to run: {err}"),
            manual_cmd=manual, detail=_trunc(blob)))

    return results


def _last_summary_line(blob: str) -> str:
    """Best-effort one-liner: the last non-empty line of output."""
    lines = [ln.strip() for ln in blob.splitlines() if ln.strip()]
    return lines[-1] if lines else "(no output)"

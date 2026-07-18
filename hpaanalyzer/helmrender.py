"""Render the chart with the real `helm` binary when available.

`helm template` is ground truth: real Go-template evaluation, real
conditionals, real values merging. The static scrubber in helmyaml.py is
the fallback, and the report says loudly which mode produced its facts.

Rendered docs are mapped back to their template file via helm's
`# Source: <chart>/templates/foo.yaml` comments.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

_SOURCE_RE = re.compile(r"^# Source:\s*(?P<path>\S+)\s*$", re.MULTILINE)


def find_helm() -> Optional[str]:
    return shutil.which("helm")


def render_chart(chart_dir: str, extra_values: Optional[List[str]] = None,
                 helm_bin: Optional[str] = None,
                 timeout: int = 60) -> Tuple[Optional[str], Optional[str]]:
    """Run `helm template` on chart_dir. Returns (stdout, error)."""
    helm_bin = helm_bin or find_helm()
    if not helm_bin:
        return None, "helm binary not found on PATH"
    cmd = [helm_bin, "template", "release-name", chart_dir]
    for vf in extra_values or []:
        cmd.extend(["-f", vf])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f"helm template failed to run: {e}"
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return None, f"helm template exited {proc.returncode}: {err[:400]}"
    return proc.stdout, None


def split_rendered(output: str) -> List[Tuple[str, str]]:
    """Split `helm template` output into (source_template_path, doc_text).

    source_template_path is relative like 'templates/deployment.yaml'
    (chart-name prefix stripped); '' when helm gave no Source comment.
    """
    docs: List[Tuple[str, str]] = []
    for chunk in re.split(r"(?m)^---\s*$", output):
        if not chunk.strip():
            continue
        m = _SOURCE_RE.search(chunk)
        src = ""
        if m:
            path = m.group("path")
            parts = path.split("/", 1)
            src = parts[1] if len(parts) == 2 else path
        docs.append((src, chunk))
    return docs

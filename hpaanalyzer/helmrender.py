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
import tempfile
from typing import Dict, List, Optional, Tuple

import yaml

_SOURCE_RE = re.compile(r"^# Source:\s*(?P<path>\S+)\s*$", re.MULTILINE)


def find_helm() -> Optional[str]:
    return shutil.which("helm")


_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
_version_cache: Dict[str, Optional[str]] = {}
_default_kv_cache: Dict[str, Optional[str]] = {}


def helm_version_string(helm_bin: Optional[str] = None) -> Optional[str]:
    """`helm version --short` for the installed binary, e.g. 'v3.16.4+g...'
    or 'v4.2.1+g...'. None when helm is absent or the command fails.
    Cached per binary path for the life of the process."""
    helm_bin = helm_bin or find_helm()
    if not helm_bin:
        return None
    if helm_bin not in _version_cache:
        try:
            p = subprocess.run([helm_bin, "version", "--short"],
                               capture_output=True, text=True, timeout=15)
            out = (p.stdout or "").strip()
            _version_cache[helm_bin] = out if p.returncode == 0 and out else None
        except (subprocess.SubprocessError, OSError):
            _version_cache[helm_bin] = None
    return _version_cache[helm_bin]


def helm_major(helm_bin: Optional[str] = None) -> Optional[int]:
    """The installed helm's major version (3, 4, ...), or None."""
    s = helm_version_string(helm_bin)
    m = _VERSION_RE.search(s) if s else None
    return int(m.group(1)) if m else None


def helm_default_kube_version(helm_bin: Optional[str] = None) -> Optional[str]:
    """OBSERVED, not assumed: the Kubernetes version this helm binary renders
    for when `--kube-version` is omitted.

    helm 3 compiled in v1.20.0 (pkg/chartutil/capabilities.go, quoted in
    renderplan.py); helm 4.2 answers v1.36.0, and the constant moves with
    every helm feature release as its vendored client-go moves. A table
    mapping helm version to default would therefore rot silently - so this
    renders a one-ConfigMap probe chart WITHOUT --kube-version and reads
    `.Capabilities.KubeVersion.Version` back out of the binary itself.

    Returns e.g. "1.36.0" (leading 'v' stripped) or None when helm is absent
    or the probe fails. One subprocess per binary per process; cached.
    """
    helm_bin = helm_bin or find_helm()
    if not helm_bin:
        return None
    if helm_bin not in _default_kv_cache:
        _default_kv_cache[helm_bin] = _probe_default_kube_version(helm_bin)
    return _default_kv_cache[helm_bin]


def _probe_default_kube_version(helm_bin: str) -> Optional[str]:
    d = tempfile.mkdtemp(prefix="hpa-helm-probe-")
    try:
        os.makedirs(os.path.join(d, "templates"))
        with open(os.path.join(d, "Chart.yaml"), "w", encoding="utf-8") as f:
            f.write("apiVersion: v2\nname: hpa-probe\nversion: 0.0.0\n")
        with open(os.path.join(d, "templates", "probe.yaml"), "w",
                  encoding="utf-8") as f:
            f.write("apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
                    "  name: hpa-probe\ndata:\n"
                    "  kv: {{ .Capabilities.KubeVersion.Version | quote }}\n")
        out, err = render_chart(d, helm_bin=helm_bin)
        if err or not out:
            return None
        m = re.search(r"kv:\s*\"v?(\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _flatten(text: str, limit: int = 300) -> str:
    """Collapse a subprocess error into one line.

    helm's errors are multi-line ("Error: ...\n\nUse --debug flag ..."). This
    string ends up inside single-line report fields and table cells; splicing
    a newline into one of those does not produce a wrapped message, it
    produces a broken report. Collapse at the source.
    """
    one = " ".join((text or "").split())
    return one if len(one) <= limit else one[:limit].rstrip() + " ..."


def render_chart(chart_dir: str, extra_values: Optional[List[str]] = None,
                 helm_bin: Optional[str] = None,
                 timeout: int = 60,
                 kube_version: Optional[str] = None
                 ) -> Tuple[Optional[str], Optional[str]]:
    """Run `helm template` on chart_dir. Returns (stdout, error).

    `kube_version` is passed straight through to `--kube-version`. When it is
    None helm falls back to a constant compiled into the binary - v1.20.0 on
    the helm 3 line, v1.36.0 on helm 4.2, moving with each helm release;
    `helm_default_kube_version()` measures it - and renderplan.py explains
    why that is almost never what anyone wants. The parameter is not
    defaulted here on purpose: choosing the version is a policy decision and
    belongs to the caller that can see the chart's declared range, not to the
    subprocess wrapper.
    """
    helm_bin = helm_bin or find_helm()
    if not helm_bin:
        return None, "helm binary not found on PATH"
    cmd = [helm_bin, "template", "release-name", chart_dir]
    if kube_version:
        cmd.extend(["--kube-version", kube_version])
    for vf in extra_values or []:
        cmd.extend(["-f", vf])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f"helm template failed to run: {_flatten(str(e))}"
    if proc.returncode != 0:
        err = _flatten(proc.stderr or proc.stdout or "")
        return None, f"helm template exited {proc.returncode}: {err}"
    return proc.stdout, None


def rendered_object_ids(output: str) -> List[Tuple[str, str]]:
    """(kind, name) for every object in a `helm template` stream, sorted.

    Used to compare two renders of the same chart at different cluster
    versions. Names, not just kinds: a chart that swaps `autoscaling/v2beta2`
    for `autoscaling/v2` emits the same kind and the same name and is NOT a
    divergence in object identity - it is one the apiVersion check already
    covers. A chart that emits a PodDisruptionBudget only above 1.21 is.
    """
    ids = set()
    for _src, chunk in split_rendered(output):
        try:
            doc = yaml.safe_load(chunk)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if not kind:
            continue
        meta = doc.get("metadata")
        name = meta.get("name") if isinstance(meta, dict) else None
        ids.add((str(kind), str(name) if name else "<unnamed>"))
    return sorted(ids)


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

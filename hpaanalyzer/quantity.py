"""Parsers for Kubernetes resource quantities and JVM memory sizes.

Kubernetes quantities:  100m (cpu millicores), 128Mi, 1Gi, 500M, 2, 0.5
JVM sizes:              -Xmx512m, -Xms1g, 268435456 (bytes), 512k

Both are returned in canonical base units:
  * cpu    -> millicores (int)
  * memory -> bytes (int)
"""

import re
from typing import Optional, Tuple

# Kubernetes suffix multipliers (bytes)
_K8S_MEM_SUFFIX = {
    "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4, "Pi": 1024**5, "Ei": 1024**6,
    "k": 1000, "K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4, "P": 1000**5, "E": 1000**6,
}

_QTY_RE = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*([A-Za-z]*)\s*$")


def parse_cpu(value) -> Optional[int]:
    """Parse a k8s CPU quantity into millicores. Returns None if unparseable."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    m = _QTY_RE.match(s)
    if not m:
        return None
    num, suffix = float(m.group(1)), m.group(2)
    if suffix == "m":
        return int(round(num))
    if suffix == "":
        return int(round(num * 1000))
    # CPU expressed with binary/decimal suffixes is technically legal but insane
    if suffix in _K8S_MEM_SUFFIX:
        return int(round(num * _K8S_MEM_SUFFIX[suffix] * 1000))
    return None


def parse_memory(value) -> Optional[int]:
    """Parse a k8s memory quantity into bytes. Returns None if unparseable.

    Note: a lowercase 'm' suffix is LEGAL k8s syntax meaning MILLI-bytes,
    which is virtually always a typo for Mi. We parse it faithfully so the
    checker can flag it.
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    m = _QTY_RE.match(s)
    if not m:
        return None
    num, suffix = float(m.group(1)), m.group(2)
    if suffix == "":
        return int(num)
    if suffix == "m":                      # millibytes - the classic footgun
        return int(num / 1000)
    if suffix in _K8S_MEM_SUFFIX:
        return int(num * _K8S_MEM_SUFFIX[suffix])
    return None


def is_millibytes(value) -> bool:
    """True when a memory quantity uses the milli suffix (e.g. '512m')."""
    if value is None:
        return False
    m = _QTY_RE.match(str(value).strip())
    return bool(m) and m.group(2) == "m"


def is_byte_scale_suspect(value) -> bool:
    """True for a bare-integer memory quantity (no unit) far too small to be a
    real request/limit - almost certainly a missing Mi/Gi suffix. `memory: 512`
    is 512 BYTES: the container is OOM-killed on its first allocation and never
    starts. Distinct from the '512m' milli-byte typo (see is_millibytes)."""
    if value is None:
        return False
    m = _QTY_RE.match(str(value).strip())
    if not m or m.group(2) != "":          # must carry NO suffix
        return False
    try:
        return 0 < float(m.group(1)) < 1024 ** 2   # under 1 MiB -> not credible
    except ValueError:
        return False


def is_decimal_mem(value) -> bool:
    """True when memory uses decimal (M/G) rather than binary (Mi/Gi) units."""
    if value is None:
        return False
    m = _QTY_RE.match(str(value).strip())
    return bool(m) and m.group(2) in ("k", "K", "M", "G", "T", "P", "E")


# ---------------------------------------------------------------------------
# JVM sizes
# ---------------------------------------------------------------------------

_JVM_SIZE_RE = re.compile(r"^([0-9]+)\s*([kKmMgGtT]?)$")

_JVM_SUFFIX = {
    "": 1,
    "k": 1024, "K": 1024,
    "m": 1024**2, "M": 1024**2,
    "g": 1024**3, "G": 1024**3,
    "t": 1024**4, "T": 1024**4,
}


def parse_jvm_size(value: str) -> Optional[int]:
    """Parse a JVM -Xmx style size (512m, 2g, 1048576) into bytes."""
    if value is None:
        return None
    m = _JVM_SIZE_RE.match(str(value).strip())
    if not m:
        return None
    return int(m.group(1)) * _JVM_SUFFIX[m.group(2)]


# ---------------------------------------------------------------------------
# Human formatting
# ---------------------------------------------------------------------------

def fmt_bytes(n: Optional[int]) -> str:
    if n is None:
        return "?"
    if n <= 0:
        return f"{n} B"
    for unit, size in (("Gi", 1024**3), ("Mi", 1024**2), ("Ki", 1024)):
        if n >= size:
            v = n / size
            return f"{v:.0f} {unit}B" if abs(v - round(v)) < 0.005 else f"{v:.1f} {unit}B"
    return f"{n} B"


def fmt_millicores(n: Optional[int]) -> str:
    if n is None:
        return "?"
    if n % 1000 == 0:
        return f"{n // 1000} core" + ("s" if n != 1000 else "")
    return f"{n}m"


def mib(n: Optional[int]) -> Optional[float]:
    """Bytes -> MiB (float)."""
    return None if n is None else n / (1024**2)


def resolve_resource(container: dict, section: str, resource: str) -> Tuple[Optional[str], object]:
    """Fetch container.resources.<section>.<resource>. Returns (raw, parsed)."""
    try:
        raw = container["resources"][section][resource]
    except (KeyError, TypeError):
        return None, None
    parsed = parse_cpu(raw) if resource == "cpu" else parse_memory(raw)
    return raw, parsed

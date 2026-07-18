"""Helm-template-tolerant YAML parsing.

Helm templates are NOT valid YAML until rendered. This module scrubs Go
template actions into resolvable markers so the document structure can be
statically analyzed WITHOUT running helm:

  * ``{{ .Values.image.tag }}``            -> ``HELMVAL@image.tag``
  * ``{{ toYaml .Values.resources | ... }}`` -> ``HELMVAL@resources``
  * ``{{ include "x.labels" . | ... }}``   -> ``HELMINC@x.labels``
  * control actions (if/else/end/range/with) -> blanked (line numbers kept)
  * anything else                          -> ``HELMTPL``

After YAML parsing, markers referring to .Values paths are resolved against
the merged values so checks see the *effective* configuration.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

TPL_MARKER = "HELMTPL"
VAL_PREFIX = "HELMVAL@"
VALD_PREFIX = "HELMVALD@"      # .Values ref with a | default literal
INC_PREFIX = "HELMINC@"

_ACTION_RE = re.compile(r"\{\{-?\s*(.*?)\s*-?\}\}", re.DOTALL)
_COMMENT_RE = re.compile(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", re.DOTALL)
# NOTE: 'template' is NOT control flow - {{ template "x" . }} emits content
# exactly like include and must reach _INCLUDE_RE below.
_CONTROL_RE = re.compile(r"^(if|else|end|range|with|define|block)\b")
_VALUES_REF_RE = re.compile(r"^\.Values\.([A-Za-z0-9_.\-]+)")
_TOYAML_RE = re.compile(r"^toYaml\s+\.Values\.([A-Za-z0-9_.\-]+)")
_INCLUDE_RE = re.compile(r'^(?:include|template)\s+"([^"]+)"')
_DEFAULT_RE = re.compile(r'^\.Values\.([A-Za-z0-9_.\-]+)\s*\|\s*default\s+("[^"]*"|\'[^\']*\'|\S+)')


def _classify_action(body: str) -> str:
    """Map one {{ ... }} body to a replacement token."""
    body = body.strip()
    if _CONTROL_RE.match(body):
        return ""                                   # control flow -> drop
    if body.startswith(".Release.Name"):
        return "RELEASE-NAME"                       # match helm's own placeholder
    if body.startswith(".Release.Namespace"):
        return "RELEASE-NAMESPACE"
    if body.startswith(".Chart.Name"):
        return "CHART-NAME"
    m = _TOYAML_RE.match(body)
    if m:
        return VAL_PREFIX + m.group(1)
    m = _DEFAULT_RE.match(body)
    if m:
        dflt = m.group(2).strip().strip('"').strip("'")
        if not dflt.startswith(".") and "@" not in dflt:
            return f"{VALD_PREFIX}{m.group(1)}@{dflt}"
        return VAL_PREFIX + m.group(1)
    m = _VALUES_REF_RE.match(body)
    if m:
        return VAL_PREFIX + m.group(1)
    m = _INCLUDE_RE.match(body)
    if m:
        return INC_PREFIX + m.group(1)
    return TPL_MARKER


def scrub_template(text: str) -> str:
    """Replace Go-template actions, preserving line numbers."""
    # 1. comments (may span lines): replace with equivalent number of newlines
    def _comment_sub(m):
        return "\n" * m.group(0).count("\n")
    text = _COMMENT_RE.sub(_comment_sub, text)

    # 2. actions
    def _action_sub(m):
        token = _classify_action(m.group(1))
        return token + "\n" * m.group(0).count("\n")
    text = _ACTION_RE.sub(_action_sub, text)

    # 3. line-level cleanup: a line whose only content was control flow is now
    #    whitespace; a line like 'key: ' followed by nothing stays valid YAML.
    cleaned: List[str] = []
    for line in text.split("\n"):
        if line.strip() == "":
            cleaned.append("")
            continue
        cleaned.append(line.rstrip())
    return "\n".join(cleaned)


class DuplicateKeyError(Exception):
    def __init__(self, key, line):
        self.key, self.line = key, line
        super().__init__(f"duplicate key {key!r} at line {line}")


def _make_dup_loader():
    """SafeLoader subclass that records duplicate mapping keys."""
    duplicates: List[Tuple[str, int]] = []

    class Loader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError:
                key = str(key)
            if key in mapping:
                duplicates.append((str(key), key_node.start_mark.line + 1))
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    Loader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    return Loader, duplicates


def load_yaml_docs(text: str):
    """Parse (possibly multi-doc) YAML. Returns (docs, duplicates, error)."""
    loader_cls, duplicates = _make_dup_loader()
    try:
        docs = [d for d in yaml.load_all(text, Loader=loader_cls) if d is not None]
        return docs, duplicates, None
    except yaml.YAMLError as e:
        return [], duplicates, str(e)


# ---------------------------------------------------------------------------
# Values lookup / marker resolution
# ---------------------------------------------------------------------------

def values_lookup(values: Dict[str, Any], dotted: str):
    """Look up 'a.b.c' in a nested dict. Returns (found, value)."""
    node: Any = values
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return False, None
    return True, node


def resolve_markers(obj: Any, values: Dict[str, Any]) -> Any:
    """Recursively resolve HELMVAL@ markers against merged values."""
    if isinstance(obj, str):
        m = re.fullmatch(rf"{VALD_PREFIX}([A-Za-z0-9_.\-]+)@(.*)", obj)
        if m:                                     # .Values ref | default literal
            found, v = values_lookup(values, m.group(1))
            if found and v is not None:
                return resolve_markers(v, values)
            try:
                return yaml.safe_load(m.group(2))
            except yaml.YAMLError:
                return m.group(2)
        m = re.fullmatch(rf"{VAL_PREFIX}([A-Za-z0-9_.\-]+)", obj)
        if m:                                     # the WHOLE string is one marker
            found, v = values_lookup(values, m.group(1))
            return resolve_markers(v, values) if found else obj
        if VAL_PREFIX in obj:                     # embedded in a larger string
            def _sub(m):
                found, v = values_lookup(values, m.group(1))
                if found and isinstance(v, (str, int, float, bool)):
                    return str(v)
                return m.group(0)
            return re.sub(rf"{VAL_PREFIX}([A-Za-z0-9_.\-]+)", _sub, obj)
        return obj
    if isinstance(obj, dict):
        return {k: resolve_markers(v, values) for k, v in obj.items()}
    if isinstance(obj, list):
        return [resolve_markers(v, values) for v in obj]
    return obj


def is_unresolved(value: Any) -> bool:
    """True when a value is still a template marker after resolution."""
    return isinstance(value, str) and (
        value == TPL_MARKER or value.startswith(VAL_PREFIX)
        or value.startswith(VALD_PREFIX)
        or value.startswith(INC_PREFIX) or TPL_MARKER in value)


def line_of(text: str, pattern: str):
    """1-based line number of the first regex match, or None."""
    m = re.search(pattern, text or "", re.MULTILINE)
    return (text[:m.start()].count("\n") + 1) if m else None


def enclosing_conditions(text: str, target_pattern: str):
    """Control-flow conditions enclosing the first line matching target_pattern.

    Scans the RAW template with a proper open/close stack over Go-template
    actions (if/range/with push, end pops, else negates the innermost if),
    instead of pattern-matching one blessed idiom. Returns:
      None  -> target not found in the file
      []    -> target found, not inside any control block
      [..]  -> condition expressions (innermost last); an else-branch is
               represented as 'NOT (<original condition>)'
    """
    m = re.search(target_pattern, text, re.MULTILINE)
    if m is None:
        return None
    pos = m.start()
    stack: List[str] = []
    for am in _ACTION_RE.finditer(text):
        if am.start() >= pos:
            break
        body = am.group(1).strip()
        if re.match(r"(if|range|with|define|block)\b", body):
            stack.append(body)
        elif re.match(r"else\s+if\b", body):
            if stack:
                stack[-1] = body[len("else"):].strip()
        elif re.match(r"else\b", body):
            if stack:
                stack[-1] = f"NOT ({stack[-1]})"
        elif re.match(r"end\b", body):
            if stack:
                stack.pop()
    # define/block delimit named-template SCOPE, not conditional rendering -
    # they are tracked for stack balance but are not conditions.
    return [s for s in stack if not re.match(r"(define|block)\b", s)]


def deep_merge(base: Dict, override: Dict) -> Dict:
    """Helm-style merge: an override value of null DELETES an existing base
    key (helm's documented way to unset a default); a null for a key the
    base never had is kept as an ordinary null value."""
    out = dict(base)
    for k, v in (override or {}).items():
        if v is None and k in out:
            del out[k]
        elif isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out

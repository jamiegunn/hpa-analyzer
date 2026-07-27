"""Dockerfile parsing and Java runtime forensics.

Extracts instructions, base images (multi-stage aware), the Java major
version and (for Java 8/11) the update/patch level, JAVA_OPTS-style env
vars, JVM flags embedded in ENTRYPOINT/CMD, and lifecycle-relevant facts
(exec vs shell form, USER, HEALTHCHECK).
"""

import re
import shlex
from typing import Dict, List, Optional, Tuple

from .models import DockerfileInfo

# env var names commonly used to pass JVM options
JAVA_OPT_VARS = (
    "JAVA_OPTS", "JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS",
    "CATALINA_OPTS", "JVM_OPTS", "JAVA_ARGS", "JVM_ARGS", "_JAVA_OPTIONS",
)

_LINE_CONT_RE = re.compile(r"\\\s*$")
_INSTR_RE = re.compile(r"^\s*([A-Za-z]+)\s+(.*)$", re.DOTALL)
# BuildKit heredoc opener: RUN <<EOT / <<-EOT / <<"EOT" / <<'EOT' (2021+).
_HEREDOC_RE = re.compile(r"<<[-~]?\s*([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _heredoc_terminators(instr_line: str) -> List[str]:
    """Terminator words for every heredoc opened on one instruction line
    (e.g. `RUN <<A cat >a <<B cat >b` opens A then B)."""
    return [m.group(2) for m in _HEREDOC_RE.finditer(instr_line)]

# base image -> java detection
_IMAGE_JAVA_PATTERNS = [
    # (regex on "repo:tag", groups give major / update info)
    # NOTE: the repo segment must BE openjdk/java (optionally +digits), not
    # merely start with it - 'myco/javaservice:1.2.3' is NOT a JDK image.
    re.compile(r"(?:^|/)(?:openjdk|java)\d*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)eclipse-temurin[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)temurin[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)amazoncorretto[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)adoptopenjdk[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)zulu-openjdk[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)liberica[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)sapmachine[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)ibm-semeru[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"(?:^|/)graalvm[^:]*:(?P<tag>[^\s]+)"),
    re.compile(r"distroless/java(?P<major_direct>\d+)?[^:]*:?(?P<tag>[^\s]*)"),
    re.compile(r"(?:ubi\d+|openshift)/openjdk-(?P<major_direct>\d+)"),
    re.compile(r"adoptopenjdk/openjdk(?P<major_direct>\d+)"),
]

_TAG_MAJOR_RE = re.compile(r"^(?:jdk-?|jre-?)?(\d+)(?:u(\d+))?")
_TAG_DOTTED_RE = re.compile(r"^(?:jdk-?|jre-?)?(\d+)\.(\d+)\.(\d+)")
_TAG_LEGACY_RE = re.compile(r"^1\.(\d+)\.0[._](\d+)")   # 1.8.0_131 style


def _strip_comments_join(text: str) -> List[Tuple[int, str]]:
    """Return logical instructions as (first_line_no, full_text).

    BuildKit heredoc bodies (`RUN <<EOT ... EOT`) are absorbed into their
    RUN instruction and NEVER emitted as separate logical lines - otherwise a
    heredoc that WRITES a file containing the words `USER 10001` or
    `ENV JAVA_TOOL_OPTIONS=...` would be misread as real Dockerfile
    instructions (fabricating flags and suppressing the real root/heap
    findings). The body text stays attached to the RUN so nothing downstream
    (which only mines ENV/ENTRYPOINT/CMD) ever treats it as configuration.
    """
    lines = text.split("\n")
    logical: List[Tuple[int, str]] = []
    buf: List[str] = []
    start_line = 0
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw
        stripped = line.strip()
        if not buf:
            if not stripped or stripped.startswith("#"):
                i += 1
                continue
            start_line = i + 1
        else:
            if stripped.startswith("#"):     # comments inside continuations
                i += 1
                continue
        if _LINE_CONT_RE.search(line):
            buf.append(_LINE_CONT_RE.sub("", line))
            i += 1
            continue
        buf.append(line)
        # heredoc(s) opened on this instruction line: swallow the body verbatim
        # up to each terminator so it is never parsed as instructions.
        pending = _heredoc_terminators("\n".join(buf))
        while pending and i + 1 < n:
            i += 1
            body = lines[i]
            buf.append(body)
            if body.strip() == pending[0]:
                pending.pop(0)
        logical.append((start_line, "\n".join(buf)))
        buf = []
        i += 1
    if buf:
        logical.append((start_line, "\n".join(buf)))
    return logical


_PLAUSIBLE = range(5, 41)                      # java versions we accept


def _detect_java_from_tag(tag: str) -> Tuple[Optional[int], Optional[int]]:
    """'8u181-jre-alpine' -> (8, 181); '11.0.16' -> (11, 16);
    '1.8.0_131' -> (8, 131); '17-jre' -> (17, None)."""
    if not tag:
        return None, None
    m = _TAG_LEGACY_RE.match(tag)
    if m:                                     # 1.8.0_131 - keep the update!
        major = int(m.group(1))
        return (major, int(m.group(2))) if major in _PLAUSIBLE else (None, None)
    m = _TAG_DOTTED_RE.match(tag)
    if m:
        major = int(m.group(1))
        if major not in _PLAUSIBLE:           # '1.2.3' app versions etc.
            return None, None
        return major, int(m.group(3))
    m = _TAG_MAJOR_RE.match(tag)
    if m:
        major = int(m.group(1))
        upd = int(m.group(2)) if m.group(2) else None
        if major not in _PLAUSIBLE:
            return None, None
        return major, upd
    return None, None


def _detect_flavor(image: str, tag: str) -> str:
    s = f"{image}:{tag}".lower()
    if "distroless" in s:
        return "distroless"
    if "jre" in s:
        return "jre"
    if "jdk" in s:
        return "jdk"
    return ""


def _extract_env_pairs(args: str) -> List[Tuple[str, str]]:
    """Parse ENV instruction arguments into (key, value) pairs.

    The form is decided by the FIRST token, per Docker's own grammar:
    'ENV KEY=VAL ...' vs legacy 'ENV KEY the rest is the value' - a legacy
    value may itself contain '=' (e.g. -XX:MaxRAMPercentage=75).
    """
    args = args.replace("\\\n", " ").strip()
    first = args.split(None, 1)[0] if args.split() else ""
    pairs: List[Tuple[str, str]] = []
    if "=" in first:
        try:
            tokens = shlex.split(args)
        except ValueError:
            tokens = args.split()
        for tok in tokens:
            if "=" in tok:
                k, _, v = tok.partition("=")
                pairs.append((k, v))
    else:
        parts = args.split(None, 1)              # legacy: ENV KEY value...
        if len(parts) == 2:
            pairs.append((parts[0], parts[1].strip().strip('"').strip("'")))
    return pairs


_JVM_FLAG_RE = re.compile(r"(?<![\w./-])(-(?:X|XX|D|server|client|javaagent|verbose)[^\s\"']*)")

# env vars the JVM reads BY ITSELF, with no entrypoint cooperation
AUTO_READ_VARS = {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}


def extract_jvm_flags(text: str) -> List[str]:
    return _JVM_FLAG_RE.findall(text or "")


def _launcher_text(df: "DockerfileInfo") -> Optional[str]:
    """The command text that actually launches the container process.

    Docker semantics honored:
      * shell-form ENTRYPOINT: CMD is IGNORED entirely.
      * exec-form ENTRYPOINT: CMD (if any) is appended as arguments.
      * no ENTRYPOINT: CMD alone is the launcher.
    (Only final-stage instructions are stored on df - see parse_dockerfile.)
    """
    if df.entrypoint and df.entrypoint["form"] == "shell":
        return df.entrypoint["args"]
    if df.entrypoint:
        text = df.entrypoint["args"]
        if df.cmd:
            text += " " + df.cmd["args"]
        return text
    if df.cmd:
        return df.cmd["args"]
    return None


def _var_referenced(var: str, text: str) -> bool:
    return ("$" + var in text) or ("${" + var in text)


_SCRIPT_TOKEN_RE = re.compile(r"[\w./-]+\.(?:sh|bash)\b")


def referenced_script_paths(df: "DockerfileInfo") -> List[str]:
    """Script files named in ENTRYPOINT/CMD (e.g. ./docker-entrypoint.sh).

    Used to resolve whether a JAVA_OPTS-style var is really inert: if the
    launch script - present in the analyzed directory - does `exec java
    $JAVA_OPTS`, the var IS applied and DF013 must not fire.
    """
    out: List[str] = []
    for rec in (df.entrypoint, df.cmd):
        if rec and rec.get("args"):
            out.extend(_SCRIPT_TOKEN_RE.findall(rec["args"]))
    return out


def _launcher_search_text(df: "DockerfileInfo") -> str:
    """Launcher text PLUS any resolved launch-script body - the full surface
    the JVM's flags could be applied from."""
    base = _launcher_text(df) or ""
    return base + "\n" + (df.launcher_script_text or "")


def effective_flags(df: "DockerfileInfo") -> List[str]:
    """JVM flags that will ACTUALLY apply at runtime.

    An env var's flags count only when the JVM reads the var itself
    (JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS / _JAVA_OPTIONS) or the launcher
    text references it ($VAR under a shell - shell-form, or an explicit
    sh -c). A JAVA_OPTS nothing expands is INERT regardless of form.
    Flags literally present in the launcher always count.
    """
    launcher = _launcher_text(df)
    if launcher is None:
        # no entrypoint/cmd at all: unknowable; count everything (conservative)
        return list(df.jvm_flags)
    search = _launcher_search_text(df)     # includes a resolved launch script
    flags: List[str] = []
    for var, val in df.java_opts.items():
        if var.upper() in AUTO_READ_VARS or _var_referenced(var, search):
            flags.extend(extract_jvm_flags(val))
    flags.extend(extract_jvm_flags(launcher))
    return flags


def inert_opt_vars(df: "DockerfileInfo") -> List[str]:
    """JAVA_OPTS-style vars that are defined but never applied."""
    launcher = _launcher_text(df)
    if launcher is None:
        return []
    # R2: if a launch script (present in the analyzed dir) references the var,
    # it is applied - do not call it inert on the strength of the ENTRYPOINT
    # line alone when the disproving evidence is on disk.
    search = _launcher_search_text(df)
    return [var for var in df.java_opts
            if var.upper() not in AUTO_READ_VARS
            and not _var_referenced(var, search)]


def flag_val(flags: List[str], name: str):
    """Value of -XX:Name=V / -Xmx style flags, or None."""
    for f in flags:
        if f.startswith(f"-XX:{name}="):
            return f.split("=", 1)[1]
        if name in ("Xmx", "Xms", "Xss") and f.startswith(f"-{name}"):
            return f[len(name) + 1:]
    return None


def has_flag(flags: List[str], token: str) -> bool:
    return any(token in f for f in flags)


def parse_dockerfile(path: str, text: str) -> DockerfileInfo:
    """Multi-stage aware: only FINAL-stage ENV/ENTRYPOINT/CMD/USER shape the
    runtime image - builder-stage tuning never reaches the shipped JVM."""
    info = DockerfileInfo(path=path, raw=text)
    args_defaults: Dict[str, str] = {}
    stage = -1
    env_records: List[Tuple[int, str, str]] = []     # (stage, key, value)
    user_records: List[Tuple[int, str]] = []         # (stage, user)
    ep_recs: Dict[str, Dict] = {}                    # ENTRYPOINT/CMD last-wins

    for line_no, logical in _strip_comments_join(text):
        m = _INSTR_RE.match(logical)
        if not m:
            continue
        instr = m.group(1).upper()
        rest = m.group(2).strip()
        info.instructions.append({"instr": instr, "args": rest, "line": line_no})

        if instr == "ARG":
            k, _, v = rest.partition("=")
            if v:
                args_defaults[k.strip()] = v.strip().strip('"').strip("'")

        elif instr == "FROM":
            stage += 1
            # substitute ARG defaults
            ref = re.sub(r"\$\{?(\w+)\}?",
                         lambda mm: args_defaults.get(mm.group(1), mm.group(0)),
                         rest.split()[0])
            image, _, tag = ref.partition(":")
            entry = {"image": image, "tag": tag, "stage": stage,
                     "line": line_no, "raw": rest}
            info.base_images.append(entry)

        elif instr == "ENV":
            for k, v in _extract_env_pairs(rest):
                env_records.append((stage, k, v))

        elif instr in ("ENTRYPOINT", "CMD"):
            form = "exec" if rest.lstrip().startswith("[") else "shell"
            ep_recs[instr] = {"form": form, "args": rest, "line": line_no,
                              "stage": stage}

        elif instr == "USER":
            user_records.append((stage, rest))

        elif instr == "HEALTHCHECK":
            info.healthcheck = True

        elif instr == "EXPOSE":
            info.exposed_ports.extend(rest.split())

    final_stage = stage
    info.multistage = len(info.base_images) > 1

    # final-stage-only runtime facts ------------------------------------------
    for s, k, v in env_records:
        if s == final_stage and k.upper() in JAVA_OPT_VARS:
            info.java_opts[k] = v
    ep = ep_recs.get("ENTRYPOINT")
    if ep and ep["stage"] == final_stage:
        info.entrypoint = ep
    cmd = ep_recs.get("CMD")
    if cmd and cmd["stage"] == final_stage:
        info.cmd = cmd
    final_users = [u for s, u in user_records if s == final_stage]
    info.user = final_users[-1] if final_users else None

    info.jvm_flags = []
    for v in info.java_opts.values():
        info.jvm_flags.extend(extract_jvm_flags(v))
    for rec in (info.entrypoint, info.cmd):
        if rec:
            info.jvm_flags.extend(extract_jvm_flags(rec["args"]))

    if info.base_images:
        info.final_base = info.base_images[-1]
        image, tag = info.final_base["image"], info.final_base["tag"]
        full = f"{image}:{tag}"
        for pat in _IMAGE_JAVA_PATTERNS:
            mm = pat.search(full)
            if mm:
                gd = mm.groupdict()
                if gd.get("major_direct"):
                    info.java_major = int(gd["major_direct"])
                major, upd = _detect_java_from_tag(gd.get("tag") or "")
                if major and not info.java_major:
                    info.java_major = major
                if upd is not None:
                    info.java_update = upd
                break
        # fallback: apk/apt installs of a jdk - FINAL stage lines only
        if info.java_major is None:
            final_text = "\n".join(
                text.split("\n")[info.final_base["line"] - 1:])
            mm = re.search(r"openjdk-?(\d+)", final_text)
            if mm and int(mm.group(1)) in _PLAUSIBLE:
                info.java_major = int(mm.group(1))
        info.java_flavor = _detect_flavor(image, tag)
    return info

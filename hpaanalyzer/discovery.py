"""Directory discovery: locate chart, values files, templates, Dockerfiles.

Rendering strategy (recorded in ctx.render_mode and the report's coverage
section — never silent):

  1. helm_mode 'auto'/'on' and a Chart.yaml exists and helm is on PATH:
     `helm template` renders ground truth. Templates that do NOT render
     with the current values (disabled flags) are additionally parsed
     statically and analyzed as conditional (rendered=False).
  2. Otherwise: static scrub-parse of every template, with per-file
     success/failure recorded in ctx.coverage.
"""

import os
import re
from typing import Dict, List, Optional, Tuple

import yaml

from .dockerparse import parse_dockerfile, referenced_script_paths
from .helmrender import (find_helm, render_chart, rendered_object_ids,
                         split_rendered)
from .renderplan import plan
from .helmyaml import (deep_merge, load_yaml_docs, resolve_markers,
                       scrub_template)
from .kube import dockerfile_jvm_evidence
from .models import ChartContext, ManifestDoc, MeasuredValues

_SKIP_DIRS = {".git", "node_modules", ".idea", "__pycache__", ".helm"}
# F11: a pathological multi-MB template took ~tens of seconds to scrub-parse
# with no bound, making a CI job look hung. Real chart templates are KBs.
_MAX_TEMPLATE_BYTES = 1_000_000
_VALUES_RE = re.compile(r"^values([.\-_].*)?\.ya?ml$", re.IGNORECASE)
_DOCKERFILE_RE = re.compile(r"^(dockerfile([.\-_].*)?|.*\.dockerfile)$", re.IGNORECASE)
_ASSUME_JAVA_RE = re.compile(r"^(\d+)(?:u(\d+)|\.0\.(\d+))?$")


def _rel(root: str, path: str) -> str:
    return os.path.relpath(path, root)


def discover(target: str, helm_mode: str = "auto",
             assume_java: Optional[str] = None,
             kube_version: Optional[str] = None,
             measured: Optional[Dict[str, int]] = None) -> ChartContext:
    ctx = ChartContext(root=os.path.abspath(target))
    ctx.kube_version_override = kube_version
    # `MeasuredValues.of`, not `dict(...)`: the plain-dict copy this used
    # to be silently discarded the literals the user typed, so the budget
    # table cited `metaspace=220200960` back at somebody who wrote 210Mi.
    ctx.measured = MeasuredValues.of(measured)
    chart_dirs: List[str] = []
    values_paths: List[str] = []
    dockerfile_paths: List[str] = []
    template_paths: List[str] = []

    for dirpath, dirnames, filenames in os.walk(ctx.root):
        if "charts" in dirnames:
            # Name them here, from the directory listing, rather than only
            # from the render. The names are a fact about the filesystem and
            # are true in static mode too, where nothing gets rendered at all
            # - and "there is a subchart called worker that I did not read" is
            # a materially different statement from "1 object(s) SKIPPED".
            cdir = os.path.join(dirpath, "charts")
            try:
                entries = sorted(os.listdir(cdir))
            except OSError:
                entries = []
            if entries:
                ctx.subcharts_present = True
            for e in entries:
                nm = e[:-4] if e.endswith(".tgz") else e
                if (os.path.isdir(os.path.join(cdir, e)) or e.endswith(".tgz")) \
                        and nm not in ctx.subchart_names:
                    ctx.subchart_names.append(nm)
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and d != "charts"]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if fn in ("Chart.yaml", "Chart.yml"):
                chart_dirs.append(dirpath)
            elif _VALUES_RE.match(fn):
                values_paths.append(full)
            elif _DOCKERFILE_RE.match(fn):
                dockerfile_paths.append(full)
            elif fn == "values.schema.json":
                ctx.schema_json = True
            elif fn == ".helmignore":
                ctx.helmignore = True
        if os.path.basename(dirpath) == "templates":
            for fn in sorted(os.listdir(dirpath)):
                full = os.path.join(dirpath, fn)
                if os.path.isfile(full) and fn.endswith((".yaml", ".yml", ".tpl", ".txt")):
                    template_paths.append(full)
            tests_dir = os.path.join(dirpath, "tests")
            if os.path.isdir(tests_dir):
                ctx.tests_dir = True
                for fn in sorted(os.listdir(tests_dir)):
                    full = os.path.join(tests_dir, fn)
                    if os.path.isfile(full) and fn.endswith((".yaml", ".yml")):
                        template_paths.append(full)

    chart_dir = None
    if chart_dirs:
        chart_dir = sorted(chart_dirs, key=lambda d: (len(d), d))[0]
        # outermost chart; ties broken LEXICOGRAPHICALLY so the same
        # repo selects the same chart on every OS (os.walk order is
        # filesystem-dependent - macOS and Linux disagree)
        for name in ("Chart.yaml", "Chart.yml"):
            p = os.path.join(chart_dir, name)
            if os.path.isfile(p):
                ctx.chart_yaml_path = _rel(ctx.root, p)
                try:
                    with open(p, encoding="utf-8", errors="replace") as f:
                        ctx.chart_yaml_raw = f.read()
                    ctx.chart = yaml.safe_load(ctx.chart_yaml_raw) or {}
                except yaml.YAMLError as e:
                    ctx.parse_errors.append(f"{ctx.chart_yaml_path}: {e}")
                break

    # F1: when several charts live under one root, analysing them as one merges
    # unrelated values across chart boundaries and fabricates cross-chart
    # findings. Scope EVERY input to the chosen chart's own subtree and record
    # the others as separate, un-analysed charts (never silently merged).
    if len(set(chart_dirs)) > 1 and chart_dir is not None:
        prefix = chart_dir + os.sep
        under = lambda p: p == chart_dir or p.startswith(prefix)
        values_paths = [p for p in values_paths if under(p)]
        dockerfile_paths = [p for p in dockerfile_paths if under(p)]
        template_paths = [p for p in template_paths if under(p)]
        chosen_rel = _rel(ctx.root, chart_dir)
        for d in sorted(set(chart_dirs)):
            if d == chart_dir:
                continue
            ctx.foreign_charts.append(_rel(ctx.root, d))
            ctx.coverage.append(
                [_rel(ctx.root, d),
                 "SEPARATE CHART - NOT analyzed (values never merged across "
                 "chart boundaries); run the analyzer against it directly"])

    ctx.chart_dir_abs = chart_dir
    _load_values(ctx, values_paths)
    _load_templates(ctx, template_paths, chart_dir, helm_mode)
    _load_dockerfiles(ctx, dockerfile_paths, assume_java)

    non_helper = [t for t in ctx.template_files
                  if not (os.path.basename(t).endswith(".tpl")
                          or os.path.basename(t) == "NOTES.txt")
                  and not _is_test_template(t)]
    ctx.templates_present = bool(non_helper)

    # F9: a chart whose entire workload surface went unanalyzed (library-chart
    # `{{ include ... }}` bodies that render to zero objects, or templates the
    # static parser could not read) must NOT get a grade - 'not graded' beats a
    # fake grade. The NOT-GRADED machinery already exists for empty input; wire
    # it here so it engages when workload objects are the thing that is missing.
    if ctx.templates_present and not ctx.workloads:
        ctx.ungradeable_reason = (
            "chart templates exist but NO workload object (Deployment / "
            "StatefulSet / DaemonSet / Job / CronJob) could be analyzed from "
            "them - the primary workload surface went unexamined, so any grade "
            "would be a statement about nothing")
        ctx.coverage.append(
            ["<workload analysis>",
             "NOT GRADED - templates present but zero workload objects parsed "
             "(see executive summary)"])

    if ctx.subcharts_present and not ctx.subchart_docs:
        # Only when the render did not already itemise what is behind the
        # boundary. That row says everything this one says and names the
        # objects too; printing both trains the reader to skim the table.
        names = ", ".join(ctx.subchart_names) if ctx.subchart_names else "(unnamed)"
        ctx.coverage.append(
            ["charts/ (subcharts)",
             f"NOT graded - vendored subchart(s) {names} are out of scope; "
             f"nothing inside them is scored, and no finding here is about "
             f"them"])
    return ctx


# ---------------------------------------------------------------------------
# values
# ---------------------------------------------------------------------------

def _load_values(ctx: ChartContext, values_paths: List[str]) -> None:
    for p in sorted(values_paths):
        rel = _rel(ctx.root, p)
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                raw = f.read()
            ctx.values_raw[rel] = raw
            docs, dups, err = load_yaml_docs(raw)
            if err:
                ctx.parse_errors.append(f"{rel}: {err}")
                ctx.coverage.append([rel, "PARSE FAILED - values not analyzed"])
                continue
            ctx.values_files[rel] = docs[0] if docs else {}
            for key, line in dups:
                ctx.parse_errors.append(
                    f"{rel}: duplicate key '{key}' at line {line} "
                    f"(later value silently wins)")
        except OSError as e:
            ctx.parse_errors.append(f"{rel}: {e}")

    base_keys = [k for k in ctx.values_files
                 if os.path.basename(k).lower() in ("values.yaml", "values.yml")]
    merged: Dict = {}
    # F11: every values file gets exactly one coverage row - including files
    # that loaded but are NOT a mapping. A list-valued values.yaml silently
    # missing from coverage hides that the primary analysis ran with an EMPTY
    # value set (a documented-guarantee breach, not a cosmetic omission).
    for k in base_keys:
        v = ctx.values_files[k]
        if isinstance(v, dict):
            merged = deep_merge(merged, v)
            ctx.coverage.append([k, "base values - used for primary analysis"])
        else:
            ctx.coverage.append(
                [k, f"loaded but NOT a mapping ({type(v).__name__}) - EXCLUDED "
                    f"from the merged values; primary analysis ran with an "
                    f"EMPTY value set here (see VA001)"])
    for k in ctx.values_files:
        if k in base_keys:
            continue
        v = ctx.values_files[k]
        if isinstance(v, dict):
            ctx.overlay_values.append(k)
            ctx.coverage.append(
                [k, "overlay values - analyzed as a separate variant"])
        else:
            ctx.coverage.append(
                [k, f"overlay loaded but NOT a mapping ({type(v).__name__}) - "
                    f"NOT analyzed as a variant (see VA001)"])
    if not merged:
        for k, v in ctx.values_files.items():
            if isinstance(v, dict):
                merged = deep_merge(merged, v)
    ctx.values = merged


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------

def is_hook_doc(data) -> bool:
    """True for helm hook objects (tests, pre-install jobs) - not workloads."""
    if not isinstance(data, dict):
        return False
    md = data.get("metadata")
    ann = md.get("annotations") if isinstance(md, dict) else None
    if isinstance(ann, dict):
        return any("helm.sh/hook" in str(k) for k in ann)
    return False


def _is_test_template(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return "tests" in parts


def scrub_parse_templates(ctx: ChartContext,
                          record_coverage: bool = True,
                          record_errors: bool = True) -> List[ManifestDoc]:
    """Static scrub-parse of every non-helper template. Pure; no ctx.docs write."""
    out: List[ManifestDoc] = []
    for rel in ctx.template_files:
        base = os.path.basename(rel)
        if base.endswith(".tpl") or base == "NOTES.txt":
            continue
        if _is_test_template(rel):
            if record_coverage:
                ctx.coverage.append([rel, "helm test hook - lint-only, not "
                                          "workload-checked"])
            continue
        raw = ctx.template_raw.get(rel, "")
        if len(raw) > _MAX_TEMPLATE_BYTES:
            if record_coverage:
                ctx.coverage.append(
                    [rel, f"SKIPPED - template is {len(raw):,} bytes (> "
                          f"{_MAX_TEMPLATE_BYTES:,} guard); NO checks ran on it. "
                          f"Split it or raise the guard."])
            if record_errors:
                ctx.parse_errors.append(
                    f"{rel}: skipped, {len(raw):,} bytes exceeds the "
                    f"{_MAX_TEMPLATE_BYTES:,}-byte template size guard")
            continue
        scrubbed = scrub_template(raw)
        docs, dups, err = load_yaml_docs(scrubbed)
        if err:
            msg = err.splitlines()[0] if err else "unknown"
            if record_errors:
                ctx.parse_errors.append(
                    f"{rel}: could not statically parse after template "
                    f"scrubbing ({msg})")
            if record_coverage:
                ctx.coverage.append(
                    [rel, "PARSE FAILED - NO checks ran on this file"])
            continue
        if record_errors:
            for key, line in dups:
                ctx.parse_errors.append(
                    f"{rel}: duplicate key '{key}' at line {line} "
                    f"(later value silently wins)")
        n = 0
        for d in docs:
            if not isinstance(d, dict):
                continue
            resolved = resolve_markers(d, ctx.values)
            if is_hook_doc(resolved):
                continue
            kind = resolved.get("kind") if isinstance(resolved.get("kind"), str) else None
            api = resolved.get("apiVersion") if isinstance(resolved.get("apiVersion"), str) else None
            out.append(ManifestDoc(file=rel, kind=kind, api_version=api,
                                   data=resolved, raw=raw))
            n += 1
        if record_coverage:
            ctx.coverage.append([rel, f"statically parsed ({n} object(s))"])
    return out


def helm_parse_output(ctx: ChartContext, output: str) -> List[ManifestDoc]:
    """Parse `helm template` stdout into ManifestDocs (real YAML).

    helm's `# Source:` paths are chart-relative; ours are relative to the
    analysis root. When the chart lives in a subdirectory the prefix is
    re-applied so rendered docs match static template paths (otherwise
    every object would appear duplicated as 'not rendered').

    Subchart output (charts/...) is NOT graded - subcharts are declared out
    of scope, and folding a vendored chart's findings into your score would
    misrepresent what you are responsible for. Until R7 it was also *thrown
    away*, which is a different and much worse thing. Every later check then
    reasoned over a world in which those objects did not exist, and at least
    one of them - HP041 - turned that absence into a HIGH-severity OBSERVED
    finding about the user's chart: it asked whether any workload matched an
    HPA's scaleTargetRef, could not see the Deployment helm had just rendered
    from charts/worker, and reported the correct HPA as dangling.

    So they are parked in ctx.subchart_docs: visible to a check that needs to
    distinguish "absent" from "outside where I look", invisible to scoring.
    C2.2 - never report a limit of the method as a finding about the target.
    """
    prefix = ""
    if ctx.chart_dir_abs:
        rel = os.path.relpath(ctx.chart_dir_abs, ctx.root)
        if rel != ".":
            prefix = rel.replace(os.sep, "/")
    out: List[ManifestDoc] = []
    for src, chunk in split_rendered(output):
        if src.startswith("charts/"):
            _record_subchart_chunk(ctx, src, chunk)
            continue
        if prefix and src:
            src = f"{prefix}/{src}"
        docs, dups, err = load_yaml_docs(chunk)
        if err:
            ctx.parse_errors.append(f"helm output ({src or '?'}): {err.splitlines()[0]}")
            continue
        for key, line in dups:
            ctx.parse_errors.append(
                f"{src or 'helm output'}: duplicate key '{key}' in RENDERED "
                f"output (later value silently wins)")
        for d in docs:
            if not isinstance(d, dict):
                continue
            if is_hook_doc(d) or _is_test_template(src):
                continue
            kind = d.get("kind") if isinstance(d.get("kind"), str) else None
            api = d.get("apiVersion") if isinstance(d.get("apiVersion"), str) else None
            out.append(ManifestDoc(file=src, kind=kind, api_version=api,
                                   data=d, raw=ctx.template_raw.get(src, "")))
    if ctx.subchart_docs:
        ctx.coverage.append(
            ["charts/ (subcharts)", _subchart_coverage_note(ctx)])
    return out


def _record_subchart_chunk(ctx: ChartContext, src: str, chunk: str) -> None:
    """Park one `charts/...` document: recorded, named, never graded.

    Parse failures here are deliberately swallowed rather than pushed into
    ctx.parse_errors. A parse error is reported to the user as a gap in the
    analysis of THEIR chart, and this document was never going to be part of
    that analysis - surfacing it would be the mirror image of the bug this
    function exists to fix, reporting something out of scope as if it bore on
    the score. The object simply stays unknown, which is the honest state.
    """
    # 'charts/worker/templates/deploy.yaml' -> 'worker'; nested subcharts
    # ('charts/a/charts/b/...') attribute to the outermost, which is the one
    # the user actually vendored.
    parts = src.split("/")
    name = parts[1] if len(parts) > 1 else "(unnamed)"
    if name not in ctx.subchart_names:
        ctx.subchart_names.append(name)
    docs, _dups, err = load_yaml_docs(chunk)
    if err:
        return
    for d in docs:
        if not isinstance(d, dict):
            continue
        if is_hook_doc(d) or _is_test_template(src):
            continue
        kind = d.get("kind") if isinstance(d.get("kind"), str) else None
        api = d.get("apiVersion") if isinstance(d.get("apiVersion"), str) else None
        ctx.subchart_docs.append(
            ManifestDoc(file=src, kind=kind, api_version=api, data=d, raw=""))


def _subchart_coverage_note(ctx: ChartContext, cap: int = 8) -> str:
    """One coverage line that says WHAT went ungraded, by kind and name.

    The pre-R7 line was `N object(s) SKIPPED`. A count cannot be acted on: it
    does not tell the reader whether the thing they are looking for is behind
    the boundary, so a reader with a question the tool refused to answer had
    no way to find that out from the report.
    """
    ids = []
    for d in ctx.subchart_docs:
        nm = ""
        if isinstance(d.data, dict):
            nm = str((d.data.get("metadata") or {}).get("name") or "")
        ids.append(f"{d.kind or '?'}/{nm}" if nm else (d.kind or "?"))
    shown = ", ".join(ids[:cap])
    more = f", +{len(ids) - cap} more" if len(ids) > cap else ""
    names = ", ".join(ctx.subchart_names) or "(unnamed)"
    return (f"{len(ids)} object(s) rendered from subchart(s) {names} were "
            f"RECORDED but NOT graded: {shown}{more}. They are visible to "
            f"existence checks (so a correct reference into a subchart is not "
            f"reported as dangling) and to nothing else - no finding, no score "
            f"impact. Run the analyzer against the subchart directly to grade "
            f"it.")


def _probe_divergence(ctx: ChartContext, chart_dir: str, helm_bin: str,
                      rp, primary_output: str) -> None:
    """Render the chart a second time at the floor of its declared range.

    The tool has to pick ONE cluster version to analyse at, and any pick is
    a claim that the answer does not depend on the pick. This tests that
    claim instead of assuming it: if the chart emits a different set of
    objects at the bottom of its own supported range than at the top, then
    no single-version report - including the one about to be printed -
    describes the whole chart, and the reader needs to know which half they
    are holding.

    A failed probe render is recorded, never silently dropped: "we could not
    check" is a different statement from "we checked and it was fine" (C2.2).
    """
    if not rp.probe:
        return
    probe_out, probe_err = render_chart(chart_dir, helm_bin=helm_bin,
                                        kube_version=rp.probe)
    if probe_out is None:
        ctx.render_divergence = {"checked": False, "probe": rp.probe,
                                 "error": probe_err}
        return
    at_top = rendered_object_ids(primary_output)
    at_floor = rendered_object_ids(probe_out)
    only_top = [i for i in at_top if i not in at_floor]
    only_floor = [i for i in at_floor if i not in at_top]
    ctx.render_divergence = {
        "checked": True,
        "at": rp.version, "probe": rp.probe,
        "only_at": [f"{k}/{n}" for k, n in only_top],
        "only_at_probe": [f"{k}/{n}" for k, n in only_floor],
        "diverges": bool(only_top or only_floor),
        "n_at": len(at_top), "n_probe": len(at_floor),
    }


def _load_templates(ctx: ChartContext, template_paths: List[str],
                    chart_dir: Optional[str], helm_mode: str) -> None:
    for p in sorted(set(template_paths)):
        rel = _rel(ctx.root, p)
        base = os.path.basename(p)
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except OSError as e:
            ctx.parse_errors.append(f"{rel}: {e}")
            continue
        ctx.template_files.append(rel)
        ctx.template_raw[rel] = raw
        if base == "_helpers.tpl" or base.endswith(".tpl"):
            ctx.helpers_tpl = True
        if base == "NOTES.txt":
            ctx.notes_txt = True

    use_helm = helm_mode in ("auto", "on") and chart_dir is not None
    helm_bin = find_helm() if use_helm else None
    ctx.helm_present = bool(find_helm())

    if use_helm and helm_bin:
        # R4: decide which cluster helm should render FOR before rendering.
        # Left to helm, the answer is the v1.20.0 constant compiled into
        # pkg/chartutil/capabilities.go, which either refuses the chart
        # outright or silently evaluates .Capabilities for a cluster that
        # went end-of-life in 2022. renderplan.plan() reads the chart's own
        # declared range - already parsed in R3 - and picks on purpose.
        rp = plan((ctx.chart or {}).get("kubeVersion"), ctx.kube_version_override)
        ctx.render_kube_version = rp.version
        ctx.render_version_source = rp.source
        ctx.render_version_reason = rp.reason
        ctx.render_probe_version = rp.probe
        output, err = render_chart(chart_dir, helm_bin=helm_bin,
                                   kube_version=rp.version)
        if output is not None:
            _probe_divergence(ctx, chart_dir, helm_bin, rp, output)
            rendered = helm_parse_output(ctx, output)
            ctx.docs = rendered
            ctx.render_mode = "helm"
            rendered_keys = {(d.kind, d.file) for d in rendered}
            rendered_kinds = {d.kind for d in rendered}
            for rel in ctx.template_files:
                if any(d.file == rel for d in rendered):
                    ctx.coverage.append([rel, "rendered by helm"])
            # templates that exist but did not render with current values
            scrub_docs = scrub_parse_templates(ctx, record_coverage=False,
                                               record_errors=False)
            for sd in scrub_docs:
                if not sd.kind:
                    continue
                if (sd.kind, sd.file) in rendered_keys:
                    continue
                # unmatched-by-file but same kind rendered elsewhere: skip
                if sd.file == "" and sd.kind in rendered_kinds:
                    continue
                sd.rendered = False
                ctx.docs.append(sd)
                ctx.coverage.append(
                    [sd.file, f"{sd.kind}: NOT rendered with current values - "
                              f"analyzed as conditional"])
            return
        ctx.helm_error = err
        ctx.render_mode = f"static (helm ran and refused: {err})"
    elif use_helm and not helm_bin:
        ctx.render_mode = "static (helm not found on PATH)"
    elif helm_mode == "on":
        ctx.render_mode = "static (helm requested but no chart directory)"
    else:
        ctx.render_mode = "static"

    ctx.docs = scrub_parse_templates(ctx, record_coverage=True)


# ---------------------------------------------------------------------------
# dockerfiles
# ---------------------------------------------------------------------------

def parse_assumed_java(spec: str) -> Optional[Tuple[int, Optional[int]]]:
    m = _ASSUME_JAVA_RE.match(spec.strip())
    if not m:
        return None
    major = int(m.group(1))
    upd = m.group(2) or m.group(3)
    return major, (int(upd) if upd else None)


def _attach_launcher_scripts(info, docker_dir: str) -> None:
    """R2: if ENTRYPOINT/CMD invokes a launch script that sits in the same
    directory as the Dockerfile, read it so the applied-flags analysis can see
    what the script actually does (e.g. `exec java $JAVA_OPTS`)."""
    texts: List[str] = []
    for spath in referenced_script_paths(info):
        cand = os.path.normpath(os.path.join(docker_dir, spath.lstrip("./")))
        # only read files that resolve inside the docker directory
        if os.path.isfile(cand) and os.path.commonpath(
                [os.path.abspath(cand), os.path.abspath(docker_dir)]
                ) == os.path.abspath(docker_dir):
            try:
                with open(cand, encoding="utf-8", errors="replace") as sf:
                    texts.append(sf.read())
            except OSError:
                pass
    info.launcher_script_text = "\n".join(texts)


def _load_dockerfiles(ctx: ChartContext, dockerfile_paths: List[str],
                      assume_java: Optional[str]) -> None:
    assumed = parse_assumed_java(assume_java) if assume_java else None
    if assume_java and not assumed:
        ctx.parse_errors.append(
            f"--assume-java '{assume_java}' not understood "
            f"(expected forms: 8, 8u151, 11.0.16, 17)")
    for p in sorted(dockerfile_paths):
        rel = _rel(ctx.root, p)
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                raw = f.read()
            info = parse_dockerfile(rel, raw)
            _attach_launcher_scripts(info, os.path.dirname(p))
            if info.java_major is None and assumed:
                info.java_major, info.java_update = assumed
                ctx.assumed_java = assume_java
                ctx.coverage.append(
                    [rel, f"Java version ASSUMED {assume_java} (--assume-java)"])
            elif info.java_major is None and dockerfile_jvm_evidence(info):
                ctx.coverage.append(
                    [rel, "Java version UNKNOWN - JVM version checks reduced; "
                          "use --assume-java"])
            elif info.java_major is None:
                # R8: a Dockerfile with no JVM in it does not have an unknown
                # Java version - it has no Java version. Telling an nginx
                # operator to re-run with --assume-java is the coverage table's
                # copy of the same invention the checks used to make.
                ctx.coverage.append(
                    [rel, "parsed; no JVM detected in this image (no JRE/JDK "
                          "base, no java entrypoint, no JVM flags) - "
                          "image-level Java version checks not applicable"])
            else:
                v = (f"Java {info.java_major}"
                     + (f"u{info.java_update}" if info.java_update is not None
                        and info.java_major == 8 else ""))
                ctx.coverage.append([rel, f"parsed ({v} detected)"])
            ctx.dockerfiles.append(info)
        except OSError as e:
            ctx.parse_errors.append(f"{rel}: {e}")

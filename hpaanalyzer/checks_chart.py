"""Checks: Helm chart structure, Chart.yaml hygiene, values files, templates."""

import re
from typing import Any

from .helmyaml import line_of, values_lookup
from .kube import DEPRECATED_APIS, RECOMMENDED_LABELS, doc_name
from .models import AnalysisResult, Category, ChartContext, Finding, Severity

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$")


def run(ctx: ChartContext, result: AnalysisResult) -> None:
    _multi_chart(ctx, result)
    _chart_yaml(ctx, result)
    _chart_files(ctx, result)
    _values_files(ctx, result)
    _template_text(ctx, result)
    _api_versions(ctx, result)
    _labels(ctx, result)
    _parse_errors(ctx, result)


def _add(result, **kw):
    result.add(Finding(**kw))


def _multi_chart(ctx, result):
    """F1: several Chart.yamls under one root. Discovery has already scoped the
    analysis to the outermost chart and refused to merge across boundaries; this
    surfaces that decision so a junior pointing at a monorepo root is never
    silently shown one chart's overlay applied to another chart's templates."""
    if not ctx.foreign_charts:
        return
    others = ", ".join(ctx.foreign_charts)
    _add(result, rule_id="CH030", severity=Severity.HIGH, category=Category.CHART,
         title="Multiple charts under one directory - only one was analyzed",
         file="",
         detail=f"Found {len(ctx.foreign_charts) + 1} Chart.yaml files. Analysis "
                f"was scoped to '{ctx.chart_yaml_path}'; NOT analyzed: {others}.",
         why="Merging values across chart boundaries (one chart's "
             "values-prod.yaml over another's templates) fabricates findings "
             "against healthy charts. The analyzer refuses to do that and "
             "reports on one chart at a time.",
         fix="Point the analyzer at each chart directory separately, e.g. "
             f"`hpa-analyzer {ctx.foreign_charts[0]}`.")


def _chart_yaml(ctx, result):
    if not ctx.chart_yaml_path:
        _add(result, rule_id="CH001", severity=Severity.CRITICAL, category=Category.CHART,
             title="No Chart.yaml found", file="",
             detail="No Chart.yaml exists anywhere under the target directory.",
             why="Without Chart.yaml this is not an installable Helm chart; helm "
                 "install/upgrade, versioning and provenance are all impossible.",
             fix="Create Chart.yaml with apiVersion: v2, name, version (SemVer) "
                 "and appVersion at the chart root.")
        return
    c = ctx.chart or {}
    f = ctx.chart_yaml_path

    # R1: Chart.yaml that is valid YAML but the wrong SHAPE (a list, or a bare
    # scalar) used to crash on the first `.get()`. A malformed input must become
    # a finding, not an uncaught exception colliding with the gate-failure exit
    # code. (Syntax-broken YAML is already handled upstream as a parse error.)
    if not isinstance(c, dict):
        _add(result, rule_id="CH012", severity=Severity.CRITICAL, category=Category.CHART,
             title="Chart.yaml is not a mapping", file=f,
             detail=f"Top-level YAML type is {type(c).__name__}; a Chart.yaml "
                    f"must be a key: value mapping.",
             why="Helm cannot load a chart whose Chart.yaml is a list or scalar; "
                 "install/upgrade fail immediately. The analyzer treats it as a "
                 "finding rather than crashing.",
             fix="Restructure Chart.yaml as apiVersion/name/version key: value "
                 "pairs.")
        return

    api = c.get("apiVersion")
    if api == "v1":
        _add(result, rule_id="CH002", severity=Severity.MEDIUM, category=Category.CHART,
             title="Chart apiVersion v1 (Helm 2 era)", file=f,
             detail=f"Chart.yaml declares apiVersion: v1.",
             why="apiVersion v1 targets Helm 2, which reached end of life in Nov 2020 "
                 "(no security fixes). v2 charts support dependencies in Chart.yaml "
                 "and library charts.",
             fix="Set apiVersion: v2 and manage dependencies via the 'dependencies' "
                 "key instead of requirements.yaml.")
    elif api != "v2":
        _add(result, rule_id="CH003", severity=Severity.HIGH, category=Category.CHART,
             title="Missing/invalid chart apiVersion", file=f,
             detail=f"apiVersion is {api!r}; expected 'v2'.",
             why="Helm refuses to install charts without a valid apiVersion.",
             fix="Add 'apiVersion: v2' to Chart.yaml.")

    if not c.get("name"):
        _add(result, rule_id="CH004", severity=Severity.HIGH, category=Category.CHART,
             title="Chart has no name", file=f,
             detail="Chart.yaml is missing the required 'name' field.",
             why="helm install fails without a chart name.",
             fix="Add a lowercase, dash-separated 'name'.")

    ver = c.get("version")
    if not ver:
        _add(result, rule_id="CH005", severity=Severity.HIGH, category=Category.CHART,
             title="Chart has no version", file=f,
             detail="Chart.yaml is missing the required 'version' field.",
             why="Helm requires SemVer chart versions; releases, rollbacks and "
                 "repository indexing depend on it.",
             fix="Add 'version: 0.1.0' (SemVer 2) and bump it on every change.")
    elif not _SEMVER_RE.match(str(ver)):
        _add(result, rule_id="CH006", severity=Severity.MEDIUM, category=Category.CHART,
             title="Chart version is not SemVer", file=f,
             detail=f"version: {ver!r} does not match MAJOR.MINOR.PATCH.",
             why="helm package/repo tooling assumes SemVer; sorting and constraint "
                 "matching (e.g. in Chart dependencies) break otherwise.",
             fix="Use a SemVer 2 version like 1.4.2.")

    if not c.get("appVersion"):
        _add(result, rule_id="CH007", severity=Severity.LOW, category=Category.CHART,
             title="No appVersion in Chart.yaml", file=f,
             detail="appVersion is not set.",
             why="appVersion documents which application build the chart deploys and "
                 "is the conventional default for the image tag "
                 "(.Chart.AppVersion). Without it, image tags tend to drift to "
                 "'latest'.",
             fix="Set appVersion to the deployed application version and reference "
                 "it as the default image tag.")

    if not c.get("description"):
        _add(result, rule_id="CH008", severity=Severity.LOW, category=Category.CHART,
             title="No chart description", file=f,
             detail="description is not set.",
             why="Descriptions surface in 'helm search' and chart repos; missing "
                 "metadata makes the chart look unmaintained.",
             fix="Add a one-line description.")

    if not c.get("maintainers"):
        _add(result, rule_id="CH009", severity=Severity.INFO, category=Category.CHART,
             title="No maintainers listed", file=f,
             detail="maintainers is not set.",
             why="Ownership metadata matters once a chart is shared beyond one team.",
             fix="Add maintainers with name/email.")

    if not c.get("kubeVersion"):
        _add(result, rule_id="CH010", severity=Severity.LOW, category=Category.CHART,
             title="No kubeVersion constraint", file=f,
             detail="kubeVersion is not set.",
             why="Without a kubeVersion constraint the chart will happily install "
                 "onto clusters whose APIs it does not support (e.g. autoscaling/v2 "
                 "requires Kubernetes >= 1.23), failing at apply time instead of "
                 "install time.",
             fix='Add e.g. kubeVersion: ">=1.23.0-0".')

    if c.get("icon") is None and c.get("home") is None and c.get("sources") is None:
        _add(result, rule_id="CH011", severity=Severity.INFO, category=Category.CHART,
             title="No icon/home/sources metadata", file=f,
             detail="None of icon, home, sources are set.",
             why="Cosmetic, but repos/UIs (ArtifactHub, Rancher) use them.",
             fix="Add links if the chart is published.")


def _chart_files(ctx, result):
    if not ctx.chart_yaml_path:
        return
    if not ctx.values_files:
        _add(result, rule_id="CH020", severity=Severity.HIGH, category=Category.CHART,
             title="No values.yaml", file="",
             detail="No values file found.",
             why="A chart without values.yaml has no documented, overridable "
                 "configuration surface; every setting is hardcoded in templates.",
             fix="Create values.yaml exposing image, resources, autoscaling, "
                 "probes and securityContext.")
    if not ctx.helpers_tpl:
        _add(result, rule_id="CH021", severity=Severity.LOW, category=Category.CHART,
             title="No _helpers.tpl", file="",
             detail="templates/_helpers.tpl not found.",
             why="Name/label boilerplate gets duplicated per template without "
                 "helpers, which is how label drift (and broken selectors) happens.",
             fix="Add _helpers.tpl with <chart>.name, <chart>.fullname, "
                 "<chart>.labels and <chart>.selectorLabels helpers.")
    if not ctx.notes_txt:
        _add(result, rule_id="CH022", severity=Severity.INFO, category=Category.CHART,
             title="No NOTES.txt", file="",
             detail="templates/NOTES.txt not found.",
             why="NOTES.txt is printed after install and is the cheapest "
                 "documentation you can ship.",
             fix="Add templates/NOTES.txt with connection/usage hints.")
    if not ctx.schema_json:
        _add(result, rule_id="CH023", severity=Severity.LOW, category=Category.CHART,
             title="No values.schema.json", file="",
             detail="values.schema.json not found.",
             why="Schema validation rejects typo'd or type-mismatched values at "
                 "install time (e.g. memory: 512 instead of '512Mi') - exactly the "
                 "class of error that breaks resources/HPA silently.",
             fix="Add values.schema.json (JSON Schema) covering at least resources "
                 "and autoscaling blocks.")
    if not ctx.helmignore:
        _add(result, rule_id="CH024", severity=Severity.INFO, category=Category.CHART,
             title="No .helmignore", file="",
             detail=".helmignore not found.",
             why="Packaged charts pick up junk (.git, editor files) without it.",
             fix="Add a .helmignore.")
    if not ctx.tests_dir:
        _add(result, rule_id="CH025", severity=Severity.INFO, category=Category.CHART,
             title="No helm test hooks", file="",
             detail="templates/tests/ not found.",
             why="'helm test' smoke tests catch broken releases immediately after "
                 "install/upgrade.",
             fix="Add a tests/ pod that curls the service readiness endpoint.")


_LATEST_TAG_RE = re.compile(r"tag:\s*['\"]?latest['\"]?", re.IGNORECASE)


def _values_files(ctx, result):
    for path, vals in ctx.values_files.items():
        if not isinstance(vals, dict):
            _add(result, rule_id="VA001", severity=Severity.HIGH, category=Category.CHART,
                 title="Values file is not a mapping", file=path,
                 detail=f"Top-level YAML type is {type(vals).__name__}.",
                 why="Helm expects values files to be a mapping; anything else "
                     "makes --set/merging behave unpredictably.",
                 fix="Restructure the file as key: value pairs.")
            continue

        # image tag checks
        found, tag = values_lookup(vals, "image.tag")
        if found and (tag is None or str(tag).strip() in ("", "latest")):
            _add(result, rule_id="VA002", severity=Severity.HIGH, category=Category.CHART,
                 title="Image tag is 'latest' or empty", file=path,
                 detail=f"image.tag is {tag!r}.",
                 why="'latest' is mutable: two pods of the same ReplicaSet can run "
                     "different builds after a node pulls a newer image; rollbacks "
                     "become impossible because the tag no longer identifies a "
                     "build. With imagePullPolicy:Always a registry outage blocks "
                     "pod restarts.",
             fix="Pin an immutable tag (version or git SHA), ideally defaulting "
                 "to .Chart.AppVersion; use digests for maximum reproducibility.")
        found, pp = values_lookup(vals, "image.pullPolicy")
        if found and str(pp) == "Always" and not (tag in (None, "latest", ""))\
                and isinstance(tag, str):
            _add(result, rule_id="VA003", severity=Severity.LOW, category=Category.CHART,
                 title="pullPolicy Always with pinned tag", file=path,
                 detail=f"image.pullPolicy=Always while image.tag={tag!r} is immutable.",
                 why="Always re-pulls on every pod start: slower cold starts and a "
                     "hard runtime dependency on the registry for no benefit when "
                     "tags are immutable.",
                 fix="Use IfNotPresent with immutable tags.")

        # empty resources block (the classic helm create default)
        found, res = values_lookup(vals, "resources")
        if found and (res is None or res == {}):
            _add(result, rule_id="VA004", severity=Severity.HIGH, category=Category.RESOURCES,
                 title="Empty resources block in values", file=path,
                 detail="'resources: {}' - no requests or limits are set.",
                 why="Empty resources means every pod is scheduled as BestEffort/"
                     "unbounded: the scheduler places it assuming zero footprint, "
                     "HPA CPU-utilization metrics cannot be computed at all "
                     "(utilization = usage / REQUEST), and the JVM inside can be "
                     "OOM-killed by node pressure first.",
                 fix="Set requests (scheduling guarantee) and limits (protection) "
                     "sized from observed usage; see the math tables below.")

        # replicaCount vs autoscaling
        f_rc, rc = values_lookup(vals, "replicaCount")
        f_auto, auto_en = values_lookup(vals, "autoscaling.enabled")
        if f_rc and isinstance(rc, int) and rc == 1 and not (f_auto and auto_en):
            _add(result, rule_id="VA005", severity=Severity.MEDIUM, category=Category.AVAIL,
                 title="Single replica, no autoscaling", file=path,
                 detail=f"replicaCount: 1 and autoscaling disabled/absent.",
                 why="One replica means every deploy, node drain, OOM kill or JVM "
                     "crash is a full outage. Availability of one pod = availability "
                     "of one node * one process.",
                 fix="Run >=2 replicas for anything user-facing (with a "
                     "PodDisruptionBudget and pod anti-affinity), or enable the HPA.")

        # template syntax inside values (not rendered!)
        raw = ctx.values_raw.get(path, "")
        if "{{" in raw:
            _add(result, rule_id="VA006", severity=Severity.HIGH, category=Category.CHART,
                 title="Go template syntax inside values file", file=path,
                 detail="Found '{{' in a values file.",
                 why="Helm does NOT render templates inside values files; the "
                     "literal string '{{ ... }}' is passed to the cluster, which "
                     "then rejects it or stores garbage.",
                 fix="Move templating into templates/ (or use the tpl function on "
                     "the value from within a template).")


_HARDCODED_NS_RE = re.compile(r"^\s*namespace:\s*['\"]?(?!HELMTPL|HELMVAL|\{)([a-z0-9-]+)['\"]?\s*$",
                              re.MULTILINE)


def _template_text(ctx, result):
    for path, raw in ctx.template_raw.items():
        if path.endswith((".tpl", "NOTES.txt")):
            continue
        if "\t" in raw:
            _add(result, rule_id="TP001", severity=Severity.MEDIUM, category=Category.TEMPLATES,
                 title="Tab characters in YAML template", file=path,
                 detail="File contains literal tab characters.",
                 why="YAML forbids tabs for indentation; whether this renders "
                     "correctly depends on where the tabs sit - a rendering time bomb.",
                 fix="Replace tabs with spaces.")
        m = _HARDCODED_NS_RE.search(raw)
        if m:
            _add(result, rule_id="TP002", severity=Severity.MEDIUM, category=Category.TEMPLATES,
                 title="Hardcoded namespace in template", file=path,
                 line=raw[:m.start()].count("\n") + 1,
                 detail=f"namespace: {m.group(1)} is hardcoded.",
                 why="Hardcoding the namespace breaks 'helm install -n <ns>' and "
                     "makes multi-env installs collide.",
                 fix="Omit metadata.namespace (Helm applies the release namespace) "
                     "or use {{ .Release.Namespace }}.")
        for todo in re.finditer(r"(TODO|FIXME|XXX|HACK)\b", raw):
            _add(result, rule_id="TP003", severity=Severity.INFO, category=Category.TEMPLATES,
                 title=f"{todo.group(1)} marker in template", file=path,
                 detail=f"Found '{todo.group(1)}' in {path}.",
                 why="Unfinished work shipping to production.",
                 fix="Resolve or ticket it.")
            break  # one per file is enough
        if re.search(r"image:.*:latest\b", raw):
            _add(result, rule_id="TP004", severity=Severity.HIGH, category=Category.TEMPLATES,
                 title="Hardcoded ':latest' image in template", file=path,
                 detail="A container image is hardcoded to the ':latest' tag.",
                 why="Mutable tags destroy reproducibility and rollback (see VA002).",
                 fix="Parameterize the tag through values with an immutable default.")


def _api_versions(ctx, result):
    for doc in ctx.docs:
        if not doc.kind or not doc.api_version:
            continue
        key = (doc.api_version, doc.kind.lower())
        if key in DEPRECATED_APIS:
            removed_in, replacement = DEPRECATED_APIS[key]
            ln = line_of(ctx.template_raw.get(doc.file, ""),
                         r"apiVersion:\s*" + re.escape(doc.api_version))
            _add(result, rule_id="TP010", severity=Severity.CRITICAL, category=Category.TEMPLATES,
                 title=f"Deprecated/removed apiVersion for {doc.kind}", file=doc.file,
                 line=ln,
                 detail=f"{doc.kind} '{doc_name(doc)}' uses apiVersion "
                        f"{doc.api_version}, removed in Kubernetes {removed_in}.",
                 why=f"On clusters >= {removed_in} the API server rejects this "
                     f"object outright: helm upgrade fails and the release can get "
                     f"stuck (existing release manifests reference dead APIs).",
                 fix=f"Move to {replacement} and adjust the spec to the new schema.")


def _labels(ctx, result):
    for doc in ctx.docs:
        if not isinstance(doc.data, dict) or not doc.kind:
            continue
        md = doc.data.get("metadata")
        labels = md.get("labels") if isinstance(md, dict) else None
        has_helper = False
        if isinstance(labels, str) and labels.startswith("HELMINC@"):
            has_helper = True
        if isinstance(labels, dict):
            keys = set(labels.keys())
            if any(str(k).startswith("HELMINC@") for k in keys):
                has_helper = True
            missing = [l for l in RECOMMENDED_LABELS if l not in keys]
            if not has_helper and len(missing) == len(RECOMMENDED_LABELS):
                _add(result, rule_id="TP011", severity=Severity.LOW, category=Category.TEMPLATES,
                     title=f"{doc.kind} missing app.kubernetes.io/* labels", file=doc.file,
                     detail=f"{doc.kind} '{doc_name(doc)}' has none of the "
                            f"recommended labels ({', '.join(RECOMMENDED_LABELS)}).",
                     why="Standard labels power kubectl selectors, cost tooling, "
                         "service meshes and dashboards; ad-hoc labels fragment all "
                         "of that.",
                     fix="Emit labels via a shared _helpers.tpl 'labels' helper.")
        elif labels is None and not has_helper:
            _add(result, rule_id="TP012", severity=Severity.LOW, category=Category.TEMPLATES,
                 title=f"{doc.kind} has no labels at all", file=doc.file,
                 detail=f"{doc.kind} '{doc_name(doc)}' defines no metadata.labels.",
                 why="Unlabeled objects are invisible to selectors and monitoring.",
                 fix="Add the standard app.kubernetes.io/* label set.")


def _parse_errors(ctx, result):
    for err in ctx.parse_errors:
        sev = Severity.HIGH if "duplicate key" in err else Severity.MEDIUM
        _add(result, rule_id="PA001", severity=sev, category=Category.CHART,
             title="Parse problem", file=err.split(":")[0],
             detail=err,
             why="Files that cannot be parsed (or contain duplicate keys, where "
                 "the last value silently wins) hide their real configuration "
                 "from both this analyzer and from humans reviewing the chart.",
             fix="Fix the syntax; run 'helm template' and a YAML linter in CI.")

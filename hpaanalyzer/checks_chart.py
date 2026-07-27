"""Checks: Helm chart structure, Chart.yaml hygiene, values files, templates."""

import re

from . import kubeversion as kv
from .helmyaml import line_of, values_lookup
from .kube import (API_AVAILABLE_SINCE, DEPRECATED_APIS, RECOMMENDED_LABELS,
                   doc_name, empty_values_resources_reach_a_container)
from .models import (AnalysisResult, Basis, Category, ChartContext, Finding,
                     Severity)

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$")

# The capability-gate detector lives in renderplan, next to the source
# quotations that justify it, so the rule and its explanation cannot drift
# apart. (helm's default kube-version is no longer imported here: it depends
# on the installed binary - 1.20 on helm 3, newer on helm 4 - and is measured
# into ctx.helm_default_version rather than assumed from a constant.)
from .renderplan import capability_gates  # noqa: E402


def run(ctx: ChartContext, result: AnalysisResult) -> None:
    _multi_chart(ctx, result)
    _chart_yaml(ctx, result)
    _chart_files(ctx, result)
    _values_files(ctx, result)
    _template_text(ctx, result)
    _api_versions(ctx, result)
    _labels(ctx, result)
    _render_divergence(ctx, result)
    _api_version_gate(ctx, result)
    _parse_errors(ctx, result)


def _add(result, **kw):
    result.add(Finding(**kw))


def _render_divergence(ctx, result):
    """CH015: the chart emits different objects at different points inside
    its OWN declared kubeVersion range.

    Every static analysis of a Helm chart has to pick one cluster version to
    reason about, and that pick is an implicit claim: that the answer does
    not depend on the pick. discovery._probe_divergence tests the claim by
    rendering at both ends of the declared range and diffing the emitted
    (kind, name) sets. When they differ the claim is false, and the honest
    thing is to say so rather than to pick a winner - because there is no
    winner. The chart genuinely is two different charts depending on where it
    lands, and the reader is the only one who knows which cluster they have.

    Note what this rule does NOT fire on. Swapping `autoscaling/v2beta2` for
    `autoscaling/v2` behind a `.Capabilities` test emits the same kind with
    the same name at both versions, so it is not an object-identity
    divergence; TP010/TP013 already cover apiVersion drift. This fires when
    an object EXISTS at one version and not the other - a PodDisruptionBudget
    that appears only above 1.21, an HPA that vanishes below 1.23 - because
    that is the case where a whole object silently escapes analysis.
    """
    div = ctx.render_divergence
    if not div:
        return

    if not div.get("checked"):
        # C2.2: "we could not check" is not "we checked and it was fine".
        # It gets an INFO so the gap is visible, not a silent pass.
        _add(result, rule_id="CH015", severity=Severity.INFO,
             category=Category.CHART,
             title="Could not verify the chart renders consistently across "
                   "its declared range",
             file=ctx.chart_yaml_path or "",
             detail=f"The chart rendered at {ctx.render_kube_version}, but the "
                    f"comparison render at {div.get('probe')} (the bottom of "
                    f"its declared kubeVersion range) failed: "
                    f"{div.get('error')}.",
             why="This report describes one cluster version. Whether it also "
                 "describes the other end of the range is unknown - not "
                 "confirmed. Treat the object set below as covering "
                 f"{ctx.render_kube_version} only.",
             fix=f"Run `helm template release-name <chart> --kube-version "
                 f"{div.get('probe')}` by hand and compare the object list "
                 f"with this report's.",
             basis=Basis.OBSERVED)
        return

    if not div.get("diverges"):
        return

    only_at = div.get("only_at") or []
    only_probe = div.get("only_at_probe") or []
    bits = []
    if only_at:
        bits.append(f"only at {div['at']}: " + ", ".join(only_at))
    if only_probe:
        bits.append(f"only at {div['probe']}: " + ", ".join(only_probe))

    _add(result, rule_id="CH015", severity=Severity.MEDIUM,
         category=Category.CHART,
         title="Chart emits different objects at different points in its own "
               "declared kubeVersion range",
         file=ctx.chart_yaml_path or "",
         detail=(f"Rendered at {div['at']} ({div['n_at']} object(s)) and at "
                 f"{div['probe']} ({div['n_probe']} object(s)); " +
                 "; ".join(bits) + "."),
         why="The chart branches on `.Capabilities` (KubeVersion or "
             "APIVersions.Has), so `helm template` is a function of the "
             "cluster version, not just of the chart. Every finding in this "
             f"report was computed from the {div['at']} render, which means "
             f"the objects listed as present only at {div['probe']} were "
             "NEVER ANALYZED - no rule ran against them, and their absence "
             "from the findings below is not evidence that they are clean. "
             "This is the one case where a single-version report cannot be "
             "complete, so it is stated rather than papered over.",
         fix=f"Re-run with --kube-version set to the cluster you actually "
             f"deploy to, and - if you support the whole declared range - run "
             f"it once per end of the range and read both reports. If the "
             f"branch is no longer needed, delete it and narrow kubeVersion "
             f"instead: a range you do not test is a range you do not "
             f"support.",
         basis=Basis.OBSERVED)


# ---------------------------------------------------------------------------
# CH016: the chart's output depends on a question `helm template` answers
# wrongly by construction.
# ---------------------------------------------------------------------------

def _gv_exists_at(gv: str, minor):
    """Does group/version `gv` exist on a real cluster at `minor`?

    Returns True / False / None, where None means "this tool has no recorded
    fact about it" - a CRD, an aggregated API, or simply a group/version
    missing from kube.py's tables. None is a real answer here and is reported
    as such; guessing would be exactly the failure this rule exists to name.

    `gv` may be "group/version" or helm's "group/version/Kind" form. For the
    bare form the group/version is present if ANY kind in it is present, which
    is what a real discovery call would report.
    """
    parts = gv.split("/")
    kind = None
    if len(parts) == 3:
        gv, kind = f"{parts[0]}/{parts[1]}", parts[2].lower()
    elif len(parts) == 2 and parts[0] in ("v1",):   # "v1/Pod" core-group form
        gv, kind = parts[0], parts[1].lower()

    kinds = {k[1] for k in API_AVAILABLE_SINCE if k[0] == gv}
    kinds |= {k[1] for k in DEPRECATED_APIS if k[0] == gv}
    if kind is not None:
        kinds &= {kind}
    if not kinds:
        return None

    for k in kinds:
        since = API_AVAILABLE_SINCE.get((gv, k))
        fact = DEPRECATED_APIS.get((gv, k))
        if since is not None and minor < since:
            continue
        if fact is not None and minor >= fact.removed_in:
            continue
        return True
    return False


def _api_version_gate(ctx, result):
    """CH016: withhold confidence in branches gated on `.Capabilities.APIVersions`.

    This is the companion to CH015 and it fires on the case CH015 provably
    CANNOT catch. CH015 renders at both ends of the declared range and diffs
    the objects; a chart gated on APIVersions.Has emits an IDENTICAL object
    set at both ends, so CH015 stays silent - and the silence means "helm gave
    the same answer twice", not "the branch is version-independent".

    The reason, established by reading helm and then by running it rather than
    by recollection (hpaanalyzer/renderplan.py carries the full quotation):

        DefaultVersionSet = allKnownVersions()            // capabilities.go
        func allKnownVersions() VersionSet {
            groups := scheme.Scheme.PrioritizedVersionsAllGroups()

    That is every group/version compiled into the helm binary's vendored
    client-go. It is not a function of --kube-version and it is not a function
    of any cluster. Probed against helm v3.16 and again against helm v4.2 at
    three versions:

        helm 3.16: APIVersions.Has "autoscaling/v2"       true  at 1.16-1.32
                   APIVersions.Has "autoscaling/v2beta1"  true  at 1.16-1.32
        helm 4.2:  APIVersions.Has "autoscaling/v2"       true  at 1.16-1.32
                   APIVersions.Has "autoscaling/v2beta1"  false at 1.16-1.32
                   APIVersions.Has "policy/v1beta1"       true  at 1.16-1.32

    autoscaling/v2 first exists in 1.23; v2beta1 was removed in 1.25;
    policy/v1beta1 was removed in 1.25. Each binary's set describes an
    impossible cluster - helm 3 answers true for groups a 1.16 cluster never
    had, helm 4 answers false for v2beta1 on the 1.16-1.24 clusters that DID
    have it and true for policy/v1beta1 seven minors after its removal - so
    upgrading helm moves the impossibility around without removing it. The
    set also fails in BOTH directions on any binary: a built-in group answers
    from the compiled-in scheme, and a CRD group answers false on clusters
    that do have it, because CRDs are not compiled into helm. And
    `--api-versions` only APPENDS (pkg/action/install.go; re-verified against
    helm 4.2), so there is no invocation that removes an entry and no way for
    any caller to correct either error.

    What this rule therefore does NOT do is guess which branch is right and
    report it. It reports that the rendered branch is not evidence. Severity
    is INFO on purpose and permanently: the chart is not doing anything wrong
    - `.Capabilities.APIVersions.Has` is the documented, recommended idiom and
    is answered correctly by a real `helm install` against a real cluster.
    The defect is in this tool's line of sight, so it costs the chart nothing.
    Withholding a claim never becomes asserting a finding.
    """
    hits = capability_gates(ctx.template_raw)   # (file, line, gv|None)
    if not hits:
        return

    rendered = ctx.render_mode.startswith("helm")
    minor = None
    at = ctx.render_kube_version
    if rendered:
        # When no --kube-version was passed, the version in force is helm's
        # compiled-in default, which depends on the installed binary and was
        # MEASURED into ctx.helm_default_version. If even that measurement is
        # missing, minor stays None and the impossible-at-this-version claim
        # below is withheld rather than computed from an assumed constant.
        src = at or ctx.helm_default_version
        v = kv.parse_version(src) if src else None
        minor = (v.major, v.minor) if v else None
        if not at:
            at = (f"v{ctx.helm_default_version} (helm's compiled-in default, "
                  f"measured from the installed binary)"
                  if ctx.helm_default_version else
                  "helm's compiled-in default (version not measured)")

    files = sorted({p for p, _l, _g in hits})
    gvs = sorted({g for _p, _l, g in hits if g})

    # The concrete, checkable half: a queried group/version that this tool
    # KNOWS does not exist at the version the render claims to be.
    impossible = []
    if minor is not None:
        for gv in gvs:
            if _gv_exists_at(gv, minor) is False:
                impossible.append(gv)

    detail = (f"{len(hits)} `.Capabilities.APIVersions` test(s) in " +
              ", ".join(files) +
              (f"; queried: {', '.join(gvs)}" if gvs else "") + ".")
    if rendered:
        detail += (f" This report was computed from a single render at {at}, "
                   f"so exactly one arm of each of those branches was "
                   f"analyzed.")
    else:
        detail += (" This report was computed by static scrubbing, which does "
                   "not evaluate the branch at all.")
    if impossible:
        verb = "does" if len(impossible) == 1 else "do"
        detail += (f" {', '.join(impossible)} {verb} not exist on a real {at} "
                   f"cluster at all, yet helm's APIVersions set is built from "
                   f"its own compiled-in scheme rather than from the version, "
                   f"so the render's answer for it is unrelated to the truth "
                   f"about that cluster.")

    fix_line = ("Decide which arm applies to the cluster you deploy to and "
                "read this report against that arm. To make the analysis "
                "cover the other arm, render it yourself and inspect it, or "
                "replace the capability test with a version test - "
                "`semverCompare \">=1.23-0\" .Capabilities.KubeVersion.Version` "
                "- which IS controlled by --kube-version and which this tool "
                "then follows correctly. Note that a version test is only "
                "equivalent for built-in APIs; for a CRD the capability test "
                "is the correct idiom and this limitation simply stands.")

    _add(result, rule_id="CH016", severity=Severity.INFO,
         category=Category.CHART,
         title="Rendered branch not verifiable: chart gates on "
               "`.Capabilities.APIVersions`",
         file=files[0] if len(files) == 1 else "",
         line=hits[0][1] if len(files) == 1 else None,
         detail=detail,
         why="`helm template` does not answer `.Capabilities.APIVersions.Has` "
             "from your cluster. It answers from the set of group/versions "
             "compiled into the helm binary, which is the same at every "
             "--kube-version - verified by probing helm v3.16 at 1.16, 1.21 "
             "and 1.32, where `autoscaling/v2` and `autoscaling/v2beta1` are "
             "both true despite never having coexisted on any real cluster. "
             "Built-in groups therefore answer true on clusters that never "
             "had them, and CRD groups answer false on clusters that do have "
             "them. `--api-versions` can only append, so no invocation fixes "
             "either. This tool states that the branch is unverified rather "
             "than reporting the arm helm happened to take as fact; the "
             "findings below describe that arm only, and the other arm was "
             "never analyzed.",
         fix=fix_line,
         basis=Basis.OBSERVED)


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

    _kube_version(ctx, result, c, f)

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
        if found and str(pp) == "Always" and tag not in (None, "latest", "")\
                and isinstance(tag, str):
            _add(result, rule_id="VA003", severity=Severity.LOW, category=Category.CHART,
                 title="pullPolicy Always with pinned tag", file=path,
                 detail=f"image.pullPolicy=Always while image.tag={tag!r} is immutable.",
                 why="Always re-pulls on every pod start: slower cold starts and a "
                     "hard runtime dependency on the registry for no benefit when "
                     "tags are immutable.",
                 fix="Use IfNotPresent with immutable tags.")

        # empty resources block (the classic helm create default)
        #
        # VA004 reads a values key and concludes something about the PODS
        # ("every pod is scheduled as BestEffort"). That inference needs a
        # container that actually consumes .Values.resources. When every
        # container sources its block from a named template instead, the
        # values key is inert - helm renders whatever the define emits, and an
        # empty `resources: {}` in values.yaml is dead weight, not a HIGH.
        # Same defect class as RS001/RS011/HP022; see tests/test_helper_blindness.
        found, res = values_lookup(vals, "resources")
        if found and (res is None or res == {}) and ctx.workloads \
                and not empty_values_resources_reach_a_container(ctx):
            _add(result, rule_id="VA011", severity=Severity.LOW,
                 category=Category.CHART,
                 title="values.yaml declares an empty resources block that no "
                       "container uses", file=path,
                 detail="'resources: {}' is present in values, but no "
                        "container's resources come from it - every container "
                        "either writes the block out or pulls it from a named "
                        "template.",
                 why="Not a scheduling defect - the pods get whatever the "
                     "helper emits. It is a documentation defect: a reader "
                     "tuning resources edits this key and nothing changes.",
                 fix="Delete the key, or make the helper default from it "
                     "(`.Values.resources`) so the values file means what it "
                     "appears to mean.",
                 basis=Basis.DERIVED)
        elif found and (res is None or res == {}):
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


# ---------------------------------------------------------------------------
# kubeVersion: the chart's own statement of which clusters it targets.
#
# Helm does not treat this field as documentation. pkg/action/action.go
# renderResources() (v3.16.4):
#
#     if ch.Metadata.KubeVersion != "" {
#         if !chartutil.IsCompatibleRange(ch.Metadata.KubeVersion, caps.KubeVersion.String()) {
#             return ..., errors.Errorf("chart requires kubeVersion: %s which is
#                 incompatible with Kubernetes %s", ...)
#         }
#     }
#
# So the constraint is executable. That is what licenses the checks below to
# let severity depend on it: an author who narrows kubeVersion until a removed
# API is out of scope has not silenced the tool, they have made helm refuse the
# install that would have failed. Caveat worth knowing and stated in the
# findings: `helm template | kubectl apply` bypasses this gate entirely.
# ---------------------------------------------------------------------------


def _implied_range(ctx):
    """The kubeVersion this chart's own manifests imply.

    Returns (floor, floor_src, ceiling, ceiling_src) as (major, minor) pairs.
    floor is the newest 'available since' among the APIs the chart uses;
    ceiling is the oldest removal among them. Both are computed from the
    chart's actual contents, because advice like 'add kubeVersion: ">=1.23"'
    that ignores what the chart ships is a guess wearing a fact's clothes.

    An apiVersion that appears in neither table contributes nothing rather
    than a guessed bound (contract C2.2: an undetermined quantity must not
    silently contribute).
    """
    floor = ceiling = None
    floor_src = ceiling_src = None
    for doc in ctx.docs:
        if not doc.kind or not doc.api_version:
            continue
        key = (doc.api_version, doc.kind.lower())
        since = API_AVAILABLE_SINCE.get(key)
        if since is not None and (floor is None or since > floor):
            floor, floor_src = since, f"{doc.api_version} {doc.kind}"
        fact = DEPRECATED_APIS.get(key)
        if fact is not None and (ceiling is None or fact.removed_in < ceiling):
            ceiling, ceiling_src = fact.removed_in, f"{doc.api_version} {doc.kind}"
    return floor, floor_src, ceiling, ceiling_src


def _kube_version_fix(ctx):
    """The concrete kubeVersion line to add, derived from the chart."""
    floor, floor_src, ceiling, ceiling_src = _implied_range(ctx)
    fm = kv.fmt_minor
    if floor and ceiling and floor >= ceiling:
        return ("This chart's own manifests admit no consistent range: "
                f"{floor_src} needs Kubernetes >= {fm(floor)}, but "
                f"{ceiling_src} was removed in {fm(ceiling)}. Migrate the "
                "removed API first (see the TP010 findings), then set "
                f'kubeVersion: ">={fm(floor)}.0-0".')
    if floor and ceiling:
        return (f'Add kubeVersion: ">={fm(floor)}.0-0 <{fm(ceiling)}.0-0". '
                f"The floor comes from {floor_src} (available since "
                f"{fm(floor)}) and the ceiling from {ceiling_src} (removed in "
                f"{fm(ceiling)}) - both read off this chart's own templates. "
                "The '-0' suffixes are load-bearing; see CH014.")
    if floor:
        return (f'Add kubeVersion: ">={fm(floor)}.0-0". The floor comes from '
                f"{floor_src}, which this chart uses and which does not exist "
                f"before Kubernetes {fm(floor)}. The '-0' suffix is "
                "load-bearing; see CH014.")
    if ceiling:
        return (f'Add kubeVersion: "<{fm(ceiling)}.0-0", because {ceiling_src} '
                f"is gone from {fm(ceiling)} onward - or better, migrate that "
                "API (see the TP010 findings) and declare a floor instead.")
    return ('Add a kubeVersion range, e.g. kubeVersion: ">=1.23.0-0". No '
            "bound could be derived from this chart's own apiVersions, so "
            "that figure is an example, not a measurement: pick the oldest "
            "cluster you actually intend to support.")


def _kube_version(ctx, result, c, f):
    raw = c.get("kubeVersion")
    rng = kv.declared_range(raw)

    if not rng.declared:
        _add(result, rule_id="CH010", severity=Severity.LOW, category=Category.CHART,
             title="No kubeVersion constraint", file=f,
             detail="kubeVersion is not set.",
             why="Without a kubeVersion constraint the chart will happily install "
                 "onto clusters whose APIs it does not support (e.g. autoscaling/v2 "
                 "requires Kubernetes >= 1.23), failing at apply time instead of "
                 "install time. It also leaves this analyzer unable to tell an "
                 "obsolete apiVersion from a merely old one, so every such finding "
                 "has to be reported at its worst-case severity.",
             fix=_kube_version_fix(ctx))
        return

    if not rng.parsed:
        _add(result, rule_id="CH013", severity=Severity.CRITICAL, category=Category.CHART,
             title="kubeVersion does not parse - chart installs on no cluster",
             file=f, line=line_of(ctx.chart_yaml_raw, r"kubeVersion:"),
             detail=f"kubeVersion: {rng.raw!r} is not a valid SemVer constraint "
                    f"({rng.error}).",
             why="helm/pkg/chartutil/compatible.go:IsCompatibleRange returns FALSE "
                 "when the constraint fails to parse - it does not skip the check. "
                 "So a typo here does not weaken the gate, it closes it: "
                 "'helm install' refuses on every cluster version with 'chart "
                 "requires kubeVersion: ... which is incompatible with Kubernetes "
                 "...'. This is silent in review because Chart.yaml still looks "
                 "like it says something reasonable.",
             fix="Use SemVer constraint syntax, e.g. '>=1.24.0-0 <1.31.0-0'. AND "
                 "is a space or a comma, OR is '||'; words like 'and' and version "
                 "strings like '1,24' do not parse.")
        return

    if not rng.minors and rng.above_domain:
        # NOT CH013. CH013 says "satisfiable by nothing", and here the
        # constraint is satisfiable - just not by any version this analyzer
        # sampled, or by any version Kubernetes has shipped. Reporting the
        # sampling horizon as a property of the constraint would be exactly
        # the C2.2 conflation the tool exists to avoid, and the FIX differs:
        # reversed bounds vs a floor that does not exist yet.
        # Two edges, two sentences. Saying "above 1.60" about a `>=2.0.0-0`
        # chart would be a precise-sounding falsehood, and the whole point of
        # splitting CH017 off CH013 was to stop emitting those.
        if rng.above_domain_edge == kv.AboveDomain.MAJOR:
            where = ("only by Kubernetes 2.0 and later, and no 2.x has ever "
                     "been released")
            more = (f"This analyzer enumerates 1.0 through "
                    f"1.{kv.DOMAIN_MAX_MINOR}; the constraint is outside that "
                    f"on the MAJOR axis, not merely past the horizon.")
            advice = ("Kubernetes has been 1.x for its whole history and the "
                      "project has announced no 2.0. A '2' in a kubeVersion "
                      "floor is almost always a typo for a 1.x minor, or a "
                      "placeholder that was never filled in. Replace it with "
                      "the oldest 1.x you actually support.")
        else:
            where = f"only by versions above 1.{kv.DOMAIN_MAX_MINOR}"
            more = ("That is past this analyzer's sampling horizon AND past "
                    "every Kubernetes release to date.")
            advice = (f"Check the floor digit-by-digit. If a future version "
                      f"really is intended, note that this analyzer only "
                      f"enumerates up to 1.{kv.DOMAIN_MAX_MINOR} and will not "
                      f"reason about the range beyond it.")
        _add(result, rule_id="CH017", severity=Severity.CRITICAL,
             category=Category.CHART,
             title="kubeVersion floor is above every Kubernetes release "
                   "that exists",
             file=f, line=line_of(ctx.chart_yaml_raw, r"kubeVersion:"),
             detail=f"kubeVersion: {rng.raw!r} parses and is satisfiable, but "
                    f"{where}. {more} This is NOT the claim that the "
                    f"constraint is contradictory (see CH013 for that); it is "
                    f"the claim that nothing shipped satisfies it.",
             why="helm/pkg/chartutil/compatible.go:IsCompatibleRange compares "
                 "the constraint against the cluster's real version, so a "
                 "floor no released cluster reaches refuses 'helm install' "
                 "everywhere today - with the same error a reversed range "
                 "produces, which is why they are easy to confuse. The usual "
                 "cause is a typo (1.61 for 1.16, 2.0 or 1.99 as a "
                 "placeholder) rather than a deliberate future pin.",
             fix=advice)
        return

    if not rng.minors:
        _add(result, rule_id="CH013", severity=Severity.CRITICAL, category=Category.CHART,
             title="kubeVersion matches no Kubernetes version",
             file=f, line=line_of(ctx.chart_yaml_raw, r"kubeVersion:"),
             detail=f"kubeVersion: {rng.raw!r} parses, but no Kubernetes 1.x "
                    f"release satisfies it (checked 1.0 through "
                    f"1.{kv.DOMAIN_MAX_MINOR}, and probed above that horizon "
                    f"too - it admits nothing there either).",
             why="The constraint is satisfiable by nothing, so IsCompatibleRange is "
                 "false everywhere and helm refuses to install the chart on any "
                 "cluster. This is usually a reversed or overlapping pair of "
                 "bounds, e.g. '>=1.30.0-0 <1.20.0-0'.",
             fix="Check the bounds are the right way round and that they overlap.")
        return

    if not rng.accepts_prerelease:
        _add(result, rule_id="CH014", severity=Severity.MEDIUM, category=Category.CHART,
             title="kubeVersion excludes every managed cluster",
             file=f, line=line_of(ctx.chart_yaml_raw, r"kubeVersion:"),
             detail=f"kubeVersion: {rng.raw!r} has no prerelease comparator, so it "
                    f"does not match version strings like 'v1.29.3-gke.1093000', "
                    f"'v1.30.0-eks-a5ec690' or 'v1.28.9-aks1'.",
             why="GKE, EKS and AKS report gitVersions that are SemVer PRERELEASES, "
                 "and Masterminds/semver - the library helm uses - excludes "
                 "prerelease versions from any constraint whose comparators carry "
                 "no prerelease part. The effect is not 'slightly stricter': "
                 "'>=1.29.0' matches no GKE cluster at any version, so the chart "
                 "fails to install on every managed cluster while working fine on "
                 "kubeadm and kind.",
             fix="Append '-0' to the lower bound(s): '>=1.29.0' becomes "
                 "'>=1.29.0-0', which is the lowest possible 1.29.0 prerelease and "
                 "so admits '-gke.N' and '-eks-N' builds.")


class _Scope:
    """The set of clusters an apiVersion finding is ranked against.

    R15. There are two sources for "which clusters does this chart have to
    work on", and before this change only the weaker one was ever consulted.

    The chart's `kubeVersion` is a CLAIM the chart makes about itself. The
    operator's `--kube-version` is a STATEMENT ABOUT THE WORLD: it names the
    cluster they actually have. When the two disagree, the chart is the one
    that is wrong - a chart cannot decide what version someone's cluster is.

    Ranking deprecated APIs against the chart's own declaration produces the
    inversion this class exists to remove: c17 declares `>=1.19.0-0 <1.21.0-0`
    and ships a v1beta1 Ingress and PDB. Analysed at `--kube-version 1.31.0`
    the tool used to report both at LOW with the words "Nothing breaks today",
    in the same report in which helm had already refused to render the chart
    against 1.31 at all. Both statements cannot be true. The operator asked
    about 1.31; the answer must be about 1.31.

    `declared` is kept alongside because the disagreement is itself worth
    saying out loud, and because the fix differs: on the chart's own range the
    remedy is to migrate the API, and where the operator's cluster is outside
    that range the remedy is that plus fixing the constraint.
    """

    def __init__(self, ctx, declared):
        self.declared = declared
        self.operator = None
        self.rng = declared
        self.phrase = f"the chart's kubeVersion ({declared.raw})"
        self.from_operator = False
        ver = getattr(ctx, "kube_version_override", None)
        if not ver:
            return
        v = kv.parse_version(str(ver))
        if v is None:
            return
        self.operator = (v.major, v.minor)
        self.rng = kv.DeclaredRange(raw=str(ver), parsed=True,
                                    minors=((v.major, v.minor),))
        self.phrase = f"the cluster you named (--kube-version {ver})"
        self.from_operator = True

    @property
    def conflict(self):
        """The named cluster is outside the range the chart claims to support."""
        return (self.from_operator and self.declared.known
                and not self.declared.includes(*self.operator))

    def note(self):
        if not self.conflict:
            return ""
        return (f" The chart's own kubeVersion ({self.declared.raw}) does not "
                f"admit {kv.fmt_minor(self.operator)}, so helm will refuse to "
                f"install it there until that constraint is corrected - but "
                f"the constraint is the chart's opinion of your cluster, and "
                f"you have stated otherwise, so this finding is ranked against "
                f"the cluster.")


def _api_versions(ctx, result):
    # ctx.chart may be a list or a bare scalar (CH012); a wrong-shaped
    # Chart.yaml must not turn a template check into a traceback.
    chart = ctx.chart if isinstance(ctx.chart, dict) else {}
    rng = kv.declared_range(chart.get("kubeVersion"))
    scope = _Scope(ctx, rng)
    for doc in ctx.docs:
        if not doc.kind or not doc.api_version:
            continue
        key = (doc.api_version, doc.kind.lower())
        fact = DEPRECATED_APIS.get(key)
        if fact is not None:
            _api_removed(ctx, result, doc, fact, scope)
        since = API_AVAILABLE_SINCE.get(key)
        if since is not None:
            _api_too_new(ctx, result, doc, since, scope)


def _api_removed(ctx, result, doc, fact, scope):
    """TP010, reconciled against the cluster range in scope.

    Before R3 this was CRITICAL unconditionally. That made the fix-first list
    stop being an order: a chart pinned to 1.20-1.21 shipping a
    networking.k8s.io/v1beta1 Ingress - which works on every cluster it claims
    to support, and which helm will refuse to install anywhere else - sat at
    the same severity as a chart pinned >=1.33 shipping batch/v1beta1 CronJob,
    which cannot work anywhere. Both are worth reporting. They are not worth
    reporting identically.

    R15: the range in scope is the operator's `--kube-version` when they gave
    one, and the chart's declaration otherwise. See `_Scope`.
    """
    rng = scope.rng
    ln = line_of(ctx.template_raw.get(doc.file, ""),
                 r"apiVersion:\s*" + re.escape(doc.api_version))
    removed = kv.fmt_minor(fact.removed_in)
    title = f"Deprecated/removed apiVersion for {doc.kind}"
    base = (f"{doc.kind} '{doc_name(doc)}' uses apiVersion {doc.api_version}, "
            f"removed in Kubernetes {removed}.")
    fix = f"Move to {fact.replacement} and adjust the spec to the new schema."
    if fact.replacement_since:
        fix += (f" {fact.replacement} exists from Kubernetes "
                f"{kv.fmt_minor(fact.replacement_since)} onward.")
    if fact.note:
        fix += " " + fact.note

    if not rng.known:
        if not rng.declared:
            why_range = "Chart.yaml declares no kubeVersion"
        elif not rng.parsed:
            why_range = f"kubeVersion {rng.raw!r} does not parse (see CH013)"
        else:
            why_range = (f"kubeVersion {rng.raw!r} matches no cluster version "
                         f"(see CH013)")
        _add(result, rule_id="TP010", severity=Severity.CRITICAL,
             category=Category.TEMPLATES, title=title, file=doc.file, line=ln,
             detail=base + f" {why_range}, so the clusters this chart may reach "
                           f"are unknown and nothing stops it reaching one at or "
                           f"above {removed}.",
             why=f"On clusters >= {removed} the API server rejects this object "
                 f"outright: helm upgrade fails and the release can get stuck "
                 f"(existing release manifests reference dead APIs). This is "
                 f"reported at the top severity because the cluster range is "
                 f"undetermined, which is the conservative reading - not because "
                 f"the failure has been confirmed for your cluster.",
             fix=fix + " Declaring kubeVersion (CH010) would also let this "
                       "analyzer rank the finding instead of assuming the worst.")
        return

    above = rng.at_or_above(*fact.removed_in)
    below = rng.below(*fact.removed_in)

    if above and not below:
        if scope.from_operator:
            why = (f"You named this cluster on the command line. The API server "
                   f"at {kv.fmt_minor(scope.operator)} rejects this object "
                   f"outright - `helm upgrade` fails, or succeeds partially and "
                   f"leaves a release referencing a dead API. This is not a "
                   f"portability note about clusters you might one day have; it "
                   f"is about the one you said you have.")
        else:
            why = (f"This is not a portability note. On EVERY cluster this chart "
                   f"claims to support the API server rejects the object, so the "
                   f"chart passes helm's kubeVersion gate and then fails at apply "
                   f"time. There is no cluster on which this chart works as "
                   f"declared.")
        _add(result, rule_id="TP010", severity=Severity.CRITICAL,
             category=Category.TEMPLATES, title=title, file=doc.file, line=ln,
             detail=base + f" {scope.phrase.capitalize()} admits "
                           f"{rng.describe()} - every one of those is at or above "
                           f"{removed}." + scope.note(),
             why=why,
             fix=fix + (" Fixing the chart's kubeVersion alone would not help: "
                        "it would only make helm refuse the install earlier."
                        if scope.conflict else ""))
    elif above and below:
        _add(result, rule_id="TP010", severity=Severity.HIGH,
             category=Category.TEMPLATES, title=title, file=doc.file, line=ln,
             detail=base + f" {scope.phrase.capitalize()} admits "
                           f"{rng.describe()}, which straddles the removal: "
                           f"{kv.fmt_minor(below[0])}-{kv.fmt_minor(below[-1])} "
                           f"still serve this API, "
                           f"{kv.fmt_minor(above[0])}-{kv.fmt_minor(above[-1])} "
                           f"do not.",
             why=f"The chart installs and works on the older part of its own "
                 f"declared range and fails at apply time on the newer part. "
                 f"That is the shape of a defect that passes CI on one cluster "
                 f"and takes down another.",
             fix=fix + f" If migrating is not possible yet, narrowing kubeVersion "
                       f"below {removed} is a real fix and not a workaround: helm "
                       f"will then refuse the installs that would have failed.")
    elif scope.from_operator:
        _add(result, rule_id="TP010", severity=Severity.LOW,
             category=Category.TEMPLATES, title=title, file=doc.file, line=ln,
             detail=base + f" {scope.phrase.capitalize()} is "
                           f"{rng.describe()}, below {removed}, so this API "
                           f"still exists there.",
             why=f"On the cluster you named the API server still serves this "
                 f"version, so nothing fails today. It remains an upgrade "
                 f"blocker: that cluster will reach {removed} before this chart "
                 f"can.",
             fix=fix + f" Nothing breaks on {kv.fmt_minor(scope.operator)}; do "
                       f"this before that cluster is upgraded.")
    else:
        _add(result, rule_id="TP010", severity=Severity.LOW,
             category=Category.TEMPLATES, title=title, file=doc.file, line=ln,
             detail=base + f" The chart's kubeVersion ({rng.raw}) admits only "
                           f"{rng.describe()}, all below {removed}, so this API "
                           f"exists on every cluster the chart claims to support.",
             why=f"Helm refuses to install this chart on a cluster >= {removed} "
                 f"(IsCompatibleRange is enforced at render time), so the removal "
                 f"cannot surface as an outage while the constraint stands. What "
                 f"remains is an upgrade blocker: the cluster will reach "
                 f"{removed} before this chart can.",
             fix=fix + " Nothing breaks today; do this before raising "
                       "kubeVersion.")


def _api_too_new(ctx, result, doc, since, scope):
    """TP013: the API is not old enough for the range the chart declares.

    The mirror image of TP010, and it did not exist before R3 even though
    CH010's own 'why' text cites it verbatim ('autoscaling/v2 requires
    Kubernetes >= 1.23') as the reason to set a constraint. The tool advised
    setting a constraint to prevent a failure it then never checked for.

    Only fires when the declared range is known: with no kubeVersion there is
    no claim to contradict, and inventing one would be a guess.

    R15: when the operator names a cluster, that is not a guess - it is the
    strongest fact available, and it replaces the chart's claim as the thing
    the apiVersion is checked against.
    """
    rng = scope.rng
    if not rng.known:
        return
    missing = rng.below(*since)
    if not missing:
        return
    ln = line_of(ctx.template_raw.get(doc.file, ""),
                 r"apiVersion:\s*" + re.escape(doc.api_version))
    s = kv.fmt_minor(since)
    span = (f"{kv.fmt_minor(missing[0])}-{kv.fmt_minor(missing[-1])}"
            if missing[0] != missing[-1] else kv.fmt_minor(missing[0]))
    everywhere = len(missing) == len(rng.minors)
    if scope.from_operator:
        tail = (f" - the cluster you named does not have this API."
                if everywhere else ".")
        why = (f"You named this cluster on the command line and this API does "
               f"not exist on it. The API server rejects the object at apply "
               f"time with 'no matches for kind', leaving a half-applied "
               f"release.")
        fix_txt = (f"Use an apiVersion that exists on "
                   f"{kv.fmt_minor(scope.operator)}, or deploy to a cluster at "
                   f"{s} or later.")
    else:
        tail = (" - that is every version the chart claims to support."
                if everywhere else ".")
        why = (f"helm's kubeVersion gate passes, because the chart says it "
               f"supports those clusters. Install therefore proceeds and the "
               f"API server rejects the object at apply time with 'no matches "
               f"for kind' - a half-applied release, which is the exact "
               f"failure the kubeVersion field exists to prevent.")
        fix_txt = (f'Raise the floor to at least ">={s}.0-0", or use an '
                   f"apiVersion that exists on {kv.fmt_minor(rng.floor)}.")
    _add(result, rule_id="TP013",
         severity=Severity.CRITICAL if everywhere else Severity.HIGH,
         category=Category.TEMPLATES,
         title=f"apiVersion is newer than the declared kubeVersion floor "
               f"({doc.kind})",
         file=doc.file, line=ln,
         detail=f"{doc.kind} '{doc_name(doc)}' uses apiVersion "
                f"{doc.api_version}, which first exists in Kubernetes {s}. "
                f"{scope.phrase.capitalize()} admits {rng.describe()}, "
                f"including {span} where this API is absent" + tail
                + scope.note(),
         why=why, fix=fix_txt)


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

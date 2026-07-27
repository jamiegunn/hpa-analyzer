"""R18 chart generator: one chart per point in the decision space.

Companion to proof/p20_kindsweep.py, which runs the analyzer over what this
writes. Everything here is a pure function of its arguments - no RNG, no clock -
so a run that finds something on Tuesday finds the same thing on Wednesday.

proof/corpus_charts.py stays exactly where it is. Its 35 charts are the
regression surface for every round up to R17, and deleting them to make a
coverage number look better would be scoring the instrument instead of using it.
This generates ADDITIONAL charts, over the axes that corpus was measured to
miss.

WHAT THE MEASUREMENT SAID (R18 task #67, docs/ITERATIONS.md)

The 35-chart corpus, run under 8 flag combinations - 352 analyzer runs - renders
40 Deployments, 1 StatefulSet and 1 CronJob. Five of the eight workload kinds
the tool accepts had never once been parsed. 90 of 138 rule IDs ever fire; the
48 that never fire are, all 48 of them, gated on a static field shape and not
one of them on a cluster probe. The corpus presents 17 distinct tuples of a
nominal 1024 over five axes: 1.7%.

So the six axes, and why each is here:

  kind        3 of 8 covered. This is the axis R16 and R17 both lived on.
  replicas    the axis the kind lists in kube.py exist to reason about.
  resources   four silent rules key on resource shape and nothing else.
  heap        one silent rule needs >= 85%, another needs -Xmx and
              MaxRAMPercentage together, and the corpus has neither shape.
  hpa         two silent rules key on v1-vs-v2 with no metrics; corpus has v2
              only, plus one v2beta2.
  probes      corpus has exactly three shapes: none, liveness+readiness, and
              all three. Single-probe charts have never been analyzed.

HONEST CAVEAT ABOUT THAT LIST. The axes were chosen with the silent-rule list in
view. That makes this TARGETED coverage, not blind coverage: where a value exists
because a specific rule wanted it, "the corpus found the defect by itself" is a
weaker claim than where the axis is structural. The acceptance test in
p20_kindsweep.py records this as AT5b and reports it failing on every run rather
than passing by deleting the sentences that admit it. What AT5a does hold, and
what actually matters, is that no kind list and no rule ID appears in the code
that decides whether an output is suspicious - only in prose explaining why an
axis exists.

FORCED PER-KIND DELTAS. Charts that differ only in `kind` do not exist - the
API will not have it. Every unavoidable difference is recorded in DELTAS and
printed next to any divergence the sweep reports, so that a difference caused
by `restartPolicy: Never` is never mistaken for a difference caused by a kind
list. This is the trap R17's own measurement nearly fell into.
"""
import os

KINDS = ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
         "ReplicationController", "Job", "CronJob", "Rollout"]

DELTAS = {
    "Deployment": "baseline",
    "StatefulSet": "spec.serviceName is required",
    "DaemonSet": "no spec.replicas field exists on a DaemonSet",
    "ReplicaSet": "none beyond the kind name",
    "ReplicationController": "apiVersion v1; selector is a plain map, "
                             "not selector.matchLabels",
    "Job": "no spec.replicas; restartPolicy: Never is required",
    "CronJob": "spec.schedule required; pod spec nested under "
               "jobTemplate.spec.template; restartPolicy: OnFailure",
    "Rollout": "apiVersion argoproj.io/v1alpha1; strategy.canary instead of "
               "strategy.rollingUpdate",
}

# kinds with no author-chosen replica count: the replicas axis is not
# applicable to them, and forcing one on would be inventing a chart nobody
# would write.
NO_REPLICAS = {"DaemonSet", "Job", "CronJob"}

API = {
    "Deployment": "apps/v1", "StatefulSet": "apps/v1", "DaemonSet": "apps/v1",
    "ReplicaSet": "apps/v1", "ReplicationController": "v1",
    "Job": "batch/v1", "CronJob": "batch/v1",
    "Rollout": "argoproj.io/v1alpha1",
}

REPLICAS = ["absent", "literal", "values", "conditional"]
RESOURCES = ["none", "requests-only", "limits-only", "both", "helper"]
HEAP = ["none", "xmx", "percentage", "both", "percentage-85"]
HPA = ["none", "v1", "v2-cpu", "v2-cpu-mem"]
PROBES = ["none", "liveness", "readiness", "liveness+readiness", "all-three"]

CHART_YAML = """apiVersion: v2
name: {name}
description: R18 generated chart - {desc}
type: application
version: 1.0.0
appVersion: "1.0.0"
"""

HELPERS = """{{- define "gen.resources" -}}
requests:
  cpu: 250m
  memory: 512Mi
limits:
  cpu: "1"
  memory: 1Gi
{{- end -}}
"""

DOCKERFILE = """FROM eclipse-temurin:21.0.3_9-jre
{env}WORKDIR /app
COPY target/app.jar /app/app.jar
USER 1000
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
"""

HEAP_ENV = {
    "none": "",
    "xmx": 'ENV JAVA_TOOL_OPTIONS="-Xmx768m"\n',
    "percentage": 'ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=60.0"\n',
    "both": 'ENV JAVA_TOOL_OPTIONS="-Xmx768m -XX:MaxRAMPercentage=60.0"\n',
    "percentage-85": 'ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=92.0"\n',
}

RES_BLOCK = {
    "none": "",
    "requests-only": ("          resources:\n"
                      "            requests:\n"
                      "              cpu: 250m\n"
                      "              memory: 512Mi\n"),
    "limits-only": ("          resources:\n"
                    "            limits:\n"
                    "              cpu: \"1\"\n"
                    "              memory: 1Gi\n"),
    "both": ("          resources:\n"
             "            requests:\n"
             "              cpu: 250m\n"
             "              memory: 512Mi\n"
             "            limits:\n"
             "              cpu: \"1\"\n"
             "              memory: 1Gi\n"),
    "helper": ("          resources:\n"
               "{{- include \"gen.resources\" . | nindent 12 }}\n"),
}

PROBE_BLOCK = {
    "none": "",
    "liveness": ("          livenessProbe:\n"
                 "            httpGet: {path: /healthz, port: http}\n"
                 "            initialDelaySeconds: 30\n"),
    "readiness": ("          readinessProbe:\n"
                  "            httpGet: {path: /ready, port: http}\n"
                  "            initialDelaySeconds: 5\n"),
    "liveness+readiness": ("          livenessProbe:\n"
                           "            httpGet: {path: /healthz, port: http}\n"
                           "            initialDelaySeconds: 30\n"
                           "          readinessProbe:\n"
                           "            httpGet: {path: /ready, port: http}\n"
                           "            initialDelaySeconds: 5\n"),
    "all-three": ("          livenessProbe:\n"
                  "            httpGet: {path: /healthz, port: http}\n"
                  "            initialDelaySeconds: 30\n"
                  "          readinessProbe:\n"
                  "            httpGet: {path: /ready, port: http}\n"
                  "            initialDelaySeconds: 5\n"
                  "          startupProbe:\n"
                  "            httpGet: {path: /healthz, port: http}\n"
                  "            failureThreshold: 30\n"
                  "            periodSeconds: 10\n"),
}


def _container(name, resources, probes, indent="        "):
    body = (
        "        - name: app\n"
        "          image: registry.example.com/%s:1.0.0\n"
        "          imagePullPolicy: IfNotPresent\n"
        "          ports:\n"
        "            - name: http\n"
        "              containerPort: 8080\n" % name
    )
    body += RES_BLOCK[resources]
    body += PROBE_BLOCK[probes]
    return body


def _replicas_line(kind, replicas, indent="  "):
    if kind in NO_REPLICAS or replicas == "absent":
        return ""
    if replicas == "literal":
        return "%sreplicas: 3\n" % indent
    if replicas == "values":
        return "%sreplicas: {{ .Values.replicaCount }}\n" % indent
    # conditional: the shape HP050 exists for
    return ("{{- if not .Values.autoscaling.enabled }}\n"
            "%sreplicas: {{ .Values.replicaCount }}\n"
            "{{- end }}\n" % indent)


def workload(name, kind, replicas, resources, probes):
    """One workload manifest. Indentation differs for CronJob because the pod
    spec is two levels deeper; everything else shares the same body."""
    ctr = _container(name, resources, probes)
    labels = "      labels:\n        app: %s\n" % name
    pod = ("    metadata:\n" + labels +
           "    spec:\n"
           "      securityContext:\n"
           "        runAsNonRoot: true\n"
           "        runAsUser: 1000\n"
           "      containers:\n" + ctr)

    head = ("apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n  labels:\n"
            "    app: %s\nspec:\n" % (API[kind], kind, name, name))

    if kind == "CronJob":
        # re-indent the pod block by four spaces
        pod4 = "\n".join(("    " + ln) if ln.strip() else ln
                         for ln in pod.splitlines()) + "\n"
        return (head +
                "  schedule: \"*/15 * * * *\"\n"
                "  jobTemplate:\n"
                "    spec:\n"
                "      template:\n" + pod4 +
                "          restartPolicy: OnFailure\n")

    body = head + _replicas_line(kind, replicas)
    if kind == "StatefulSet":
        body += "  serviceName: %s\n" % name
    if kind == "Rollout":
        body += ("  strategy:\n    canary:\n      steps:\n"
                 "        - setWeight: 20\n        - pause: {duration: 60}\n")
    if kind == "ReplicationController":
        body += "  selector:\n    app: %s\n" % name
    elif kind != "Job":
        body += "  selector:\n    matchLabels:\n      app: %s\n" % name
    body += "  template:\n" + pod
    if kind in ("Job", "CronJob"):
        body += "      restartPolicy: Never\n"
    return body


def hpa_manifest(name, kind, mode):
    if mode == "none":
        return None
    ref = ("    apiVersion: %s\n    kind: %s\n    name: %s\n"
           % (API[kind], kind, name))
    if mode == "v1":
        return ("apiVersion: autoscaling/v1\nkind: HorizontalPodAutoscaler\n"
                "metadata:\n  name: %s\nspec:\n  scaleTargetRef:\n%s"
                "  minReplicas: 2\n  maxReplicas: 10\n"
                "  targetCPUUtilizationPercentage: 70\n" % (name, ref))
    metrics = ("  metrics:\n"
               "    - type: Resource\n      resource:\n        name: cpu\n"
               "        target:\n          type: Utilization\n"
               "          averageUtilization: 70\n")
    if mode == "v2-cpu-mem":
        metrics += ("    - type: Resource\n      resource:\n        name: memory\n"
                    "        target:\n          type: Utilization\n"
                    "          averageUtilization: 80\n")
    return ("apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
            "metadata:\n  name: %s\nspec:\n  scaleTargetRef:\n%s"
            "  minReplicas: 2\n  maxReplicas: 10\n" % (name, ref) + metrics)


VALUES = """replicaCount: 3
autoscaling:
  enabled: {auto}
image:
  repository: registry.example.com/{name}
  tag: "1.0.0"
"""


def write_chart(root, name, kind, replicas, resources, heap, hpa, probes):
    d = os.path.join(root, name)
    os.makedirs(os.path.join(d, "templates"), exist_ok=True)
    desc = "%s/%s/%s/%s/%s/%s" % (kind, replicas, resources, heap, hpa, probes)
    open(os.path.join(d, "Chart.yaml"), "w").write(
        CHART_YAML.format(name=name, desc=desc))
    open(os.path.join(d, "values.yaml"), "w").write(
        VALUES.format(name=name, auto="true" if hpa != "none" else "false"))
    open(os.path.join(d, "templates", "workload.yaml"), "w").write(
        workload(name, kind, replicas, resources, probes))
    h = hpa_manifest(name, kind, hpa)
    if h:
        open(os.path.join(d, "templates", "hpa.yaml"), "w").write(h)
    if resources == "helper":
        open(os.path.join(d, "templates", "_helpers.tpl"), "w").write(HELPERS)
    open(os.path.join(d, "Dockerfile"), "w").write(
        DOCKERFILE.format(env=HEAP_ENV[heap]))
    return d, desc


# --------------------------------------------------------------------------
# Tier A: the kind sweep. One shape, eight kinds, nothing else varying.
# --------------------------------------------------------------------------
# Two baselines, not one, and the second was added because the first FAILED
# the acceptance test. Run with an HPA present, the pre-R16 tree surfaced the
# ReplicaSet, Rollout and ReplicationController defects (AT1-AT3) and did not
# surface the DaemonSet one (AT4) - because R16's defect is about what the tool
# does when there is NO HPA and the kind cannot have one, and a sweep that
# always ships an HPA never asks that question. The design was changed; the
# test was not.
BASELINES = {
    "hpa-present": dict(replicas="literal", resources="both",
                        heap="percentage", hpa="v2-cpu",
                        probes="liveness+readiness"),
    "hpa-absent": dict(replicas="literal", resources="both",
                       heap="percentage", hpa="none",
                       probes="liveness+readiness"),
}
BASELINE = BASELINES["hpa-present"]


def write_kind_sweep(root, baseline="hpa-present"):
    out = []
    for k in KINDS:
        name = "ks-%s-%s" % (baseline, k.lower())
        d, desc = write_chart(root, name, k, **BASELINES[baseline])
        out.append((name, k, d, desc))
    return out


# --------------------------------------------------------------------------
# Tier B: pairwise covering array over the six axes.
# --------------------------------------------------------------------------
AXES = [("kind", KINDS), ("replicas", REPLICAS), ("resources", RESOURCES),
        ("heap", HEAP), ("hpa", HPA), ("probes", PROBES)]


def pairwise():
    """Greedy IPO-style covering array. Deterministic: no RNG, and ties break
    on the axis order above, so the same call always returns the same rows."""
    need = set()
    for i in range(len(AXES)):
        for j in range(i + 1, len(AXES)):
            for a in AXES[i][1]:
                for b in AXES[j][1]:
                    need.add((i, a, j, b))
    rows = []
    while need:
        row = [None] * len(AXES)
        # seed with the pair that is still uncovered and comes first
        i, a, j, b = sorted(need)[0]
        row[i], row[j] = a, b
        for k in range(len(AXES)):
            if row[k] is not None:
                continue
            best, best_gain = None, -1
            for v in AXES[k][1]:
                gain = 0
                for m in range(len(AXES)):
                    if m == k or row[m] is None:
                        continue
                    pair = ((k, v, m, row[m]) if k < m
                            else (m, row[m], k, v))
                    if pair in need:
                        gain += 1
                if gain > best_gain:
                    best, best_gain = v, gain
            row[k] = best
        covered = set()
        for x in range(len(AXES)):
            for y in range(x + 1, len(AXES)):
                covered.add((x, row[x], y, row[y]))
        if not (covered & need):
            # no progress possible - the remaining pairs are all in this row's
            # own combination space; take the first uncovered pair verbatim
            break
        need -= covered
        rows.append(tuple(row))
    return rows


def write_shape_sweep(root):
    out = []
    for n, row in enumerate(pairwise()):
        kw = dict(zip([a for a, _ in AXES], row))
        name = "sw%03d-%s" % (n, kw["kind"].lower())
        d, desc = write_chart(root, name, **kw)
        out.append((name, kw, d, desc))
    return out

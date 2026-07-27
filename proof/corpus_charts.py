"""Thirty-five Java charts, written to disk, for running the analyzer against.

WHY A GENERATOR AND NOT THIRTY COMMITTED DIRECTORIES
----------------------------------------------------
Thirty charts is roughly a hundred and fifty files. Committed, they would be a
hundred and fifty files nobody ever reads, in which a subtle edit (a tab, a
changed tag) is invisible in review and silently changes what the corpus proves.
As one file of dicts, the entire corpus is diffable: you can see at a glance that
c05 is the only chart with a removed flag on Java 11, because that is one line.

The generator is committed. Its output is not.

WHAT "RANDOM" MEANS HERE
------------------------
The request was for "random charts with various java configs". These are not
RNG-generated, and that is deliberate: a randomly seeded corpus that finds a bug
on Tuesday and cannot reproduce it on Wednesday is not evidence, it is an
anecdote. What was actually wanted - unbiased coverage rather than fifteen
charts that all happen to exercise the paths I already knew about - is served by
varying the SHAPE of each chart, not just its values:

  * where the resources live       template literal / values / values overlay /
                                   _helpers.tpl include / nowhere
  * where the JVM flags live       Dockerfile ENV JAVA_TOOL_OPTIONS / an ENV the
                                   entrypoint never reads / ENTRYPOINT argv /
                                   shell-form CMD / pod env / nowhere
  * what the base image says       pinned temurin, bare `8`, an internal
                                   registry tag with no version in it, distroless
  * workload kind                  Deployment / StatefulSet
  * container count                one / app+sidecar
  * autoscaling                    CPU / memory / none / v2beta2 apiVersion
  * whether a Dockerfile exists    at all

Several charts are deliberately reasonable. A corpus of fifteen disasters would
tell me the tool can find disasters and nothing about its false-positive rate,
which is the failure mode that actually gets a tool uninstalled.
"""

import os

# --------------------------------------------------------------------------
# building blocks
# --------------------------------------------------------------------------

CHART_YAML = """apiVersion: v2
name: {name}
description: {desc}
type: application
version: 1.0.0
appVersion: "{app}"
"""

SERVICE = """apiVersion: v1
kind: Service
metadata:
  name: {{{{ .Release.Name }}}}-{name}
spec:
  type: ClusterIP
  ports:
    - port: 8080
      targetPort: http
  selector:
    app: {name}
"""


def hpa(name, metric="cpu", target=70, api="autoscaling/v2",
        minr=2, maxr=10, kind="Deployment"):
    """An HPA manifest. `api` is a knob because v2beta2 is gone in k8s 1.26+
    and plenty of charts in the wild still ship it."""
    if api == "autoscaling/v2":
        metrics = f"""  metrics:
    - type: Resource
      resource:
        name: {metric}
        target:
          type: Utilization
          averageUtilization: {target}"""
    else:
        metrics = f"""  metrics:
    - type: Resource
      resource:
        name: {metric}
        targetAverageUtilization: {target}"""
    return f"""apiVersion: {api}
kind: HorizontalPodAutoscaler
metadata:
  name: {{{{ .Release.Name }}}}-{name}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: {kind}
    name: {{{{ .Release.Name }}}}-{name}
  minReplicas: {minr}
  maxReplicas: {maxr}
{metrics}
"""


def workload(name, image, *, kind="Deployment", resources="", env="",
             extra_containers="", probes=True, replicas=None,
             container="app"):
    """A Deployment or StatefulSet. `resources` and `env` are pasted in at the
    right indent by the caller, because the whole point of the corpus is that
    they arrive by different routes."""
    probe_block = """          readinessProbe:
            httpGet:
              path: /health
              port: http
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: http
            periodSeconds: 20
""" if probes else ""
    rep = f"  replicas: {replicas}\n" if replicas is not None else ""
    sts = """  serviceName: {}-svc
""".format(name) if kind == "StatefulSet" else ""
    return f"""apiVersion: apps/v1
kind: {kind}
metadata:
  name: {{{{ .Release.Name }}}}-{name}
  labels:
    app: {name}
spec:
{rep}{sts}  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
        - name: {container}
          image: {image}
          ports:
            - name: http
              containerPort: 8080
{env}{resources}{probe_block}{extra_containers}"""


def dockerfile(base, *, env=None, entrypoint=None, cmd=None, multistage=False,
               user=True):
    lines = []
    if multistage:
        lines += [f"FROM {base.replace('-jre', '-jdk')} AS build",
                  "WORKDIR /src", "COPY . .",
                  "RUN ./mvnw -q -DskipTests package", ""]
    lines.append(f"FROM {base}")
    lines.append("WORKDIR /app")
    if multistage:
        lines.append("COPY --from=build /src/target/app.jar app.jar")
    else:
        lines.append("COPY target/app.jar app.jar")
    for k, v in (env or {}).items():
        lines.append(f'ENV {k}="{v}"')
    if user:
        lines.append("USER 10001")
    lines.append("EXPOSE 8080")
    if entrypoint:
        lines.append("ENTRYPOINT " + entrypoint)
    if cmd:
        lines.append("CMD " + cmd)
    return "\n".join(lines) + "\n"


def res(cpu_req, mem_req, cpu_lim, mem_lim, indent=10):
    """A literal resources block at container indent."""
    pad = " " * indent
    out = [f"{pad}resources:", f"{pad}  requests:"]
    if cpu_req:
        out.append(f"{pad}    cpu: {cpu_req}")
    if mem_req:
        out.append(f"{pad}    memory: {mem_req}")
    if cpu_lim or mem_lim:
        out.append(f"{pad}  limits:")
        if cpu_lim:
            out.append(f"{pad}    cpu: {cpu_lim}")
        if mem_lim:
            out.append(f"{pad}    memory: {mem_lim}")
    return "\n".join(out) + "\n"


def envblock(pairs, indent=10):
    pad = " " * indent
    out = [f"{pad}env:"]
    for k, v in pairs:
        out.append(f"{pad}  - name: {k}")
        out.append(f'{pad}    value: "{v}"')
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# the fifteen
# --------------------------------------------------------------------------

def _c01():
    """Modern, boring, correct. The false-positive control."""
    n = "orders"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Spring Boot on Temurin 21", app="1.4.0"),
        "values.yaml": "resources:\n  requests:\n    cpu: 500m\n    memory: 1Gi\n"
                       "  limits:\n    memory: 1Gi\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/orders:1.4.0",
            resources="          resources:\n"
                      "            {{- toYaml .Values.resources | nindent 12 }}\n"),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=12),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre", multistage=True,
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=70 -XX:+UseG1GC "
                                      "-XX:+ExitOnOutOfMemoryError"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c02():
    """Java 8u131 and an ENV nothing reads. The inert-flag path."""
    n = "billing"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Legacy billing service", app="7.2.1"),
        "values.yaml": "replicaCount: 4\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/billing:7.2.1", replicas="{{ .Values.replicaCount }}",
            resources=res("1", "2Gi", None, "2Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 80, minr=4, maxr=16),
        "templates/service.yaml": SERVICE.format(name=n),
        # JAVA_OPTS is a convention, not a thing the JVM reads. The ENTRYPOINT
        # here never mentions it, so every flag in it is decoration.
        "Dockerfile": dockerfile(
            "openjdk:8u131-jre-alpine",
            env={"JAVA_OPTS": "-Xmx1500m -XX:+UnlockExperimentalVMOptions "
                              "-XX:+UseCGroupMemoryLimitForHeap"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c03():
    """Bare `8` tag, shell-form CMD, no HPA, no limits."""
    n = "reports"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Nightly report generator", app="3.0.0"),
        "values.yaml": "replicaCount: 2\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/reports:3.0.0", replicas=2,
            resources=res("250m", "512Mi", None, None), probes=False),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "openjdk:8-jre", user=False,
            cmd='java -Xmx512m -jar /app/app.jar'),
    }


def _c04():
    """Java 17, no heap configuration at all, HPA on memory."""
    n = "search"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Search API", app="2.1.0"),
        "values.yaml": "replicaCount: 3\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/search:2.1.0",
            resources=res("500m", "3Gi", "2", "3Gi")),
        "templates/hpa.yaml": hpa(n, "memory", 80, minr=3, maxr=20),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile("eclipse-temurin:17.0.11_9-jre",
                                 entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c05():
    """Java 11 carrying a flag that was removed in Java 11. Armed crash."""
    n = "ledger"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Ledger service", app="5.5.0"),
        "values.yaml": "resources:\n  requests:\n    cpu: 1\n    memory: 4Gi\n"
                       "  limits:\n    cpu: 2\n    memory: 4Gi\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/ledger:5.5.0",
            resources="          resources:\n"
                      "            {{- toYaml .Values.resources | nindent 12 }}\n"),
        "templates/hpa.yaml": hpa(n, "cpu", 60, minr=2, maxr=8),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:11.0.12_7-jre",
            entrypoint='["java", "-XX:+UnlockExperimentalVMOptions", '
                       '"-XX:+UseCGroupMemoryLimitForHeap", '
                       '"-XX:+UseConcMarkSweepGC", "-jar", "/app/app.jar"]'),
    }


def _c06():
    """Resources arrive from a _helpers.tpl include. The R11 path.

    This is the chart the R11 fix exists for: statically, the analyzer sees
    HELMINC@ledger.resources and knows only that it did not open the file.
    With helm on PATH it renders and sees a real block. Both runs are in the
    corpus deliberately - see p14's mode note.
    """
    n = "gateway"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Edge gateway", app="4.0.2"),
        "values.yaml": "sizing: medium\n",
        "templates/_helpers.tpl": """{{- define "gateway.resources" -}}
{{- if eq .Values.sizing "medium" -}}
requests:
  cpu: 750m
  memory: 1536Mi
limits:
  memory: 1536Mi
{{- else -}}
requests:
  cpu: 2
  memory: 4Gi
limits:
  memory: 4Gi
{{- end -}}
{{- end -}}
""",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/gateway:4.0.2",
            resources="          resources:\n"
                      '            {{- include "gateway.resources" . | nindent 12 }}\n'),
        "templates/hpa.yaml": hpa(n, "cpu", 65, minr=3, maxr=15),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c07():
    """-Xmx larger than the memory limit. The arithmetic case."""
    n = "batch"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Batch worker", app="1.9.3"),
        "values.yaml": "replicaCount: 2\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/batch:1.9.3", replicas=2,
            resources=res("1", "2Gi", "1", "2Gi")),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:8u372-b05-jre",
            entrypoint='["java", "-Xmx3g", "-Xms3g", "-jar", "/app/app.jar"]'),
    }


def _c08():
    """An internal base image whose tag says nothing about Java. DF003."""
    n = "notify"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Notification fanout", app="2.0.0"),
        "values.yaml": "replicaCount: 3\n",
        "templates/deployment.yaml": workload(
            n, "registry.corp.internal/platform/notify:2.0.0",
            env=envblock([("JAVA_TOOL_OPTIONS", "-XX:MaxRAMPercentage=60"),
                          ("SPRING_PROFILES_ACTIVE", "prod")]),
            resources=res("500m", "1Gi", None, "1Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 75, minr=3, maxr=12),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "registry.corp.internal/base/java-runtime:2024.3",
            entrypoint='["/app/entrypoint.sh"]'),
    }


def _c09():
    """No Dockerfile in the chart at all. Flags come from the pod spec."""
    n = "catalog"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Catalog service (image built elsewhere)",
                                        app="6.1.0"),
        "values.yaml": "replicaCount: 3\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/catalog:6.1.0",
            env=envblock([("JAVA_TOOL_OPTIONS",
                           "-XX:MaxRAMPercentage=75 -XX:+UseG1GC")]),
            resources=res("1", "2Gi", "2", "2Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=18),
        "templates/service.yaml": SERVICE.format(name=n),
    }


def _c10():
    """A StatefulSet, distroless base, no HPA. Kafka-consumer shaped."""
    n = "streams"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Kafka Streams processor", app="3.3.0"),
        "values.yaml": "replicaCount: 6\n",
        "templates/statefulset.yaml": workload(
            n, "registry.example.com/streams:3.3.0", kind="StatefulSet",
            replicas=6, resources=res("2", "8Gi", None, "8Gi")),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "gcr.io/distroless/java17-debian12:nonroot", user=False,
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=60 -XX:+UseG1GC "
                                      "-XX:MaxMetaspaceSize=256m"},
            cmd='["/app/app.jar"]'),
    }


def _c11():
    """MaxRAMPercentage on a JVM too old to have it, plus a PermGen flag."""
    n = "auth"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Auth service", app="8.4.0"),
        "values.yaml": "replicaCount: 4\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/auth:8.4.0", replicas=4,
            resources=res("500m", "1Gi", "500m", "1Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 70, api="autoscaling/v2beta2",
                                  minr=4, maxr=10),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "openjdk:8u151-jre-slim",
            entrypoint='["java", "-XX:MaxRAMPercentage=75", '
                       '"-XX:MaxPermSize=256m", "-jar", "/app/app.jar"]'),
    }


def _c12():
    """Requests but no memory limit, with a percentage-of-what heap setting."""
    n = "media"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Media transcoder", app="1.0.5"),
        "values.yaml": "replicaCount: 2\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/media:1.0.5", replicas=2,
            resources=res("1", "2Gi", None, None)),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=2, maxr=6),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:17.0.11_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c13():
    """App plus an unsized sidecar. Pod-level arithmetic."""
    n = "inventory"
    sidecar = """        - name: log-shipper
          image: fluent/fluent-bit:2.2.0
          ports:
            - name: metrics
              containerPort: 2020
"""
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Inventory service + log sidecar",
                                        app="4.4.1"),
        "values.yaml": "replicaCount: 3\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/inventory:4.4.1",
            resources=res("1", "2Gi", "1", "2Gi"),
            extra_containers=sidecar),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=12),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=80"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c14():
    """Resources defined ONLY in a non-default values file.

    `helm template` without -f reads values.yaml, where resources is {}. That
    is a genuine absence for the default install, and RS001's CRITICAL is
    correct here - which is the case R11 had to be careful not to break.
    """
    n = "payments"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Payments service", app="9.0.0"),
        "values.yaml": "replicaCount: 3\nresources: {}\n",
        "values-prod.yaml": "resources:\n  requests:\n    cpu: 2\n    memory: 4Gi\n"
                            "  limits:\n    memory: 4Gi\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/payments:9.0.0",
            resources="          resources:\n"
                      "            {{- toYaml .Values.resources | nindent 12 }}\n"),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=30),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c15():
    """Java 21, generous limits, tiny heap percentage. Waste, not danger."""
    n = "profile"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Profile service", app="2.7.0"),
        "values.yaml": "replicaCount: 5\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/profile:2.7.0",
            resources=res("2", "8Gi", "4", "8Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 50, minr=5, maxr=25),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre", multistage=True,
            env={"JAVA_TOOL_OPTIONS": "-Xmx1g -Xms1g -XX:+UseG1GC"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }



# --------------------------------------------------------------------------
# the second fifteen — chosen against the FLAG surface, not the JVM surface
# --------------------------------------------------------------------------
#
# The first fifteen varied the shape of the chart. They were run on defaults,
# because that is how most people run the tool, and they found three defects.
#
# These fifteen vary something different: the thing each flag is supposed to
# change. `--kube-version` is meant to move deprecated-API severity, so c16 and
# c17 ship deprecated APIs with and without a declared `kubeVersion` and differ
# in nothing else. `--measured` is meant to collapse an UNDETERMINED fit, so c18
# is built to BE undetermined. `--helm on/off` is meant to be the difference
# between a render and a guess, so c19, c20 and c21 are charts where that
# difference is not cosmetic. `--assume-java` is meant not to fire on things
# that are not Java, so c24 is not Java.
#
# A flag that changes nothing on any chart in the corpus is a flag whose effect
# is untested, and a corpus that cannot make a flag matter cannot catch it
# breaking. Several of these charts exist only to give a flag something to do.

def _c16():
    """Deprecated APIs, and no `kubeVersion` in Chart.yaml to judge them by.

    Pairs with c17, which is byte-identical except for the kubeVersion line.
    Two charts differing in one field are how you measure what that field does;
    one chart plus an assertion about it is how you measure your own opinion.
    """
    n = "legacyweb"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Web front end, old manifests",
                                        app="1.2.0"),
        "values.yaml": "replicaCount: 2\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/legacyweb:1.2.0", replicas=2,
            resources=res("500m", "1Gi", "1", "1Gi")),
        "templates/ingress.yaml": """apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: {{ .Release.Name }}-legacyweb
spec:
  rules:
    - host: legacyweb.example.com
      http:
        paths:
          - path: /
            backend:
              serviceName: legacyweb
              servicePort: 8080
""",
        "templates/pdb.yaml": """apiVersion: policy/v1beta1
kind: PodDisruptionBudget
metadata:
  name: {{ .Release.Name }}-legacyweb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: legacyweb
""",
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:17.0.11_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=70"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c17():
    """c16 with `kubeVersion: ">=1.19.0-0 <1.21.0-0"` and nothing else changed.

    On that range both deprecated APIs still EXIST, so the honest severity is
    low. R3 built that reconciliation; this chart is what makes it observable,
    and it is also the chart on which `--kube-version 1.31.0` should disagree
    with the chart's own declaration - a conflict the tool has to do something
    visible about rather than silently pick a winner.
    """
    c = _c16()
    n = "legacyweb"
    c["Chart.yaml"] = (CHART_YAML.format(name=n, desc="Web front end, old manifests",
                                         app="1.2.0")
                       + 'kubeVersion: ">=1.19.0-0 <1.21.0-0"\n')
    return c


def _c18():
    """A fit that lands INSIDE the estimate interval. Built for `--measured`.

    R9's whole apparatus - bands, an interval for peak RSS, an UNDETERMINED
    verdict instead of a false one - only ever engages when the limit falls
    between the interval's endpoints. Every other chart in this corpus is
    comfortably inside or comfortably outside, so none of them can tell you
    whether that apparatus still works. The numbers here (`-Xmx1400m` under a
    2Gi limit, ~650Mi of headroom against a non-heap estimate band that is
    wider than that) are chosen to straddle, and the claim in p17 asserts the
    straddle rather than assuming it - if a band constant is ever retuned this
    chart stops straddling, and the claim should say so out loud rather than
    quietly passing.
    """
    n = "recs"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Recommendation engine", app="3.1.0"),
        "values.yaml": "replicaCount: 4\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/recs:3.1.0",
            env=envblock([("JAVA_TOOL_OPTIONS",
                           "-Xmx1400m -Xms1400m -XX:MaxMetaspaceSize=256m "
                           "-XX:MaxDirectMemorySize=256m -Xss1m")]),
            resources=res("1", "2Gi", "2", "2Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=4, maxr=16),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile("eclipse-temurin:21.0.3_9-jre",
                                 entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c19():
    """An entire container behind `{{- if .Values.sidecar.enabled }}`, default off.

    Static mode analyses conditionals as taken, so it sees a two-container pod
    with an unsized sidecar. helm renders the default and sees one container.
    Neither is lying and the answers are different, which is the single
    clearest case for why `--helm` exists and why the mode banner is not
    decoration.
    """
    n = "feed"
    sidecar = """{{- if .Values.sidecar.enabled }}
        - name: metrics-agent
          image: registry.example.com/agent:1.0.0
{{- end }}
"""
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Activity feed", app="2.2.0"),
        "values.yaml": "replicaCount: 3\nsidecar:\n  enabled: false\n",
        "values-observability.yaml": "sidecar:\n  enabled: true\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/feed:2.2.0",
            resources=res("1", "2Gi", "1", "2Gi"),
            extra_containers=sidecar),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=12),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c20():
    """`required` and `tpl`, with the required value unset in values.yaml.

    `helm template` FAILS on this chart, by design - that is what `required` is
    for. So this is the chart that asks what the tool does when the render it
    depends on returns a non-zero exit and an error on stderr: `--helm on` must
    not pretend, `--helm auto` must not silently downgrade to static and
    present the result as if nothing happened, and neither may report a grade
    computed from half a chart without saying so.
    """
    n = "checkout"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Checkout service", app="5.0.0"),
        "values.yaml": "replicaCount: 3\nimage:\n  repository: registry.example.com/checkout\n",
        "templates/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-checkout
  labels:
    app: checkout
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: checkout
  template:
    metadata:
      labels:
        app: checkout
    spec:
      containers:
        - name: app
          image: "{{ .Values.image.repository }}:{{ required "image.tag must be set for this chart" .Values.image.tag }}"
          ports:
            - name: http
              containerPort: 8080
          env:
            - name: JAVA_TOOL_OPTIONS
              value: {{ tpl "-XX:MaxRAMPercentage={{ .Values.heapPercent | default 70 }}" . | quote }}
          resources:
            requests:
              cpu: 1
              memory: 2Gi
            limits:
              memory: 2Gi
""",
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=12),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile("eclipse-temurin:21.0.3_9-jre",
                                 entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c21():
    """An umbrella chart: parent HPA, workload in `charts/worker/`.

    The R7 path. Statically the parent's HPA points at a Deployment that does
    not exist in `templates/`; under helm the subchart renders it. A tool that
    reports a dangling HPA here without saying which mode it was in has told
    two different users two different facts with the same words.
    """
    n = "pipeline"
    sub = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-worker
  labels:
    app: worker
spec:
  replicas: 2
  selector:
    matchLabels:
      app: worker
  template:
    metadata:
      labels:
        app: worker
    spec:
      containers:
        - name: app
          image: registry.example.com/worker:1.0.0
          env:
            - name: JAVA_TOOL_OPTIONS
              value: "-XX:MaxRAMPercentage=75"
          resources:
            requests:
              cpu: 1
              memory: 2Gi
            limits:
              memory: 2Gi
"""
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Ingest pipeline umbrella", app="1.0.0")
                      + "dependencies:\n  - name: worker\n    version: 1.0.0\n",
        "values.yaml": "replicaCount: 2\n",
        "charts/worker/Chart.yaml": CHART_YAML.format(name="worker", desc="Worker subchart",
                                                     app="1.0.0"),
        "charts/worker/values.yaml": "replicaCount: 2\n",
        "charts/worker/templates/deployment.yaml": sub,
        "templates/hpa.yaml": hpa("worker", "cpu", 70, minr=2, maxr=10),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile("eclipse-temurin:21.0.3_9-jre",
                                 entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c22():
    """A CronJob carrying the Java container, and an HPA pointed at it.

    An HPA whose scaleTargetRef is a CronJob cannot work - the kind has no
    scale subresource - and it is a mistake people actually make when a batch
    job outgrows its window. The corpus had only Deployments and one
    StatefulSet, so nothing in it could tell whether the workload walk handles
    a kind it does not scale.
    """
    n = "recon"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Nightly reconciliation", app="1.1.0"),
        "values.yaml": "schedule: \"0 2 * * *\"\n",
        "templates/cronjob.yaml": """apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ .Release.Name }}-recon
  labels:
    app: recon
spec:
  schedule: {{ .Values.schedule | quote }}
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: recon
        spec:
          restartPolicy: OnFailure
          containers:
            - name: app
              image: registry.example.com/recon:1.1.0
              env:
                - name: JAVA_TOOL_OPTIONS
                  value: "-Xmx6g"
              resources:
                requests:
                  cpu: 2
                  memory: 4Gi
                limits:
                  memory: 4Gi
""",
        "templates/hpa.yaml": """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ .Release.Name }}-recon
spec:
  scaleTargetRef:
    apiVersion: batch/v1
    kind: CronJob
    name: {{ .Release.Name }}-recon
  minReplicas: 1
  maxReplicas: 5
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
""",
        "Dockerfile": dockerfile("eclipse-temurin:17.0.11_9-jre",
                                 entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c23():
    """A native sidecar (`initContainers` + `restartPolicy: Always`) and a real init.

    R2 established that a native sidecar runs for the pod's whole life and must
    be summed into the footprint, while an ordinary init container must not be
    summed but does set a floor. Both are here, in one pod, sized differently,
    so a walk that confuses them produces a number that is wrong in a
    direction the chart can name.
    """
    n = "edge"
    inits = """      initContainers:
        - name: proxy
          image: envoyproxy/envoy:v1.30.1
          restartPolicy: Always
          resources:
            requests:
              cpu: 200m
              memory: 512Mi
            limits:
              memory: 512Mi
        - name: schema-migrate
          image: registry.example.com/migrate:1.0.0
          resources:
            requests:
              cpu: 2
              memory: 3Gi
            limits:
              memory: 3Gi
"""
    wl = workload(n, "registry.example.com/edge:2.0.0",
                  resources=res("1", "2Gi", "1", "2Gi"))
    wl = wl.replace("      containers:", inits + "      containers:")
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Edge service with a native sidecar",
                                        app="2.0.0"),
        "values.yaml": "replicaCount: 3\n",
        "templates/deployment.yaml": wl,
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=12),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c24():
    """Not Java. Nothing here is Java. The false-positive control for `--assume-java`.

    `--assume-java 17` on this chart must NOT produce a JVM analysis. A flag
    that says "assume the version is 17 when the tag hides it" turning into
    "assume there is a JVM" is how a tool starts inventing findings about
    software that is not present, and the JAVA category reading NOT ASSESSED
    here is the correct answer both with and without the flag.
    """
    n = "static"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Static asset server", app="1.25.3"),
        "values.yaml": "replicaCount: 2\n",
        "templates/deployment.yaml": workload(
            n, "nginx:1.25.3-alpine", replicas=2,
            resources=res("100m", "128Mi", "200m", "128Mi")),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=2, maxr=8),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": "FROM nginx:1.25.3-alpine\nCOPY dist/ /usr/share/nginx/html/\n"
                      "EXPOSE 8080\n",
    }


def _c25():
    """`-XX:MaxRAMFraction=2` on 8u191 — the release where container support landed.

    The corpus had 8u131 (before `UseCGroupMemoryLimitForHeap`), 8u151 and
    8u372, and nothing at the 8u191 boundary where `UseContainerSupport`
    became the default. MaxRAMFraction is also the pre-percentage way of
    saying the same thing, with the opposite sense - fraction 2 means half,
    not two percent - and a tool that reads it as a percentage is off by a
    factor nobody would notice in a report.
    """
    n = "sessions"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Session store front end", app="4.1.0"),
        "values.yaml": "replicaCount: 4\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/sessions:4.1.0", replicas=4,
            resources=res("1", "4Gi", "1", "4Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=4, maxr=12),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "openjdk:8u191-jre-slim",
            entrypoint='["java", "-XX:+UnlockExperimentalVMOptions", '
                       '"-XX:MaxRAMFraction=2", "-jar", "/app/app.jar"]'),
    }


def _c26():
    """A 500m CPU limit under a JVM that sizes its pools off the core count.

    `Runtime.availableProcessors()` reads the cgroup CPU LIMIT, so 500m means
    the JVM sees 1 - and G1's region count, the common pool's parallelism and
    the JIT compiler threads all follow. Meanwhile 400 threads at the default
    1MB stack is 400MB of memory nothing in the heap arithmetic accounts for.
    Two different flags' worth of behaviour meeting in one pod.
    """
    n = "worker"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Thread-pool heavy worker", app="6.0.0"),
        "values.yaml": "replicaCount: 8\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/worker:6.0.0", replicas=8,
            env=envblock([("JAVA_TOOL_OPTIONS",
                           "-XX:MaxRAMPercentage=75 -Xss1m"),
                          ("SERVER_TOMCAT_THREADS_MAX", "400")]),
            resources=res("200m", "2Gi", "500m", "2Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 90, minr=8, maxr=40),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile("eclipse-temurin:17.0.11_9-jre",
                                 entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c27():
    """Two workloads, one HPA, and a scaleTargetRef that matches neither exactly.

    Every other chart in the corpus has exactly one workload, so the target
    resolution has never had to choose. Here `api` and `worker` both exist and
    the HPA names `{{ .Release.Name }}-API` - a case difference, which
    Kubernetes will not resolve and a human reading the file will not see. The
    tool either resolves it (wrong), reports it dangling (right), or picks the
    single Java workload by inference and stamps the finding ASSUMED (also
    defensible, and it must say which).
    """
    n = "twin"
    api = workload("api", "registry.example.com/api:1.0.0",
                   resources=res("1", "2Gi", "1", "2Gi"),
                   env=envblock([("JAVA_TOOL_OPTIONS", "-XX:MaxRAMPercentage=75")]))
    wrk = workload("worker", "registry.example.com/worker:1.0.0",
                   resources=res("500m", "1Gi", "500m", "1Gi"), probes=False)
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="API plus worker in one chart",
                                        app="1.0.0"),
        "values.yaml": "replicaCount: 2\n",
        "templates/api.yaml": api,
        "templates/worker.yaml": wrk,
        "templates/hpa.yaml": """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ .Release.Name }}-api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ .Release.Name }}-API
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
""",
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile("eclipse-temurin:21.0.3_9-jre",
                                 entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c28():
    """minReplicas == maxReplicas, scaling on memory, against a fixed heap.

    Two faults that look like one. An HPA whose bounds are equal cannot scale
    and is a more expensive way of writing `replicas: 6`. And scaling a JVM on
    MEMORY utilisation is close to useless whatever the bounds: a heap that has
    grown does not shrink back, so the metric ratchets up, never recovers, and
    the autoscaler either sits at max or never scales down. c04 scales on
    memory too, but with a live range, so the degenerate-bounds case has never
    been in the corpus.
    """
    n = "cache"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Read-through cache", app="2.5.0"),
        "values.yaml": "replicaCount: 6\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/cache:2.5.0", replicas=6,
            env=envblock([("JAVA_TOOL_OPTIONS", "-Xmx3g -Xms3g -XX:+UseG1GC")]),
            resources=res("2", "4Gi", "2", "4Gi")),
        "templates/hpa.yaml": hpa(n, "memory", 75, minr=6, maxr=6),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile("eclipse-temurin:21.0.3_9-jre",
                                 entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c29():
    """Resources under `global.`, plus an overlay that halves them.

    `global` is the one values key helm gives special meaning to, it is where
    umbrella charts put shared sizing, and no chart in the corpus used it. The
    staging overlay halves the limit without halving `-Xmx`, so the same
    Dockerfile is safe under the default values and fatal under the overlay -
    which is exactly the case the overlay pass exists for, and the one R14b
    found the coverage gate blind to.
    """
    n = "risk"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Risk scoring service", app="3.0.0"),
        "values.yaml": "global:\n  resources:\n    requests:\n      cpu: 2\n"
                       "      memory: 4Gi\n    limits:\n      memory: 4Gi\n",
        "values-staging.yaml": "global:\n  resources:\n    requests:\n      cpu: 1\n"
                               "      memory: 2Gi\n    limits:\n      memory: 2Gi\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/risk:3.0.0",
            resources="          resources:\n"
                      "            {{- toYaml .Values.global.resources | nindent 12 }}\n"),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=15),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-Xmx3g -Xms3g"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c30():
    """Inputs in the wrong places. Built for `--check`.

    The Dockerfile is under `build/`, there is a stray `k8s/deployment.yaml`
    outside `templates/` that helm will never render, and the values file is
    named `config.yaml`. `--check` exists to say "here is what I found and here
    is what looks misplaced" BEFORE anyone reads a grade computed from half the
    inputs, and this is the only chart in the corpus that gives it anything to
    say.
    """
    n = "misfiled"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Correct chart, misfiled inputs",
                                        app="1.0.0"),
        "config.yaml": "replicaCount: 2\nresources:\n  requests:\n    cpu: 1\n"
                       "    memory: 2Gi\n  limits:\n    memory: 2Gi\n",
        "values.yaml": "replicaCount: 2\n",
        "templates/deployment.yaml": workload(
            n, "registry.example.com/misfiled:1.0.0", replicas=2,
            resources=res("1", "2Gi", None, "2Gi")),
        "k8s/deployment.yaml": workload(
            n + "-legacy", "registry.example.com/misfiled:0.9.0", replicas=1),
        "templates/service.yaml": SERVICE.format(name=n),
        "build/Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=75"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


# --------------------------------------------------------------------------
# c31-c35: the ablation set (R16)
# --------------------------------------------------------------------------
#
# Every one of c01-c30 was written to TRIP a rule. That makes the corpus
# useless for the question R16 opened on: a dozen rules fire on 30 of the 32
# charts, and a corpus of deliberate mistakes cannot distinguish "these rules
# are miscalibrated" from "I wrote thirty charts that are all sloppy in the
# same ways".
#
# `fixtures/good-chart` clears them, so they are demonstrably clearable - but
# good-chart clears ALL of them at once, so it cannot say WHICH change did it,
# and it was written by the same hand that wrote the rules, which is the one
# chart whose passing proves least.
#
# c31-c35 are an ablation instead of five more good charts. Each fixes exactly
# ONE family and leaves the rest of the chart ordinary:
#
#     c31  security block only        -> should silence SC001-SC006, nothing else
#     c32  probes only                -> should silence PB004/PB005, nothing else
#     c33  chart hygiene only         -> should silence CH0xx/TP01x, nothing else
#     c34  spread + JVM flags only    -> should silence AV003/JV026, nothing else
#     c35  all four, and one real bug -> everything above goes quiet and the
#                                        real defect still fires at full weight
#
# If a family goes quiet when and only when its own fix is applied, the rules
# were right and c01-c30 were uniformly sloppy. If a rule keeps firing on the
# chart built to satisfy it, the rule is wrong and the reason is the finding.
# c35 is the control that matters most: a corpus where the noise rules go quiet
# is only an improvement if the signal rules did not go quiet with them.

SECURE_CONTAINER_SC = """          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
"""

GOOD_PROBES = """          startupProbe:
            httpGet:
              path: /actuator/health/liveness
              port: http
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 36
          livenessProbe:
            httpGet:
              path: /actuator/health/liveness
              port: http
            periodSeconds: 20
            timeoutSeconds: 5
            failureThreshold: 5
          readinessProbe:
            httpGet:
              path: /actuator/health/readiness
              port: http
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
"""

SPREAD = """      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: {name}
"""

STD_LABELS = """    app.kubernetes.io/name: {name}
    app.kubernetes.io/instance: {{{{ .Release.Name }}}}
    app.kubernetes.io/version: "1.0.0"
    app.kubernetes.io/component: server
    app.kubernetes.io/part-of: {name}
    app.kubernetes.io/managed-by: {{{{ .Release.Service }}}}
"""

HELPERS_TPL = """{{{{- define "{name}.name" -}}}}
{name}
{{{{- end }}}}

{{{{- define "{name}.fullname" -}}}}
{{{{ .Release.Name }}}}-{name}
{{{{- end }}}}

{{{{- define "{name}.labels" -}}}}
app.kubernetes.io/name: {name}
app.kubernetes.io/instance: {{{{ .Release.Name }}}}
app.kubernetes.io/managed-by: {{{{ .Release.Service }}}}
{{{{- end }}}}

{{{{- define "{name}.selectorLabels" -}}}}
app.kubernetes.io/name: {name}
app.kubernetes.io/instance: {{{{ .Release.Name }}}}
{{{{- end }}}}
"""

VALUES_SCHEMA = """{
  "$schema": "https://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "replicaCount": {"type": "integer", "minimum": 1},
    "image": {
      "type": "object",
      "properties": {
        "repository": {"type": "string"},
        "tag": {"type": "string"}
      },
      "required": ["repository"]
    },
    "resources": {
      "type": "object",
      "properties": {
        "requests": {"type": "object"},
        "limits": {"type": "object"}
      }
    }
  },
  "required": ["resources"]
}
"""

CHART_YAML_FULL = """apiVersion: v2
name: {name}
description: {desc}
type: application
version: 1.0.0
appVersion: "{app}"
kubeVersion: ">=1.23.0-0"
home: https://example.com/{name}
icon: https://example.com/{name}.png
sources:
  - https://github.com/example/{name}
maintainers:
  - name: Platform Team
    email: platform@example.com
"""

# Appended to an hpa() block. HP030 (LOW, "no behavior block") fires on 25 of
# the 26 corpus charts that HAVE an HPA, which is why the practical ceiling for
# the HPA category is 97.0 and not 100.0 - see the R16 measurement. c35 is the
# only chart other than fixtures/good-chart that clears it, and it has to, or
# "everything right except the heap" is not true of it.
BEHAVIOR = """  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Pods
          value: 2
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
"""

PDB = """apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{{{ .Release.Name }}}}-{name}
  labels:
    app.kubernetes.io/name: {name}
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: {name}
"""

HELM_TEST = """apiVersion: v1
kind: Pod
metadata:
  name: "{{{{ .Release.Name }}}}-{name}-test"
  labels:
    app.kubernetes.io/name: {name}
  annotations:
    "helm.sh/hook": test
spec:
  restartPolicy: Never
  containers:
    - name: wget
      image: busybox:1.36
      command: ["wget"]
      args: ["{{{{ .Release.Name }}}}-{name}:8080/actuator/health"]
"""


def pass_workload(name, image, *, labels="", pod_extra="", container_sc="",
                  probes=None, resources="", env="", replicas=None,
                  volumes=""):
    """A Deployment for the c31-c35 ablation set.

    Deliberately NOT a new mode on workload(): c01-c30's output has to stay
    byte-identical, because their thirty scores are the baseline this round is
    measured against and a shared helper that grew a keyword argument is
    exactly how that gets silently broken.
    """
    lab = labels or f"    app: {name}\n"
    probe_block = GOOD_PROBES if probes is True else (
        """          readinessProbe:
            httpGet:
              path: /health
              port: http
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: http
            periodSeconds: 20
""" if probes is None else "")
    rep = f"  replicas: {replicas}\n" if replicas is not None else ""
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{{{ .Release.Name }}}}-{name}
  labels:
{lab}spec:
{rep}  selector:
    matchLabels:
      app.kubernetes.io/name: {name}
  template:
    metadata:
      labels:
{lab}    spec:
{pod_extra}      containers:
        - name: app
          image: {image}
          ports:
            - name: http
              containerPort: 8080
{container_sc}{env}{resources}{probe_block}{volumes}"""


def _c31():
    """Security block only. Everything else is c01-grade ordinary.

    The SC family (SC001 HIGH, SC002 MEDIUM, SC003 LOW, SC004 LOW, SC006 INFO)
    fires on 30 of 32 charts and takes SECURITY to a flat 76.0 on almost all of
    them. Twenty-four points of a seven-weight category that never varies is
    not a measurement of anything - it is a constant. This chart applies the
    exact remedy each of those rules prints in its `fix` field, and nothing
    else, so if SECURITY does not come back to 100 here the fix text is wrong.
    """
    n = "secure"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Security context only", app="1.0.0"),
        "values.yaml": "replicaCount: 3\n",
        "templates/deployment.yaml": pass_workload(
            n, "registry.example.com/secure:1.0.0",
            pod_extra="      automountServiceAccountToken: false\n",
            container_sc=SECURE_CONTAINER_SC,
            resources=res("500m", "2Gi", None, "2Gi"),
            volumes="          volumeMounts:\n"
                    "            - name: tmp\n"
                    "              mountPath: /tmp\n"
                    "      volumes:\n"
                    "        - name: tmp\n"
                    "          emptyDir: {}\n"),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=9),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=70"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c32():
    """Probes only: a startupProbe and explicit timeouts, nothing else.

    PB004 (HIGH) and PB005 (MEDIUM) fire on 27 of 32 and cost eighteen points
    of a ten-weight category. Both are about a JVM that is slow to start being
    killed by a liveness probe that does not know that. This chart adds the
    startupProbe and the timeoutSeconds their fix text asks for and changes
    nothing else, so PROBES should return to 100 and every other category
    should stay exactly where a c01-shaped chart puts it.
    """
    n = "probed"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Probes done properly", app="1.0.0"),
        "values.yaml": "replicaCount: 3\n",
        "templates/deployment.yaml": pass_workload(
            n, "registry.example.com/probed:1.0.0", probes=True,
            resources=res("500m", "2Gi", None, "2Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=9),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=70"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c33():
    """Chart hygiene only: the metadata and packaging rules, nothing else.

    CH009/CH010/CH011/CH021/CH022/CH023/CH024/CH025 and TP011/TP012 fire on
    30-31 of 32. Most are INFO and cost nothing, but CH010, CH021, CH023,
    TP011 and TP012 are LOW and together take fifteen points off two small
    categories on essentially every chart. This is the family most likely to be
    a corpus artefact rather than a rule fault - a generator that emits five
    files per chart was never going to produce a .helmignore - and this chart
    is what settles that.
    """
    n = "tidy"
    return {
        "Chart.yaml": CHART_YAML_FULL.format(name=n, desc="Full chart metadata", app="1.0.0"),
        ".helmignore": ".git/\n*.tgz\n.DS_Store\n",
        "values.schema.json": VALUES_SCHEMA,
        "values.yaml": "replicaCount: 3\nimage:\n  repository: registry.example.com/tidy\n"
                       "  tag: \"1.0.0\"\nresources:\n  requests:\n    cpu: 500m\n"
                       "    memory: 2Gi\n  limits:\n    memory: 2Gi\n",
        "templates/_helpers.tpl": HELPERS_TPL.format(name=n),
        "templates/NOTES.txt": "{{ .Chart.Name }} {{ .Chart.Version }} installed.\n"
                               "Watch rollout:\n"
                               "  kubectl rollout status deploy/{{ .Release.Name }}-tidy\n",
        "templates/tests/test-connection.yaml": HELM_TEST.format(name=n),
        "templates/deployment.yaml": pass_workload(
            n, "registry.example.com/tidy:1.0.0",
            labels=STD_LABELS.format(name=n),
            resources=res("500m", "2Gi", None, "2Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=9).replace(
            "  name: {{ .Release.Name }}-tidy\n",
            "  name: {{ .Release.Name }}-tidy\n  labels:\n"
            + STD_LABELS.format(name=n)),
        "templates/service.yaml": SERVICE.format(name=n).replace(
            "  name: {{ .Release.Name }}-tidy\n",
            "  name: {{ .Release.Name }}-tidy\n  labels:\n"
            + STD_LABELS.format(name=n)),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=70"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
        ".dockerignore": "target/\n.git/\n*.md\n",
    }


def _c34():
    """Availability and the OOM flag: AV003, AV010 and JV026, nothing else.

    Three rules that fire on 29-32 of 32 for unrelated reasons, grouped here
    because each is a few lines and none has anywhere else to go. AV003 wants
    topologySpreadConstraints; AV010 wants a PodDisruptionBudget; JV026 wants
    -XX:+ExitOnOutOfMemoryError applied (not merely present in an ENV nothing
    reads - c02 already covers that distinction). If any of them keeps firing
    here, its fix text does not describe what its predicate actually checks.

    AV010 was added to this chart on the second pass. The first version of the
    ablation omitted it, AV010 was then the ONE rule still firing on all six
    charts including the clean control, and the honest reading of that is not
    "AV010 is miscalibrated" - it is that a chart with no PDB has no PDB. The
    experiment was incomplete, not the rule. Recording it here rather than
    quietly adding the file, because "the one rule the ablation could not
    silence" is exactly the shape of result that gets over-read.
    """
    n = "spread"
    return {
        "Chart.yaml": CHART_YAML.format(name=n, desc="Spread, PDB and OOM flag", app="1.0.0"),
        "values.yaml": "replicaCount: 3\n",
        "templates/deployment.yaml": pass_workload(
            n, "registry.example.com/spread:1.0.0",
            pod_extra=SPREAD.format(name=n),
            resources=res("500m", "2Gi", None, "2Gi")),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=9),
        "templates/pdb.yaml": PDB.format(name=n),
        "templates/service.yaml": SERVICE.format(name=n),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre",
            env={"JAVA_TOOL_OPTIONS": "-XX:MaxRAMPercentage=70 "
                                      "-XX:+ExitOnOutOfMemoryError"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
    }


def _c35():
    """All four fixes at once, plus one real defect. The control that matters.

    A corpus where the ubiquitous rules go quiet is only an improvement if the
    rules that carry information did not go quiet with them. This chart applies
    every remedy c31-c34 apply - and sets -Xmx3g inside a 2Gi limit, which is
    XF001: OBSERVED, CRITICAL, arithmetically certain, and the finding that
    triggered the R14 grade cap.

    So the assertion is not "this chart scores well". It is that this chart
    scores well in nine categories, fails CROSS outright, and is still capped
    at C by R14 - because a chart that cannot start is not a B+ no matter how
    tidy its labels are.
    """
    n = "control"
    return {
        "Chart.yaml": CHART_YAML_FULL.format(name=n, desc="Everything right except the heap",
                                             app="2.0.0"),
        ".helmignore": ".git/\n*.tgz\n",
        "values.schema.json": VALUES_SCHEMA,
        "values.yaml": "replicaCount: 3\nimage:\n  repository: registry.example.com/control\n"
                       "  tag: \"2.0.0\"\nresources:\n  requests:\n    cpu: 1\n"
                       "    memory: 2Gi\n  limits:\n    memory: 2Gi\n",
        "templates/_helpers.tpl": HELPERS_TPL.format(name=n),
        "templates/NOTES.txt": "{{ .Chart.Name }} installed.\n",
        "templates/tests/test-connection.yaml": HELM_TEST.format(name=n),
        "templates/deployment.yaml": pass_workload(
            n, "registry.example.com/control:2.0.0", probes=True,
            labels=STD_LABELS.format(name=n),
            pod_extra="      automountServiceAccountToken: false\n"
                      + SPREAD.format(name=n),
            container_sc=SECURE_CONTAINER_SC,
            resources=res("1", "2Gi", None, "2Gi"),
            volumes="          volumeMounts:\n"
                    "            - name: tmp\n"
                    "              mountPath: /tmp\n"
                    "      volumes:\n"
                    "        - name: tmp\n"
                    "          emptyDir: {}\n"),
        "templates/hpa.yaml": hpa(n, "cpu", 70, minr=3, maxr=9).replace(
            "  name: {{ .Release.Name }}-control\n",
            "  name: {{ .Release.Name }}-control\n  labels:\n"
            + STD_LABELS.format(name=n)) + BEHAVIOR,
        "templates/pdb.yaml": PDB.format(name=n),
        "templates/service.yaml": SERVICE.format(name=n).replace(
            "  name: {{ .Release.Name }}-control\n",
            "  name: {{ .Release.Name }}-control\n  labels:\n"
            + STD_LABELS.format(name=n)),
        "Dockerfile": dockerfile(
            "eclipse-temurin:21.0.3_9-jre", multistage=True,
            env={"JAVA_TOOL_OPTIONS": "-Xmx3g -XX:+UseG1GC "
                                      "-XX:+ExitOnOutOfMemoryError"},
            entrypoint='["java", "-jar", "/app/app.jar"]'),
        ".dockerignore": "target/\n.git/\n",
    }


CHARTS = [
    ("c01-temurin21-pct-cpu",     "Java 21, MaxRAMPercentage, CPU HPA, values-supplied resources", _c01),
    ("c02-8u131-inert-javaopts",  "Java 8u131, flags in an ENV nothing reads",                     _c02),
    ("c03-openjdk8-shellcmd",     "bare `8` tag, shell-form CMD, no limits, no HPA",               _c03),
    ("c04-17-noflags-memhpa",     "Java 17, zero heap config, HPA on memory",                      _c04),
    ("c05-11-removed-flags",      "Java 11 with UseCGroupMemoryLimitForHeap + CMS",                _c05),
    ("c06-helper-resources",      "resources from _helpers.tpl (the R11 path)",                    _c06),
    ("c07-xmx-over-limit",        "-Xmx3g under a 2Gi limit",                                      _c07),
    ("c08-corporate-base",        "internal base image, JAVA_TOOL_OPTIONS in pod env",             _c08),
    ("c09-no-dockerfile",         "chart only, no Dockerfile, flags via pod env",                  _c09),
    ("c10-statefulset-distroless", "StatefulSet, distroless java17, no HPA",                       _c10),
    ("c11-pct-on-java8",          "MaxRAMPercentage + MaxPermSize on 8u151, v2beta2 HPA",          _c11),
    ("c12-no-mem-limit",          "percentage heap with no memory limit to take a percentage of",  _c12),
    ("c13-unsized-sidecar",       "app sized, log sidecar not",                                    _c13),
    ("c14-resources-in-overlay",  "resources only in values-prod.yaml",                            _c14),
    ("c15-tiny-heap-big-limit",   "-Xmx1g inside an 8Gi limit",                                    _c15),
    ("c16-deprecated-apis-nokubeversion", "v1beta1 Ingress + PDB, no declared kubeVersion",       _c16),
    ("c17-deprecated-apis-kubeversion",   "same chart, kubeVersion \">=1.19.0-0 <1.21.0-0\"",       _c17),
    ("c18-undetermined-fit",      "sized to straddle the R9 estimate band (for --measured)",      _c18),
    ("c19-conditional-sidecar",   "whole container behind an if, default off",                    _c19),
    ("c20-render-fails",          "`required` on an unset value: helm template fails by design",  _c20),
    ("c21-umbrella-split",        "workload in charts/worker, HPA in the parent",                 _c21),
    ("c22-cronjob-hpa",           "HPA targeting a CronJob, -Xmx6g under a 4Gi limit",            _c22),
    ("c23-native-sidecar-init",   "restartPolicy:Always init + a 3Gi ordinary init",              _c23),
    ("c24-not-java",              "nginx, no JVM anywhere - the --assume-java control",           _c24),
    ("c25-maxramfraction",        "8u191 boundary, -XX:MaxRAMFraction=2",                         _c25),
    ("c26-one-cpu-many-threads",  "500m limit, 400 tomcat threads, -Xss1m",                       _c26),
    ("c27-case-mismatch-target",  "two Deployments, HPA scaleTargetRef case does not match",      _c27),
    ("c28-pinned-hpa",            "minReplicas == maxReplicas == 6, memory HPA, fixed heap",      _c28),
    ("c29-overlay-shrinks-limit", "values-staging halves the limit but not -Xmx3g",               _c29),
    ("c30-misfiled-inputs",       "Dockerfile under build/, stray k8s/, values named config.yaml", _c30),
    ("c31-security-only",         "SC001-SC006 fixed, everything else ordinary",                  _c31),
    ("c32-probes-only",           "startupProbe + timeouts, everything else ordinary",            _c32),
    ("c33-hygiene-only",          "full chart metadata + standard labels, workload ordinary",     _c33),
    ("c34-spread-and-oomflag",    "topologySpread + applied ExitOnOutOfMemoryError",              _c34),
    ("c35-all-clean-one-bug",     "all four ablations plus -Xmx3g under a 2Gi limit (XF001)",     _c35),
]


def write_corpus(root):
    """Materialise every chart in CHARTS under `root`. Returns [(dirname, blurb), ...]."""
    made = []
    for dirname, blurb, fn in CHARTS:
        base = os.path.join(root, dirname)
        for rel, content in fn().items():
            path = os.path.join(base, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        made.append((dirname, blurb))
    return made


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/java-corpus"
    for d, b in write_corpus(out):
        print(f"{d:30s} {b}")
    print(f"\nwritten to {out}")

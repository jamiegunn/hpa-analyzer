"""Test helpers: build throwaway chart directories."""

import os
import tempfile


def make_tree(files: dict) -> str:
    """Create a temp dir from {relpath: content}. Caller need not clean up
    (tempdirs live under the test runner's tmp and vanish with it)."""
    root = tempfile.mkdtemp(prefix="hpa-test-")
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    return root


CHART_YAML = """apiVersion: v2
name: t
version: 1.0.0
appVersion: "1.0"
description: test
kubeVersion: ">=1.23.0-0"
maintainers: [{name: t}]
icon: https://x/i.png
"""

DEPLOYMENT_TPL = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
spec:
  %(replicas_block)s
  selector:
    matchLabels: {app: t}
  template:
    metadata:
      labels: {app: t}
    spec:
      containers:
        - name: app
          image: "repo/app:1.0"
          resources:
            requests: {cpu: 500m, memory: 1Gi}
            limits: {memory: 1Gi}
"""

HPA_TPL = """{{- if .Values.autoscaling.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ .Release.Name }}-app
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: {{ .Release.Name }}-app}
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource: {name: cpu, target: {type: Utilization, averageUtilization: 70}}
{{- end }}
"""

VALUES_AUTOSCALE_ON = """replicaCount: 2
autoscaling:
  enabled: true
"""


def chart_with_replicas(replicas_block: str, values: str = VALUES_AUTOSCALE_ON,
                        extra: dict = None) -> str:
    files = {
        "Chart.yaml": CHART_YAML,
        "values.yaml": values,
        "templates/deployment.yaml": DEPLOYMENT_TPL % {
            "replicas_block": replicas_block},
        "templates/hpa.yaml": HPA_TPL,
    }
    files.update(extra or {})
    return make_tree(files)

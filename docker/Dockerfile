# hpa-analyzer, containerised.
#
# WHY THIS EXISTS
# ---------------
# The analyzer's answer is a function of what is on PATH. That is not a
# figure of speech: with helm absent, the same chart's report changes its
# `Analysis mode` from `helm (rendered truth)` to `static`, rewrites every
# row of the coverage table from `rendered by helm` to `statically parsed`,
# and even rewords a finding (HP050 loses the word "Rendered"). So a report
# is only reproducible if the toolchain that produced it is. Pinning the four
# binaries here is the point of the image, not incidental packaging.
#
# WHAT IS DELIBERATELY ABSENT
# ---------------------------
# No USER line. The wrapper passes `--user "$(id -u):$(id -g)"` so that files
# written to your output directory belong to you rather than to root. That
# means the container runs as a uid with no /etc/passwd entry and no writable
# home, which is why HOME is pinned to /tmp below - helm tolerates a missing
# HOME (verified: `env -u HOME helm template ... --kube-version 1.29.0`
# exits 0) but does not tolerate one it cannot write to.
#
# No kubectl, no kubeconfig, no network at run time. The analyzer never
# contacts a cluster: clusterprobes.py only *emits* kubectl command text for
# a human to run. The only subprocess calls in the whole package are helm
# (helmrender.py) and the cross-check tools (external.py).

# Bump these deliberately, never implicitly. A toolchain change can move a
# report's findings, so it is a versioned decision - see docs/DOCKER.md.
#
# They sit ABOVE the first FROM, in global scope, because stage 2 needs them
# too (it stamps them into /etc/hpa-analyzer-image). A bare `ARG HELM_VERSION`
# inside a stage inherits a GLOBAL default but not another stage's; declared
# per-stage, stage 2 would read empty on any build without --build-arg and the
# marker would record `helm=` while the image contained 3.16.4. A provenance
# file that is silently blank is worse than none.
ARG HELM_VERSION=3.16.4
ARG KUBECONFORM_VERSION=0.6.7
ARG KUBE_SCORE_VERSION=1.20.0
ARG POLARIS_VERSION=9.6.4

# ---------------------------------------------------------------------------
# stage 1: fetch the pinned toolchain
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS tools

ARG HELM_VERSION
ARG KUBECONFORM_VERSION
ARG KUBE_SCORE_VERSION
ARG POLARIS_VERSION

# Set by BuildKit automatically (amd64 / arm64). Every one of these projects
# publishes both, so an Apple Silicon build gets native binaries rather than
# emulated ones.
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates tar \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /out; \
    \
    # helm publishes only to get.helm.sh - there are no binaries on its
    # GitHub releases page, so do not "fix" this URL to point there.
    curl -fsSL "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${TARGETARCH}.tar.gz" \
      | tar -xz -C /tmp; \
    install -m 0755 "/tmp/linux-${TARGETARCH}/helm" /out/helm; \
    \
    curl -fsSL "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/kubeconform-linux-${TARGETARCH}.tar.gz" \
      | tar -xz -C /tmp kubeconform; \
    install -m 0755 /tmp/kubeconform /out/kubeconform; \
    \
    curl -fsSL "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/kube-score_${KUBE_SCORE_VERSION}_linux_${TARGETARCH}.tar.gz" \
      | tar -xz -C /tmp kube-score; \
    install -m 0755 /tmp/kube-score /out/kube-score; \
    \
    curl -fsSL "https://github.com/FairwindsOps/polaris/releases/download/${POLARIS_VERSION}/polaris_linux_${TARGETARCH}.tar.gz" \
      | tar -xz -C /tmp polaris; \
    install -m 0755 /tmp/polaris /out/polaris; \
    \
    # Prove each one runs in THIS image before it is copied into the next
    # stage. A binary that downloaded but cannot execute (wrong arch, missing
    # loader) would otherwise surface as a silent coverage downgrade at
    # analysis time, which is exactly the failure this image exists to stop.
    /out/helm version --short; \
    /out/kubeconform -v; \
    /out/kube-score version; \
    /out/polaris version

# ---------------------------------------------------------------------------
# stage 2: the runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim

COPY --from=tools /out/helm /out/kubeconform /out/kube-score /out/polaris \
     /usr/local/bin/

# ca-certificates is NOT optional, and it is not here out of caution - it is
# here because its absence was measured. kubeconform downloads JSON schemas
# over HTTPS. An image without a CA bundle does not fail loudly; kubeconform
# reports `tls: failed to verify certificate: x509: certificate signed by
# unknown authority`, the analyzer correctly records that as "not checkable",
# and a chart that validates cleanly on the host reads as
# `0 valid, 0 invalid, 3 not checkable` in the container. Nobody lies at any
# step and the answer still changes. The base image is very likely to carry
# the bundle already, in which case this line is a no-op - which is a cheaper
# price than being wrong about it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "PyYAML>=5.4"

COPY hpaanalyzer/ /opt/hpa-analyzer/hpaanalyzer/

# The marker __main__._require_image() looks for. Without it the module
# refuses to run, which is the whole point: a report is only comparable
# between two people if the four binaries above are the same two binaries,
# and the only place that is guaranteed is in here.
#
# It records the pinned versions rather than being an empty touch-file, so a
# report that looks wrong can be traced to a toolchain: `docker run
# --entrypoint cat <image> /etc/hpa-analyzer-image` says exactly what
# produced it. Nothing parses this content - the guard is an existence check
# - so the format is for humans and may change.
#
# It is written world-readable on purpose. The wrapper passes --user, so the
# process reading it is an arbitrary uid with no /etc/passwd entry.
ARG HELM_VERSION
ARG KUBECONFORM_VERSION
ARG KUBE_SCORE_VERSION
ARG POLARIS_VERSION
RUN printf '%s\n' \
      "hpa-analyzer container image" \
      "helm=${HELM_VERSION}" \
      "kubeconform=${KUBECONFORM_VERSION}" \
      "kube-score=${KUBE_SCORE_VERSION}" \
      "polaris=${POLARIS_VERSION}" \
      > /etc/hpa-analyzer-image \
 && chmod 0444 /etc/hpa-analyzer-image

ENV PYTHONPATH=/opt/hpa-analyzer \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp

# `docker run` propagates the container's exit status, so the CI gates
# (--fail-on, --min-score, --require-coverage, and --check's exit 2) keep
# working through the wrapper unchanged. Nothing here may swallow a code.
#
# There is deliberately no CMD. `CMD ["--help"]` is the obvious friendly
# default and it was measured to break the contract: `python3 -m hpaanalyzer`
# with no arguments is an argparse usage error and exits 2, while
# `docker run <image>` with a --help CMD prints help and exits 0. That is a
# green build where the native command gives a red one, produced by nothing
# but a convenience. An empty argv therefore reaches argparse untouched.
ENTRYPOINT ["python3", "-m", "hpaanalyzer"]

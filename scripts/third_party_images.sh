#!/usr/bin/env bash
# The third-party images VaultGate's environments run, one per line, for the Security
# workflow's image scan (M10, docs/security-scans.md). Rendered from what is deployed,
# so an image added or bumped is scanned with nothing else to update: docker compose,
# the local cluster's node, manifests and charts, the upstream charts at the versions
# deploy/argocd/local/values.yaml pins, and the cluster check's probe pod. VaultGate's
# own images are scanned apart (built from this repository).
set -euo pipefail
cd "$(dirname "$0")/.."

pinned() { sed -n "s/^$1: *//p" deploy/argocd/local/values.yaml; }
# The local cluster's Kubernetes version (its k3s image's), for charts that check it.
kube=$(sed -n 's/^image: rancher\/k3s:v\([0-9.]*\).*/\1/p' deploy/k3d/cluster.yaml)

render() {
  cat docker-compose.yml deploy/k3d/cluster.yaml
  helm template vaultgate deploy/helm/vaultgate -n vaultgate \
    -f deploy/helm/vaultgate/values-k3d.yaml
  helm template observability deploy/k3d/observability -n monitoring
  kubectl kustomize deploy/k3d/openbao
  kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k3d/deps
  kubectl kustomize deploy/k3d/argocd
  helm template kps kube-prometheus-stack --skip-tests -n monitoring --kube-version "$kube" \
    --repo https://prometheus-community.github.io/helm-charts \
    --version "$(pinned kubePrometheusStack)" -f deploy/k3d/kube-prometheus-stack.yaml
  helm template cert-manager cert-manager --skip-tests -n cert-manager --kube-version "$kube" \
    --repo https://charts.jetstack.io --version "$(pinned certManager)"
  helm template trust-manager trust-manager --skip-tests -n cert-manager --kube-version "$kube" \
    --repo https://charts.jetstack.io --version "$(pinned trustManager)"
  helm template keda keda --skip-tests -n keda --kube-version "$kube" \
    --repo https://kedacore.github.io/charts --version "$(pinned keda)"
  grep -h -- '--image=' scripts/k3d.sh
}

# `image:` fields, and the images passed as arguments that run: the config reloader the
# operator adds to Prometheus' and Alertmanager's pods, and the probe pod's. Not the
# defaults for what the cluster doesn't use (Thanos, cert-manager's ACME solver), nor the
# charts' test hooks, which Argo CD doesn't run.
render \
  | grep -oE "(image: *|--image=|--prometheus-config-reloader=)[\"']?[a-z0-9][^\"' ]*" \
  | sed -E "s/^[^:=]*[:=] *[\"']?//" \
  | grep -vE '^vaultgate-|/vaultgate-(api|gateway|scanner)(:|$)' \
  | sort -u

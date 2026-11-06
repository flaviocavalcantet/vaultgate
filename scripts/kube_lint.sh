#!/usr/bin/env bash
# The Kubernetes manifests against kube-linter's checks (M10, docs/security-scans.md):
# VaultGate's chart with its default values and with the local cluster's, and the local
# cluster's own manifests (OpenBao, the PKI, the dependencies, observability). Argo CD's
# upstream install is not ours, and is left out. A finding accepted for one object is
# recorded on that object (an ignore-check.kube-linter.io annotation, with the reason).
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

helm template vaultgate deploy/helm/vaultgate -n vaultgate >"$out/chart-default.yaml"
helm template vaultgate deploy/helm/vaultgate -n vaultgate \
  -f deploy/helm/vaultgate/values-k3d.yaml >"$out/chart-k3d.yaml"
helm template observability deploy/k3d/observability -n monitoring >"$out/observability.yaml"
kubectl kustomize deploy/k3d/openbao >"$out/openbao.yaml"
kubectl kustomize deploy/k3d/pki >"$out/pki.yaml"
# The realm comes from infra/keycloak, outside the directory (as Argo CD allows it).
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k3d/deps >"$out/deps.yaml"

kube-linter lint "$out"/*.yaml

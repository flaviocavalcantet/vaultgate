#!/usr/bin/env bash
# The local Kubernetes cluster (M7, deploy/k3d): k3d, Argo CD syncing this repo, and
# VaultGate with its dependencies in the cluster.
#
#   scripts/k3d.sh up      create the cluster, build and push the images, install Argo CD,
#                          hand it the repo, wait until everything is synced and healthy,
#                          then create the buckets, key and queues (Terraform) and seed the
#                          local access policy
#   scripts/k3d.sh images  rebuild and push the images, and restart the pods to pull them
#   scripts/k3d.sh check   the vault end-to-end check against the cluster, plus cluster
#                          checks: Argo CD in sync, the gateway's autoscaler reading CPU,
#                          and the network policy closing the API's internal port
#   scripts/k3d.sh down    delete the cluster (and its registry)
#
# Argo CD deploys what is in git, not the working tree: it syncs VAULTGATE_REVISION
# (default: the current branch, which must be pushed) from VAULTGATE_REPO. The images
# are the exception: they are built from the working tree and pushed to the cluster's
# registry (localhost:5050).
#
# Needs Docker, k3d, kubectl, Python 3 and Terraform. The host ports are those of docker
# compose (8000, 8888, 8080, 4566, 8025): stop compose first (`make down`).
set -euo pipefail

cd "$(dirname "$0")/.."
CLUSTER=vaultgate
REGISTRY=localhost:5050
REPO=${VAULTGATE_REPO:-https://github.com/flaviocavalcantet/vaultgate}
REVISION=${VAULTGATE_REVISION:-$(git rev-parse --abbrev-ref HEAD)}

log() { printf '\n==> %s\n' "$*"; }

wait_for() { # wait_for <seconds> <description> <command...>
  local deadline=$((SECONDS + $1)) what=$2
  shift 2
  until "$@" >/dev/null 2>&1; do
    if ((SECONDS > deadline)); then
      echo "timed out waiting for $what" >&2
      return 1
    fi
    sleep 5
  done
}

images() {
  for service in api gateway scanner; do
    log "image vaultgate-$service"
    docker build -t "$REGISTRY/vaultgate-$service:dev" "$service"
    docker push "$REGISTRY/vaultgate-$service:dev"
  done
}

app_ready() { # Synced and Healthy
  local status
  status=$(kubectl -n argocd get application "$1" \
    -o jsonpath='{.status.sync.status}/{.status.health.status}' 2>/dev/null) || return 1
  [[ $status == Synced/Healthy ]]
}

up() {
  if ! k3d cluster list "$CLUSTER" >/dev/null 2>&1; then
    log "cluster $CLUSTER"
    k3d cluster create --config deploy/k3d/cluster.yaml
  fi
  images

  log "Argo CD"
  kubectl apply --server-side --force-conflicts -k deploy/k3d/argocd
  for deployment in argocd-server argocd-repo-server argocd-redis; do
    kubectl -n argocd rollout status "deployment/$deployment" --timeout=300s
  done
  kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=300s
  # The settings above are read at start: make sure the pods have them.
  kubectl -n argocd rollout restart deployment/argocd-repo-server statefulset/argocd-application-controller
  kubectl -n argocd rollout status deployment/argocd-repo-server --timeout=300s
  kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=300s

  if [[ $REVISION != main ]] && ! git ls-remote --exit-code "$REPO" "$REVISION" >/dev/null 2>&1 \
    && ! [[ $REVISION =~ ^[0-9a-f]{40}$ ]]; then
    echo "warning: $REVISION is not on $REPO; Argo CD syncs what is pushed" >&2
  fi
  log "root application: $REPO at $REVISION"
  sed -e "s#\${REPO}#$REPO#g" -e "s#\${REVISION}#$REVISION#g" deploy/k3d/root-application.yaml |
    kubectl apply -f -

  log "waiting for Argo CD to sync the dependencies and VaultGate"
  wait_for 900 "vaultgate-deps to be synced and healthy" app_ready vaultgate-deps
  wait_for 900 "vaultgate to be synced and healthy" app_ready vaultgate

  log "Terraform against the in-cluster LocalStack"
  wait_for 120 "LocalStack" curl -sf http://localhost:4566/_localstack/health
  make tf-local
  python3 scripts/seed_policies.py
  log "ready: API http://localhost:8000, gateway http://localhost:8888, Keycloak http://localhost:8080, Mailpit http://localhost:8025"
}

restart() {
  kubectl -n vaultgate rollout restart deployment
  kubectl -n vaultgate rollout status deployment --timeout=300s
}

check_cluster() {
  log "Argo CD: every application synced and healthy"
  for app in vaultgate-local vaultgate-deps vaultgate; do
    app_ready "$app" || {
      kubectl -n argocd get application "$app" -o yaml >&2
      return 1
    }
    echo "ok  $app is Synced and Healthy"
  done

  log "the gateway's autoscaler reads CPU"
  wait_for 300 "the HPA to report CPU utilization" \
    sh -c "kubectl -n vaultgate get hpa vaultgate-gateway -o jsonpath='{.status.currentMetrics[0].resource.current.averageUtilization}' | grep -q '[0-9]'"
  kubectl -n vaultgate get hpa vaultgate-gateway
  echo "ok  the gateway scales on CPU"

  log "network policy: only the gateway and the scanner reach the API's internal port"
  local probe=(kubectl -n vaultgate run "netpol-probe-$RANDOM" --rm -i --restart=Never --quiet
    --image=curlimages/curl:8.11.1 --command --)
  # The public port first: it proves the probe itself works, so a refusal below is the
  # policy's and not a probe that never ran.
  "${probe[@]}" curl -sf -m 5 -o /dev/null http://vaultgate-api:8000/healthz
  if "${probe[@]}" curl -s -m 5 -o /dev/null http://vaultgate-api:8001/healthz; then
    echo "another pod reached the API's internal port" >&2
    return 1
  fi
  echo "ok  another pod reaches the public port, not the internal one"
}

check() {
  check_cluster
  log "vault end to end, against the cluster"
  # Traces and logs come with the cluster's observability stack (next M7 step).
  python3 scripts/vault_e2e.py --skip-traces
}

case ${1:-} in
up) up ;;
images) images && restart ;;
check) check ;;
down) k3d cluster delete "$CLUSTER" ;;
*)
  sed -n '2,20p' "$0"
  exit 2
  ;;
esac

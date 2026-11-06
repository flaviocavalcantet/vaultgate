#!/usr/bin/env bash
# The local Kubernetes cluster (M7, deploy/k3d): k3d, Argo CD syncing this repo, and
# VaultGate with its dependencies in the cluster.
#
#   scripts/k3d.sh up      create the cluster, build and push the images, give OpenBao its
#                          TLS certificate (from the offline root) and seal key, install
#                          Argo CD, hand it the repo, wait until everything is synced and
#                          healthy, install the intermediate CA (the PKI ceremony), then
#                          create the buckets, key and queues (Terraform) and seed the
#                          local access policy
#   scripts/k3d.sh images  rebuild and push the images, and restart the pods to pull them
#   scripts/k3d.sh check   the vault end-to-end check against the cluster (traces in
#                          Tempo and logs in Loki included), plus cluster checks: Argo CD
#                          in sync, OpenBao unsealed with its CA chained to the root, the
#                          gateway's autoscaler reading CPU, the network policy closing the
#                          API's internal port, Prometheus scraping every service,
#                          Grafana's dashboards, and Alertmanager's mail
#   scripts/k3d.sh down    delete the cluster (and its registry)
#
# Argo CD deploys what is in git, not the working tree: it syncs VAULTGATE_REVISION
# (default: the current branch, which must be pushed) from VAULTGATE_REPO. The images
# are the exception: they are built from the working tree and pushed to the cluster's
# registry (localhost:5050).
#
# The root CA (ADR 0012) is kept in ~/.vaultgate/pki (VAULTGATE_PKI_DIR), its key
# encrypted with a passphrase that `up` asks for, or takes from VAULTGATE_PKI_PASSPHRASE.
# In CI each job gets a root of its own, whose key is deleted once the ceremony is done.
#
# Needs Docker, k3d, kubectl, Python 3, openssl and Terraform. The host ports are those of
# docker compose (8000, 8888, 8080, 4566, 8025, 3000, 9090, 3100, 3200; and 9093 for
# Alertmanager, 8200 for OpenBao): stop compose first (`make down`).
set -euo pipefail

cd "$(dirname "$0")/.."
CLUSTER=vaultgate
REGISTRY=localhost:5050
REPO=${VAULTGATE_REPO:-https://github.com/flaviocavalcantet/vaultgate}
REVISION=${VAULTGATE_REVISION:-$(git rev-parse --abbrev-ref HEAD)}
if [[ -n ${CI:-} ]]; then
  export VAULTGATE_PKI_DIR=${VAULTGATE_PKI_DIR:-${RUNNER_TEMP:-/tmp}/vaultgate-pki}
fi

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

# OpenBao's two Secrets, before Argo CD starts it: its server certificate, signed by the
# offline root, and its seal key. Neither is in git; both are kept if they exist.
pki_bootstrap() {
  if [[ -n ${CI:-} && -z ${VAULTGATE_PKI_PASSPHRASE:-} ]]; then
    VAULTGATE_PKI_PASSPHRASE=$(openssl rand -hex 32) # this job's root only
    export VAULTGATE_PKI_PASSPHRASE
  fi
  log "the root CA"
  python3 scripts/pki.py root
  kubectl create namespace openbao --dry-run=client -o yaml | kubectl apply -f -
  local tmp
  tmp=$(mktemp -d)
  if ! kubectl -n openbao get secret openbao-unseal >/dev/null 2>&1; then
    openssl rand -out "$tmp/key" 32
    kubectl -n openbao create secret generic openbao-unseal --from-file=key="$tmp/key"
  fi
  if ! kubectl -n openbao get secret openbao-tls >/dev/null 2>&1; then
    python3 scripts/pki.py openbao-tls "$tmp"
    kubectl -n openbao create secret tls openbao-tls --cert="$tmp/tls.crt" --key="$tmp/tls.key"
  fi
  rm -rf "$tmp"
}

# The intermediate CA, once OpenBao is up: it generates the key and a CSR, the root
# signs it here, and OpenBao installs it. Logged in as the pki-ceremony service account.
pki_ceremony() {
  log "the intermediate CA (PKI ceremony)"
  wait_for 120 "OpenBao on localhost:8200" python3 scripts/pki.py check-tls
  VAULTGATE_OPENBAO_JWT=$(kubectl -n openbao create token pki-ceremony --audience openbao --duration 10m) \
    python3 scripts/pki.py intermediate
  if [[ -n ${CI:-} ]]; then
    rm -f "$VAULTGATE_PKI_DIR/root-ca.key" # nothing else will ever be signed by this root
  fi
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
  # The node pulls one image itself, so a registry problem fails here with its reason,
  # not as pods stuck in ImagePullBackOff behind a long wait.
  docker exec "k3d-$CLUSTER-server-0" crictl pull "vaultgate-registry.localhost:5000/vaultgate-api:dev"

  pki_bootstrap

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
  for app in vaultgate-deps vaultgate-openbao kube-prometheus-stack vaultgate-observability vaultgate; do
    wait_for 900 "$app to be synced and healthy" app_ready "$app"
  done
  pki_ceremony

  log "Terraform against the in-cluster LocalStack"
  wait_for 120 "LocalStack" curl -sf http://localhost:4566/_localstack/health
  make tf-local
  python3 scripts/seed_policies.py
  log "ready: OpenBao https://localhost:8200 (root CA in ${VAULTGATE_PKI_DIR:-~/.vaultgate/pki}), API http://localhost:8000, gateway http://localhost:8888, Keycloak http://localhost:8080, Mailpit http://localhost:8025, Grafana http://localhost:3000 (admin/admin), Prometheus http://localhost:9090, Alertmanager http://localhost:9093"
}

restart() {
  kubectl -n vaultgate rollout restart deployment
  kubectl -n vaultgate rollout status deployment --timeout=300s
}

check_cluster() {
  log "Argo CD: every application synced and healthy"
  for app in vaultgate-local vaultgate-deps vaultgate-openbao kube-prometheus-stack \
    vaultgate-observability vaultgate; do
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

check_observability() {
  log "Prometheus scrapes every service"
  wait_for 300 "every target to be up" python3 scripts/k3d_checks.py targets
  python3 scripts/k3d_checks.py targets
  log "Grafana has VaultGate's dashboards and data sources"
  python3 scripts/k3d_checks.py grafana
  log "Alertmanager sends mail (Watchdog, to Mailpit)"
  wait_for 300 "Alertmanager's heartbeat mail" python3 scripts/k3d_checks.py alertmanager
  python3 scripts/k3d_checks.py alertmanager
}

check_pki() {
  log "PKI: OpenBao unsealed, its TLS and its intermediate CA chained to the root"
  python3 scripts/pki.py check
}

check() {
  check_cluster
  check_pki
  check_observability
  log "vault end to end, against the cluster"
  python3 scripts/vault_e2e.py
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

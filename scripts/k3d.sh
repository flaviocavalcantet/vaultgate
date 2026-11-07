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
#                          in sync, OpenBao unsealed with its CA chained to the root, TLS on
#                          the API, gateway, Keycloak and PostgreSQL, the
#                          gateway's autoscaler reading CPU, the network policy closing the
#                          API's internal port, Prometheus scraping every service,
#                          Grafana's dashboards, and Alertmanager's mail; then negative
#                          tests: what the API, the gateway and the cluster must refuse
#   scripts/k3d.sh zap     OWASP ZAP against the API and the gateway (passive and active
#                          scans); its reports go to VAULTGATE_ZAP_DIR (zap-reports)
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
ROOT_CA=${VAULTGATE_PKI_DIR:-$HOME/.vaultgate/pki}/root-ca.crt
# The API and the gateway serve TLS from the cluster's CA: the host's scripts trust the
# root (Python's ssl reads SSL_CERT_FILE, Python's requests REQUESTS_CA_BUNDLE).
API=https://localhost:8000
KEYCLOAK=https://localhost:8080
host_trust() { SSL_CERT_FILE=$ROOT_CA REQUESTS_CA_BUNDLE=$ROOT_CA "$@"; }

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
  # PostgreSQL's passwords, random (deploy/k3d/deps/postgres.yaml): the superuser's, and
  # OpenBao's first one, which OpenBao reads at its first start and rotates once
  # PostgreSQL is up (secrets_rotate below). The API's credentials are OpenBao's to issue.
  if ! kubectl -n vaultgate-deps get secret postgres-credentials >/dev/null 2>&1; then
    local openbao_password
    openbao_password=$(openssl rand -hex 24)
    kubectl create namespace vaultgate-deps --dry-run=client -o yaml | kubectl apply -f -
    kubectl -n vaultgate-deps create secret generic postgres-credentials \
      --from-literal=superuser-password="$(openssl rand -hex 24)" \
      --from-literal=openbao-password="$openbao_password"
    kubectl -n openbao create secret generic openbao-postgres --from-literal=password="$openbao_password" \
      --dry-run=client -o yaml | kubectl apply -f -
  fi
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
  # Only now, with the intermediate installed, the root goes to cert-manager: its issuer
  # stays not ready until then, so certificate requests wait instead of failing (a
  # failed one is retried an hour later), and to trust-manager, which hands it out.
  # VaultGate's namespace gets it too (M10, ADR 0013): its client certificates' Issuer
  # verifies OpenBao with it, and the API verifies those certificates against it.
  local ns
  for ns in cert-manager vaultgate; do
    kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
    kubectl -n "$ns" create secret generic vaultgate-root-ca --from-file=ca.crt="$ROOT_CA" \
      --dry-run=client -o yaml | kubectl apply -f -
  done
  # If the issuers already exist, have cert-manager look at them now rather than after
  # its retry backoff (up to five minutes).
  kubectl annotate clusterissuer vaultgate-ca --overwrite \
    "vaultgate.io/root-ca-installed=$(date +%s)" >/dev/null 2>&1 || true
  kubectl -n vaultgate annotate issuer vaultgate-clients --overwrite \
    "vaultgate.io/root-ca-installed=$(date +%s)" >/dev/null 2>&1 || true
}

# The services' credentials, in OpenBao (M9, ADR 0012): random values for the tokens,
# created once and kept. The pods' OpenBao agents wait for them.
secrets_seed() {
  log "the services' credentials, in OpenBao"
  VAULTGATE_OPENBAO_JWT=$(kubectl -n openbao create token secrets-seed --audience openbao --duration 10m) \
    python3 scripts/service_secrets.py seed
}

# Once PostgreSQL is up: OpenBao changes its own password there, so the first one (in the
# Secrets above) opens nothing any more.
secrets_rotate() {
  log "OpenBao's PostgreSQL password, rotated"
  # OpenBao verifies PostgreSQL with the trust bundle, which trust-manager writes and
  # kubelet then copies into OpenBao's pod, up to a minute after PostgreSQL is ready:
  # retried until it can (a failed attempt changes nothing).
  local jwt
  jwt=$(kubectl -n openbao create token secrets-seed --audience openbao --duration 10m)
  # The last try in the open, so a failure says why.
  wait_for 300 "OpenBao to reach PostgreSQL over TLS" \
    env VAULTGATE_OPENBAO_JWT="$jwt" python3 scripts/service_secrets.py rotate-db ||
    VAULTGATE_OPENBAO_JWT="$jwt" python3 scripts/service_secrets.py rotate-db
  echo "ok  OpenBao's PostgreSQL password rotated: only OpenBao knows it"
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
  # OpenBao first: the ceremony gives it the intermediate CA that VaultGate's
  # certificates come from, and the pods wait for those.
  wait_for 900 "vaultgate-openbao to be synced and healthy" app_ready vaultgate-openbao
  pki_ceremony
  secrets_seed
  wait_for 900 "vaultgate-deps to be synced and healthy" app_ready vaultgate-deps
  secrets_rotate
  for app in cert-manager kube-prometheus-stack trust-manager vaultgate-observability \
    vaultgate-pki vaultgate; do
    wait_for 900 "$app to be synced and healthy" app_ready "$app"
  done

  log "Terraform against the in-cluster LocalStack"
  wait_for 120 "LocalStack" curl -sf http://localhost:4566/_localstack/health
  make tf-local
  host_trust python3 scripts/seed_policies.py --api "$API" --keycloak "$KEYCLOAK"
  log "ready: OpenBao https://localhost:8200, API $API, gateway https://localhost:8888 (TLS: trust $ROOT_CA), Keycloak $KEYCLOAK, Mailpit http://localhost:8025, Grafana http://localhost:3000 (admin/admin), Prometheus http://localhost:9090, Alertmanager http://localhost:9093"
}

restart() {
  kubectl -n vaultgate rollout restart deployment
  kubectl -n vaultgate rollout status deployment --timeout=300s
}

check_cluster() {
  log "Argo CD: every application synced and healthy"
  for app in vaultgate-local vaultgate-deps vaultgate-openbao cert-manager trust-manager \
    vaultgate-pki kube-prometheus-stack vaultgate-observability vaultgate; do
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
  # policy's and not a probe that never ran. Reachability only, hence -k (the probe pod
  # has no trust bundle); the TLS checks are check_pki's.
  "${probe[@]}" curl -sfk -m 5 -o /dev/null https://vaultgate-api.vaultgate.svc:8000/healthz
  if "${probe[@]}" curl -sk -m 5 -o /dev/null https://vaultgate-api.vaultgate.svc:8001/healthz; then
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
  log "TLS: the API, the gateway and Keycloak serve certificates from the cluster's CA, and nothing in plain HTTP"
  kubectl -n vaultgate wait --for=condition=Ready certificate --all --timeout=120s
  kubectl -n vaultgate-deps wait --for=condition=Ready certificate --all --timeout=120s
  for url in "$API/healthz" https://localhost:8888/healthz "$KEYCLOAK/realms/vaultgate"; do
    curl -sf --cacert "$ROOT_CA" -o /dev/null "$url"
    if curl -s -m 5 -o /dev/null "${url/https:/http:}"; then
      echo "${url/https:/http:} answered in plain HTTP" >&2
      return 1
    fi
  done
  python3 scripts/pki.py check-service localhost:8000 localhost:8888 localhost:8080
  log "PostgreSQL: the API logs in with its own short-lived credentials, over TLS, verified; without TLS PostgreSQL refuses"
  kubectl -n vaultgate exec -i deploy/vaultgate-api -c api -- python - <scripts/postgres_tls_check.py
  log "mutual TLS: the API's internal port wants the gateway's client certificate, not none or a server's"
  kubectl -n vaultgate exec -i deploy/vaultgate-gateway -c gateway -- python - <scripts/mtls_check.py
}

check_secrets() {
  log "credentials: each service reads its own from OpenBao, none is in a Secret or an environment"
  local jwts=() service
  for service in api gateway scanner; do
    jwts+=("$service=$(kubectl -n vaultgate create token "vaultgate-$service" --audience openbao --duration 10m)")
  done
  VAULTGATE_SERVICE_JWTS=$(IFS=,; echo "${jwts[*]}") python3 scripts/service_secrets.py check
  if kubectl -n vaultgate get secret vaultgate >/dev/null 2>&1; then
    echo "the vaultgate Secret exists: the credentials should come from OpenBao only" >&2
    return 1
  fi
  if kubectl -n vaultgate get deploy -o yaml | grep -E -q "secretKeyRef|_TOKEN$|AWS_SECRET_ACCESS_KEY"; then
    echo "a deployment takes a credential from its environment" >&2
    return 1
  fi
  echo "ok  no Secret holds them, no deployment has one in its environment"
}

check() {
  check_cluster
  check_pki
  check_secrets
  check_observability
  log "vault end to end, against the cluster"
  host_trust python3 scripts/vault_e2e.py --api "$API" --keycloak "$KEYCLOAK"
  log "negative tests: what the API, the gateway and the cluster's services must refuse"
  host_trust python3 scripts/negative_checks.py --api "$API" --keycloak "$KEYCLOAK"
}

# OWASP ZAP (M10, docs/security-scans.md), from the host: the API's every route from its
# OpenAPI document, as alice (a real Keycloak login), and the gateway's routes from
# security/zap/gateway-openapi.yaml with a token that isn't an intent (one real intent
# would be spent by the first request). Passive and active scans; any warning that
# security/zap/<target>.conf doesn't mark as ignored fails the run. Its attacks create
# files and shares as alice: run it on a cluster nothing else needs, last.
ZAP_IMAGE=zaproxy/zap-stable:2.17.0
zap() {
  local out=${VAULTGATE_ZAP_DIR:-zap-reports} status=0 token
  mkdir -p "$out"
  chmod 777 "$out" # ZAP runs as its own user
  cp security/zap/* "$out"/
  token=$(host_trust env PYTHONPATH=scripts python3 -c 'from keycloak_smoke import login, wait_for
print(login(wait_for("'"$KEYCLOAK"'"), "alice", "alice-dev-password")["access_token"])')
  log "ZAP: the API, from its OpenAPI document, as alice"
  docker run --rm --network host -v "$PWD/$out:/zap/wrk:rw" -e ZAP_AUTH_HEADER=Authorization \
    -e ZAP_AUTH_HEADER_VALUE="Bearer $token" "$ZAP_IMAGE" zap-api-scan.py \
    -t "$API/openapi.json" -f openapi -c api.conf -r api.html -J api.json || status=1
  log "ZAP: the gateway"
  docker run --rm --network host -v "$PWD/$out:/zap/wrk:rw" -e ZAP_AUTH_HEADER=Authorization \
    -e ZAP_AUTH_HEADER_VALUE="Bearer not-an-intent" "$ZAP_IMAGE" zap-api-scan.py \
    -t /zap/wrk/gateway-openapi.yaml -f openapi -O https://localhost:8888 \
    -c gateway.conf -r gateway.html -J gateway.json || status=1
  return $status
}

case ${1:-} in
up) up ;;
images) images && restart ;;
check) check ;;
zap) zap ;;
down) k3d cluster delete "$CLUSTER" ;;
*)
  sed -n '2,20p' "$0"
  exit 2
  ;;
esac

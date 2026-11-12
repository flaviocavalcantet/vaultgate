#!/usr/bin/env bash
# The local Kubernetes cluster (M7, deploy/k3d): k3d, Argo CD syncing this repo, and
# VaultGate with its dependencies in the cluster.
#
#   scripts/k3d.sh up      create the cluster, build the images and load them into it (or
#                          have it pull the published ones), give OpenBao its
#                          TLS certificate (from the offline root) and seal key, install
#                          Argo CD, hand it the repo, wait until everything is synced and
#                          healthy, install the intermediate CA (the PKI ceremony), seed
#                          the services' credentials, create the bucket, key, queues and
#                          one IAM user per service (Terraform) and give each service its
#                          own AWS key, then seed the local access policy
#   scripts/k3d.sh images  rebuild the images, load them into the cluster and restart the
#                          pods
#   scripts/k3d.sh check   the vault end-to-end check against the cluster (traces in
#                          Tempo and logs in Loki included), plus cluster checks: Argo CD
#                          in sync, OpenBao unsealed with its CA chained to the root, TLS on
#                          the API, gateway, Keycloak and PostgreSQL, the
#                          gateway's autoscaler reading CPU and the transfers in
#                          progress (KEDA), the network policy closing the
#                          API's internal port, Prometheus scraping every service,
#                          Grafana's dashboards, and Alertmanager's mail; then negative
#                          tests: what the API, the gateway and the cluster must refuse
#   scripts/k3d.sh zap     OWASP ZAP against the API and the gateway (passive and active
#                          scans); its reports go to VAULTGATE_ZAP_DIR (zap-reports)
#   scripts/k3d.sh browser the web app's browser tests (vaultgate-frontend's Playwright and
#                          axe suite) against the cluster, at the commit whose image the
#                          cluster runs (VAULTGATE_FRONTEND_TESTS_REF to choose another)
#   scripts/k3d.sh dev-cert  copy the cluster's localhost certificate and key to
#                          VAULTGATE_DEV_TLS_DIR (~/.vaultgate/dev-tls), for the
#                          frontend's development server over HTTPS (`npm run dev:k3d`)
#   scripts/k3d.sh down    delete the cluster
#
# Argo CD deploys what is in git, not the working tree: it syncs VAULTGATE_REVISION
# (default: the current branch, which must be pushed) from VAULTGATE_REPO, and runs the
# images tagged with that commit (M12): ghcr.io/flaviocavalcantet/vaultgate-<service>:<commit>.
# CI publishes those on every merge to main. For anything else the images are the
# exception to "what is in git": they are built from the working tree under that same
# name and loaded straight into the cluster's node (`k3d image import`), which then has
# no reason to pull. VAULTGATE_IMAGES=pull builds nothing and has the node pull the
# published images instead (VAULTGATE_GHCR_TOKEN, with VAULTGATE_GHCR_USER, if the
# packages are private). After a new commit is pushed, Argo CD wants that commit's
# images: run `make k3d-images` again.
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
# The chart's default registry (deploy/helm/vaultgate/values.yaml).
REGISTRY=ghcr.io/flaviocavalcantet
REPO=${VAULTGATE_REPO:-https://github.com/flaviocavalcantet/vaultgate}
REVISION=${VAULTGATE_REVISION:-$(git rev-parse --abbrev-ref HEAD)}
IMAGES=${VAULTGATE_IMAGES:-build}
if [[ -n ${CI:-} ]]; then
  export VAULTGATE_PKI_DIR=${VAULTGATE_PKI_DIR:-${RUNNER_TEMP:-/tmp}/vaultgate-pki}
fi
ROOT_CA=${VAULTGATE_PKI_DIR:-$HOME/.vaultgate/pki}/root-ca.crt
# The API and the gateway serve TLS from the cluster's CA: the host's scripts trust the
# root (Python's ssl reads SSL_CERT_FILE, Python's requests REQUESTS_CA_BUNDLE).
API=https://localhost:8000
KEYCLOAK=https://localhost:8080
FRONTEND=https://localhost:5174
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

# The images' tag: the commit Argo CD syncs, which it passes to the chart as image.tag
# (deploy/argocd). A branch is resolved where Argo CD resolves it: on the remote.
image_tag() {
  if [[ $REVISION =~ ^[0-9a-f]{40}$ ]]; then
    echo "$REVISION"
    return
  fi
  local commit
  commit=$(git ls-remote "$REPO" "refs/heads/$REVISION" | cut -f1)
  if [[ -z $commit ]]; then
    echo "$REVISION is not a branch of $REPO: push it first (Argo CD syncs what is pushed)" >&2
    return 1
  fi
  echo "$commit"
}

images() {
  local tag service names=()
  tag=$(image_tag)
  if [[ $IMAGES == pull ]]; then
    # The node pulls the published images itself, now: a missing image or a registry
    # problem fails here with its reason, not as pods stuck in ImagePullBackOff behind a
    # long wait.
    local creds=()
    if [[ -n ${VAULTGATE_GHCR_TOKEN:-} ]]; then
      creds=(--creds "${VAULTGATE_GHCR_USER:-vaultgate}:$VAULTGATE_GHCR_TOKEN")
    fi
    for service in api gateway scanner; do
      log "image $REGISTRY/vaultgate-$service:$tag, pulled by the node"
      docker exec "k3d-$CLUSTER-server-0" crictl pull "${creds[@]}" "$REGISTRY/vaultgate-$service:$tag"
    done
    return
  fi
  for service in api gateway scanner; do
    log "image vaultgate-$service, from the working tree, as $tag"
    docker build -t "$REGISTRY/vaultgate-$service:$tag" "$service"
    names+=("$REGISTRY/vaultgate-$service:$tag")
  done
  log "loading the images into the cluster"
  k3d image import --cluster "$CLUSTER" "${names[@]}"
  # k3d reports a failed import as a warning: make sure the node has them.
  for name in "${names[@]}"; do
    docker exec "k3d-$CLUSTER-server-0" crictl inspecti "$name" >/dev/null
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
  # A local stand-in for AWS's instance identity signing key (M11, ADR 0014): k3d has no
  # EC2, so the cluster check signs its instance identity documents with this key, and
  # the API trusts its certificate in AWS's place. Local only; kept with the root.
  local pki=${VAULTGATE_PKI_DIR:-$HOME/.vaultgate/pki}
  if [[ ! -f $pki/local-aws-iid.key ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$pki/local-aws-iid.key" 2>/dev/null
    chmod 600 "$pki/local-aws-iid.key"
    openssl req -x509 -new -key "$pki/local-aws-iid.key" -days 3650 -sha256 \
      -subj "/O=VaultGate local stand-in for AWS instance identity" -out "$pki/local-aws-iid.crt"
  fi
  kubectl create namespace vaultgate --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n vaultgate create secret generic vaultgate-aws-iid \
    --from-file=certificates.pem="$pki/local-aws-iid.crt" --dry-run=client -o yaml | kubectl apply -f -
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

# The intermediate CAs (the services' and, since M11, the nodes'), once OpenBao is up:
# for each, it generates the key and a CSR, the root signs it here, and OpenBao installs
# it. Logged in as the pki-ceremony service account.
pki_ceremony() {
  log "the intermediate CAs (PKI ceremony)"
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

# The AWS resources and each service's own AWS key (M10, TM-2): Terraform creates the
# bucket, key and queues and one IAM user per service, with its own least-privilege
# policy, in the in-cluster LocalStack; each user's key goes into that service's secret
# in OpenBao. Before VaultGate's pods are waited for, as their agents wait for the keys.
aws_setup() {
  log "Terraform against the in-cluster LocalStack, and each service's AWS key in OpenBao"
  wait_for 120 "LocalStack" curl -sf http://localhost:4566/_localstack/health
  make tf-local
  terraform -chdir=infra/terraform/envs/local output -json service_credentials |
    VAULTGATE_OPENBAO_JWT=$(kubectl -n openbao create token secrets-seed --audience openbao --duration 10m) \
      python3 scripts/service_secrets.py seed-aws
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
  aws_setup
  for app in cert-manager kube-prometheus-stack trust-manager keda vaultgate-observability \
    vaultgate-pki vaultgate; do
    wait_for 900 "$app to be synced and healthy" app_ready "$app"
  done

  host_trust python3 scripts/seed_policies.py --api "$API" --keycloak "$KEYCLOAK"
  log "ready: web app $FRONTEND, OpenBao https://localhost:8200, API $API, gateway https://localhost:8888 (TLS: trust $ROOT_CA), Keycloak $KEYCLOAK, Mailpit http://localhost:8025, Grafana http://localhost:3000 (admin/admin), Prometheus http://localhost:9090, Alertmanager http://localhost:9093"
}

# The localhost certificate (deploy/k3d/pki) for the frontend's development server,
# written to <dir> with the key readable only by its owner. It lasts a day: run it again
# when the browser says it has expired.
dev_cert() { # dev_cert <dir>
  local dir=$1 tmp
  kubectl -n cert-manager wait --for=condition=Ready certificate/vaultgate-dev-localhost --timeout=120s >/dev/null
  mkdir -p "$dir"
  chmod 700 "$dir"
  tmp=$(mktemp -d "$dir/.new.XXXXXX")
  (
    umask 077
    for file in tls.crt tls.key; do
      kubectl -n cert-manager get secret vaultgate-dev-localhost-tls -o "jsonpath={.data.${file//./\\.}}" |
        base64 -d >"$tmp/$file"
    done
  )
  # The chain (the certificate, then the intermediate) must verify for localhost
  # against the root the browser trusts.
  openssl verify -CAfile "$ROOT_CA" -untrusted "$tmp/tls.crt" -verify_hostname localhost \
    -purpose sslserver "$tmp/tls.crt" >/dev/null || {
    rm -rf "$tmp"
    return 1
  }
  mv "$tmp/tls.crt" "$tmp/tls.key" "$dir/"
  rmdir "$tmp"
  echo "localhost certificate in $dir, $(openssl x509 -in "$dir/tls.crt" -noout -enddate)"
}

# The frontend's commit the chart deploys on this cluster (values-k3d.yaml).
frontend_tag() {
  awk '/^frontend:/ {f = 1; next} f && /^[^ #]/ {f = 0} f && $1 == "tag:" {print $2; exit}' \
    deploy/helm/vaultgate/values-k3d.yaml
}

# The web app's browser tests against the cluster: vaultgate-frontend's e2e suite, at
# the commit whose image the cluster runs, so the tests and the app match. Chromium
# trusts the cluster's root the way a person's browser does (its certificate store),
# rather than ignoring certificate errors. Needs Node 22 and certutil (libnss3-tools).
browser() {
  local ref dir=${VAULTGATE_FRONTEND_DIR:-.frontend-e2e}
  ref=${VAULTGATE_FRONTEND_TESTS_REF:-$(frontend_tag)}
  [[ -n $ref ]] || { echo "no frontend commit in values-k3d.yaml" >&2; return 1; }
  log "the web app's browser tests, vaultgate-frontend at $ref"
  if [[ ! -d $dir/.git ]]; then
    git init -q "$dir"
    git -C "$dir" remote add origin https://github.com/flaviocavalcantet/vaultgate-frontend
  fi
  git -C "$dir" fetch -q --depth 1 origin "$ref"
  git -C "$dir" checkout -q --force FETCH_HEAD
  (cd "$dir" && npm ci --no-audit --no-fund && npx playwright install ${CI:+--with-deps} chromium)
  mkdir -p "$HOME/.pki/nssdb"
  [[ -f $HOME/.pki/nssdb/cert9.db ]] || certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password
  certutil -d "sql:$HOME/.pki/nssdb" -D -n vaultgate-local 2>/dev/null || true
  certutil -d "sql:$HOME/.pki/nssdb" -A -t C,, -n vaultgate-local -i "$ROOT_CA"
  (cd "$dir" && VAULTGATE_E2E_URL=$FRONTEND VAULTGATE_E2E_MAILPIT=http://localhost:8025 \
    npm run e2e)
}

restart() {
  kubectl -n vaultgate rollout restart deployment
  kubectl -n vaultgate rollout status deployment --timeout=300s
}

check_cluster() {
  log "Argo CD: every application synced and healthy"
  for app in vaultgate-local vaultgate-deps vaultgate-openbao cert-manager trust-manager \
    vaultgate-pki kube-prometheus-stack keda vaultgate-observability vaultgate; do
    app_ready "$app" || {
      kubectl -n argocd get application "$app" -o yaml >&2
      return 1
    }
    echo "ok  $app is Synced and Healthy"
  done

  # KEDA (M12) manages the gateway's HorizontalPodAutoscaler from the chart's
  # ScaledObject: it must have accepted both triggers, and the autoscaler must have a
  # current value for each, CPU from metrics-server and the transfers from Prometheus
  # through KEDA's metrics server.
  log "the gateway's autoscaler reads CPU and the transfers in progress (KEDA)"
  local hpa=keda-hpa-vaultgate-gateway
  wait_for 300 "KEDA to accept the gateway's ScaledObject" \
    sh -c "kubectl -n vaultgate get scaledobject vaultgate-gateway -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"
  wait_for 300 "the autoscaler to report CPU utilization" \
    sh -c "kubectl -n vaultgate get hpa $hpa -o jsonpath='{.status.currentMetrics[?(@.type==\"Resource\")].resource.current.averageUtilization}' | grep -q '[0-9]'"
  wait_for 300 "the autoscaler to report the transfers in progress" \
    sh -c "kubectl -n vaultgate get hpa $hpa -o jsonpath='{.status.currentMetrics[?(@.type==\"External\")].external.current.averageValue}' | grep -q '[0-9]'"
  kubectl -n vaultgate get scaledobject vaultgate-gateway
  kubectl -n vaultgate get hpa "$hpa"
  echo "ok  the gateway scales on CPU and on transfers in progress"

  log "network policy: only the gateway and the scanner reach the API's internal port"
  local probe=(kubectl -n vaultgate run "netpol-probe-$RANDOM" --rm -i --restart=Never --quiet
    --image=curlimages/curl:8.23.0 --command --)
  # The public port first: it proves the probe itself works, so a refusal below is the
  # policy's and not a probe that never ran. Reachability only, hence -k (the probe pod
  # has no trust bundle); the TLS checks are check_pki's.
  "${probe[@]}" curl -sfk -m 5 -o /dev/null https://vaultgate-api.vaultgate.svc:8000/healthz
  if "${probe[@]}" curl -sk -m 5 -o /dev/null https://vaultgate-api.vaultgate.svc:8001/healthz; then
    echo "another pod reached the API's internal port" >&2
    return 1
  fi
  # Metrics only from Prometheus' namespace (TM-5); the Prometheus check below scrapes them.
  if "${probe[@]}" curl -sk -m 5 -o /dev/null https://vaultgate-api.vaultgate.svc:9100/metrics; then
    echo "another pod reached the API's metrics port" >&2
    return 1
  fi
  echo "ok  another pod reaches the public port, not the internal or the metrics one"
  log "network policy: each component connects only where its policy lets it (TM-1)"
  kubectl -n vaultgate exec -i deploy/vaultgate-api -c api -- python - <scripts/egress_check.py

  # The web frontend (M12.5, ADR 0019): the app, this cluster's settings, and a
  # Content-Security-Policy that names this cluster's API, gateway and Keycloak.
  log "web frontend: served on $FRONTEND with this cluster's settings and policy"
  local headers config
  # Over TLS from the cluster's CA, 1.3 only, like the other components.
  headers=$(curl -sfI --cacert "$ROOT_CA" "$FRONTEND/files")
  config=$(curl -sf --cacert "$ROOT_CA" "$FRONTEND/config.json")
  if curl -s --cacert "$ROOT_CA" --tls-max 1.2 -o /dev/null "$FRONTEND/"; then
    echo "the frontend accepted TLS 1.2" >&2
    return 1
  fi
  grep -qi "^strict-transport-security:" <<<"$headers" || { echo "$headers" >&2; return 1; }
  grep -q "\"apiUrl\": \"$API\"" <<<"$config" || { echo "$config" >&2; return 1; }
  grep -qi "^content-security-policy: .*connect-src 'self' $API https://localhost:8888 $KEYCLOAK" \
    <<<"$headers" || { echo "$headers" >&2; return 1; }
  grep -qi "form-action https://localhost:8888" <<<"$headers" || { echo "$headers" >&2; return 1; }
  echo "ok  the frontend serves the app over TLS 1.3, its settings point at this cluster, its policy names it"
  # Its origin is the one the API and the gateway allow (CORS, ADR 0017).
  local allowed
  allowed=$(curl -s --cacert "$ROOT_CA" -o /dev/null -D - -X OPTIONS "$API/me" -H "Origin: $FRONTEND" \
    -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Headers: authorization" |
    tr -d '\r' | sed -n 's/^[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin: //p')
  [[ $allowed == "$FRONTEND" ]] || { echo "the API doesn't allow $FRONTEND: '$allowed'" >&2; return 1; }
  echo "ok  the API allows the frontend's origin"
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
  log "PKI: OpenBao unsealed, its TLS and its intermediate CAs chained to the root"
  python3 scripts/pki.py check
  log "PKI: each intermediate's name constraints reject what it may not sign (a throwaway root)"
  python3 scripts/pki.py check-constraints
  log "the nodes' CA: a node certificate for clients only, refused a service's identity, revoked through the API's OCSP"
  VAULTGATE_OPENBAO_JWT=$(kubectl -n openbao create token pki-nodes-check --audience openbao --duration 10m) \
    python3 scripts/pki.py check-nodes
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
  log "the development server's localhost certificate (make dev-cert) verifies against the root"
  local devtls
  devtls=$(mktemp -d)
  dev_cert "$devtls"
  rm -rf "$devtls"
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

# Node enrollment (M11, ADR 0014): a node asks, carol approves once the fingerprint
# matches, the node completes with the code, calls the nodes' port with its certificate,
# renews with a new key, and is revoked.
check_nodes() {
  log "node enrollment: admin approval, the nodes' port (mutual TLS), renewal, revocation"
  host_trust python3 scripts/node_check.py --api "$API" --nodes https://localhost:8002 --keycloak "$KEYCLOAK"
}

check() {
  check_cluster
  check_pki
  check_secrets
  check_observability
  check_nodes
  log "vault end to end, against the cluster"
  host_trust python3 scripts/vault_e2e.py --api "$API" --keycloak "$KEYCLOAK"
  log "negative tests: what the API, the gateway and the cluster's services must refuse"
  host_trust python3 scripts/negative_checks.py --api "$API" --keycloak "$KEYCLOAK"
}

# OWASP ZAP (M10, docs/security-scans.md), from the host: the API's every route from its
# OpenAPI document, as zap-scanner (a real Keycloak login; a user exempt from the
# per-user rate limits on this cluster, or ZAP would mostly scan the limiter), and the
# gateway's routes from security/zap/gateway-openapi.yaml with a token that isn't an
# intent (one real intent would be spent by the first request). Passive and active
# scans; any warning that security/zap/<target>.conf doesn't mark as ignored fails the
# run. Its attacks create files and shares: run it on a cluster nothing else needs, last.
# The token lasts 5 minutes (the realm's accessTokenLifespan) and is fetched right
# before the API's scan, whose active part is capped at 3 (the whole scan takes about a
# minute). The token must still be accepted once the scan is done, or the run fails: a
# scan that went on unauthenticated would pass without testing what a user can reach.
# The share recipients' per-address limit is off on this cluster (values-k3d.yaml), as
# its 429s mid-scan look like a change of behaviour to ZAP; the gateway keeps its own,
# so ZAP reaches it until it answers 429 (its unit tests cover the rest).
ZAP_IMAGE=zaproxy/zap-stable:2.17.0
# ZAP's own proxy port, on the host's network. Fixed, and below the kernel's ephemeral
# range: left to itself the scan script picks a free port from that range and ZAP binds
# it seconds later, by which time something else on the host may hold it (a run on main
# ended with "Failed to start the main proxy: Address already in use").
ZAP_PORT=${VAULTGATE_ZAP_PORT:-8090}
# Alerts that are false positives on certain URLs only, so the rule still applies to
# every other route: "Unexpected Content-Type" (100001) on the nodes' CA's routes, which
# answer with their protocols' own types (a certificate, CRLs, OCSP: application/pkix-*,
# application/ocsp-response; M11, ADR 0014), not ones ZAP expects of an API.
ZAP_API_FILTERS="-config globalalertfilter.filters.filter(0).ruleid=100001 \
-config globalalertfilter.filters.filter(0).url=https?://[^/]+/pki/nodes/.* \
-config globalalertfilter.filters.filter(0).urlregex=true \
-config globalalertfilter.filters.filter(0).newrisk=-1 \
-config globalalertfilter.filters.filter(0).enabled=true"
zap() {
  local out=${VAULTGATE_ZAP_DIR:-zap-reports} status=0 token
  mkdir -p "$out"
  chmod 777 "$out" # ZAP runs as its own user
  cp security/zap/* "$out"/
  token=$(host_trust env PYTHONPATH=scripts python3 -c 'from keycloak_smoke import login, wait_for
print(login(wait_for("'"$KEYCLOAK"'"), "zap-scanner", "zap-scanner-dev-password")["access_token"])')
  log "ZAP: the API, from its OpenAPI document, as zap-scanner"
  docker run --rm --network host -v "$PWD/$out:/zap/wrk:rw" -e ZAP_AUTH_HEADER=Authorization \
    -e ZAP_AUTH_HEADER_VALUE="Bearer $token" "$ZAP_IMAGE" zap-api-scan.py -P "$ZAP_PORT" \
    -t "$API/openapi.json" -f openapi -c api.conf -r api.html -J api.json \
    -z "-config scanner.maxScanDurationInMins=3 $ZAP_API_FILTERS" || status=1
  if ! curl -sf --cacert "$ROOT_CA" -o /dev/null -H "Authorization: Bearer $token" "$API/me"; then
    echo "zap-scanner's token expired during the API's scan: part of it ran unauthenticated" >&2
    status=1
  fi
  log "ZAP: the gateway"
  docker run --rm --network host -v "$PWD/$out:/zap/wrk:rw" -e ZAP_AUTH_HEADER=Authorization \
    -e ZAP_AUTH_HEADER_VALUE="Bearer not-an-intent" "$ZAP_IMAGE" zap-api-scan.py -P "$ZAP_PORT" \
    -t /zap/wrk/gateway-openapi.yaml -f openapi -O https://localhost:8888 \
    -c gateway.conf -r gateway.html -J gateway.json || status=1
  return $status
}

case ${1:-} in
up) up ;;
images) images && restart ;;
check) check ;;
zap) zap ;;
browser) browser ;;
dev-cert) dev_cert "${VAULTGATE_DEV_TLS_DIR:-$HOME/.vaultgate/dev-tls}" ;;
down) k3d cluster delete "$CLUSTER" ;;
*)
  sed -n '2,20p' "$0"
  exit 2
  ;;
esac

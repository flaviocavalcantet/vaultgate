#!/usr/bin/env bash
# Checks are functions called indirectly through run().
# shellcheck disable=SC2329
# Check VaultGate on your machine, from lint and unit tests up to the whole stack.
# Guide: docs/local-testing.md
#
#   scripts/local_check.sh quick   lint and unit tests; no Docker (Python 3.12+, Go 1.23+)
#   scripts/local_check.sh full    quick, then start the stack and run the end-to-end
#                                  checks (also needs Docker and Terraform)
#   scripts/local_check.sh down    stop the stack and delete its data
#
# Every check runs even if an earlier one fails; a summary is printed at the end and
# the exit status is non-zero if anything failed. The stack is left running after
# `full` so you can explore it; `down` removes it.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

MODE="${1:-full}"
VENV=.venv
PY="$VENV/bin/python"
TEST_DB_URL=postgresql+asyncpg://vaultgate:vaultgate@localhost:5432/vaultgate_test
RESULTS=()
FAILED=0

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# run "description" command...: run a check, record the result, keep going.
run() {
  local name="$1"
  shift
  say "$name"
  if "$@"; then
    RESULTS+=("ok    $name")
  else
    RESULTS+=("FAIL  $name")
    FAILED=1
    return 1
  fi
}

# at_least "found" "minimum": compare dotted versions (portable; no sort -V on macOS).
at_least() {
  python3 -c 'import sys
v = lambda s: tuple(int(p) for p in s.split(".")[:3] if p.isdigit())
sys.exit(v(sys.argv[1]) < v(sys.argv[2]))' "$1" "$2"
}

require_tools() {
  local missing=0
  command -v python3 >/dev/null || die "python3 not found (need 3.12+)"
  local py
  py=$(python3 -c 'import platform; print(platform.python_version())')
  at_least "$py" 3.12 || { echo "python3 is $py; need 3.12+"; missing=1; }
  if command -v go >/dev/null; then
    local go_version
    go_version=$(go env GOVERSION | sed 's/^go//')
    at_least "$go_version" 1.23 || { echo "Go is $go_version; need 1.23+"; missing=1; }
  else
    echo "go not found (need 1.23+)"
    missing=1
  fi
  if [ "$MODE" = full ]; then
    command -v curl >/dev/null || { echo "curl not found"; missing=1; }
    command -v make >/dev/null || { echo "make not found"; missing=1; }
    if ! command -v docker >/dev/null; then
      echo "docker not found"
      missing=1
    elif ! docker info >/dev/null 2>&1; then
      echo "Docker is installed but not running: start Docker Desktop (or the daemon)"
      missing=1
    elif ! docker compose version >/dev/null 2>&1; then
      echo "the Docker Compose plugin is missing (docker compose)"
      missing=1
    fi
    if command -v terraform >/dev/null; then
      local tf
      tf=$(terraform version | head -1 | sed 's/^Terraform v//')
      at_least "$tf" 1.6 || { echo "Terraform is $tf; need 1.6+"; missing=1; }
    else
      echo "terraform not found (need 1.6+)"
      missing=1
    fi
  fi
  [ "$missing" = 0 ] || die "install the tools above (see docs/local-testing.md) and run again"
  echo "tools ok: Python $py, $(go env GOVERSION)"
}

setup_venv() {
  if [ ! -x "$PY" ]; then
    python3 -m venv "$VENV" || return 1
  fi
  "$PY" -m pip install --quiet --upgrade pip &&
    "$PY" -m pip install --quiet -e "api[dev]" -e "gateway[dev]"
}

lint_python() {
  local service ok=0
  for service in api gateway; do
    (cd "$service" && "../$VENV/bin/ruff" check . && "../$VENV/bin/ruff" format --check .) || ok=1
  done
  return "$ok"
}

test_gateway() { (cd gateway && "../$PY" -m pytest -q); }

# Without VAULTGATE_TEST_DATABASE_URL the database tests are skipped; `full` runs them.
test_api_unit() { (cd api && env -u VAULTGATE_TEST_DATABASE_URL "../$PY" -m pytest -q); }

test_scanner() {
  (cd scanner && test -z "$(gofmt -l .)" && go vet ./... && go test -race ./...)
}

wait_for() { # url, seconds
  local url="$1" deadline=$((SECONDS + $2))
  until curl -sf -o /dev/null "$url"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "timed out waiting for $url"
      return 1
    fi
    sleep 3
  done
}

start_stack() {
  docker compose up --build -d || return 1
  echo "waiting for the services (the first run builds images and takes a few minutes)..."
  wait_for http://localhost:4566/_localstack/health 180 &&
    wait_for http://localhost:8080/realms/vaultgate/.well-known/openid-configuration 240 &&
    wait_for http://localhost:8000/readyz 180 &&
    wait_for http://localhost:8888/healthz 120 &&
    wait_for http://localhost:3000/api/health 120
}

apply_terraform() { make tf-local; }

test_api_database() {
  docker compose exec -T postgres psql -U vaultgate -d vaultgate -tAc \
    "SELECT 1 FROM pg_database WHERE datname = 'vaultgate_test'" | grep -q 1 ||
    docker compose exec -T postgres createdb -U vaultgate vaultgate_test || return 1
  (cd api && VAULTGATE_TEST_DATABASE_URL="$TEST_DB_URL" "../$PY" -m pytest -q)
}

check_login() { python3 scripts/keycloak_smoke.py http://localhost:8080 --api http://localhost:8000; }

check_vault() { python3 scripts/vault_e2e.py; }

check_observability() {
  make obs-check &&
    curl -sf http://localhost:9090/api/v1/targets |
    python3 -c 'import json, sys
targets = json.load(sys.stdin)["data"]["activeTargets"]
down = [t["labels"]["job"] for t in targets if t["health"] != "up"]
print("Prometheus targets:", ", ".join(sorted(t["labels"]["job"] for t in targets)))
sys.exit(f"targets down: {down}" if down else 0)'
}

summary() {
  say "Summary"
  printf '%s\n' "${RESULTS[@]}"
  if [ "$MODE" = full ]; then
    cat <<'EOF'

The stack is still running. Explore it (logins are in docs/local-testing.md):
  API docs        http://localhost:8000/docs
  Keycloak        http://localhost:8080        admin / admin
  Grafana         http://localhost:3000        admin / admin  (VaultGate folder)
  Prometheus      http://localhost:9090
Stop it with:     scripts/local_check.sh down
EOF
  fi
  exit "$FAILED"
}

case "$MODE" in
  quick | full) ;;
  down)
    docker compose down -v
    exit $?
    ;;
  *) die "usage: $0 [quick|full|down]" ;;
esac

say "Checking tools"
require_tools
run "Python environment (.venv)" setup_venv || summary

run "Lint: ruff (api, gateway)" lint_python
run "Gateway tests (moto S3/KMS, no Docker)" test_gateway
run "API tests without a database" test_api_unit
run "Scanner: gofmt, go vet, go test -race" test_scanner

if [ "$MODE" = full ]; then
  if run "Start the stack (docker compose)" start_stack; then
    run "Terraform: bucket and KMS key in LocalStack" apply_terraform
    run "API tests with PostgreSQL" test_api_database
    run "Login: Keycloak PKCE, token checks, /me, admin" check_login
    run "Vault end to end: upload, ciphertext in S3, download" check_vault
    run "Observability: configs, alert rules, dashboards, targets" check_observability
  else
    echo "the stack did not start; see: docker compose ps && docker compose logs"
  fi
fi

summary

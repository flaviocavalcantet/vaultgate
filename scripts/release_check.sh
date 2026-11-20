#!/usr/bin/env bash
# Checks that a release tag can be cut: the tag is vX.Y.Z, every version this repository
# records is X.Y.Z, and the release has its notes (docs/releases/vX.Y.Z.md).
# Run by the Release workflow before anything is published; also handy before tagging:
#
#   scripts/release_check.sh v0.1.0
set -euo pipefail
cd "$(dirname "$0")/.."

tag=${1:?usage: scripts/release_check.sh vX.Y.Z}
[[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || { echo "not a vX.Y.Z tag: $tag" >&2; exit 1; }
want=${BASH_REMATCH[1]}

failed=0
check() {
  local where=$1 got=$2
  if [[ $got == "$want" ]]; then
    echo "ok  $where: $got"
  else
    echo "MISMATCH  $where: ${got:-none}, the tag says $want" >&2
    failed=1
  fi
}

field() { sed -nE "$2" "$1" | head -1; }
check "api/pyproject.toml" "$(field api/pyproject.toml 's/^version = "(.*)"$/\1/p')"
check "api (FastAPI app)" "$(field api/src/vaultgate_api/main.py 's/^ *version="(.*)",$/\1/p')"
check "gateway/pyproject.toml" "$(field gateway/pyproject.toml 's/^version = "(.*)"$/\1/p')"
check "gateway (build info)" \
  "$(field gateway/src/vaultgate_gateway/app.py 's/.*"service": "gateway", "version": "([^"]*)".*/\1/p')"
check "scanner (worker)" "$(field scanner/cmd/worker/main.go 's/^const version = "(.*)"$/\1/p')"
check "chart appVersion" "$(field deploy/helm/vaultgate/Chart.yaml 's/^appVersion: "?([^"]*)"?$/\1/p')"

if [[ -s docs/releases/$tag.md ]]; then
  echo "ok  release notes: docs/releases/$tag.md"
else
  echo "MISSING  release notes: docs/releases/$tag.md" >&2
  failed=1
fi
exit $failed

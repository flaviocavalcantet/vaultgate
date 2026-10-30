#!/bin/sh
# Install Docker Engine and the compose plugin from Docker's signed apt repository,
# inside a WSL distribution (Ubuntu or Debian). Run as root; local_check.ps1 setup
# calls it. Follows https://docs.docker.com/engine/install/ubuntu/ and checks the
# repository key against Docker's published fingerprint before trusting it.
set -eu

DOCKER_KEY_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
KEYRING=/etc/apt/keyrings/docker.asc

# shellcheck source=/dev/null
. /etc/os-release
case "$ID" in
  ubuntu | debian) ;;
  *)
    echo "unsupported distribution '$ID': install Docker Engine by hand (docs.docker.com/engine/install)" >&2
    exit 1
    ;;
esac

apt-get update
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o "$KEYRING.new"
if ! gpg --show-keys --with-colons "$KEYRING.new" | grep -q "^fpr:::::::::$DOCKER_KEY_FINGERPRINT:"; then
  rm -f "$KEYRING.new"
  echo "the downloaded Docker repository key does not match fingerprint $DOCKER_KEY_FINGERPRINT" >&2
  exit 1
fi
mv "$KEYRING.new" "$KEYRING"
chmod a+r "$KEYRING"

echo "deb [arch=$(dpkg --print-architecture) signed-by=$KEYRING] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
docker --version
docker compose version

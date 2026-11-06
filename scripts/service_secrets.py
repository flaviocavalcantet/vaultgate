#!/usr/bin/env python3
"""The services' credentials in OpenBao (M9, ADR 0012).

    scripts/service_secrets.py seed    create each secret that doesn't exist yet, with a random
                               value (the local cluster's dependencies' own credentials
                               for the AWS keys and the database URL); existing ones are
                               kept: the seed role may create a secret and see that one
                               exists, never read or overwrite one
    scripts/service_secrets.py check   each service's login reads its own secrets, and is refused
                               the others'

Settings, from the environment:

    VAULTGATE_OPENBAO         OpenBao's address (https://localhost:8200)
    VAULTGATE_PKI_DIR         where the root CA's certificate is (~/.vaultgate/pki)
    VAULTGATE_OPENBAO_JWT     for `seed`: a token of the openbao/secrets-seed service
                              account, audience "openbao"
    VAULTGATE_SERVICE_JWTS    for `check`: tokens of the vaultgate/vaultgate-api, -gateway
                              and -scanner service accounts, as api=...,gateway=...,scanner=...

scripts/k3d.sh mints those tokens with kubectl create token. Values are never printed.
"""

import os
import secrets
import sys

import pki

# What the local cluster's services use (deploy/k3d): LocalStack takes any key, and the
# database URL is PostgreSQL's in vaultgate-deps, over TLS with the server verified.
LOCAL_DATABASE_URL = (
    "postgresql+asyncpg://vaultgate:vaultgate@postgres.vaultgate-deps.svc:5432/vaultgate"
    "?ssl=verify-full"
)


def generated() -> dict[str, dict[str, str]]:
    """Every secret, as path -> data, with fresh random tokens."""
    return {
        "internal-token": {"value": secrets.token_urlsafe(32)},
        "scanner-token": {"value": secrets.token_urlsafe(32)},
        "database-url": {"value": LOCAL_DATABASE_URL},
        # The AWS SDKs read this file (AWS_SHARED_CREDENTIALS_FILE).
        "aws": {"value": "[default]\naws_access_key_id = test\naws_secret_access_key = test\n"},
    }


# Who may read what, as the policies in deploy/k3d/openbao/openbao.hcl say.
ACCESS = {
    "api": {"database-url", "internal-token", "scanner-token", "aws"},
    "gateway": {"internal-token", "aws"},
    "scanner": {"scanner-token", "aws"},
}


def login(role: str, jwt: str) -> str:
    body = {"role": role, "jwt": jwt}
    return pki.bao("POST", "auth/kubernetes/login", body=body)["auth"]["client_token"]


def exists(token: str, name: str) -> bool:
    """From the secret's metadata, which the seed role may read (never its value)."""
    try:
        pki.bao("GET", f"secret/metadata/vaultgate/{name}", token)
        return True
    except pki.Failure as e:
        if " 404 " in str(e):
            return False
        raise  # a refusal here is a wrong policy, not an existing secret


def seed_with(token: str) -> None:
    for name, data in generated().items():
        if exists(token, name):
            print(f"ok  secret {name} exists (kept)")
            continue
        pki.bao("POST", f"secret/data/vaultgate/{name}", token, {"data": data})
        print(f"ok  secret {name} created")


def seed() -> None:
    jwt = os.getenv("VAULTGATE_OPENBAO_JWT")
    if not jwt:
        raise pki.Failure("VAULTGATE_OPENBAO_JWT is not set (a secrets-seed service account token)")
    token = login("secrets-seed", jwt)
    try:
        seed_with(token)
    finally:
        pki.bao("POST", "auth/token/revoke-self", token)


def readable(token: str, name: str) -> bool:
    try:
        pki.bao("GET", f"secret/data/vaultgate/{name}", token)
        return True
    except pki.Failure as e:
        if " 403 " in str(e):
            return False
        raise


def check_with(tokens: dict[str, str]) -> None:
    every = set(generated())
    for service, token in tokens.items():
        allowed = {name for name in every if readable(token, name)}
        if allowed != ACCESS[service]:
            raise pki.Failure(
                f"{service} reads {sorted(allowed)}, should read {sorted(ACCESS[service])}"
            )
        print(f"ok  {service} reads {', '.join(sorted(allowed))}, and is refused the rest")


def check() -> None:
    jwts = dict(
        item.split("=", 1) for item in os.getenv("VAULTGATE_SERVICE_JWTS", "").split(",") if item
    )
    if set(jwts) != set(ACCESS):
        raise pki.Failure("VAULTGATE_SERVICE_JWTS needs api=...,gateway=...,scanner=...")
    tokens = {service: login(f"vaultgate-{service}", jwt) for service, jwt in jwts.items()}
    try:
        check_with(tokens)
    finally:
        for token in tokens.values():
            pki.bao("POST", "auth/token/revoke-self", token)


def main(argv: list[str]) -> int:
    commands = {"seed": seed, "check": check}
    if len(argv) != 1 or argv[0] not in commands:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    try:
        commands[argv[0]]()
    except pki.Failure as e:
        print(f"FAIL {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

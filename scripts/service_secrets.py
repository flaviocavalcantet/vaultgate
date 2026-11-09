#!/usr/bin/env python3
"""The services' credentials in OpenBao (M9, ADR 0012).

    scripts/service_secrets.py seed    create each secret that doesn't exist yet, with a random
                               value; existing ones are kept: the seed role may create a
                               secret and see that one exists, never read or overwrite one
    scripts/service_secrets.py seed-aws
                               likewise each service's own AWS key (aws-api, aws-gateway,
                               aws-scanner; M10, TM-2), from Terraform's output on stdin:
                               terraform output -json service_credentials
    scripts/service_secrets.py rotate-db
                               rotate OpenBao's own PostgreSQL password, once PostgreSQL
                               is up: from then on only OpenBao knows it
    scripts/service_secrets.py check   each service's login may read its own secrets (the API
                               also its database credentials), and nothing else

Settings, from the environment:

    VAULTGATE_OPENBAO         OpenBao's address (https://localhost:8200)
    VAULTGATE_PKI_DIR         where the root CA's certificate is (~/.vaultgate/pki)
    VAULTGATE_OPENBAO_JWT     for `seed`: a token of the openbao/secrets-seed service
                              account, audience "openbao"
    VAULTGATE_SERVICE_JWTS    for `check`: tokens of the vaultgate/vaultgate-api, -gateway
                              and -scanner service accounts, as api=...,gateway=...,scanner=...

scripts/k3d.sh mints those tokens with kubectl create token. Values are never printed.
"""

import json
import os
import secrets
import sys

import pki


def generated() -> dict[str, dict[str, str]]:
    """Every secret, as path -> data, with fresh random tokens. The database credentials
    are not among them: OpenBao's database engine issues them per pod."""
    return {
        "internal-token": {"value": secrets.token_urlsafe(32)},
        "scanner-token": {"value": secrets.token_urlsafe(32)},
    }


DATABASE_CREDS = "database/creds/vaultgate-api"

# Who may read what, as the policies in deploy/k3d/openbao/openbao.hcl say.
# Each service's AWS key is its own (M10, TM-2): no service may read another's.
ACCESS = {
    "api": {
        "secret/data/vaultgate/internal-token",
        "secret/data/vaultgate/scanner-token",
        "secret/data/vaultgate/aws-api",
        DATABASE_CREDS,
    },
    "gateway": {"secret/data/vaultgate/internal-token", "secret/data/vaultgate/aws-gateway"},
    "scanner": {"secret/data/vaultgate/scanner-token", "secret/data/vaultgate/aws-scanner"},
}
EVERY_PATH = set().union(*ACCESS.values())


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


def seed_with(token: str, values: dict[str, dict[str, str]] | None = None) -> None:
    for name, data in (values or generated()).items():
        if exists(token, name):
            print(f"ok  secret {name} exists (kept)")
            continue
        pki.bao("POST", f"secret/data/vaultgate/{name}", token, {"data": data})
        print(f"ok  secret {name} created")


def as_seed(action) -> None:
    jwt = os.getenv("VAULTGATE_OPENBAO_JWT")
    if not jwt:
        raise pki.Failure("VAULTGATE_OPENBAO_JWT is not set (a secrets-seed service account token)")
    token = login("secrets-seed", jwt)
    try:
        action(token)
    finally:
        pki.bao("POST", "auth/token/revoke-self", token)


def seed() -> None:
    as_seed(seed_with)


def aws_keys(terraform_output: str) -> dict[str, dict[str, str]]:
    """Each service's AWS credentials file, from `terraform output -json
    service_credentials`, as the secrets to create."""
    files = json.loads(terraform_output)
    if set(files) != set(ACCESS):
        raise pki.Failure(f"expected AWS keys for {sorted(ACCESS)}, got {sorted(files)}")
    return {f"aws-{service}": {"value": text} for service, text in files.items()}


def seed_aws() -> None:
    values = aws_keys(sys.stdin.read())
    as_seed(lambda token: seed_with(token, values))


def rotate_db_with(token: str) -> None:
    pki.bao("POST", "database/rotate-root/vaultgate", token)
    print("ok  OpenBao's PostgreSQL password rotated: only OpenBao knows it")


def rotate_db() -> None:
    as_seed(rotate_db_with)


def readable(token: str) -> set[str]:
    """The paths this token may read, as OpenBao's policies say: asked, not tried, so no
    database credential is issued by checking."""
    answer = pki.bao("POST", "sys/capabilities-self", token, {"paths": sorted(EVERY_PATH)})
    return {path for path in EVERY_PATH if "read" in answer.get(path, [])}


def short(path: str) -> str:
    return path.removeprefix("secret/data/vaultgate/")


def check_with(tokens: dict[str, str]) -> None:
    for service, token in tokens.items():
        allowed = readable(token)
        if allowed != ACCESS[service]:
            raise pki.Failure(
                f"{service} may read {sorted(allowed)}, should read {sorted(ACCESS[service])}"
            )
        names = ", ".join(sorted(short(path) for path in allowed))
        print(f"ok  {service} may read {names}, and nothing else of VaultGate's")


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
    commands = {"seed": seed, "seed-aws": seed_aws, "rotate-db": rotate_db, "check": check}
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

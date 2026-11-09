#!/usr/bin/env python3
"""A node's Keycloak client, for first trust by a Keycloak client (M11, ADR 0014): what an
admin creates in Keycloak so the node can enroll without an approval.

    keycloak_node_client.py create NAME CERT   the confidential client node-NAME: it
                                               authenticates with a JWT signed by the key
                                               of CERT (private_key_jwt; Keycloak keeps the
                                               certificate, never a secret), its tokens are
                                               for the audience vaultgate-nodes, and its
                                               service account has the enrollment role
    keycloak_node_client.py delete NAME        delete the client (a new one, even of the
                                               same name, is a new credential to VaultGate)
    keycloak_node_client.py unassign NAME      take the enrollment role from the client

The node makes CERT: `scripts/vaultgate_node.py credential`. VaultGate accepts a client's
token for one enrollment only; removing the role (unassign) or the client afterwards is
the admin's tidying, not VaultGate's protection.

Settings, from the environment:

    VAULTGATE_KEYCLOAK         Keycloak's address (https://localhost:8080)
    VAULTGATE_KEYCLOAK_REALM   the realm (vaultgate)
    KEYCLOAK_ADMIN             an admin's username in the master realm (admin)
    KEYCLOAK_ADMIN_PASSWORD    their password (admin: the local cluster's bootstrap admin,
                               TM-12; anywhere else, a real admin's)
    SSL_CERT_FILE              the CA bundle to verify Keycloak with

Standard library and OpenSSL 3 only.
"""

import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

KEYCLOAK = os.getenv("VAULTGATE_KEYCLOAK", "https://localhost:8080").rstrip("/")
REALM = os.getenv("VAULTGATE_KEYCLOAK_REALM", "vaultgate")
ROLE = "vaultgate-node-enroll"
AUDIENCE = "vaultgate-nodes"
PREFIX = "node-"


class Failure(Exception):
    pass


def request(method: str, path: str, token: str | None = None, body=None, form=None):
    headers = {}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{KEYCLOAK}{path}", data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:300]


def admin_token() -> str:
    status, answer = request(
        "POST",
        "/realms/master/protocol/openid-connect/token",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": os.getenv("KEYCLOAK_ADMIN", "admin"),
            "password": os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin"),
        },
    )
    if status != 200:
        raise Failure(f"Keycloak admin login: {status} {answer}")
    return answer["access_token"]


def admin(method: str, path: str, token: str, body=None):
    return request(method, f"/admin/realms/{REALM}{path}", token, body)


def client_named(token: str, name: str) -> dict | None:
    status, found = admin("GET", f"/clients?clientId={PREFIX}{name}", token)
    if status != 200:
        raise Failure(f"looking for the client: {status} {found}")
    return found[0] if found else None


def role(token: str) -> dict:
    status, found = admin("GET", f"/roles/{ROLE}", token)
    if status == 404:
        status, answer = admin("POST", "/roles", token, {
            "name": ROLE,
            "description": "May enroll a VaultGate node once (M11): for nodes' own clients only.",
        })  # fmt: skip
        if status != 201:
            raise Failure(f"creating the role {ROLE}: {status} {answer}")
        status, found = admin("GET", f"/roles/{ROLE}", token)
    if status != 200:
        raise Failure(f"the role {ROLE}: {status} {found}")
    return found


def service_account(token: str, client: dict) -> dict:
    status, user = admin("GET", f"/clients/{client['id']}/service-account-user", token)
    if status != 200:
        raise Failure(f"the client's service account: {status} {user}")
    return user


def certificate_der_b64(cert_file: str) -> str:
    der = subprocess.run(
        ["openssl", "x509", "-in", cert_file, "-outform", "DER"], capture_output=True, check=True
    ).stdout
    return base64.b64encode(der).decode()


def create(name: str, cert_file: str) -> None:
    token = admin_token()
    if client_named(token, name) is not None:
        raise Failure(f"{PREFIX}{name} exists: delete it first, or use another name")
    enroll = role(token)
    status, answer = admin("POST", "/clients", token, {
        "clientId": f"{PREFIX}{name}",
        "name": f"VaultGate node {name}",
        "description": "A VaultGate node's credential for its first certificate (M11).",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "clientAuthenticatorType": "client-jwt",
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "attributes": {
            "jwt.credential.certificate": certificate_der_b64(cert_file),
            "use.jwks.url": "false",
            "token.endpoint.auth.signing.alg": "RS256",
            "access.token.lifespan": "120",
        },
        "protocolMappers": [{
            "name": f"audience: {AUDIENCE}",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": AUDIENCE,
                "access.token.claim": "true",
                "id.token.claim": "false",
                "introspection.token.claim": "true",
            },
        }],
    })  # fmt: skip
    if status != 201:
        raise Failure(f"creating {PREFIX}{name}: {status} {answer}")
    client = client_named(token, name)
    user = service_account(token, client)
    status, answer = admin("POST", f"/users/{user['id']}/role-mappings/realm", token, [enroll])
    if status != 204:
        raise Failure(f"giving {PREFIX}{name} the role: {status} {answer}")
    print(f"ok  {PREFIX}{name} created: signed-JWT authentication with the node's key, "
          f"tokens for {AUDIENCE}, role {ROLE}")  # fmt: skip


def delete(name: str) -> None:
    token = admin_token()
    client = client_named(token, name)
    if client is None:
        raise Failure(f"no client {PREFIX}{name}")
    status, answer = admin("DELETE", f"/clients/{client['id']}", token)
    if status != 204:
        raise Failure(f"deleting {PREFIX}{name}: {status} {answer}")
    print(f"ok  {PREFIX}{name} deleted")


def unassign(name: str) -> None:
    token = admin_token()
    client = client_named(token, name)
    if client is None:
        raise Failure(f"no client {PREFIX}{name}")
    user = service_account(token, client)
    status, answer = admin("DELETE", f"/users/{user['id']}/role-mappings/realm", token,
                           [role(token)])  # fmt: skip
    if status != 204:
        raise Failure(f"taking the role from {PREFIX}{name}: {status} {answer}")
    print(f"ok  {PREFIX}{name} no longer has {ROLE}")


def main(argv: list[str]) -> int:
    try:
        match argv:
            case ["create", name, cert]:
                create(name, cert)
            case ["delete", name]:
                delete(name)
            case ["unassign", name]:
                unassign(name)
            case _:
                print(__doc__.split("\n\n")[1], file=sys.stderr)
                return 2
    except (Failure, subprocess.CalledProcessError) as e:
        print(f"FAIL {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

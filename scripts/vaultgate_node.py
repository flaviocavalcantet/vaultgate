#!/usr/bin/env python3
"""A node's side of enrollment (M11, ADR 0014): a minimal client, for trying it and for
`make k3d-check`.

The node's key never leaves it: it is generated here (ECDSA P-256, by OpenSSL), kept in
DIR/node.key (mode 0600), and only a CSR is sent.

    vaultgate_node.py request NAME      generate the key, ask to enroll as NAME, and show
                                        the key's fingerprint, which the operator compares
                                        with the one the admin sees before approving
    vaultgate_node.py status            where the request is (pending, approved, ...)
    vaultgate_node.py complete CODE     complete it with the admin's one-time code:
                                        DIR/node.crt (with its chain) and DIR/node.json
    vaultgate_node.py enroll-token      first trust by an admin's enrollment token instead:
                                        enroll with it (it names the node), at once; the
                                        token from VAULTGATE_ENROLLMENT_TOKEN, else asked for
                                        (never a command-line argument: shell history)
    vaultgate_node.py enroll-cloud      first trust by cloud instance identity instead (AWS):
                                        enroll with the instance's signed identity document,
                                        from the instance metadata service (IMDSv2); the node
                                        is named after its instance (aws-<instance ID>)
    vaultgate_node.py credential        first trust by a Keycloak client instead: make the
                                        node's Keycloak credential, an RSA key and a
                                        certificate for it (DIR/keycloak.crt), which an admin
                                        registers (scripts/keycloak_node_client.py create)
    vaultgate_node.py enroll-client NAME
                                        enroll as NAME with that client (node-NAME): a token
                                        from Keycloak, the client authenticated by a JWT the
                                        key signs (private_key_jwt), and a CSR; no approval
    vaultgate_node.py whoami            the node, as the API sees it, on the nodes' port
    vaultgate_node.py renew [--new-key] a new certificate, with the current one; the
                                        current one is revoked

Settings, from the environment:

    VAULTGATE_NODE_DIR   the node's files (~/.vaultgate/node)
    VAULTGATE_API        the API's public address (https://localhost:8000)
    VAULTGATE_NODES_URL  the API's nodes' port (https://localhost:8002)
    VAULTGATE_KEYCLOAK   Keycloak's address, for enroll-client (https://localhost:8080)
    VAULTGATE_IMDS       the instance metadata service, for enroll-cloud
                         (http://169.254.169.254, AWS's)
    SSL_CERT_FILE        the CA bundle to verify the API with (VaultGate's root, locally)

Standard library and OpenSSL 3 only (VAULTGATE_OPENSSL names the command).
"""

import base64
import getpass
import hashlib
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NODE_DIR = Path(os.getenv("VAULTGATE_NODE_DIR", Path.home() / ".vaultgate" / "node"))
API = os.getenv("VAULTGATE_API", "https://localhost:8000").rstrip("/")
NODES_URL = os.getenv("VAULTGATE_NODES_URL", "https://localhost:8002").rstrip("/")
OPENSSL = os.getenv("VAULTGATE_OPENSSL", "openssl")
KEYCLOAK = os.getenv("VAULTGATE_KEYCLOAK", "https://localhost:8080").rstrip("/")
IMDS = os.getenv("VAULTGATE_IMDS", "http://169.254.169.254").rstrip("/")
REALM = os.getenv("VAULTGATE_KEYCLOAK_REALM", "vaultgate")


class Failure(Exception):
    pass


def openssl(*args: str, data: bytes | None = None) -> bytes:
    result = subprocess.run([OPENSSL, *args], input=data, capture_output=True, check=False)
    if result.returncode != 0:
        raise Failure(f"openssl {args[0]}: {result.stderr.decode().strip()}")
    return result.stdout


def call(
    url: str, method: str = "GET", body: dict | None = None, *, client: bool = False, token=None
) -> tuple[int, dict]:
    """A JSON request; with `client`, presenting the node's certificate (mutual TLS)."""
    context = ssl.create_default_context()
    if client:
        context.load_cert_chain(NODE_DIR / "node.crt", NODE_DIR / "node.key")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"detail": raw.decode(errors="replace")[:200]}


def fingerprint(key_file: Path) -> str:
    """SHA-256 over the public key (SubjectPublicKeyInfo), as the API shows it."""
    spki = openssl("pkey", "-in", str(key_file), "-pubout", "-outform", "DER")
    return "SHA256:" + base64.b64encode(hashlib.sha256(spki).digest()).decode().rstrip("=")


def new_key(path: Path) -> None:
    key = openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)


def csr(key_file: Path) -> str:
    return openssl("req", "-new", "-key", str(key_file), "-subj", "/").decode()


def save(answer: dict) -> None:
    """The certificate with its chain (a client presents both), and what the API said."""
    (NODE_DIR / "node.crt").write_text(
        answer["certificate"].strip() + "\n" + "".join(c.strip() + "\n" for c in answer["chain"])
    )
    (NODE_DIR / "node.json").write_text(json.dumps({k: answer[k] for k in answer
                                                    if k not in ("certificate", "chain")}))  # fmt: skip


def request(name: str) -> dict:
    NODE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = NODE_DIR / "node.key"
    if not key.exists():
        new_key(key)
    status, answer = call(f"{API}/nodes/enrollments", "POST", {"name": name, "csr": csr(key)})
    if status != 202:
        raise Failure(f"enrollment request: {status} {answer.get('detail')}")
    mine = fingerprint(key)
    if answer["key_fingerprint"] != mine:
        raise Failure(f"the API saw key {answer['key_fingerprint']}, this node's is {mine}")
    (NODE_DIR / "enrollment.json").write_text(json.dumps(answer))
    print(f"ok  asked to enroll as {answer['identity']}")
    print(f"    request {answer['id']}, waiting for an admin until {answer['expires_at']}")
    print(f"    key fingerprint: {mine}")
    print("    the admin must confirm this fingerprint before approving")
    return answer


def enrollment_id() -> str:
    try:
        return json.loads((NODE_DIR / "enrollment.json").read_text())["id"]
    except FileNotFoundError:
        raise Failure("no enrollment request: run `request NAME` first") from None


def status() -> str:
    code, answer = call(f"{API}/nodes/enrollments/{enrollment_id()}")
    if code != 200:
        raise Failure(f"enrollment status: {code} {answer.get('detail')}")
    print(f"ok  {answer['identity']}: {answer['status']}")
    return answer["status"]


def complete(code: str) -> dict:
    status_, answer = call(
        f"{API}/nodes/enrollments/{enrollment_id()}/complete", "POST", {"code": code}
    )
    if status_ != 200:
        raise Failure(f"completing the enrollment: {status_} {answer.get('detail')}")
    save(answer)
    print(f"ok  enrolled as {answer['identity']}, certificate {answer['serial']} "
          f"until {answer['expires_at']}")  # fmt: skip
    return answer


def enroll_token(token: str | None = None) -> dict:
    token = (
        token or os.getenv("VAULTGATE_ENROLLMENT_TOKEN") or getpass.getpass("enrollment token: ")
    )
    NODE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = NODE_DIR / "node.key"
    if not key.exists():
        new_key(key)
    code, answer = call(f"{API}/nodes/enrollments/by-token", "POST",
                        {"token": token.strip(), "csr": csr(key)})  # fmt: skip
    if code != 201:
        raise Failure(f"enrollment with the token: {code} {answer.get('detail')}")
    save(answer)
    print(f"ok  enrolled as {answer['identity']} with an enrollment token, certificate "
          f"{answer['serial']} until {answer['expires_at']}")  # fmt: skip
    return answer


def instance_identity() -> tuple[str, str]:
    """The instance's identity document and its signature, from the metadata service
    (IMDSv2: a session token first, then the document and the RSA-SHA256 signature)."""

    def imds(method: str, path: str, headers: dict) -> str:
        request = urllib.request.Request(f"{IMDS}{path}", method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.read().decode()
        except (urllib.error.URLError, OSError) as e:
            raise Failure(f"the instance metadata service ({IMDS}{path}): {e}") from None

    token = imds("PUT", "/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "60"})
    headers = {"X-aws-ec2-metadata-token": token}
    document = imds("GET", "/latest/dynamic/instance-identity/document", headers)
    signature = imds("GET", "/latest/dynamic/instance-identity/signature", headers)
    return document, signature


def enroll_cloud() -> dict:
    document, signature = instance_identity()
    NODE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = NODE_DIR / "node.key"
    if not key.exists():
        new_key(key)
    body = {"provider": "aws", "document": document, "signature": signature, "csr": csr(key)}
    code, answer = call(f"{API}/nodes/enrollments/by-cloud", "POST", body)
    if code != 201:
        raise Failure(f"enrollment by instance identity: {code} {answer.get('detail')}")
    save(answer)
    print(f"ok  enrolled as {answer['identity']} by its instance identity, certificate "
          f"{answer['serial']} until {answer['expires_at']}")  # fmt: skip
    return answer


def credential() -> None:
    """The node's Keycloak credential: an RSA key (RS256 client assertions) that stays
    here, and a self-signed certificate for it that the admin gives Keycloak."""
    NODE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = NODE_DIR / "keycloak.key"
    if not key.exists():
        pem = openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072")
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    cert = openssl("req", "-x509", "-new", "-key", str(key), "-subj", "/CN=vaultgate-node",
                   "-days", "365", "-sha256")  # fmt: skip
    (NODE_DIR / "keycloak.crt").write_bytes(cert)
    print(f"ok  Keycloak credential: give {NODE_DIR / 'keycloak.crt'} to an admin")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def client_assertion(client_id: str, audience: str) -> str:
    """A JWT the node's Keycloak key signs (RFC 7523): who it is, for which token
    endpoint, valid a minute, used once (jti)."""
    now = int(time.time())
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = b64url(json.dumps({
        "iss": client_id, "sub": client_id, "aud": audience,
        "jti": secrets.token_urlsafe(16), "iat": now, "exp": now + 60,
    }).encode())  # fmt: skip
    signature = openssl("dgst", "-sha256", "-sign", str(NODE_DIR / "keycloak.key"),
                        data=f"{header}.{claims}".encode())  # fmt: skip
    return f"{header}.{claims}.{b64url(signature)}"


def client_token(name: str) -> str:
    """An access token for the node's client, from Keycloak's token endpoint."""
    token_endpoint = f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token"
    form = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": f"node-{name}",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion(f"node-{name}", f"{KEYCLOAK}/realms/{REALM}"),
    }).encode()  # fmt: skip
    request = urllib.request.Request(token_endpoint, data=form, method="POST")
    try:
        with urllib.request.urlopen(request, context=ssl.create_default_context(),
                                    timeout=30) as response:  # fmt: skip
            return json.loads(response.read())["access_token"]
    except urllib.error.HTTPError as e:
        raise Failure(f"Keycloak token: {e.code} {e.read().decode(errors='replace')[:200]}")


def enroll_client(name: str) -> dict:
    NODE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = NODE_DIR / "node.key"
    if not key.exists():
        new_key(key)
    token = client_token(name)
    status_, answer = call(f"{API}/nodes/enrollments/by-client", "POST", {"csr": csr(key)},
                           token=token)  # fmt: skip
    if status_ != 201:
        raise Failure(f"enrollment with the Keycloak client: {status_} {answer.get('detail')}")
    save(answer)
    print(f"ok  enrolled as {answer['identity']} with its Keycloak client, certificate "
          f"{answer['serial']} until {answer['expires_at']}")  # fmt: skip
    return answer


def whoami() -> dict:
    code, answer = call(f"{NODES_URL}/whoami", client=True)
    if code != 200:
        raise Failure(f"whoami: {code} {answer.get('detail')}")
    print(f"ok  {answer['identity']} ({answer['status']}), certificate {answer['cert_serial']}")
    return answer


def renew(rotate_key: bool = False) -> dict:
    key = NODE_DIR / "node.key"
    if rotate_key:
        new_key(NODE_DIR / "node.key.new")
        key = NODE_DIR / "node.key.new"
    code, answer = call(f"{NODES_URL}/renew", "POST", {"csr": csr(key)}, client=True)
    if code != 200:
        raise Failure(f"renewal: {code} {answer.get('detail')}")
    if rotate_key:
        key.replace(NODE_DIR / "node.key")
    save(answer)
    print(f"ok  renewed: certificate {answer['serial']} until {answer['expires_at']}"
          f"{', with a new key' if rotate_key else ''}")  # fmt: skip
    return answer


def main(argv: list[str]) -> int:
    try:
        match argv:
            case ["request", name]:
                request(name)
            case ["status"]:
                status()
            case ["complete", code]:
                complete(code)
            case ["enroll-token"]:
                enroll_token()
            case ["enroll-cloud"]:
                enroll_cloud()
            case ["credential"]:
                credential()
            case ["enroll-client", name]:
                enroll_client(name)
            case ["whoami"]:
                whoami()
            case ["renew"]:
                renew()
            case ["renew", "--new-key"]:
                renew(rotate_key=True)
            case _:
                print(__doc__.split("\n\n")[2], file=sys.stderr)
                return 2
    except Failure as e:
        print(f"FAIL {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

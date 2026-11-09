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
    vaultgate_node.py whoami            the node, as the API sees it, on the nodes' port
    vaultgate_node.py renew [--new-key] a new certificate, with the current one; the
                                        current one is revoked

Settings, from the environment:

    VAULTGATE_NODE_DIR   the node's files (~/.vaultgate/node)
    VAULTGATE_API        the API's public address (https://localhost:8000)
    VAULTGATE_NODES_URL  the API's nodes' port (https://localhost:8002)
    SSL_CERT_FILE        the CA bundle to verify the API with (VaultGate's root, locally)

Standard library and OpenSSL 3 only (VAULTGATE_OPENSSL names the command).
"""

import base64
import hashlib
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

NODE_DIR = Path(os.getenv("VAULTGATE_NODE_DIR", Path.home() / ".vaultgate" / "node"))
API = os.getenv("VAULTGATE_API", "https://localhost:8000").rstrip("/")
NODES_URL = os.getenv("VAULTGATE_NODES_URL", "https://localhost:8002").rstrip("/")
OPENSSL = os.getenv("VAULTGATE_OPENSSL", "openssl")


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

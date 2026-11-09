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
    vaultgate_node.py tpm-ek            first trust by TPM attestation instead: the TPM's
                                        endorsement key's fingerprint, which an admin
                                        registers for the node's name
    vaultgate_node.py enroll-tpm        enroll by TPM attestation: an attestation key and the
                                        node's key, made in the TPM (the node's key never
                                        leaves it), the AK's certification of it, and the
                                        credential the TPM decrypts; then whoami and renew
                                        use the key in the TPM (OpenSSL's tpm2 provider)
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
    TPM2TOOLS_TCTI,      the TPM, for tpm-ek and enroll-tpm (tpm2-tools' and the tpm2
    TPM2OPENSSL_TCTI     provider's; their default is the device /dev/tpmrm0)
    VAULTGATE_TPM_HANDLE the persistent handle of the node's key in the TPM (0x81000101)
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
TPM_HANDLE = os.getenv("VAULTGATE_TPM_HANDLE", "0x81000101")
# OpenSSL with the tpm2 provider: preferring it, to make and sign with the key in the TPM;
# for TLS, preferring the default one, so that only the node's own key uses the TPM (the
# handshake's other keys, in the TPM, would soon fill its few object slots).
TPM2 = ["-provider", "tpm2", "-provider", "default", "-propquery", "?provider=tpm2"]
TPM2_TLS = ["-provider", "tpm2", "-provider", "default", "-propquery", "?provider=default"]
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


# --- TPM attestation ----------------------------------------------------------------------


def tpm2(*args: str) -> bytes:
    """A tpm2-tools command, then the TPM's transient objects and sessions flushed (a
    TPM holds only a few)."""
    result = subprocess.run(["tpm2_" + args[0], *args[1:]], capture_output=True, check=False)
    for kind in ("-t", "-s"):
        subprocess.run(["tpm2_flushcontext", kind], capture_output=True, check=False)
    if result.returncode != 0:
        raise Failure(f"tpm2_{args[0]}: {result.stderr.decode().strip()[-300:]}")
    return result.stdout


def tpm_ek() -> str:
    """The TPM's endorsement key (RSA, the TCG's default template), and its fingerprint."""
    NODE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    tpm2("createek", "-c", str(NODE_DIR / "ek.ctx"), "-G", "rsa", "-f", "pem",
         "-u", str(NODE_DIR / "ek.pem"))  # fmt: skip
    print_ek = fingerprint_pem(NODE_DIR / "ek.pem")
    print(f"ok  the TPM's endorsement key: {print_ek}")
    print("    an admin registers it for the node's name (POST /admin/nodes/tpms)")
    return print_ek


def fingerprint_pem(path: Path) -> str:
    spki = openssl("pkey", "-pubin", "-in", str(path), "-outform", "DER")
    return "SHA256:" + base64.b64encode(hashlib.sha256(spki).digest()).decode().rstrip("=")


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    length = (
        bytes([n])
        if n < 128
        else bytes([0x80 | ((n.bit_length() + 7) // 8)])
        + n.to_bytes((n.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + length + body


def tpm_csr(handle: str) -> str:
    """A CSR for the key in the TPM, signed there. Built here rather than by `openssl
    req`, whose tpm2 provider writes ecdsa-with-SHA256 with a NULL parameter, which RFC
    5758 forbids and strict parsers (VaultGate's among them) refuse."""
    spki = openssl("pkey", *TPM2, "-in", f"handle:{handle}", "-pubout", "-outform", "DER")
    info = _der(0x30, _der(0x02, b"\0") + _der(0x30, b"") + spki + _der(0xA0, b""))
    signature = openssl("dgst", *TPM2, "-sha256", "-sign", f"handle:{handle}", data=info)
    ecdsa_sha256 = _der(0x30, _der(0x06, bytes.fromhex("2a8648ce3d040302")))
    der = _der(0x30, info + ecdsa_sha256 + _der(0x03, b"\0" + signature))
    body = base64.encodebytes(der).decode()
    return f"-----BEGIN CERTIFICATE REQUEST-----\n{body}-----END CERTIFICATE REQUEST-----\n"


def enroll_tpm() -> dict:
    NODE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    d = NODE_DIR
    if not (d / "ek.ctx").exists():
        tpm_ek()
    tpm2("createak", "-C", str(d / "ek.ctx"), "-c", str(d / "ak.ctx"), "-G", "rsa",
         "-g", "sha256", "-s", "rsassa", "-u", str(d / "ak.pub"), "-r", str(d / "ak.priv"))  # fmt: skip
    # The node's key: made in the TPM, never to leave it. Kept at a staging handle until
    # its certificate is issued, then moved to TPM_HANDLE: a failed enrollment leaves the
    # node's current key and certificate as they were.
    staging = hex(int(TPM_HANDLE, 16) + 1)
    tpm2("createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", str(d / "primary.ctx"))
    tpm2("create", "-C", str(d / "primary.ctx"), "-G", "ecc256:ecdsa",
         "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
         "-u", str(d / "new-key.pub"), "-r", str(d / "new-key.priv"))  # fmt: skip
    persist(d / "new-key", staging)
    tpm2("certify", "-c", staging, "-C", str(d / "ak.ctx"), "-g", "sha256",
         "-o", str(d / "attest.out"), "-s", str(d / "sig.out"), "-f", "plain")  # fmt: skip

    def b64(name: str) -> str:
        return base64.b64encode((d / name).read_bytes()).decode()

    body = {
        "ek": (d / "ek.pem").read_text(), "ak": b64("ak.pub"), "key": b64("new-key.pub"),
        "attest": b64("attest.out"), "signature": b64("sig.out"), "csr": tpm_csr(staging),
    }  # fmt: skip
    code, challenge = call(f"{API}/nodes/enrollments/by-tpm", "POST", body)
    if code != 202:
        raise Failure(f"TPM attestation: {code} {challenge.get('detail')}")
    (d / "credential.out").write_bytes(base64.b64decode(challenge["credential"]))
    # The EK's use needs the endorsement hierarchy's authorization: a policy session, used
    # by the next two commands, so not flushed between them.
    session = str(d / "session.ctx")
    try:
        for command in (
            ["tpm2_startauthsession", "--policy-session", "-S", session],
            ["tpm2_policysecret", "-S", session, "-c", "e"],
            ["tpm2_activatecredential", "-c", str(d / "ak.ctx"), "-C", str(d / "ek.ctx"),
             "-i", str(d / "credential.out"), "-o", str(d / "secret.out"),
             "-P", f"session:{session}"],
        ):  # fmt: skip
            result = subprocess.run(command, capture_output=True, check=False)
            if result.returncode != 0:
                raise Failure(f"{command[0]}: {result.stderr.decode().strip()[-300:]}")
    finally:
        for flush in ([session], ["-t"], ["-s"]):
            subprocess.run(["tpm2_flushcontext", *flush], capture_output=True, check=False)
    secret = base64.b64encode((d / "secret.out").read_bytes()).decode()
    (d / "secret.out").unlink()
    code, answer = call(f"{API}/nodes/enrollments/by-tpm/{challenge['id']}/complete", "POST",
                        {"secret": secret})  # fmt: skip
    if code != 201:
        raise Failure(f"completing the TPM enrollment: {code} {answer.get('detail')}")
    persist(d / "new-key", TPM_HANDLE)  # the certified key, at the node's handle now
    evict(staging)
    for part in ("pub", "priv"):
        (d / f"new-key.{part}").replace(d / f"key.{part}")
    save(answer)
    print(f"ok  enrolled as {answer['identity']} by TPM attestation, certificate "
          f"{answer['serial']} until {answer['expires_at']}; its key is in the TPM "
          f"({TPM_HANDLE})")  # fmt: skip
    return answer


def evict(handle: str) -> None:
    try:
        tpm2("evictcontrol", "-C", "o", "-c", handle)
    except Failure:
        pass  # nothing there


def persist(key: Path, handle: str) -> None:
    """The key (its .pub and .priv, under the owner's primary key, which the same template
    makes again) at the persistent `handle`, in place of whatever was there."""
    tpm2("load", "-C", str(NODE_DIR / "primary.ctx"), "-u", f"{key}.pub", "-r", f"{key}.priv",
         "-c", str(NODE_DIR / "loaded.ctx"))  # fmt: skip
    evict(handle)
    tpm2("evictcontrol", "-C", "o", "-c", str(NODE_DIR / "loaded.ctx"), handle)


def tpm_call(path: str, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
    """A request to the nodes' port with the key in the TPM: through `openssl s_client`
    and the tpm2 provider (Python's ssl can't use a key it can't read)."""
    url = urllib.parse.urlparse(NODES_URL)
    payload = json.dumps(body).encode() if body is not None else b""
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {url.hostname}\r\nConnection: close\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n"
    ).encode() + payload
    ca = ["-CAfile", os.environ["SSL_CERT_FILE"]] if os.getenv("SSL_CERT_FILE") else []
    result = subprocess.run(
        # -ign_eof: read the answer after the request ends; -cert_chain: send the nodes'
        # CA too, as a client's chain must be.
        [OPENSSL, "s_client", *TPM2_TLS, "-quiet", "-ign_eof",
         "-connect", f"{url.hostname}:{url.port}", "-servername", url.hostname,
         "-verify_return_error", *ca, "-cert", str(NODE_DIR / "node.crt"),
         "-cert_chain", str(NODE_DIR / "node.crt"), "-key", f"handle:{TPM_HANDLE}"],
        input=request, capture_output=True, check=False, timeout=30,
    )  # fmt: skip
    head, _, raw = result.stdout.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 "):
        raise Failure(f"the nodes' port: {result.stderr.decode().strip()[-300:]}")
    status_ = int(head.split()[1])
    if b"transfer-encoding: chunked" in head.lower():
        raw = _unchunk(raw)
    return status_, json.loads(raw) if raw.strip() else {}


def _unchunk(raw: bytes) -> bytes:
    out = b""
    while raw:
        size_line, _, raw = raw.partition(b"\r\n")
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            break
        out, raw = out + raw[:size], raw[size + 2 :]
    return out


def whoami() -> dict:
    if in_tpm():
        code, answer = tpm_call("/whoami")
    else:
        code, answer = call(f"{NODES_URL}/whoami", client=True)
    if code != 200:
        raise Failure(f"whoami: {code} {answer.get('detail')}")
    print(f"ok  {answer['identity']} ({answer['status']}), certificate {answer['cert_serial']}")
    return answer


def in_tpm() -> bool:
    """Whether the node's key is in its TPM (enrolled by TPM attestation)."""
    return not (NODE_DIR / "node.key").exists() and (NODE_DIR / "key.pub").exists()


def renew(rotate_key: bool = False) -> dict:
    if in_tpm():
        # The same key, the TPM's: VaultGate renews a TPM-attested node for no other.
        if rotate_key:
            raise Failure("the node's key is in its TPM: renew without --new-key")
        code, answer = tpm_call("/renew", "POST", {"csr": tpm_csr(TPM_HANDLE)})
        if code != 200:
            raise Failure(f"renewal: {code} {answer.get('detail')}")
        save(answer)
        print(f"ok  renewed: certificate {answer['serial']} until {answer['expires_at']}, "
              "the key in the TPM")  # fmt: skip
        return answer
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
            case ["tpm-ek"]:
                tpm_ek()
            case ["enroll-tpm"]:
                enroll_tpm()
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

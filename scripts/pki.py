#!/usr/bin/env python3
"""VaultGate's offline root CA and the ceremonies that use it (M9, ADR 0012).

The root CA's key never enters the cluster. It lives here, on the operator's machine,
encrypted with a passphrase, and is used for two things only: signing the intermediate
CAs, whose keys OpenBao generates and keeps, and signing OpenBao's own server certificate
(OpenBao can't issue its own before it holds an intermediate). The intermediates are:

- the services' (`pki` mount): server certificates for cluster names, and the services'
  client identities, spiffe://vaultgate/... (M9, M10);
- the nodes' (`pki-nodes` mount, M11, ADR 0014): client certificates for external nodes,
  spiffe://nodes.vaultgate/..., and nothing else.

    scripts/pki.py root              create the root CA, unless there is one
    scripts/pki.py openbao-tls DIR   OpenBao's server certificate: DIR/tls.crt, DIR/tls.key
    scripts/pki.py intermediate      the intermediate CAs: for each, OpenBao generates its key
                                     and a CSR, the root signs it here, OpenBao installs it
                                     (skipped while the installed one is valid for 30 days more)
    scripts/pki.py check             OpenBao unsealed, its TLS and the intermediates chained to
                                     the root, each one's constraints
    scripts/pki.py check-tls         only the first: OpenBao answers, unsealed, over TLS
    scripts/pki.py check-nodes       the nodes' CA at work: a node certificate signed under the
                                     node role (a service's identity refused), for clients
                                     only, then revoked; its CA, revocation list and OCSP
                                     answers fetched from the API
    scripts/pki.py check-constraints the intermediates' name constraints, on a throwaway root
                                     and intermediates made from the same extensions: what
                                     each may sign verifies, what it may not is rejected (by
                                     OpenSSL, and in a TLS handshake as the API's internal port
                                     does), however it was signed
    scripts/pki.py check-service HOST:PORT...
                                     each serves TLS that verifies against the root, with a
                                     certificate from the intermediate that lasts 3 days at most

Settings, from the environment:

    VAULTGATE_PKI_DIR         where root-ca.crt and root-ca.key (encrypted) are kept
                              (~/.vaultgate/pki)
    VAULTGATE_PKI_PASSPHRASE  the root key's passphrase; asked for when unset
    VAULTGATE_OPENBAO         OpenBao's address (https://localhost:8200)
    VAULTGATE_OPENBAO_JWT     for `intermediate`: a token of the openbao/pki-ceremony
                              service account, audience "openbao" (scripts/k3d.sh mints a
                              10-minute one with kubectl create token); for `check-nodes`,
                              of openbao/pki-nodes-check
    VAULTGATE_API             for `check-nodes`: the API's public address
                              (https://localhost:8000)

Needs Python 3 and OpenSSL 3 (VAULTGATE_OPENSSL names the command; macOS's own `openssl`
is LibreSSL: use Homebrew's openssl@3). The private keys are handled by openssl only; the
passphrase reaches it through its environment, never its command line.
"""

import getpass
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

PKI_DIR = Path(os.getenv("VAULTGATE_PKI_DIR", Path.home() / ".vaultgate" / "pki"))
ROOT_CERT = PKI_DIR / "root-ca.crt"
ROOT_KEY = PKI_DIR / "root-ca.key"
OPENBAO = os.getenv("VAULTGATE_OPENBAO", "https://localhost:8200").rstrip("/")
OPENSSL = os.getenv("VAULTGATE_OPENSSL", "openssl")
API = os.getenv("VAULTGATE_API", "https://localhost:8000").rstrip("/")
NODE_IDENTITY = "spiffe://nodes.vaultgate/node/"

ROOT_DAYS = 3650
INTERMEDIATE_DAYS = 365
OPENBAO_TLS_DAYS = 365
RENEW_BEFORE_DAYS = 30

# The services' intermediate may only issue for names inside the cluster (*.svc,
# *.cluster.local), on this machine (localhost, loopback), and the services' identities
# (URIs spiffe://vaultgate/...): even a compromised OpenBao can't mint a certificate for
# any other name that a verifying client would accept, nor a node's identity.
NAME_CONSTRAINTS = (
    "critical, permitted;DNS:svc, permitted;DNS:cluster.local, permitted;DNS:localhost, "
    "permitted;IP:127.0.0.0/255.0.0.0, "
    "permitted;IP:0:0:0:0:0:0:0:1/FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF, "
    "permitted;URI:vaultgate"
)
# The nodes' intermediate may only issue nodes' identities (URIs spiffe://nodes.vaultgate/
# ...): no DNS name, IP address or email address it signs is accepted (each type is
# limited to a name that can't exist: the reserved `invalid` domain, the unspecified
# addresses), and its certificates are for clients only. So it can never mint a service's
# identity (spiffe://vaultgate/...) or a server certificate.
NODES_NAME_CONSTRAINTS = (
    "critical, permitted;URI:nodes.vaultgate, permitted;DNS:invalid, "
    "permitted;email:invalid, permitted;IP:0.0.0.0/255.255.255.255, "
    "permitted;IP:0:0:0:0:0:0:0:0/FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
)

OPENSSL_CONFIG = f"""
[req]
distinguished_name = root_dn
prompt = no

[root_dn]
O = VaultGate
CN = VaultGate Local Root CA

[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
nameConstraints = {NAME_CONSTRAINTS}

[nodes_intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
nameConstraints = {NODES_NAME_CONSTRAINTS}

[openbao]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:openbao.openbao.svc, DNS:openbao.openbao.svc.cluster.local, DNS:localhost, IP:127.0.0.1
"""


# The intermediates, by OpenBao mount: their name, and their extensions above.
INTERMEDIATES = {
    "pki": ("VaultGate Local Intermediate CA", "intermediate"),
    "pki-nodes": ("VaultGate Local Nodes CA", "nodes_intermediate"),
}


class Failure(Exception):
    pass


# --- openssl ---------------------------------------------------------------------------


def passphrase() -> str:
    value = os.getenv("VAULTGATE_PKI_PASSPHRASE")
    if value is None:
        if not sys.stdin.isatty():
            raise Failure("VAULTGATE_PKI_PASSPHRASE is not set and there is no terminal to ask")
        value = getpass.getpass(f"passphrase of the root CA key ({ROOT_KEY}): ")
    if len(value) < 12:
        raise Failure("the root CA passphrase needs at least 12 characters")
    return value


def openssl(*args: str, data: bytes | None = None, secret: str | None = None) -> bytes:
    """Runs openssl; `secret` is passed as $PKI_PASS, for `-pass env:PKI_PASS` arguments."""
    env = dict(os.environ)
    env.pop("VAULTGATE_PKI_PASSPHRASE", None)
    if secret is not None:
        env["PKI_PASS"] = secret
    result = subprocess.run([OPENSSL, *args], input=data, capture_output=True, env=env, check=False)
    if result.returncode != 0:
        raise Failure(f"openssl {args[0]}: {result.stderr.decode().strip()}")
    return result.stdout


def serial() -> str:
    return f"0x{secrets.randbits(127):x}"  # random and positive, as RFC 5280 wants


def sign(csr: bytes, extensions: str, days: int, secret: str) -> bytes:
    """A certificate for `csr`, signed by the root, with the named extensions of
    OPENSSL_CONFIG only: nothing the CSR asks for is copied."""
    with tempfile.TemporaryDirectory() as tmp:
        config, request = Path(tmp, "openssl.cnf"), Path(tmp, "request.csr")
        config.write_text(OPENSSL_CONFIG)
        request.write_bytes(csr)
        return openssl(
            "x509", "-req", "-in", str(request), "-CA", str(ROOT_CERT),
            "-CAkey", str(ROOT_KEY), "-passin", "env:PKI_PASS", "-set_serial", serial(),
            "-days", str(days), "-sha384", "-extfile", str(config), "-extensions", extensions,
            secret=secret,
        )  # fmt: skip


def expires_within(certificate: bytes, days: int) -> bool:
    with tempfile.NamedTemporaryFile(suffix=".pem") as f:
        f.write(certificate)
        f.flush()
        result = subprocess.run(
            [OPENSSL, "x509", "-in", f.name, "-noout", "-checkend", str(days * 86400)],
            capture_output=True,
            check=False,
        )
    return result.returncode != 0


def verify(certificate: bytes) -> None:
    """The certificate chains to the root (strict RFC 5280 checks)."""
    with tempfile.NamedTemporaryFile(suffix=".pem") as f:
        f.write(certificate)
        f.flush()
        openssl("verify", "-x509_strict", "-CAfile", str(ROOT_CERT), f.name)


def describe(certificate: bytes) -> str:
    return openssl("x509", "-noout", "-text", data=certificate).decode()


# --- commands --------------------------------------------------------------------------


def root() -> None:
    if ROOT_CERT.exists() and ROOT_KEY.exists():
        print(f"ok  root CA in {PKI_DIR} (kept)")
    else:
        if ROOT_CERT.exists() or ROOT_KEY.exists():
            raise Failure(f"{PKI_DIR} holds only half a root CA: remove it or restore it")
        PKI_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        secret = passphrase()
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp, "openssl.cnf")
            config.write_text(OPENSSL_CONFIG)
            key = openssl(
                "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384",
                "-aes-256-cbc", "-pass", "env:PKI_PASS", secret=secret,
            )  # fmt: skip
            fd = os.open(ROOT_KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
            cert = openssl(
                "req", "-x509", "-new", "-key", str(ROOT_KEY), "-passin", "env:PKI_PASS",
                "-config", str(config), "-extensions", "root", "-set_serial", serial(),
                "-days", str(ROOT_DAYS), "-sha384", secret=secret,
            )  # fmt: skip
        ROOT_CERT.write_bytes(cert)
        print(f"ok  root CA created in {PKI_DIR}")
    fingerprint = openssl("x509", "-in", str(ROOT_CERT), "-noout", "-fingerprint", "-sha256")
    print(f"    {fingerprint.decode().strip()}")


def need_root() -> None:
    if not (ROOT_CERT.exists() and ROOT_KEY.exists()):
        raise Failure(f"no root CA in {PKI_DIR}: run `scripts/pki.py root` first")


def openbao_tls(out: Path) -> None:
    """OpenBao's server certificate, with a fresh key, signed by the root."""
    need_root()
    secret = passphrase()
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
    csr = openssl("req", "-new", "-key", "/dev/stdin", "-subj", "/CN=openbao.openbao.svc", data=key)
    cert = sign(csr, "openbao", OPENBAO_TLS_DAYS, secret)
    fd = os.open(out / "tls.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    (out / "tls.crt").write_bytes(cert + ROOT_CERT.read_bytes())
    print(f"ok  OpenBao's server certificate in {out}, valid for {OPENBAO_TLS_DAYS} days")


def bao(method: str, path: str, token: str | None = None, body: dict | None = None) -> dict:
    """A request to OpenBao, over TLS verified against the root alone."""
    context = ssl.create_default_context(cafile=str(ROOT_CERT))
    request = urllib.request.Request(
        f"{OPENBAO}/v1/{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"X-Vault-Token": token} if token else {},
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            text = response.read()
    except urllib.error.HTTPError as e:
        raise Failure(f"OpenBao {method} {path}: {e.code} {e.read().decode()[:300]}") from None
    return json.loads(text) if text else {}


def bao_text(path: str) -> bytes:
    context = ssl.create_default_context(cafile=str(ROOT_CERT))
    with urllib.request.urlopen(f"{OPENBAO}/v1/{path}", context=context, timeout=30) as r:
        return r.read()


def installed_intermediate(token: str, mount: str) -> bytes | None:
    """The mount's installed intermediate certificate, if one chains to this root and
    stays valid long enough."""
    try:
        keys = bao("GET", f"{mount}/issuers?list=true", token)["data"]["keys"]
    except Failure as e:
        if " 404 " in str(e):
            return None
        raise
    root = ROOT_CERT.read_text().strip()
    for issuer in keys:
        data = bao("GET", f"{mount}/issuer/{issuer}", token)["data"]
        cert = data["certificate"].encode()
        # The root comes in with the chain, without its key: it chains to itself, but
        # issues nothing.
        if not data.get("key_id") or data["certificate"].strip() == root:
            continue
        try:
            verify(cert)
        except Failure:
            continue
        if not expires_within(cert, RENEW_BEFORE_DAYS):
            return cert
    return None


def intermediate() -> None:
    need_root()
    jwt = os.getenv("VAULTGATE_OPENBAO_JWT")
    if not jwt:
        raise Failure("VAULTGATE_OPENBAO_JWT is not set (a pki-ceremony service account token)")
    # Ready can come a moment before self-initialization has created the role: retry.
    for attempt in range(12):
        try:
            login = bao("POST", "auth/kubernetes/login", body={"role": "pki-ceremony", "jwt": jwt})
            break
        except Failure:
            if attempt == 11:
                raise
            time.sleep(5)
    token = login["auth"]["client_token"]
    try:
        for mount in INTERMEDIATES:
            install_intermediate(token, mount)
    finally:
        try:  # never hides an error from the ceremony itself
            bao("POST", "auth/token/revoke-self", token)
        except (Failure, OSError) as e:
            print(f"warn the ceremony token was not revoked (expires in 10 minutes): {e}")


def install_intermediate(token: str, mount: str) -> None:
    name, extensions = INTERMEDIATES[mount]
    if installed_intermediate(token, mount):
        print(f"ok  {name} is installed and valid (kept)")
        return
    secret = passphrase()
    # The key is generated inside OpenBao ("internal") and can never be read back.
    csr = bao(
        "POST",
        f"{mount}/intermediate/generate/internal",
        token,
        {
            "common_name": name,
            "organization": "VaultGate",
            "key_type": "ec",
            "key_bits": 384,
            "exclude_cn_from_sans": True,
        },
    )["data"]["csr"].encode()
    cert = sign(csr, extensions, INTERMEDIATE_DAYS, secret)
    verify(cert)
    installed = bao(
        "POST",
        f"{mount}/intermediate/set-signed",
        token,
        {"certificate": (cert + ROOT_CERT.read_bytes()).decode()},
    )
    # The import adds the intermediate and the root (without its key) as issuers; the
    # default, which issues and which pki/ca/pem serves, stays the old one unless set.
    # On a renewal that would keep signing with the expiring intermediate.
    imported = installed.get("data", {}).get("imported_issuers") or []
    new = next(
        (
            issuer
            for issuer in imported
            if bao("GET", f"{mount}/issuer/{issuer}", token)["data"]["certificate"].strip()
            == cert.decode().strip()
        ),
        None,
    )
    if new is None:
        raise Failure(f"the installed intermediate is not among the imported issuers {imported}")
    bao("POST", f"{mount}/config/issuers", token, {"default": new})
    print(f"ok  {name} installed as {mount}'s default issuer ({new}), valid for "
          f"{INTERMEDIATE_DAYS} days")  # fmt: skip


def check_tls() -> None:
    try:
        health = bao("GET", "sys/health")  # over TLS verified against the root
    except (OSError, ssl.SSLError) as e:  # URLError is an OSError
        raise Failure(f"OpenBao at {OPENBAO}: {e}") from None
    if not health.get("initialized") or health.get("sealed"):
        raise Failure(f"OpenBao is not ready: {health}")
    print(f"ok  OpenBao {health.get('version')} is initialized and unsealed, its TLS from the root")


# What each intermediate must carry: the text `openssl x509 -text` shows, and what it
# means.
CONSTRAINTS = {
    "pki": [
        ("CA:TRUE, pathlen:0", "may sign leaf certificates only"),
        ("X509v3 Name Constraints: critical", "carries the name constraints"),
        ("DNS:svc", "is limited to cluster names"),
        ("URI:vaultgate\n", "is limited to the services' identities"),
    ],
    "pki-nodes": [
        ("CA:TRUE, pathlen:0", "may sign leaf certificates only"),
        ("X509v3 Name Constraints: critical", "carries the name constraints"),
        ("URI:nodes.vaultgate", "is limited to the nodes' identities"),
        ("DNS:invalid", "allows no DNS names"),
        (
            "X509v3 Extended Key Usage: \n                TLS Web Client Authentication\n",
            "is for client certificates only",
        ),
    ],
}


def check() -> None:
    check_tls()
    for mount, (name, _) in INTERMEDIATES.items():
        cert = bao_text(f"{mount}/ca/pem")
        verify(cert)
        text = describe(cert)
        for wanted, what in CONSTRAINTS[mount]:
            if wanted not in text:
                raise Failure(f"{name} {what}: {wanted!r} missing")
        print(f"ok  {name} chains to the root, signs leaves only, within its names")
        if expires_within(cert, RENEW_BEFORE_DAYS):
            raise Failure(f"{name} expires within {RENEW_BEFORE_DAYS} days")


def login(role: str) -> str:
    """An OpenBao token for `role`, from the service account token in the environment."""
    jwt = os.getenv("VAULTGATE_OPENBAO_JWT")
    if not jwt:
        raise Failure(f"VAULTGATE_OPENBAO_JWT is not set (a {role} service account token)")
    return bao("POST", "auth/kubernetes/login", body={"role": role, "jwt": jwt})["auth"][
        "client_token"
    ]


def api(path: str, body: bytes | None = None) -> bytes:
    """GET (or POST `body` to) the API's public `path`, over TLS verified against the root."""
    context = ssl.create_default_context(cafile=str(ROOT_CERT))
    request = urllib.request.Request(
        f"{API}{path}",
        data=body,
        headers={"Content-Type": "application/ocsp-request"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return response.read()
    except (OSError, ssl.SSLError) as e:  # HTTPError and URLError are OSErrors
        raise Failure(f"the API's {path}: {e}") from None


def ocsp_status(tmp: Path) -> str:
    """The node certificate's status, as the API's OCSP responder signs it."""
    request = openssl(
        "ocsp", "-issuer", str(tmp / "ca.pem"), "-cert", str(tmp / "node.pem"), "-no_nonce",
        "-reqout", "/dev/stdout",
    )  # fmt: skip
    (tmp / "response.der").write_bytes(api("/pki/nodes/ocsp", request))
    out = openssl(
        "ocsp", "-respin", str(tmp / "response.der"), "-issuer", str(tmp / "ca.pem"),
        "-cert", str(tmp / "node.pem"), "-CAfile", str(ROOT_CERT),
        "-VAfile", str(tmp / "ca.pem"),
    ).decode()  # fmt: skip
    return out.split(": ", 1)[1].split()[0] if ": " in out else out


def check_nodes() -> None:
    token = login("pki-nodes-check")
    try:
        with tempfile.TemporaryDirectory() as directory:
            check_node_certificate(token, Path(directory))
    finally:
        try:
            bao("POST", "auth/token/revoke-self", token)
        except (Failure, OSError) as e:
            print(f"warn the check's token was not revoked (expires in 10 minutes): {e}")


def check_node_certificate(token: str, tmp: Path) -> None:
    ca = openssl("x509", "-inform", "DER", "-in", "/dev/stdin", data=api("/pki/nodes/ca"))
    (tmp / "ca.pem").write_bytes(ca)
    verify(ca)
    key = openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
    (tmp / "node.key").write_bytes(key)
    csr = openssl("req", "-new", "-key", str(tmp / "node.key"), "-subj", "/").decode()

    # A service's identity, or any other name, is refused: nodes are named by URI only.
    for refused in ({"uri_sans": "spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway"},
                    {"common_name": "node.example.com"}):  # fmt: skip
        try:
            bao("POST", "pki-nodes/sign/node", token, {"csr": csr, **refused})
        except Failure:
            continue
        raise Failure(f"the node role signed {refused}")
    print("ok  the node role refuses a service's identity and DNS names")

    identity = f"{NODE_IDENTITY}k3d-check-{secrets.token_hex(4)}"
    signed = bao(
        "POST", "pki-nodes/sign/node", token, {"csr": csr, "uri_sans": identity, "ttl": "10m"}
    )["data"]
    node = signed["certificate"].encode()
    (tmp / "node.pem").write_bytes(node)
    text = describe(node)
    for wanted, what in [
        (f"URI:{identity}", "names the node"),
        ("TLS Web Client Authentication", "is for clients"),
        (f"OCSP - URI:{API}/pki/nodes/ocsp", "names the API's OCSP"),
        (f"URI:{API}/pki/nodes/crl", "names the API's revocation list"),
    ]:
        if wanted not in text:
            raise Failure(f"the node certificate {what}: {wanted!r} missing")
    chain = ["-CAfile", str(ROOT_CERT), "-untrusted", str(tmp / "ca.pem"), str(tmp / "node.pem")]
    openssl("verify", "-x509_strict", "-purpose", "sslclient", *chain)
    try:
        openssl("verify", "-x509_strict", "-purpose", "sslserver", *chain)
    except Failure:
        pass
    else:
        raise Failure("the node certificate verifies as a server's")
    print(f"ok  {identity}: chains to the root through the nodes' CA, as a client only")

    if (status := ocsp_status(tmp)) != "good":
        raise Failure(f"OCSP, before revocation: {status}")
    bao("POST", "pki-nodes/revoke", token, {"serial_number": signed["serial_number"]})
    if (status := ocsp_status(tmp)) != "revoked":
        raise Failure(f"OCSP, after revocation: {status}")
    print("ok  the API's OCSP: good, then revoked at once")

    crl = openssl("crl", "-inform", "DER", "-in", "/dev/stdin", data=api("/pki/nodes/crl"))
    (tmp / "crl.pem").write_bytes(crl)
    openssl("crl", "-in", str(tmp / "crl.pem"), "-CAfile", str(tmp / "ca.pem"), "-noout")
    print("ok  the API's revocation list is signed by the nodes' CA")


# Leaves each intermediate signs, whatever its OpenBao role allows (as a compromised
# OpenBao could): (intermediate's extensions, the leaf's names, its use, accepted?).
CONSTRAINT_CASES = [
    ("nodes_intermediate", "URI:spiffe://nodes.vaultgate/node/n1", "clientAuth", True),
    (
        "nodes_intermediate",
        "URI:spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway",
        "clientAuth",
        False,
    ),
    ("nodes_intermediate", "DNS:vaultgate-api.vaultgate.svc", "clientAuth", False),
    ("nodes_intermediate", "DNS:node1.example.com", "clientAuth", False),
    ("nodes_intermediate", "IP:10.0.0.1", "clientAuth", False),
    ("nodes_intermediate", "email:node@example.com", "clientAuth", False),
    ("nodes_intermediate", "URI:spiffe://nodes.vaultgate/node/n1", "serverAuth", False),
    (
        "intermediate",
        "URI:spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway",
        "clientAuth",
        True,
    ),
    ("intermediate", "URI:spiffe://nodes.vaultgate/node/n1", "clientAuth", False),
    ("intermediate", "DNS:vaultgate-api.vaultgate.svc", "serverAuth", True),
    ("intermediate", "DNS:example.com", "serverAuth", False),
]


def check_constraints() -> None:
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        (tmp / "openssl.cnf").write_text(OPENSSL_CONFIG)

        def key(name: str) -> Path:
            path = tmp / f"{name}.key"
            path.write_bytes(openssl("genpkey", "-algorithm", "EC", "-pkeyopt",
                                     "ec_paramgen_curve:P-256"))  # fmt: skip
            return path

        def signed(name: str, ca: str, extfile: Path, section: str, subject: str = "/") -> Path:
            csr = tmp / f"{name}.csr"
            csr.write_bytes(openssl("req", "-new", "-key", str(key(name)), "-subj", subject))
            cert = tmp / f"{name}.pem"
            cert.write_bytes(openssl(
                "x509", "-req", "-in", str(csr), "-CA", str(tmp / f"{ca}.pem"),
                "-CAkey", str(tmp / f"{ca}.key"), "-set_serial", serial(), "-days", "1",
                "-extfile", str(extfile), "-extensions", section,
            ))  # fmt: skip
            return cert

        (tmp / "root.pem").write_bytes(openssl(
            "req", "-x509", "-new", "-key", str(key("root")), "-config", str(tmp / "openssl.cnf"),
            "-extensions", "root", "-days", "1",
        ))  # fmt: skip
        for section in {case[0] for case in CONSTRAINT_CASES}:
            signed(section, "root", tmp / "openssl.cnf", section, f"/CN=test {section}")
        # The server end of the handshakes: the API's internal port, which wants a client
        # certificate chaining to the root.
        (tmp / "server.cnf").write_text(
            "[x]\nbasicConstraints = CA:FALSE\nextendedKeyUsage = serverAuth\n"
            "subjectAltName = DNS:localhost\n"
        )
        server = signed("server", "intermediate", tmp / "server.cnf", "x")
        (tmp / "server-chain.pem").write_bytes(
            server.read_bytes() + (tmp / "intermediate.pem").read_bytes()
        )

        for section, names, use, accepted in CONSTRAINT_CASES:
            (tmp / "leaf.cnf").write_text(
                "[x]\nbasicConstraints = CA:FALSE\nkeyUsage = critical, digitalSignature\n"
                f"extendedKeyUsage = {use}\nsubjectAltName = critical, {names}\n"
                "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n"
            )
            leaf = signed("leaf", section, tmp / "leaf.cnf", "x")
            purpose = "sslclient" if use == "clientAuth" else "sslserver"
            try:
                openssl("verify", "-x509_strict", "-purpose", purpose, "-CAfile",
                        str(tmp / "root.pem"), "-untrusted", str(tmp / f"{section}.pem"),
                        str(leaf))  # fmt: skip
                verified = True
            except Failure:
                verified = False
            results = {"openssl": verified}
            if use == "clientAuth":
                results["a TLS handshake"] = handshake(tmp, leaf, section)
            for verifier, result in results.items():
                if result != accepted:
                    what = "accepted" if result else "rejected"
                    raise Failure(f"{section} signing {names} ({use}): {what} by {verifier}")
            print(f"ok  {section} signing {names} ({use}): "
                  f"{'accepted' if accepted else 'rejected'}")  # fmt: skip


def handshake(tmp: Path, leaf: Path, section: str) -> bool:
    """Whether a TLS server that wants client certificates from the root (as the API's
    internal port does) accepts `leaf`, with its intermediate, as the client's."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(tmp / "server-chain.pem"), str(tmp / "server.key"))
    server.verify_mode = ssl.CERT_REQUIRED
    server.load_verify_locations(str(tmp / "root.pem"))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(str(tmp / "root.pem"))
    (tmp / "leaf-chain.pem").write_bytes(leaf.read_bytes() + (tmp / f"{section}.pem").read_bytes())
    client.load_cert_chain(str(tmp / "leaf-chain.pem"), str(tmp / "leaf.key"))
    ends = socket.socketpair()
    accepted: list[bool] = []

    def serve() -> None:
        try:
            with server.wrap_socket(ends[0], server_side=True):
                accepted.append(True)
        except (ssl.SSLError, OSError):
            accepted.append(False)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        with client.wrap_socket(ends[1], server_hostname="localhost") as tls:
            tls.recv(1)  # TLS 1.3: the server's verdict on the client comes after
    except (ssl.SSLError, OSError):
        pass
    thread.join(timeout=10)
    ends[0].close()
    ends[1].close()
    return accepted == [True]


SERVICE_MAX_DAYS = 3  # OpenBao's vaultgate-service role: 72h at most


def check_service(addresses: list[str]) -> None:
    context = ssl.create_default_context(cafile=str(ROOT_CERT))
    for address in addresses:
        host, _, port = address.rpartition(":")
        try:
            with (
                socket.create_connection((host, int(port)), timeout=10) as sock,
                context.wrap_socket(sock, server_hostname=host) as tls,
            ):
                cert = tls.getpeercert()
        except (OSError, ssl.SSLError) as e:
            raise Failure(f"{address}: {e}") from None
        issuer = dict(item for rdn in cert["issuer"] for item in rdn).get("commonName")
        if issuer != "VaultGate Local Intermediate CA":
            raise Failure(f"{address}: certificate issued by {issuer!r}, not the intermediate")
        lifetime = ssl.cert_time_to_seconds(cert["notAfter"]) - ssl.cert_time_to_seconds(
            cert["notBefore"]
        )
        if lifetime > SERVICE_MAX_DAYS * 86400 + 60:
            raise Failure(f"{address}: certificate valid for {lifetime / 86400:.1f} days")
        print(f"ok  {address}: TLS from the intermediate, valid {lifetime / 3600:.0f} hours")


def need_openssl3() -> None:
    try:
        version = openssl("version").decode()
    except FileNotFoundError:
        raise Failure(f"{OPENSSL} not found: install OpenSSL 3") from None
    if not version.startswith("OpenSSL 3"):
        raise Failure(f"{OPENSSL} is {version.strip()}: OpenSSL 3 is needed (VAULTGATE_OPENSSL)")


def main(argv: list[str]) -> int:
    commands = {
        "root": lambda: root(),
        "intermediate": lambda: intermediate(),
        "check": lambda: check(),
        "check-tls": lambda: check_tls(),
        "check-nodes": lambda: check_nodes(),
        "check-constraints": lambda: check_constraints(),
    }
    try:
        need_openssl3()
        if len(argv) == 2 and argv[0] == "openbao-tls":
            openbao_tls(Path(argv[1]))
        elif len(argv) >= 2 and argv[0] == "check-service":
            check_service(argv[1:])
        elif len(argv) == 1 and argv[0] in commands:
            commands[argv[0]]()
        else:
            print(__doc__.split("\n\n")[2], file=sys.stderr)
            return 2
    except Failure as e:
        print(f"FAIL {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

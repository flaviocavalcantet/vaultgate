#!/usr/bin/env python3
"""VaultGate's offline root CA and the ceremonies that use it (M9, ADR 0012).

The root CA's key never enters the cluster. It lives here, on the operator's machine,
encrypted with a passphrase, and is used for two things only: signing the intermediate
CA, whose key OpenBao generates and keeps, and signing OpenBao's own server certificate
(OpenBao can't issue its own before it holds the intermediate).

    scripts/pki.py root              create the root CA, unless there is one
    scripts/pki.py openbao-tls DIR   OpenBao's server certificate: DIR/tls.crt, DIR/tls.key
    scripts/pki.py intermediate      the intermediate CA: OpenBao generates its key and a
                                     CSR, the root signs it here, OpenBao installs it (skipped
                                     while the installed one is valid for 30 days more)
    scripts/pki.py check             OpenBao unsealed, its TLS and the intermediate chained to
                                     the root, the intermediate's constraints
    scripts/pki.py check-tls         only the first: OpenBao answers, unsealed, over TLS

Settings, from the environment:

    VAULTGATE_PKI_DIR         where root-ca.crt and root-ca.key (encrypted) are kept
                              (~/.vaultgate/pki)
    VAULTGATE_PKI_PASSPHRASE  the root key's passphrase; asked for when unset
    VAULTGATE_OPENBAO         OpenBao's address (https://localhost:8200)
    VAULTGATE_OPENBAO_JWT     for `intermediate`: a token of the openbao/pki-ceremony
                              service account, audience "openbao" (scripts/k3d.sh mints a
                              10-minute one with kubectl create token)

Needs Python 3 and OpenSSL 3 (VAULTGATE_OPENSSL names the command; macOS's own `openssl`
is LibreSSL: use Homebrew's openssl@3). The private keys are handled by openssl only; the
passphrase reaches it through its environment, never its command line.
"""

import getpass
import json
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PKI_DIR = Path(os.getenv("VAULTGATE_PKI_DIR", Path.home() / ".vaultgate" / "pki"))
ROOT_CERT = PKI_DIR / "root-ca.crt"
ROOT_KEY = PKI_DIR / "root-ca.key"
OPENBAO = os.getenv("VAULTGATE_OPENBAO", "https://localhost:8200").rstrip("/")
OPENSSL = os.getenv("VAULTGATE_OPENSSL", "openssl")

ROOT_DAYS = 3650
INTERMEDIATE_DAYS = 365
OPENBAO_TLS_DAYS = 365
RENEW_BEFORE_DAYS = 30

# The intermediate may only issue for names inside the cluster (*.svc, *.cluster.local)
# and on this machine (localhost, loopback): even a compromised OpenBao can't mint a
# certificate for any other name that a verifying client would accept.
NAME_CONSTRAINTS = (
    "critical, permitted;DNS:svc, permitted;DNS:cluster.local, permitted;DNS:localhost, "
    "permitted;IP:127.0.0.0/255.0.0.0, "
    "permitted;IP:0:0:0:0:0:0:0:1/FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
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

[openbao]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:openbao.openbao.svc, DNS:openbao.openbao.svc.cluster.local, DNS:localhost, IP:127.0.0.1
"""


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


def installed_intermediate(token: str) -> bytes | None:
    """The installed intermediate certificate, if one chains to this root and stays valid
    long enough."""
    try:
        keys = bao("GET", "pki/issuers?list=true", token)["data"]["keys"]
    except Failure as e:
        if " 404 " in str(e):
            return None
        raise
    root = ROOT_CERT.read_text().strip()
    for issuer in keys:
        data = bao("GET", f"pki/issuer/{issuer}", token)["data"]
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
        install_intermediate(token)
    finally:
        try:  # never hides an error from the ceremony itself
            bao("POST", "auth/token/revoke-self", token)
        except (Failure, OSError) as e:
            print(f"warn the ceremony token was not revoked (expires in 10 minutes): {e}")


def install_intermediate(token: str) -> None:
    if installed_intermediate(token):
        print("ok  the intermediate CA is installed and valid (kept)")
        return
    secret = passphrase()
    # The key is generated inside OpenBao ("internal") and can never be read back.
    csr = bao(
        "POST",
        "pki/intermediate/generate/internal",
        token,
        {
            "common_name": "VaultGate Local Intermediate CA",
            "organization": "VaultGate",
            "key_type": "ec",
            "key_bits": 384,
            "exclude_cn_from_sans": True,
        },
    )["data"]["csr"].encode()
    cert = sign(csr, "intermediate", INTERMEDIATE_DAYS, secret)
    verify(cert)
    installed = bao(
        "POST",
        "pki/intermediate/set-signed",
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
            if bao("GET", f"pki/issuer/{issuer}", token)["data"]["certificate"].strip()
            == cert.decode().strip()
        ),
        None,
    )
    if new is None:
        raise Failure(f"the installed intermediate is not among the imported issuers {imported}")
    bao("POST", "pki/config/issuers", token, {"default": new})
    print(f"ok  intermediate CA installed as the default issuer ({new}), valid for "
          f"{INTERMEDIATE_DAYS} days")  # fmt: skip


def check_tls() -> None:
    try:
        health = bao("GET", "sys/health")  # over TLS verified against the root
    except (OSError, ssl.SSLError) as e:  # URLError is an OSError
        raise Failure(f"OpenBao at {OPENBAO}: {e}") from None
    if not health.get("initialized") or health.get("sealed"):
        raise Failure(f"OpenBao is not ready: {health}")
    print(f"ok  OpenBao {health.get('version')} is initialized and unsealed, its TLS from the root")


def check() -> None:
    check_tls()
    cert = bao_text("pki/ca/pem")
    verify(cert)
    text = describe(cert)
    for wanted, what in [
        ("CA:TRUE, pathlen:0", "may sign leaf certificates only"),
        ("X509v3 Name Constraints: critical", "carries the name constraints"),
        ("DNS:svc", "is limited to cluster names"),
    ]:
        if wanted not in text:
            raise Failure(f"the intermediate CA {what}: {wanted!r} missing")
    print("ok  the intermediate CA chains to the root, signs leaves only, cluster names only")
    if expires_within(cert, RENEW_BEFORE_DAYS):
        raise Failure(f"the intermediate CA expires within {RENEW_BEFORE_DAYS} days")


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
    }
    try:
        need_openssl3()
        if len(argv) == 2 and argv[0] == "openbao-tls":
            openbao_tls(Path(argv[1]))
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

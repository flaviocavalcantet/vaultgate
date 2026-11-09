#!/usr/bin/env python3
"""Node enrollment on the cluster (M11, ADR 0014), for `make k3d-check`: a node asks,
carol (an admin) approves once the fingerprint matches, the node completes with the
one-time code, calls the nodes' port with its certificate, renews with a new key, and is
revoked; what must be refused on the way, is.

    python3 scripts/node_check.py --api URL --nodes URL --keycloak URL

The node is scripts/vaultgate_node.py, in a temporary directory. Needs the root in
SSL_CERT_FILE (scripts/k3d.sh's host_trust). Standard library and OpenSSL only.
"""

import argparse
import os
import secrets
import socket
import ssl
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import vaultgate_node as node
from keycloak_smoke import login, wait_for


def root() -> str:
    return os.environ["SSL_CERT_FILE"]  # VaultGate's root (host_trust)


def ocsp(cert: str, issuer: str) -> str:
    """The certificate's status, from the OCSP responder it names (the API's)."""
    url = node.openssl("x509", "-in", cert, "-noout", "-ocsp_uri").decode().strip()
    request = node.openssl("ocsp", "-issuer", issuer, "-cert", cert, "-no_nonce",
                           "-reqout", "/dev/stdout")  # fmt: skip
    post = urllib.request.Request(
        url, data=request, headers={"Content-Type": "application/ocsp-request"}
    )
    with urllib.request.urlopen(post, context=ssl.create_default_context(), timeout=30) as r:
        answer = r.read()
    with tempfile.NamedTemporaryFile(suffix=".der") as f:
        f.write(answer)
        f.flush()
        out = node.openssl("ocsp", "-respin", f.name, "-issuer", issuer, "-cert", cert,
                           "-VAfile", issuer, "-CAfile", root()).decode()  # fmt: skip
    return out.split(": ", 1)[1].split()[0]


def split_chain(path: Path) -> tuple[str, str]:
    """The node's certificate and its issuer (the nodes' CA), as separate files."""
    pems = path.read_text().split("-----END CERTIFICATE-----")
    leaf, issuer = path.with_suffix(".leaf.pem"), path.with_suffix(".issuer.pem")
    leaf.write_text(pems[0] + "-----END CERTIFICATE-----\n")
    issuer.write_text(pems[1].lstrip() + "-----END CERTIFICATE-----\n")
    return str(leaf), str(issuer)


def no_certificate_refused(nodes_url: str) -> None:
    """The nodes' port's handshake fails without a client certificate (TLS 1.3: the
    server's verdict comes with the first read)."""
    parsed = urllib.parse.urlparse(nodes_url)
    context = ssl.create_default_context()
    with socket.create_connection((parsed.hostname, parsed.port), timeout=10) as sock:
        try:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                tls.sendall(b"GET /whoami HTTP/1.1\r\nHost: x\r\n\r\n")
                if tls.recv(1):
                    raise node.Failure("the nodes' port answered a client without a certificate")
        except (ssl.SSLError, ConnectionResetError):
            return


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", default="https://localhost:8000")
    parser.add_argument("--nodes", default="https://localhost:8002")
    parser.add_argument("--keycloak", default="https://localhost:8080")
    args = parser.parse_args(argv)
    api = node.API = args.api.rstrip("/")
    node.NODES_URL = args.nodes.rstrip("/")
    carol = login(wait_for(args.keycloak.rstrip("/")), "carol", "carol-dev-password")[
        "access_token"
    ]
    name = f"k3d-check-{secrets.token_hex(3)}"

    with tempfile.TemporaryDirectory() as directory:
        node.NODE_DIR = Path(directory)
        asked = node.request(name)
        eid = asked["id"]

        status, _ = node.call(f"{api}/admin/nodes/enrollments/{eid}/approve", "POST",
                              {"key_fingerprint": "SHA256:" + "A" * 43}, token=carol)  # fmt: skip
        assert status == 409, f"an approval with another key's fingerprint: {status}"
        print("ok  an approval naming another key's fingerprint is refused")
        status, approval = node.call(
            f"{api}/admin/nodes/enrollments/{eid}/approve", "POST",
            {"key_fingerprint": node.fingerprint(node.NODE_DIR / "node.key")}, token=carol,
        )  # fmt: skip
        assert status == 200, f"approval: {status} {approval}"
        print("ok  carol approved, once the fingerprint matched")

        status, wrong = node.call(f"{api}/nodes/enrollments/{eid}/complete", "POST",
                                  {"code": "AAAAA-AAAAA"})  # fmt: skip
        assert status == 403, f"a wrong code: {status} {wrong}"
        issued = node.complete(approval["code"])
        status, _ = node.call(f"{api}/nodes/enrollments/{eid}/complete", "POST",
                              {"code": approval["code"]})  # fmt: skip
        assert status == 409, f"the code a second time: {status}"
        print("ok  the code is single use, and a wrong one is refused")

        leaf, issuer = split_chain(node.NODE_DIR / "node.crt")
        text = node.openssl("x509", "-in", leaf, "-noout", "-text").decode()
        assert f"URI:spiffe://nodes.vaultgate/node/{name}" in text, text
        assert "TLS Web Client Authentication" in text, text
        node.openssl("verify", "-purpose", "sslclient", "-untrusted", issuer, "-CAfile", root(),
                     leaf)  # fmt: skip
        print("ok  the certificate names the node, for client use, from the nodes' CA")

        assert node.whoami()["name"] == name
        no_certificate_refused(node.NODES_URL)
        print("ok  the nodes' port wants a client certificate")

        old_leaf = Path(directory, "old.pem")
        old_leaf.write_text(Path(leaf).read_text())
        old_key = Path(directory, "old.key")
        old_key.write_bytes((node.NODE_DIR / "node.key").read_bytes())
        renewed = node.renew(rotate_key=True)
        assert renewed["serial"] != issued["serial"]
        assert node.whoami()["cert_serial"] == renewed["serial"]
        # The previous certificate renews nothing, and is revoked.
        old_dir = Path(directory, "old")
        old_dir.mkdir()
        (old_dir / "node.crt").write_text(old_leaf.read_text() + Path(issuer).read_text())
        (old_dir / "node.key").write_bytes(old_key.read_bytes())
        current_dir, node.NODE_DIR = node.NODE_DIR, old_dir
        status, _ = node.call(f"{node.NODES_URL}/whoami", client=True)
        node.NODE_DIR = current_dir
        assert status == 403, f"the previous certificate: {status}"
        assert ocsp(str(old_leaf), issuer) == "revoked"
        print("ok  after renewal the previous certificate is refused and revoked (OCSP)")

        status, revoked = node.call(f"{api}/admin/nodes/{issued['node_id']}/revoke", "POST",
                                    token=carol)  # fmt: skip
        assert status == 200 and revoked["status"] == "revoked", (status, revoked)
        status, _ = node.call(f"{node.NODES_URL}/whoami", client=True)
        assert status == 403, f"a revoked node: {status}"
        leaf, issuer = split_chain(node.NODE_DIR / "node.crt")
        assert ocsp(leaf, issuer) == "revoked"
        print("ok  carol revoked the node: the nodes' port refuses it, OCSP says revoked")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except node.Failure as e:
        print(f"FAIL {e}", file=sys.stderr)
        sys.exit(1)

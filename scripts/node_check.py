#!/usr/bin/env python3
"""Node enrollment on the cluster (M11, ADR 0014), for `make k3d-check`: a node asks,
carol (an admin) approves once the fingerprint matches, the node completes with the
one-time code, calls the nodes' port with its certificate, renews with a new key, and is
revoked; then a second node enrolls with its own Keycloak client (private_key_jwt),
once; a third with carol's enrollment token, once; and a fourth by its (stand-in) AWS
instance identity, once. What must be refused on the way, is.

    python3 scripts/node_check.py --api URL --nodes URL --keycloak URL

The node is scripts/vaultgate_node.py, in a temporary directory. Needs the root in
SSL_CERT_FILE (scripts/k3d.sh's host_trust). Standard library and OpenSSL only.
"""

import argparse
import base64
import datetime
import http.server
import json
import os
import secrets
import socket
import ssl
import sys
import tempfile
import threading
import urllib.parse
import urllib.request
from pathlib import Path

import keycloak_node_client as kc_admin
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

    by_client(args.keycloak.rstrip("/"), f"{name}-kc", carol)
    by_token(f"{name}-tok", carol)
    by_cloud(carol)
    return 0


def fake_imds(key: Path, document: str) -> http.server.ThreadingHTTPServer:
    """An instance metadata service (IMDSv2's paths) serving `document`, signed with
    `key`: the local stand-in for AWS's (scripts/k3d.sh), which the cluster's API trusts."""
    signature = base64.b64encode(node.openssl("dgst", "-sha256", "-sign", str(key),
                                              data=document.encode())).decode()  # fmt: skip

    class Handler(http.server.BaseHTTPRequestHandler):
        def answer(self, body: str) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body.encode())

        def do_PUT(self) -> None:
            self.answer("imds-session-token")

        def do_GET(self) -> None:
            if self.headers.get("X-aws-ec2-metadata-token") != "imds-session-token":
                self.send_response(401)
                self.end_headers()
            elif self.path.endswith("/document"):
                self.answer(document)
            elif self.path.endswith("/signature"):
                self.answer(signature)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def by_cloud(carol: str) -> None:
    """First trust by cloud instance identity: a document for a made-up instance of the
    allowed account, signed by the stand-in for AWS; the instance enrolls once."""
    pki = Path(os.getenv("VAULTGATE_PKI_DIR", Path.home() / ".vaultgate" / "pki"))
    instance = f"i-0{secrets.token_hex(8)}"
    document = json.dumps({
        "accountId": "000000000000", "instanceId": instance, "region": "ap-northeast-1",
        "pendingTime": datetime.datetime.now(datetime.UTC).isoformat(),
    })  # fmt: skip
    server = fake_imds(pki / "local-aws-iid.key", document)
    node.IMDS = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with tempfile.TemporaryDirectory() as directory:
            node.NODE_DIR = Path(directory)
            enrolled = node.enroll_cloud()
            assert enrolled["identity"] == f"spiffe://nodes.vaultgate/node/aws-{instance}"
            assert node.whoami()["name"] == f"aws-{instance}"
            again_doc, again_sig = node.instance_identity()
            status, _ = node.call(f"{node.API}/nodes/enrollments/by-cloud", "POST",
                                  {"provider": "aws", "document": again_doc,
                                   "signature": again_sig,
                                   "csr": node.csr(node.NODE_DIR / "node.key")})  # fmt: skip
            assert status == 409, f"the instance a second time: {status}"
            print("ok  enrolled by its instance identity, which enrolls no second node")
            forged = json.loads(document) | {"accountId": "000000000001"}
            status, _ = node.call(f"{node.API}/nodes/enrollments/by-cloud", "POST",
                                  {"provider": "aws", "document": json.dumps(forged),
                                   "signature": again_sig,
                                   "csr": node.csr(node.NODE_DIR / "node.key")})  # fmt: skip
            assert status == 403, f"a changed document: {status}"
            print("ok  a document changed after signing is refused")
            node.call(f"{node.API}/admin/nodes/{enrolled['node_id']}/revoke", "POST",
                      token=carol)  # fmt: skip
    finally:
        server.shutdown()


def by_token(name: str, carol: str) -> None:
    """First trust by an admin's enrollment token: carol issues one for the name, the node
    enrolls with it, once."""
    status, issued = node.call(f"{node.API}/admin/nodes/tokens", "POST", {"name": name},
                               token=carol)  # fmt: skip
    assert status == 201 and issued["token"].startswith("vgn_"), (status, issued)
    with tempfile.TemporaryDirectory() as directory:
        node.NODE_DIR = Path(directory)
        enrolled = node.enroll_token(issued["token"])
        assert enrolled["identity"] == f"spiffe://nodes.vaultgate/node/{name}", enrolled
        assert node.whoami()["name"] == name
        status, _ = node.call(f"{node.API}/nodes/enrollments/by-token", "POST",
                              {"token": issued["token"],
                               "csr": node.csr(node.NODE_DIR / "node.key")})  # fmt: skip
        assert status == 403, f"the token a second time: {status}"
        print("ok  enrolled with carol's enrollment token, which works once")
        status, spare = node.call(f"{node.API}/admin/nodes/tokens", "POST",
                                  {"name": f"{name}-2"}, token=carol)  # fmt: skip
        assert status == 201, spare
        status, _ = node.call(f"{node.API}/admin/nodes/tokens/{spare['id']}/revoke", "POST",
                              token=carol)  # fmt: skip
        assert status == 204, status
        status, _ = node.call(f"{node.API}/nodes/enrollments/by-token", "POST",
                              {"token": spare["token"],
                               "csr": node.csr(node.NODE_DIR / "node.key")})  # fmt: skip
        assert status == 403, f"a revoked token: {status}"
        print("ok  a revoked token enrolls nothing")
        node.call(f"{node.API}/admin/nodes/{enrolled['node_id']}/revoke", "POST", token=carol)


def by_client(keycloak: str, name: str, carol: str) -> None:
    """First trust by a Keycloak client: the node's client, made by Keycloak's admin (the
    local bootstrap admin), with the node's certificate; a token by private_key_jwt."""
    node.KEYCLOAK = kc_admin.KEYCLOAK = keycloak
    with tempfile.TemporaryDirectory() as directory:
        node.NODE_DIR = Path(directory)
        node.credential()
        kc_admin.create(name, str(node.NODE_DIR / "keycloak.crt"))
        try:
            issued = node.enroll_client(name)
            assert issued["identity"] == f"spiffe://nodes.vaultgate/node/{name}", issued
            assert node.whoami()["name"] == name
            status, answer = node.call(f"{node.API}/nodes/enrollments/by-client", "POST",
                                        {"csr": node.csr(node.NODE_DIR / "node.key")},
                                        token=node.client_token(name))  # fmt: skip
            assert status == 409, f"the client a second time: {status} {answer}"
            print("ok  enrolled by its Keycloak client, which enrolls no second node")
            status, _ = node.call(f"{node.API}/me", token=node.client_token(name))
            assert status == 401, f"a node client's token on a user route: {status}"
            print("ok  a node client's token opens no user route")
            status, _ = node.call(f"{node.API}/nodes/enrollments/by-client", "POST",
                                  {"csr": node.csr(node.NODE_DIR / "node.key")},
                                  token=carol)  # fmt: skip
            assert status == 401, f"a user's token for a node client's: {status}"
            print("ok  a user's token isn't a node client's")
            node.call(f"{node.API}/admin/nodes/{issued['node_id']}/revoke", "POST", token=carol)
        finally:
            kc_admin.delete(name)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except node.Failure as e:
        print(f"FAIL {e}", file=sys.stderr)
        sys.exit(1)

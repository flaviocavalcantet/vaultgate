"""Mutual TLS on the internal port (vaultgate_api.mtls, ADR 0013), over real connections.

A test CA signs the server's certificate and the clients': the gateway's and the
scanner's, each with its identity as a URI. The server is uvicorn as __main__ runs the
internal port, with two routes guarded like the gateway's and the scanner's.
"""

import asyncio
import datetime
import socket
import ssl
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import Depends, FastAPI, Request
from pydantic import SecretStr

from vaultgate_api import internal
from vaultgate_api.config import settings
from vaultgate_api.mtls import (
    ClientIdentityProtocol,
    certificate_uris,
    client_identities,
    client_serial,
)

GATEWAY = "spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway"
SCANNER = "spiffe://vaultgate/ns/vaultgate/sa/vaultgate-scanner"
NOW = datetime.datetime.now(datetime.UTC)


def _pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


class CA:
    def __init__(self, name: str) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(minutes=1))
            .not_valid_after(NOW + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False
            )
            .sign(self.key, hashes.SHA256())
        )

    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def issue(self, tmp_path, name: str, san: x509.GeneralName, usage) -> tuple[str, str]:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(minutes=1))
            .not_valid_after(NOW + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([san]), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        cert_file, key_file = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(_pem(key))
        return str(cert_file), str(key_file)


def client_cert(ca: CA, tmp_path, name: str, uri: str) -> tuple[str, str]:
    return ca.issue(
        tmp_path, name, x509.UniformResourceIdentifier(uri), ExtendedKeyUsageOID.CLIENT_AUTH
    )


app = FastAPI()


@app.get("/gateway", dependencies=[Depends(internal.require_gateway)])
async def gateway_route() -> dict:
    return {}


@app.get("/scanner", dependencies=[Depends(internal.require_scanner)])
async def scanner_route() -> dict:
    return {}


@app.get("/seen")
async def seen_route(request: Request) -> dict:
    """What the protocol put in the scope (the nodes' port reads the serial too)."""
    return {
        "identities": list(client_identities(request.scope)),
        "serial": client_serial(request.scope),
    }


@pytest.fixture
def ca():
    return CA("VaultGate test root")


@pytest.fixture
async def server(tmp_path, ca, monkeypatch):
    ca_file = tmp_path / "ca.crt"
    ca_file.write_bytes(ca.pem())
    cert, key = ca.issue(
        tmp_path, "server", x509.DNSName("localhost"), ExtendedKeyUsageOID.SERVER_AUTH
    )
    monkeypatch.setattr(settings, "internal_client_ca_file", str(ca_file))
    monkeypatch.setattr(settings, "internal_gateway_identity", GATEWAY)
    monkeypatch.setattr(settings, "internal_scanner_identity", SCANNER)
    monkeypatch.setattr(settings, "internal_token", SecretStr("gateway-token"))
    monkeypatch.setattr(settings, "scanner_token", SecretStr("scanner-token"))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # As __main__ configures the internal port.
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_config=None,
        ssl_certfile=cert,
        ssl_keyfile=key,
        ssl_ca_certs=str(ca_file),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        http=ClientIdentityProtocol,
    )
    srv = uvicorn.Server(config)
    task = asyncio.create_task(srv.serve())
    while not srv.started:
        await asyncio.sleep(0.01)
    yield f"https://localhost:{port}", str(ca_file)
    srv.should_exit = True
    await task


async def get(server, path: str, token: str, cert: tuple[str, str] | None) -> int:
    url, ca_file = server
    context = ssl.create_default_context(cafile=ca_file)
    if cert:
        context.load_cert_chain(*cert)
    async with httpx.AsyncClient(verify=context) as client:
        response = await client.get(url + path, headers={"Authorization": f"Bearer {token}"})
    return response.status_code


async def test_each_service_reaches_its_own_routes(server, ca, tmp_path):
    gateway = client_cert(ca, tmp_path, "gateway", GATEWAY)
    scanner = client_cert(ca, tmp_path, "scanner", SCANNER)
    assert await get(server, "/gateway", "gateway-token", gateway) == 200
    assert await get(server, "/scanner", "scanner-token", scanner) == 200


async def test_a_certificate_opens_only_its_identitys_routes(server, ca, tmp_path):
    gateway = client_cert(ca, tmp_path, "gateway", GATEWAY)
    other = client_cert(ca, tmp_path, "other", "spiffe://vaultgate/ns/vaultgate/sa/other")
    # The scanner's token does not help a gateway certificate onto the scanner's routes.
    assert await get(server, "/scanner", "scanner-token", gateway) == 401
    assert await get(server, "/gateway", "gateway-token", other) == 401


async def test_the_token_is_still_required(server, ca, tmp_path):
    gateway = client_cert(ca, tmp_path, "gateway", GATEWAY)
    assert await get(server, "/gateway", "wrong", gateway) == 401
    assert await get(server, "/gateway", "scanner-token", gateway) == 401


async def test_no_connection_without_a_certificate_from_the_ca(server, tmp_path):
    with pytest.raises(httpx.HTTPError):
        await get(server, "/gateway", "gateway-token", None)
    stranger = client_cert(CA("someone else"), tmp_path, "stranger", GATEWAY)
    with pytest.raises(httpx.HTTPError):
        await get(server, "/gateway", "gateway-token", stranger)


async def test_an_unset_identity_refuses_its_routes(server, ca, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "internal_scanner_identity", None)
    scanner = client_cert(ca, tmp_path, "scanner", SCANNER)
    assert await get(server, "/scanner", "scanner-token", scanner) == 401


def test_certificate_uris():
    cert = {"subjectAltName": (("DNS", "a.svc"), ("URI", GATEWAY), ("URI", SCANNER))}
    assert certificate_uris(cert) == (GATEWAY, SCANNER)
    assert certificate_uris({}) == ()
    assert certificate_uris(None) == ()


async def test_the_scope_has_the_certificates_uris_and_serial(server, ca, tmp_path):
    cert_file, key_file = client_cert(ca, tmp_path, "node", "spiffe://nodes.vaultgate/node/n1")
    url, ca_file = server
    context = ssl.create_default_context(cafile=ca_file)
    context.load_cert_chain(cert_file, key_file)
    async with httpx.AsyncClient(verify=context) as client:
        seen = (await client.get(url + "/seen")).json()
    cert = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
    assert seen["identities"] == ["spiffe://nodes.vaultgate/node/n1"]
    assert int(seen["serial"], 16) == cert.serial_number

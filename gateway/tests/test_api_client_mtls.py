"""The gateway's client certificate on the API's internal port (mutual TLS, ADR 0013).

A test CA signs a server certificate and the gateway's; the server wants a client
certificate from that CA and answers with the identities (URIs) in the one it got.
"""

import datetime
import ipaddress
import json
import os
import shutil
import ssl
import tempfile
import uuid

import tornado.web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from tornado.testing import AsyncHTTPSTestCase, gen_test

from vaultgate_gateway.api_client import ApiUnavailable, InternalApi
from vaultgate_gateway.tls import CertificateReloader

NOW = datetime.datetime.now(datetime.UTC)
FIRST = "spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway"
RENEWED = "spiffe://vaultgate/ns/vaultgate/sa/renewed"


class CA:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test root")])
        self.cert = (
            self._builder(self.key, name)
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

    def _builder(self, key, subject) -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject if hasattr(self, "cert") else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(minutes=1))
            .not_valid_after(NOW + datetime.timedelta(days=1))
        )

    def issue(self, san: list[x509.GeneralName], usage) -> tuple[bytes, bytes]:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            self._builder(key, x509.Name([]))
            .add_extension(x509.SubjectAlternativeName(san), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return cert.public_bytes(serialization.Encoding.PEM), key_pem

    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)


class Echo(tornado.web.RequestHandler):
    def post(self, path: str) -> None:
        peer = self.request.connection.stream.socket.getpeercert() or {}
        uris = [v for k, v in peer.get("subjectAltName", ()) if k == "URI"]
        self.write(
            {"file_id": str(uuid.uuid4()), "storage_key": json.dumps(uris), "declared_size": 1}
        )
        self.application.settings["seen"].append(uris)


class ClientCertificateTest(AsyncHTTPSTestCase):
    def setUp(self) -> None:
        self.ca = CA()
        self.seen: list = []
        self.directory = tempfile.mkdtemp()
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()
        shutil.rmtree(self.directory, ignore_errors=True)

    def get_app(self):
        return tornado.web.Application([(r"/internal/(.*)", Echo)], seen=self.seen)

    def get_ssl_options(self):
        cert, key = self.ca.issue(
            [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], ExtendedKeyUsageOID.SERVER_AUTH
        )
        cert_file, key_file = self._write("server", cert, key)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cadata=self.ca.pem().decode())
        context.load_cert_chain(cert_file, key_file)
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def _write(self, name: str, cert: bytes, key: bytes, mtime: int = 1_000_000_000):
        directory = self.directory
        paths = []
        for suffix, data in (("crt", cert), ("key", key)):
            path = os.path.join(directory, f"{name}.{suffix}")
            with open(path, "wb") as f:
                f.write(data)
            os.utime(path, ns=(mtime, mtime))
            paths.append(path)
        return paths

    def _client_context(self, uri: str):
        cert, key = self.ca.issue(
            [x509.UniformResourceIdentifier(uri)], ExtendedKeyUsageOID.CLIENT_AUTH
        )
        cert_file, key_file = self._write("client", cert, key)
        context = ssl.create_default_context(cadata=self.ca.pem().decode())
        context.load_cert_chain(cert_file, key_file)
        return context, cert_file, key_file

    @gen_test
    async def test_the_api_sees_the_gateways_identity(self) -> None:
        context, *_ = self._client_context(FIRST)
        api = InternalApi(self.get_url(""), "secret", ssl_context=context)
        await api.consume_upload("tok", uuid.uuid4(), None)
        assert self.seen == [[FIRST]]

    @gen_test
    async def test_without_a_certificate_the_api_is_unavailable(self) -> None:
        context = ssl.create_default_context(cadata=self.ca.pem().decode())
        api = InternalApi(self.get_url(""), "secret", ssl_context=context)
        try:
            await api.consume_upload("tok", uuid.uuid4(), None)
        except ApiUnavailable:
            pass
        else:
            raise AssertionError("connected without a client certificate")
        assert self.seen == []

    @gen_test
    async def test_a_renewed_certificate_is_used_for_the_next_request(self) -> None:
        context, cert_file, key_file = self._client_context(FIRST)
        reloader = CertificateReloader(cert_file, key_file, [context])
        api = InternalApi(self.get_url(""), "secret", ssl_context=context)
        await api.consume_upload("tok", uuid.uuid4(), None)
        cert, key = self.ca.issue(
            [x509.UniformResourceIdentifier(RENEWED)], ExtendedKeyUsageOID.CLIENT_AUTH
        )
        self._write("client", cert, key, mtime=2_000_000_000)
        assert reloader.check()
        await api.consume_upload("tok", uuid.uuid4(), None)
        assert self.seen == [[FIRST], [RENEWED]]

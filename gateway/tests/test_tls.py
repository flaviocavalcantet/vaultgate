"""A renewed certificate reaches the running server's SSLContext (vaultgate_gateway.tls).

Each check does a real TLS handshake in memory, with a client that trusts one
certificate only: it succeeds only if the server presents that certificate.
"""

import datetime
import os
import socket
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vaultgate_gateway.tls import CertificateReloader, start_metrics_server


def self_signed(name: str) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM), pem_key


def handshake(server: ssl.SSLContext, trusted_cert: bytes) -> bool:
    client = ssl.create_default_context(cadata=trusted_cert.decode())
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    c = client.wrap_bio(c_in, c_out, server_hostname="localhost")
    s = server.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        for side, out, peer_in in ((c, c_out, s_in), (s, s_out, c_in)):
            try:
                side.do_handshake()
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError:
                return False
            peer_in.write(out.read())
        try:
            c.do_handshake()
            return True
        except ssl.SSLWantReadError:
            continue
        except ssl.SSLError:
            return False
    return False


def write(path, data: bytes, mtime: int) -> None:
    path.write_bytes(data)
    os.utime(path, ns=(mtime, mtime))


@pytest.fixture
def pair(tmp_path):
    cert_file, key_file = tmp_path / "tls.crt", tmp_path / "tls.key"
    first = self_signed("first")
    write(cert_file, first[0], 1_000_000_000)
    write(key_file, first[1], 1_000_000_000)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    return cert_file, key_file, context, first


def test_unchanged_files_are_not_reloaded(pair):
    cert_file, key_file, context, first = pair
    reloader = CertificateReloader(str(cert_file), str(key_file), [context])
    assert reloader.check() is False
    assert handshake(context, first[0])


def test_renewed_certificate_is_served(pair):
    cert_file, key_file, context, first = pair
    reloader = CertificateReloader(str(cert_file), str(key_file), [context])
    second = self_signed("second")
    write(cert_file, second[0], 2_000_000_000)
    write(key_file, second[1], 2_000_000_000)

    assert reloader.check() is True
    assert handshake(context, second[0])
    assert not handshake(context, first[0])
    assert reloader.check() is False  # loaded once


def test_mismatched_pair_keeps_the_loaded_certificate(pair, caplog):
    cert_file, key_file, context, first = pair
    reloader = CertificateReloader(str(cert_file), str(key_file), [context])
    second = self_signed("second")
    write(cert_file, second[0], 2_000_000_000)  # the key is still the first one

    assert reloader.check() is False
    assert handshake(context, first[0])
    assert "not reloaded" in caplog.text

    write(key_file, second[1], 3_000_000_000)  # the pair is complete: tried again
    assert reloader.check() is True
    assert handshake(context, second[0])


def test_missing_files_keep_the_loaded_certificate(pair):
    cert_file, key_file, context, first = pair
    reloader = CertificateReloader(str(cert_file), str(key_file), [context])
    cert_file.unlink()
    assert reloader.check() is False
    assert handshake(context, first[0])


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def served_certificate(port: int, trusted_cert: bytes) -> bool:
    """A real TLS connection to the metrics port, trusting one certificate only."""
    client = ssl.create_default_context(cadata=trusted_cert.decode())
    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=5) as sock,
            client.wrap_socket(sock, server_hostname="localhost") as tls,
        ):
            tls.sendall(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
            return tls.recv(12).startswith(b"HTTP/1.0 200")
    except ssl.SSLError:
        return False


def test_metrics_server_without_a_certificate_is_plain_http():
    assert start_metrics_server(free_port(), None, None) is None


def test_metrics_server_speaks_tls_and_renews(pair):
    cert_file, key_file, _, first = pair
    port = free_port()
    context = start_metrics_server(port, str(cert_file), str(key_file))
    reloader = CertificateReloader(str(cert_file), str(key_file), [context])
    assert served_certificate(port, first[0])

    second = self_signed("second")
    write(cert_file, second[0], 2_000_000_000)
    write(key_file, second[1], 2_000_000_000)
    assert reloader.check() is True
    assert served_certificate(port, second[0])
    assert not served_certificate(port, first[0])

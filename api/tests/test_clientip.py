import ipaddress
import json
import logging

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from vaultgate_api.clientip import ClientAddressMiddleware, parse_ip, parse_networks, resolve
from vaultgate_api.logs import RequestContextMiddleware

PROXIES = parse_networks("10.0.0.0/8, 2001:db8:ffff::/48")


@pytest.mark.parametrize(
    ("peer", "forwarded", "expected"),
    [
        # Direct connection: the header is the client's own claim and is ignored.
        ("203.0.113.7", ["198.51.100.1"], "203.0.113.7"),
        ("203.0.113.7", [], "203.0.113.7"),
        # One trusted proxy in front: the address it appended is the client.
        ("10.0.0.2", ["198.51.100.1"], "198.51.100.1"),
        # A client-supplied prefix is skipped: only the hop the proxy added counts.
        ("10.0.0.2", ["6.6.6.6, 198.51.100.1"], "198.51.100.1"),
        # Chains of trusted proxies are walked from the right.
        ("10.0.0.2", ["6.6.6.6, 198.51.100.1, 10.0.0.9"], "198.51.100.1"),
        # Several header lines are one list, in order.
        ("10.0.0.2", ["6.6.6.6", "198.51.100.1, 10.1.1.1"], "198.51.100.1"),
        # A trusted proxy with no header: the proxy is the client.
        ("10.0.0.2", [], "10.0.0.2"),
        # Only trusted hops: as far as the chain goes.
        ("10.0.0.2", ["10.0.0.3, 10.0.0.4"], "10.0.0.3"),
        # Ports and brackets some proxies add.
        ("10.0.0.2", ["198.51.100.1:52311"], "198.51.100.1"),
        ("10.0.0.2", ["[2001:db8::7]:443"], "2001:db8::7"),
        ("10.0.0.2", ["2001:db8::7"], "2001:db8::7"),
        # IPv6 proxies and IPv4-mapped peers.
        ("2001:db8:ffff::1", ["198.51.100.1"], "198.51.100.1"),
        ("::ffff:10.0.0.2", ["198.51.100.1"], "198.51.100.1"),
        ("::ffff:203.0.113.7", [], "203.0.113.7"),
        # Garbage the trusted proxy passed on: unknown, never the proxy's address.
        ("10.0.0.2", ["not-an-ip"], None),
        ("10.0.0.2", ["198.51.100.1,,10.0.0.3"], None),  # empty hop behind a trusted one
        ("10.0.0.2", [", 10.0.0.3"], None),
        # Garbage left of the client is never reached.
        ("10.0.0.2", ["junk, 198.51.100.1"], "198.51.100.1"),
        # No usable peer.
        (None, ["198.51.100.1"], None),
        ("testclient", [], None),
    ],
)
def test_resolve(peer, forwarded, expected) -> None:
    assert resolve(peer, forwarded, PROXIES) == expected


def test_nothing_is_trusted_by_default() -> None:
    assert resolve("127.0.0.1", ["198.51.100.1"], []) == "127.0.0.1"
    assert resolve("10.0.0.2", ["198.51.100.1"], []) == "10.0.0.2"


def test_parse_networks() -> None:
    assert parse_networks("") == []
    assert parse_networks(" 10.0.0.0/8 ,, 192.0.2.10 ") == [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("192.0.2.10/32"),
    ]
    assert parse_networks(["::1"]) == [ipaddress.ip_network("::1/128")]
    with pytest.raises(ValueError):
        parse_networks("10.0.0.1/8")


def test_parse_ip_unwraps_ipv4_mapped() -> None:
    assert parse_ip("::ffff:192.0.2.1") == ipaddress.IPv4Address("192.0.2.1")


def _app() -> FastAPI:
    app = FastAPI()

    @app.get("/whoami")
    async def whoami(request: Request) -> dict:
        return {"client": request.client.host if request.client else None}

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(ClientAddressMiddleware, trusted=PROXIES)
    return app


def test_middleware_rewrites_the_client_for_handlers_and_logs(caplog) -> None:
    client = TestClient(_app(), client=("10.0.0.2", 40000))
    with caplog.at_level(logging.INFO, logger="vaultgate.access"):
        response = client.get("/whoami", headers={"X-Forwarded-For": "6.6.6.6, 198.51.100.1"})
    assert response.json() == {"client": "198.51.100.1"}
    [record] = [r for r in caplog.records if r.name == "vaultgate.access"]
    assert record.client_ip == "198.51.100.1"


def test_middleware_ignores_the_header_from_untrusted_peers() -> None:
    client = TestClient(_app(), client=("203.0.113.7", 40000))
    response = client.get("/whoami", headers={"X-Forwarded-For": "10.0.0.5"})
    assert response.json() == {"client": "203.0.113.7"}


def test_middleware_leaves_the_client_unknown_when_it_cannot_tell() -> None:
    client = TestClient(_app(), client=("10.0.0.2", 40000))
    response = client.get("/whoami", headers={"X-Forwarded-For": "bogus"})
    assert json.loads(response.text) == {"client": None}

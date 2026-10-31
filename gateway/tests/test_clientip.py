import logging

import pytest
from tornado.testing import AsyncHTTPTestCase

from vaultgate_gateway.app import make_app
from vaultgate_gateway.clientip import parse_networks, resolve

PROXIES = parse_networks("10.0.0.0/8, 2001:db8:ffff::/48")


# The same rules as the API (api/tests/test_clientip.py has the full table).
@pytest.mark.parametrize(
    ("peer", "forwarded", "expected"),
    [
        ("203.0.113.7", ["198.51.100.1"], "203.0.113.7"),
        ("10.0.0.2", ["6.6.6.6, 198.51.100.1"], "198.51.100.1"),
        ("10.0.0.2", ["6.6.6.6", "198.51.100.1, 10.1.1.1"], "198.51.100.1"),
        ("10.0.0.2", [], "10.0.0.2"),
        ("10.0.0.2", ["[2001:db8::7]:443"], "2001:db8::7"),
        ("::ffff:10.0.0.2", ["198.51.100.1:52311"], "198.51.100.1"),
        ("10.0.0.2", ["not-an-ip"], None),
        ("10.0.0.2", ["junk, 198.51.100.1"], "198.51.100.1"),
        (None, [], None),
    ],
)
def test_resolve(peer, forwarded, expected) -> None:
    assert resolve(peer, forwarded, PROXIES) == expected


class AccessLogCase(AsyncHTTPTestCase):
    """The access log records the resolved client; the test client connects from
    127.0.0.1. No tests of its own."""

    trusted = ""

    @pytest.fixture(autouse=True)
    def _caplog(self, caplog: pytest.LogCaptureFixture) -> None:
        self.caplog = caplog

    def get_app(self):
        return make_app(None, tuple(parse_networks(self.trusted)))

    def logged_client(self, headers: dict) -> str | None:
        with self.caplog.at_level(logging.INFO, logger="vaultgate.access"):
            assert self.fetch("/healthz", headers=headers).code == 200
        [record] = [r for r in self.caplog.records if r.name == "vaultgate.access"]
        return record.client_ip


class DirectAccessLogTest(AccessLogCase):
    def test_header_from_an_untrusted_peer_is_ignored(self) -> None:
        assert self.logged_client({"X-Forwarded-For": "198.51.100.1"}) == "127.0.0.1"


class TrustedProxyAccessLogTest(AccessLogCase):
    trusted = "127.0.0.0/8"

    def test_header_from_a_trusted_proxy_names_the_client(self) -> None:
        headers = {"X-Forwarded-For": "6.6.6.6, 198.51.100.1"}
        assert self.logged_client(headers) == "198.51.100.1"

    def test_unparseable_header_leaves_the_client_unknown(self) -> None:
        assert self.logged_client({"X-Forwarded-For": "bogus"}) is None

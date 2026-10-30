import logging

import pytest
from tornado.testing import AsyncHTTPTestCase

from vaultgate_gateway.app import make_app
from vaultgate_gateway.logs import resolve_request_id


class AccessLogTest(AsyncHTTPTestCase):
    def get_app(self):
        return make_app()

    @pytest.fixture(autouse=True)
    def _caplog(self, caplog: pytest.LogCaptureFixture) -> None:
        self.caplog = caplog

    def _access_records(self) -> list[logging.LogRecord]:
        return [r for r in self.caplog.records if r.name == "vaultgate.access"]

    def test_generates_request_id_when_missing(self) -> None:
        response = self.fetch("/healthz")
        assert len(response.headers["X-Request-ID"]) == 32

    def test_unknown_route_is_still_logged(self) -> None:
        with self.caplog.at_level(logging.INFO, logger="vaultgate.access"):
            self.fetch("/nope")
        [record] = self._access_records()
        assert record.status == 404


def test_rejects_unsafe_request_ids() -> None:
    for bad in ["", "a" * 65, "line\nbreak", '"}{"']:
        assert resolve_request_id(bad) != bad

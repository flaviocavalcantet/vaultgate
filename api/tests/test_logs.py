import json
import logging

import pytest
from fastapi.testclient import TestClient

from vaultgate_api.logs import JsonFormatter, request_id_var, resolve_request_id
from vaultgate_api.main import app


def _access_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "vaultgate.access"]


def test_generates_request_id_and_logs_access(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="vaultgate.access"):
        response = TestClient(app).get("/healthz?token=secret")

    request_id = response.headers["x-request-id"]
    assert len(request_id) == 32
    [record] = _access_records(caplog)
    assert record.method == "GET"
    assert record.path == "/healthz"  # query string is never logged
    assert record.status == 200
    assert record.duration_ms >= 0
    assert "secret" not in JsonFormatter("api").format(record)


def test_propagates_valid_incoming_request_id() -> None:
    response = TestClient(app).get("/healthz", headers={"X-Request-ID": "abc-123.x_y"})
    assert response.headers["x-request-id"] == "abc-123.x_y"


@pytest.mark.parametrize("bad", ["", "a" * 65, 'x"}, "level": "fake', "line\nbreak", "sp ace"])
def test_rejects_unsafe_request_ids(bad: str) -> None:
    resolved = resolve_request_id(bad)
    assert resolved != bad
    assert len(resolved) == 32


def test_json_formatter_shape() -> None:
    record = logging.makeLogRecord(
        {"name": "vaultgate.test", "levelname": "WARNING", "msg": "hello %s", "args": ("world",)}
    )
    record.user_id = "u-1"
    token = request_id_var.set("req-1")
    try:
        entry = json.loads(JsonFormatter("api").format(record))
    finally:
        request_id_var.reset(token)

    assert entry["level"] == "warning"
    assert entry["service"] == "api"
    assert entry["logger"] == "vaultgate.test"
    assert entry["msg"] == "hello world"
    assert entry["request_id"] == "req-1"
    assert entry["user_id"] == "u-1"
    assert entry["ts"].endswith("+00:00")


def test_json_formatter_includes_exceptions() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "failed", None, None)
        import sys

        record.exc_info = sys.exc_info()
    entry = json.loads(JsonFormatter("api").format(record))
    assert "ValueError: boom" in entry["exc"]

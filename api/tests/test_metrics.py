from fastapi.testclient import TestClient
from prometheus_client import REGISTRY, generate_latest

from vaultgate_api.main import app
from vaultgate_api.metrics import UNMATCHED_ROUTE


def _requests(method: str, route: str, status: str) -> float:
    value = REGISTRY.get_sample_value(
        "vaultgate_http_requests_total", {"method": method, "route": route, "status": status}
    )
    return value or 0.0


def _duration_count(method: str, route: str) -> float:
    value = REGISTRY.get_sample_value(
        "vaultgate_http_request_duration_seconds_count", {"method": method, "route": route}
    )
    return value or 0.0


def test_counts_requests_by_route_template() -> None:
    before = _requests("GET", "/healthz", "200")
    durations_before = _duration_count("GET", "/healthz")

    TestClient(app).get("/healthz")

    assert _requests("GET", "/healthz", "200") == before + 1
    assert _duration_count("GET", "/healthz") == durations_before + 1
    assert REGISTRY.get_sample_value("vaultgate_http_requests_in_progress") == 0


def test_unknown_paths_share_one_label() -> None:
    """Raw paths never become labels, so scanners probing URLs can't explode cardinality."""
    before = _requests("GET", UNMATCHED_ROUTE, "404")
    client = TestClient(app)
    for path in ("/wp-admin", "/.env", "/does/not/exist"):
        assert client.get(path).status_code == 404

    assert _requests("GET", UNMATCHED_ROUTE, "404") == before + 3
    exposition = generate_latest(REGISTRY).decode()
    assert "wp-admin" not in exposition
    assert ".env" not in exposition


def test_metrics_are_not_served_on_the_api_port() -> None:
    assert TestClient(app).get("/metrics").status_code == 404


def test_build_info() -> None:
    assert (
        REGISTRY.get_sample_value(
            "vaultgate_build_info", {"service": "api", "version": app.version}
        )
        == 1
    )

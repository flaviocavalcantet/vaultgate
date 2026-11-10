"""Cross-origin requests (vaultgate_api.cors, M12.5): an exact allow-list of origins,
none by default, which grants a page the right to read answers and nothing else."""

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from vaultgate_api.config import Settings
from vaultgate_api.cors import install_cors, parse_origins
from vaultgate_api.headers import SecurityHeadersMiddleware
from vaultgate_api.main import app

FRONTEND = "https://vault.example.test"
OTHER = "https://evil.example.test"


def client(origins: list[str]) -> TestClient:
    """A small API shaped like the real one: a route that wants a token, CORS for
    `origins`, and the security headers around everything."""

    def token_required() -> None:
        raise HTTPException(401, headers={"WWW-Authenticate": "Bearer"})

    api = FastAPI()
    api.add_api_route("/me", lambda: {"ok": True}, dependencies=[Depends(token_required)])
    api.add_api_route("/open", lambda: {"ok": True})
    install_cors(api, origins)
    api.add_middleware(SecurityHeadersMiddleware)
    return TestClient(api)


def preflight(origin: str, method: str = "GET", headers: str = "authorization") -> dict:
    return {
        "Origin": origin,
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": headers,
    }


def test_an_allowed_origin_passes_the_preflight_without_a_token() -> None:
    response = client([FRONTEND]).options("/me", headers=preflight(FRONTEND, "POST"))
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FRONTEND
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "authorization" in response.headers["access-control-allow-headers"].lower()
    assert response.headers["access-control-max-age"] == "600"
    assert "access-control-allow-credentials" not in response.headers


def test_an_allowed_origin_may_read_answers_and_errors() -> None:
    api = client([FRONTEND])
    ok = api.get("/open", headers={"Origin": FRONTEND})
    assert ok.headers["access-control-allow-origin"] == FRONTEND
    assert "Retry-After" in ok.headers["access-control-expose-headers"]
    assert "origin" in ok.headers["vary"].lower()
    # Still 401 without a token: the list lets the page read the refusal, no more.
    refused = api.get("/me", headers={"Origin": FRONTEND})
    assert refused.status_code == 401
    assert refused.headers["access-control-allow-origin"] == FRONTEND
    # And the security headers are still on both.
    assert refused.headers["x-content-type-options"] == "nosniff"


def test_another_origin_is_not_named() -> None:
    api = client([FRONTEND])
    response = api.get("/open", headers={"Origin": OTHER})
    assert "access-control-allow-origin" not in response.headers
    refused = api.options("/open", headers=preflight(OTHER))
    assert refused.status_code == 400
    assert "access-control-allow-origin" not in refused.headers


def test_a_method_or_header_off_the_list_fails_the_preflight() -> None:
    api = client([FRONTEND])
    assert api.options("/open", headers=preflight(FRONTEND, "PATCH")).status_code == 400
    assert api.options("/open", headers=preflight(FRONTEND, "GET", "x-evil")).status_code == 400


def test_without_origins_nothing_changes() -> None:
    # The default, and the real app in these tests: no origin is named, and a
    # preflight is an ordinary request to a route that has no OPTIONS.
    response = TestClient(app).get("/healthz", headers={"Origin": FRONTEND})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert TestClient(app).options("/healthz", headers=preflight(FRONTEND)).status_code == 405
    assert "access-control-allow-origin" not in client([]).get("/open").headers


def test_origins_setting() -> None:
    assert parse_origins("") == []
    assert parse_origins(" https://a.example.test , http://localhost:5173 ,") == [
        "https://a.example.test",
        "http://localhost:5173",
    ]
    settings = Settings(cors_origins="https://a.example.test,http://localhost:5173")
    assert settings.cors_origins == ["https://a.example.test", "http://localhost:5173"]
    assert Settings().cors_origins == []


@pytest.mark.parametrize(
    "bad",
    [
        "*",
        "https://*.example.test",
        "https://a.example.test/",
        "https://a.example.test/app",
        "a.example.test",
        "ftp://a.example.test",
        "https://user@a.example.test",
        "HTTPS://A.example.test",
        "null",
    ],
)
def test_what_is_not_an_origin_is_refused_at_start(bad: str) -> None:
    with pytest.raises(ValueError, match="not an origin"):
        parse_origins(bad)
    with pytest.raises(ValueError):
        Settings(cors_origins=bad)

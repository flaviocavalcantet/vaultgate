"""Security headers (vaultgate_api.headers) and the servers' TLS settings (M10)."""

import ssl

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from tests.test_tls import self_signed
from vaultgate_api import __main__ as entry
from vaultgate_api.config import settings
from vaultgate_api.headers import SecurityHeadersMiddleware
from vaultgate_api.main import app


def test_every_response_gets_the_headers() -> None:
    for response in (
        TestClient(app).get("/healthz"),
        TestClient(app).get("/no-such-route"),  # errors too
        TestClient(app).get("/me"),  # 401
    ):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cross-origin-resource-policy"] == "same-origin"
        assert response.headers["content-security-policy"] == (
            "default-src 'none'; frame-ancestors 'none'"
        )
        assert response.headers["cache-control"] == "no-store"
        assert "strict-transport-security" not in response.headers  # plain HTTP here
        assert "server" not in response.headers


def test_an_unhandled_error_gets_them_too() -> None:
    async def fails() -> None:
        raise RuntimeError("boom")

    app.add_api_route("/test-fails", fails)
    try:
        response = TestClient(app, raise_server_exceptions=False).get("/test-fails")
    finally:
        app.router.routes = [
            r for r in app.router.routes if getattr(r, "path", None) != "/test-fails"
        ]
    assert response.status_code == 500
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert response.headers["cache-control"] == "no-store"


def test_https_gets_hsts() -> None:
    response = TestClient(app, base_url="https://testserver").get("/healthz")
    assert response.headers["strict-transport-security"] == "max-age=63072000"


def test_the_docs_load_their_scripts() -> None:
    response = TestClient(app).get("/docs")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"


def test_a_response_keeps_its_own_cache_control() -> None:
    small = FastAPI()
    small.add_middleware(SecurityHeadersMiddleware)

    @small.get("/cached")
    async def cached() -> JSONResponse:
        return JSONResponse({}, headers={"Cache-Control": "max-age=60"})

    response = TestClient(small).get("/cached")
    assert response.headers["cache-control"] == "max-age=60"


def test_servers_speak_tls_13_only_and_name_no_server(tmp_path, monkeypatch) -> None:
    cert, key = self_signed("api")
    (tmp_path / "tls.crt").write_bytes(cert)
    (tmp_path / "tls.key").write_bytes(key)
    monkeypatch.setattr(settings, "tls_cert_file", str(tmp_path / "tls.crt"))
    monkeypatch.setattr(settings, "tls_key_file", str(tmp_path / "tls.key"))
    server = entry._server("vaultgate_api.main:app", 0)
    assert server.config.ssl.minimum_version == ssl.TLSVersion.TLSv1_3
    assert server.config.server_header is False


def test_the_documentation_can_be_turned_off(monkeypatch) -> None:
    from vaultgate_api.main import docs_urls

    assert docs_urls() == {
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json",
    }
    monkeypatch.setattr(settings, "docs_enabled", False)
    assert docs_urls() == {"docs_url": None, "redoc_url": None, "openapi_url": None}

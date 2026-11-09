"""The nodes' CA, published (vaultgate_api.routers.pki, M11): its certificate, revocation
lists and OCSP, from OpenBao, without a token."""

import asyncio
import base64
from urllib.parse import quote

import httpx
import pytest
from fastapi.testclient import TestClient

from vaultgate_api import ratelimit
from vaultgate_api.config import settings
from vaultgate_api.main import app
from vaultgate_api.routers import pki

OPENBAO = "https://openbao.test:8200"


@pytest.fixture
def openbao(monkeypatch):
    """A fake OpenBao: answers[path] = (status, content type, body); records requests."""
    answers: dict[str, tuple[int, str, bytes]] = {}
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        await asyncio.sleep(0.01)  # as a real round trip: concurrent requests overlap
        if request.url.host == "down.test":
            raise httpx.ConnectError("refused", request=request)
        code, ctype, body = answers.get(request.url.path, (404, "application/json", b"{}"))
        return httpx.Response(code, content=body, headers={"content-type": ctype})

    monkeypatch.setattr(settings, "openbao_address", OPENBAO)
    monkeypatch.setattr(settings, "nodes_pki_mount", "pki-nodes")
    monkeypatch.setattr(
        app.state,
        "openbao",
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        raising=False,
    )
    pki.reset()
    yield answers, seen
    pki.reset()


def test_the_ca_and_the_lists_without_a_token(openbao) -> None:
    answers, seen = openbao
    answers["/v1/pki-nodes/ca"] = (200, "application/pkix-cert", b"DER-CA")
    answers["/v1/pki-nodes/ca/pem"] = (200, "application/pem-file", b"-----BEGIN")
    answers["/v1/pki-nodes/crl"] = (200, "application/pkix-crl", b"DER-CRL")
    answers["/v1/pki-nodes/crl/delta"] = (200, "application/pkix-crl", b"DER-DELTA")
    client = TestClient(app)
    for path, body, ctype in [
        ("/pki/nodes/ca", b"DER-CA", "application/pkix-cert"),
        ("/pki/nodes/ca/pem", b"-----BEGIN", "application/x-pem-file"),
        ("/pki/nodes/crl", b"DER-CRL", "application/pkix-crl"),
        ("/pki/nodes/crl/delta", b"DER-DELTA", "application/pkix-crl"),
    ]:
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.content == body
        assert response.headers["content-type"] == ctype
        assert response.headers["cache-control"] == "max-age=60"
    assert {r.url.path for r in seen} == {
        "/v1/pki-nodes/ca", "/v1/pki-nodes/ca/pem", "/v1/pki-nodes/crl", "/v1/pki-nodes/crl/delta"
    }  # fmt: skip


def test_the_lists_are_cached_for_a_minute(openbao, monkeypatch) -> None:
    answers, seen = openbao
    answers["/v1/pki-nodes/crl"] = (200, "application/pkix-crl", b"one")
    now = [1000.0]
    monkeypatch.setattr(pki, "monotonic", lambda: now[0])
    client = TestClient(app)
    assert client.get("/pki/nodes/crl").content == b"one"
    answers["/v1/pki-nodes/crl"] = (200, "application/pkix-crl", b"two")
    now[0] += 59
    assert client.get("/pki/nodes/crl").content == b"one"
    now[0] += 2
    assert client.get("/pki/nodes/crl").content == b"two"
    assert len(seen) == 2


def test_ocsp_passes_through(openbao) -> None:
    answers, seen = openbao
    answers["/v1/pki-nodes/ocsp"] = (200, "application/ocsp-response", b"SIGNED")
    response = TestClient(app).post(
        "/pki/nodes/ocsp", content=b"REQUEST", headers={"content-type": "application/ocsp-request"}
    )
    assert response.status_code == 200
    assert response.content == b"SIGNED"
    assert response.headers["content-type"] == "application/ocsp-response"
    assert response.headers["cache-control"] == "no-store"  # a revocation shows at once
    assert seen[0].method == "POST"
    assert seen[0].content == b"REQUEST"
    assert seen[0].headers["content-type"] == "application/ocsp-request"


def test_ocsp_errors_are_ocsp_responses(openbao) -> None:
    answers, _ = openbao
    answers["/v1/pki-nodes/ocsp"] = (400, "application/ocsp-response", b"MALFORMED")
    response = TestClient(app).post("/pki/nodes/ocsp", content=b"junk")
    assert response.status_code == 400
    assert response.content == b"MALFORMED"


def test_a_large_ocsp_request_is_refused(openbao) -> None:
    _, seen = openbao
    response = TestClient(app).post("/pki/nodes/ocsp", content=b"x" * (pki.MAX_OCSP_REQUEST + 1))
    assert response.status_code == 413
    assert seen == []


@pytest.mark.parametrize("path", ["/pki/nodes/ca", "/pki/nodes/crl"])
def test_openbao_failing_is_503(openbao, monkeypatch, path) -> None:
    answers, _ = openbao
    answers["/v1/pki-nodes/ca"] = (500, "application/json", b'{"errors":[]}')
    answers["/v1/pki-nodes/crl"] = (500, "application/json", b'{"errors":[]}')
    assert TestClient(app).get(path).status_code == 503
    monkeypatch.setattr(settings, "openbao_address", "https://down.test:8200")
    assert TestClient(app).get(path).status_code == 503


def test_an_ocsp_answer_that_is_not_ocsp_is_503(openbao) -> None:
    answers, _ = openbao
    answers["/v1/pki-nodes/ocsp"] = (500, "application/json", b'{"errors":["sealed"]}')
    assert TestClient(app).post("/pki/nodes/ocsp", content=b"REQUEST").status_code == 503


def test_without_openbao_the_routes_are_404(monkeypatch) -> None:
    monkeypatch.setattr(settings, "openbao_address", None)
    client = TestClient(app)
    for path in ["/pki/nodes/ca", "/pki/nodes/crl", "/pki/nodes/crl/delta"]:
        assert client.get(path).status_code == 404
    assert client.post("/pki/nodes/ocsp", content=b"REQUEST").status_code == 404


def test_limited_per_address(openbao, monkeypatch) -> None:
    answers, _ = openbao
    answers["/v1/pki-nodes/ocsp"] = (200, "application/ocsp-response", b"SIGNED")
    monkeypatch.setattr(settings, "rate_limit_pki_per_minute", 3)
    ratelimit.reset()
    client = TestClient(app)
    codes = [client.post("/pki/nodes/ocsp", content=b"R").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_ocsp_get_form(openbao) -> None:
    """RFC 6960 appendix A: the request base64 and URL-encoded in the path; a "/" in
    the base64 arrives as %2F and must not split it."""
    answers, seen = openbao
    answers["/v1/pki-nodes/ocsp"] = (200, "application/ocsp-response", b"SIGNED")
    der = bytes(range(250, 256)) * 3  # base64 with "/" and "+"
    encoded = quote(base64.b64encode(der).decode(), safe="")
    assert "%2F" in encoded and "%2B" in encoded
    response = TestClient(app).get(f"/pki/nodes/ocsp/{encoded}")
    assert response.status_code == 200
    assert response.content == b"SIGNED"
    assert seen[0].method == "POST" and seen[0].content == der


def test_ocsp_get_form_refuses_junk_and_size(openbao) -> None:
    _, seen = openbao
    client = TestClient(app)
    assert client.get("/pki/nodes/ocsp/not*base64").status_code == 400
    big = quote(base64.b64encode(b"x" * (pki.MAX_OCSP_REQUEST + 1)).decode(), safe="")
    assert client.get(f"/pki/nodes/ocsp/{big}").status_code == 413
    assert seen == []


async def test_concurrent_misses_fetch_once(openbao) -> None:
    answers, seen = openbao
    answers["/v1/pki-nodes/crl"] = (200, "application/pkix-crl", b"CRL")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        responses = await asyncio.gather(*(client.get("/pki/nodes/crl") for _ in range(10)))
    assert [r.content for r in responses] == [b"CRL"] * 10
    assert len(seen) == 1

"""Cross-origin requests (vaultgate_gateway.cors, M12.5): an exact allow-list of
origins, none by default; a preflight spends no intent and holds no transfer slot."""

import pytest

from tests.test_app import BUCKET, GatewayCase, MiB
from vaultgate_gateway.app import Services, make_app
from vaultgate_gateway.cors import parse_origins

FRONTEND = "https://vault.example.test"
OTHER = "https://evil.example.test"


def preflight(origin: str, method: str) -> dict:
    return {
        "Origin": origin,
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "authorization",
    }


class CorsTest(GatewayCase):
    def get_app(self):
        services = Services(
            api=self.api, keys=self.keys, s3=self.s3, bucket=BUCKET, part_size=5 * MiB
        )
        return make_app(services, cors_origins=frozenset({FRONTEND}))

    def options(self, path: str, origin: str, method: str):
        return self.fetch(path, method="OPTIONS", headers=preflight(origin, method))

    def test_an_allowed_origin_passes_the_upload_preflight_and_spends_nothing(self) -> None:
        file_id = self.api.grant(5)
        response = self.options(f"/uploads/{file_id}", FRONTEND, "PUT")
        assert response.code == 204
        assert response.headers["Access-Control-Allow-Origin"] == FRONTEND
        assert response.headers["Access-Control-Allow-Methods"] == "PUT"
        assert "Authorization" in response.headers["Access-Control-Allow-Headers"]
        assert response.headers["Access-Control-Max-Age"] == "600"
        assert "Access-Control-Allow-Credentials" not in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        # The intent is untouched: the upload that follows still works.
        assert self.api.failed == []
        uploaded = self.put(file_id, b"hello", headers={"Origin": FRONTEND})
        assert uploaded.code == 201
        assert uploaded.headers["Access-Control-Allow-Origin"] == FRONTEND

    def test_the_download_preflight_and_what_the_page_may_read(self) -> None:
        file_id = self.api.grant(5)
        assert self.put(file_id, b"hello").code == 201
        response = self.options(f"/downloads/{file_id}", FRONTEND, "GET")
        assert response.code == 204
        assert response.headers["Access-Control-Allow-Methods"] == "GET"
        token = self.api.grant_download(file_id)
        download = self.fetch(
            f"/downloads/{file_id}",
            headers={"Authorization": f"Bearer {token}", "Origin": FRONTEND},
        )
        assert download.code == 200 and download.body == b"hello"
        assert download.headers["Access-Control-Allow-Origin"] == FRONTEND
        exposed = download.headers["Access-Control-Expose-Headers"]
        assert "Content-Disposition" in exposed and "Repr-Digest" in exposed

    def test_an_error_is_readable_by_the_allowed_origin(self) -> None:
        file_id = self.api.grant(5)
        response = self.put(file_id, b"hello", token=None, headers={"Origin": FRONTEND})
        assert response.code == 401
        assert response.headers["Access-Control-Allow-Origin"] == FRONTEND

    def test_another_origin_is_refused_the_preflight_and_never_named(self) -> None:
        file_id = self.api.grant(5)
        response = self.options(f"/uploads/{file_id}", OTHER, "PUT")
        assert response.code == 405
        assert "Access-Control-Allow-Origin" not in response.headers
        uploaded = self.put(file_id, b"hello", headers={"Origin": OTHER})
        assert uploaded.code == 201  # a token is a token; the browser just can't read this
        assert "Access-Control-Allow-Origin" not in uploaded.headers

    def test_routes_without_cors_have_no_preflight(self) -> None:
        assert self.options("/healthz", FRONTEND, "GET").code == 405
        assert self.options("/no-such-route", FRONTEND, "GET").code == 404


class NoCorsTest(GatewayCase):
    """The default: no origins, so no preflight and no origin named."""

    def test_nothing_is_allowed(self) -> None:
        file_id = self.api.grant(5)
        response = self.fetch(
            f"/uploads/{file_id}", method="OPTIONS", headers=preflight(FRONTEND, "PUT")
        )
        assert response.code == 405
        uploaded = self.put(file_id, b"hello", headers={"Origin": FRONTEND})
        assert uploaded.code == 201
        assert "Access-Control-Allow-Origin" not in uploaded.headers


def test_origins_setting() -> None:
    assert parse_origins("") == frozenset()
    assert parse_origins(" https://a.example.test , http://localhost:5173 ,") == {
        "https://a.example.test",
        "http://localhost:5173",
    }


@pytest.mark.parametrize(
    "bad",
    [
        "*",
        "https://*.example.test",
        "https://a.example.test/",
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

"""Downloads a browser can follow (M12.5, ADR 0018): the intent token as an HTML form
field, POSTed to /downloads/{file_id}, so the browser's own downloader takes the file.
The token is never in the address, and the form's body is capped before it is read."""

import os
import urllib.parse
import uuid

import pytest

from tests.test_app import GatewayCase, MiB
from vaultgate_gateway.app import FORM_MAX_BYTES, form_token

FORM = {"Content-Type": "application/x-www-form-urlencoded"}


class FormDownloadTest(GatewayCase):
    def upload(self, payload: bytes) -> uuid.UUID:
        file_id = self.api.grant(len(payload))
        assert self.put(file_id, payload).code == 201
        return file_id

    def post_form(self, file_id, body: bytes | str, headers: dict | None = None, **kwargs):
        if isinstance(body, str):
            body = body.encode()
        return self.fetch(
            f"/downloads/{file_id}", method="POST", body=body, headers=headers or FORM, **kwargs
        )

    def test_a_form_downloads_the_file_as_an_attachment(self) -> None:
        payload = os.urandom(2 * MiB + 77)
        file_id = self.upload(payload)
        token = self.api.grant_download(file_id)
        response = self.post_form(file_id, urllib.parse.urlencode({"token": token}))
        assert response.code == 200
        assert response.body == payload
        assert response.headers["Content-Disposition"].startswith("attachment;")
        assert response.headers["Content-Security-Policy"] == "sandbox; default-src 'none'"
        assert response.headers["Cache-Control"] == "no-store"

    def test_the_form_token_is_single_use(self) -> None:
        file_id = self.upload(b"hello")
        body = urllib.parse.urlencode({"token": self.api.grant_download(file_id)})
        assert self.post_form(file_id, body).code == 200
        assert self.post_form(file_id, body).code == 403

    def test_a_token_in_the_address_is_not_accepted(self) -> None:
        file_id = self.upload(b"hello")
        token = self.api.grant_download(file_id)
        assert self.fetch(f"/downloads/{file_id}").code == 401
        response = self.fetch(f"/downloads/{file_id}?token={token}")
        assert response.code == 401
        assert token in self.api.download_grants  # not spent

    def test_a_form_that_is_not_just_a_token_is_refused_and_spends_nothing(self) -> None:
        file_id = self.upload(b"hello")
        token = self.api.grant_download(file_id)
        for body in (
            "",
            "token=",
            f"token={token}&token={token}",
            f"token={token}&next=/x",
            "tokn=abc",
            "%ff",
        ):
            assert self.post_form(file_id, body).code == 401, body
        assert token in self.api.download_grants

    def test_another_content_type_is_refused(self) -> None:
        file_id = self.upload(b"hello")
        token = self.api.grant_download(file_id)
        for content_type in ("application/json", "multipart/form-data; boundary=x", "text/plain"):
            response = self.post_form(file_id, f"token={token}", {"Content-Type": content_type})
            assert response.code == 415, content_type
        assert token in self.api.download_grants

    def test_a_large_body_is_refused_before_it_is_read(self) -> None:
        file_id = self.upload(b"hello")
        token = self.api.grant_download(file_id)
        body = f"token={token}&pad=" + "x" * (FORM_MAX_BYTES + 1)
        response = self.post_form(file_id, body, raise_error=False)
        assert response.code in (400, 413)
        assert token in self.api.download_grants

    def test_an_unknown_file_is_404(self) -> None:
        assert self.post_form("not-a-uuid", "token=x").code == 404
        assert self.post_form(uuid.uuid4(), "token=x").code == 403


@pytest.mark.parametrize(
    ("body", "token"),
    [
        (b"token=abc", "abc"),
        (b"token=a%2Bb%3D", "a+b="),
        (b"", None),
        (b"token=", None),
        (b"token=a&token=b", None),
        (b"token=a&x=1", None),
        (b"x=1", None),
        (b"\xff", None),
        (b"token", None),
    ],
)
def test_form_token(body: bytes, token: str | None) -> None:
    assert form_token(body) == token

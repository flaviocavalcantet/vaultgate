import base64
import json
import uuid

import tornado.web
from tornado.testing import AsyncHTTPTestCase, gen_test

from vaultgate_gateway.api_client import ApiUnavailable, IntentRefused, InternalApi

SECRET = "internal-secret"


class FakeInternal(tornado.web.RequestHandler):
    def post(self, path: str) -> None:
        self.application.settings["calls"].append(
            (path, self.request.headers.get("Authorization"), json.loads(self.request.body))
        )
        self.application.settings.setdefault("headers", []).append(self.request.headers.copy())
        status = self.application.settings["status"]
        self.set_status(status)
        if status == 200 and path == "intents/consume":
            body = json.loads(self.request.body)
            grant = {
                "file_id": body["file_id"],
                "storage_key": f"files/{body['file_id']}",
                "declared_size": 42,
            }
            if body["kind"] == "download":
                grant |= {
                    "name": "a.pdf",
                    "content_type": "application/pdf",
                    "size": 42,
                    "sha256": "ab" * 32,
                    "wrapped_key": base64.b64encode(b"wrapped").decode(),
                    "kms_key_id": "k",
                }
                if self.application.settings.get("incomplete"):
                    grant["wrapped_key"] = None
            self.write(grant)
        elif status == 200 and path == "deletions/claim":
            self.write(
                self.application.settings.get("claim")
                or {"items": [{"id": 7, "storage_key": "files/x"}], "pending": 3}
            )
        else:
            self.write({})


class InternalApiTest(AsyncHTTPTestCase):
    status = 200

    def get_app(self):
        self.calls: list = []
        return tornado.web.Application(
            [(r"/internal/(.*)", FakeInternal)], calls=self.calls, status=self.status
        )

    def client(self, token: str | None = SECRET) -> InternalApi:
        return InternalApi(self.get_url(""), token)

    def answer(self, status: int) -> None:
        self._app.settings["status"] = status

    @gen_test
    async def test_consume_sends_secret_and_returns_grant(self) -> None:
        file_id = uuid.uuid4()
        grant = await self.client().consume_upload("tok", file_id, "198.51.100.1")
        assert grant.file_id == file_id
        assert grant.storage_key == f"files/{file_id}"
        assert grant.declared_size == 42
        [(path, auth, body)] = self.calls
        assert path == "intents/consume"
        assert auth == f"Bearer {SECRET}"
        assert body == {
            "token": "tok",
            "kind": "upload",
            "file_id": str(file_id),
            "client_ip": "198.51.100.1",
        }

    @gen_test
    async def test_consume_download_returns_key_material(self) -> None:
        file_id = uuid.uuid4()
        grant = await self.client().consume_download("tok", file_id, None)
        assert grant.file_id == file_id
        assert grant.wrapped_key == b"wrapped"
        assert (grant.name, grant.size, grant.kms_key_id) == ("a.pdf", 42, "k")
        assert b"wrapped" not in repr(grant).encode()
        [(_, _, body)] = self.calls
        assert (body["kind"], body["client_ip"]) == ("download", None)

    @gen_test
    async def test_incomplete_download_grant_is_unavailable(self) -> None:
        self._app.settings["incomplete"] = True
        try:
            await self.client().consume_download("tok", uuid.uuid4(), None)
        except ApiUnavailable:
            return
        raise AssertionError("a grant without a key must not be used")

    @gen_test
    async def test_complete_sends_base64_wrapped_key(self) -> None:
        file_id = uuid.uuid4()
        await self.client().complete(
            file_id, size=3, sha256="ab" * 32, wrapped_key=b"\x00\xff", kms_key_id="k"
        )
        [(path, _, body)] = self.calls
        assert path == f"files/{file_id}/complete"
        assert base64.b64decode(body["wrapped_key"]) == b"\x00\xff"

    @gen_test
    async def test_refused_intent(self) -> None:
        for status in (403, 409):
            self.answer(status)
            try:
                await self.client().consume_upload("tok", uuid.uuid4(), None)
            except IntentRefused:
                continue
            raise AssertionError(f"{status} should refuse the intent")

    @gen_test
    async def test_other_errors_mean_unavailable(self) -> None:
        for status in (401, 500, 503):
            self.answer(status)
            try:
                await self.client().fail(uuid.uuid4())
            except ApiUnavailable:
                continue
            raise AssertionError(f"{status} should be ApiUnavailable")

    @gen_test
    async def test_unreachable_api(self) -> None:
        api = InternalApi("http://127.0.0.1:9", SECRET, timeout=2)
        try:
            await api.fail(uuid.uuid4())
        except ApiUnavailable:
            return
        raise AssertionError("connection refused should be ApiUnavailable")

    @gen_test
    async def test_no_secret_configured_fails_closed(self) -> None:
        try:
            await self.client(token=None).fail(uuid.uuid4())
        except ApiUnavailable:
            assert self.calls == []
            return
        raise AssertionError("missing secret should not call the API")

    @gen_test
    async def test_claims_and_confirms_deletions(self) -> None:
        claimed = await self.client().claim_deletions(50)
        assert [(i.id, i.storage_key) for i in claimed.items] == [(7, "files/x")]
        assert claimed.pending == 3
        await self.client().confirm_deletions([7])
        assert [(path, body) for path, _, body in self.calls] == [
            ("deletions/claim", {"limit": 50}),
            ("deletions/done", {"ids": [7]}),
        ]
        assert all(auth == f"Bearer {SECRET}" for _, auth, _ in self.calls)

    @gen_test
    async def test_an_incomplete_claim_is_unavailable(self) -> None:
        self._app.settings["claim"] = {"items": [{"id": 1}], "pending": 1}
        with self.assertRaises(ApiUnavailable):
            await self.client().claim_deletions(1)

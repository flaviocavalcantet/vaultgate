import hashlib
import json

from tornado.testing import AsyncHTTPTestCase

from vaultgate_gateway.app import make_app


class GatewayTest(AsyncHTTPTestCase):
    def get_app(self):
        return make_app()

    def test_health(self) -> None:
        response = self.fetch("/healthz")
        assert response.code == 200
        assert json.loads(response.body) == {"status": "ok", "service": "gateway"}

    def test_streaming_upload_reports_size_and_hash(self) -> None:
        payload = b"x" * (3 * 1024 * 1024)  # several chunks
        response = self.fetch("/uploads/abc123", method="PUT", body=payload)
        assert response.code == 200
        body = json.loads(response.body)
        assert body["bytes"] == len(payload)
        assert body["sha256"] == hashlib.sha256(payload).hexdigest()

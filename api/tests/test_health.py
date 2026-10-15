from fastapi.testclient import TestClient

from vaultgate_api.main import app


def test_liveness() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "api"}

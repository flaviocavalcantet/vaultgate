from prometheus_client import REGISTRY
from tornado.testing import AsyncHTTPTestCase

from vaultgate_gateway.app import make_app
from vaultgate_gateway.metrics import UNMATCHED_ROUTE


def _sample(name: str, labels: dict[str, str] | None = None) -> float:
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


class GatewayMetricsTest(AsyncHTTPTestCase):
    def get_app(self):
        return make_app()

    def test_unknown_paths_share_one_label(self) -> None:
        labels = {"method": "GET", "route": UNMATCHED_ROUTE, "status": "404"}
        before = _sample("vaultgate_http_requests_total", labels)
        self.fetch("/admin")
        self.fetch("/uploads/not.a.valid.id")
        assert _sample("vaultgate_http_requests_total", labels) == before + 2

    def test_health_is_labelled_by_route(self) -> None:
        labels = {"method": "GET", "route": "/healthz", "status": "200"}
        before = _sample("vaultgate_http_requests_total", labels)
        self.fetch("/healthz")
        assert _sample("vaultgate_http_requests_total", labels) == before + 1

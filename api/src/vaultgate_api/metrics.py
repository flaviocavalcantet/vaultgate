"""Prometheus metrics for the API.

Metrics are served on a separate port (VAULTGATE_METRICS_PORT), never on the public
API port, so scraping needs no auth and the endpoint cannot be reached through the
ingress. Request metrics are labelled by route template ("/files/{file_id}"), not by
raw path, which keeps label cardinality bounded no matter what clients send.
"""

import time

from prometheus_client import Counter, Gauge, Histogram, Info
from starlette.types import ASGIApp, Message, Receive, Scope, Send

UNMATCHED_ROUTE = "<unmatched>"

BUILD_INFO = Info("vaultgate_build", "Service build information")

HTTP_REQUESTS = Counter(
    "vaultgate_http_requests_total",
    "HTTP requests handled, by route template and status code",
    ["method", "route", "status"],
)
HTTP_DURATION = Histogram(
    "vaultgate_http_request_duration_seconds",
    "Time from receiving a request to sending its last response byte",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
HTTP_IN_PROGRESS = Gauge(
    "vaultgate_http_requests_in_progress",
    "HTTP requests currently being handled",
)


def route_template(scope: Scope) -> str:
    """The matched route's path template, set on the scope by the router."""
    route = scope.get("route")
    return getattr(route, "path", None) or UNMATCHED_ROUTE


class MetricsMiddleware:
    """Records request count, latency and concurrency for every HTTP request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        HTTP_IN_PROGRESS.inc()
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            HTTP_IN_PROGRESS.dec()
            method = scope["method"]
            route = route_template(scope)
            HTTP_REQUESTS.labels(method, route, str(status_code)).inc()
            HTTP_DURATION.labels(method, route).observe(time.perf_counter() - start)

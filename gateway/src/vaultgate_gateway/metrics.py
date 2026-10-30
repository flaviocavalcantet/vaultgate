"""Prometheus metrics for the gateway.

Served on a separate port (VAULTGATE_METRICS_PORT), never on the public port.
Request metrics share names and labels with the API's so one dashboard query covers
both services; the scrape job tells them apart. Upload metrics are what the gateway
exists for: throughput, concurrency and size, plus the process memory metrics that
prometheus_client exports by default, which show memory staying flat under load.
"""

from prometheus_client import Counter, Gauge, Histogram, Info

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
    # Uploads of several GB take minutes, so the buckets reach further than the API's.
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600),
)
UPLOADS_IN_PROGRESS = Gauge(
    "vaultgate_gateway_uploads_in_progress",
    "Uploads currently streaming through the gateway",
)
UPLOAD_BYTES = Counter(
    "vaultgate_gateway_upload_bytes_total",
    "Bytes received in upload bodies, counted as chunks arrive",
)
UPLOAD_SIZE = Histogram(
    "vaultgate_gateway_upload_size_bytes",
    "Size of completed uploads",
    buckets=tuple(2**n for n in range(10, 34, 2)),  # 1 KiB .. 8 GiB
)
UPLOAD_FAILURES = Counter(
    "vaultgate_gateway_upload_failures_total",
    "Uploads that did not complete, by reason",
    ["reason"],
)
DOWNLOADS_IN_PROGRESS = Gauge(
    "vaultgate_gateway_downloads_in_progress",
    "Downloads currently streaming through the gateway",
)
DOWNLOAD_BYTES = Counter(
    "vaultgate_gateway_download_bytes_total",
    "Decrypted bytes sent to download clients",
)
DOWNLOAD_SIZE = Histogram(
    "vaultgate_gateway_download_size_bytes",
    "Size of completed downloads",
    buckets=tuple(2**n for n in range(10, 34, 2)),  # 1 KiB .. 8 GiB
)
DOWNLOAD_FAILURES = Counter(
    "vaultgate_gateway_download_failures_total",
    "Downloads that did not complete, by reason",
    ["reason"],
)

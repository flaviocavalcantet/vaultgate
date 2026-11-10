"""Cross-origin requests (CORS, M12.5): which web origins' pages may upload to and
download from the gateway.

The web frontend is served from its own origin, and a browser lets its pages call the
gateway only when the gateway says so. The origins are an exact allow-list
(settings.cors_origins), empty by default: then no page of another origin gets an
answer it may read, and a preflight is refused.

Being on the list grants nothing by itself: a transfer still needs its single-use
intent token, which only the API hands out. The gateway has no cookies, so
`Access-Control-Allow-Credentials` is never sent.
"""

from urllib.parse import urlsplit

# What the frontend sends, and what it may read of a response. Preflights are cached
# ten minutes.
REQUEST_HEADERS = ("Authorization", "Content-Type")
EXPOSED_HEADERS = (
    "Content-Disposition",
    "Content-Length",
    "Repr-Digest",
    "Retry-After",
    "X-Request-ID",
)
MAX_AGE_SECONDS = 600


def parse_origins(value: str) -> frozenset[str]:
    """Origins from a comma-separated setting, each exactly as a browser sends it:
    scheme://host[:port], http or https, with no path, wildcard or trailing slash."""
    origins = set()
    for item in (item.strip() for item in value.split(",")):
        if not item:
            continue
        parts = urlsplit(item)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or "*" in item
            or parts.username is not None
            or item != f"{parts.scheme}://{parts.netloc}"
            or item != item.lower()
        ):
            raise ValueError(
                f"{item!r} is not an origin: scheme://host[:port], lower case, no path or wildcard"
            )
        origins.add(item)
    return frozenset(origins)

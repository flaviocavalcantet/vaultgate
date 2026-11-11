"""Cross-origin requests (CORS, M12.5): which web origins' pages may call the API.

A browser lets a page call another origin only when that origin says so. The web
frontend is served from its own origin, so the API names the origins it accepts
(settings.cors_origins): an exact allow-list, empty by default, which leaves the API
answering no cross-origin page at all.

Being on the list grants a page nothing by itself. Every route still wants its bearer
token (or, for share recipients, the link's token and code): the API has no cookies, so
a page of another origin has nothing of the user's to ride on, and
`Access-Control-Allow-Credentials` is never sent. What the list decides is whose
JavaScript may read the API's answers at all.
"""

from urllib.parse import urlsplit

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

# What the frontend sends and reads. Preflights are cached ten minutes.
METHODS = ["GET", "POST", "PUT", "DELETE"]
REQUEST_HEADERS = ["Authorization", "Content-Type"]
EXPOSED_HEADERS = ["X-Request-ID", "Retry-After"]
MAX_AGE_SECONDS = 600


def parse_origins(value: str | list[str]) -> list[str]:
    """Origins from a comma-separated setting, each exactly as a browser sends it:
    scheme://host[:port], http or https, with no path, wildcard or trailing slash."""
    items = value.split(",") if isinstance(value, str) else value
    origins = []
    for item in (item.strip() for item in items):
        if not item:
            continue
        parts = urlsplit(item)
        rebuilt = f"{parts.scheme}://{parts.netloc}"
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or "*" in item
            or parts.username is not None
            or item != rebuilt
            or item != item.lower()
        ):
            raise ValueError(
                f"{item!r} is not an origin: scheme://host[:port], lower case, no path or wildcard"
            )
        origins.append(item)
    return origins


def install_cors(app: FastAPI, origins: list[str]) -> None:
    """Adds the CORS layer when there are origins to allow; none, and nothing changes."""
    if not origins:
        return
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=METHODS,
        allow_headers=REQUEST_HEADERS,
        expose_headers=EXPOSED_HEADERS,
        allow_credentials=False,
        max_age=MAX_AGE_SECONDS,
    )

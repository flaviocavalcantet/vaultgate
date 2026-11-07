"""Security headers on every response (M10, docs/security-scans.md).

The API answers JSON to programs, never pages to render, so a browser that gets one
anyway may not sniff it into something else, run scripts in it, frame it or cache it;
and once it has reached the API over TLS, it keeps to HTTPS (HSTS). Two exceptions: the
interactive docs (/docs, /redoc) are pages that load Swagger UI's and ReDoc's scripts,
so they get no Content-Security-Policy; and a response that sets its own Cache-Control
keeps it.
"""

from starlette.types import ASGIApp, Message, Receive, Scope, Send

DOC_PATHS = ("/docs", "/redoc")
CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")
HSTS = (b"strict-transport-security", b"max-age=63072000")


class SecurityHeadersMiddleware:
    """Pure ASGI, so streaming responses aren't buffered."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        extra = [(b"x-content-type-options", b"nosniff")]
        if not scope["path"].startswith(DOC_PATHS):
            extra.append(CSP)
        if scope.get("scheme") == "https":
            extra.append(HSTS)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                if not any(name.lower() == b"cache-control" for name, _ in headers):
                    headers.append((b"cache-control", b"no-store"))
                headers.extend(extra)
            await send(message)

        await self.app(scope, receive, send_with_headers)

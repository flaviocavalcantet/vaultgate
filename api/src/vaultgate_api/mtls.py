"""Who is calling the internal port, from its client certificate (M10, ADR 0013).

With mutual TLS on (VAULTGATE_INTERNAL_CLIENT_CA_FILE), the internal server refuses a
connection whose client has no certificate from that CA, and the routes want more than
a valid certificate: the identity in it, a URI such as
spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway. The gateway's routes take the
gateway's identity only and the scanner's the scanner's, next to the tokens, which stay
required (a second factor: a leaked token alone opens nothing, nor does a certificate).

uvicorn doesn't hand the client certificate to the application, so the internal server
runs this HTTP protocol instead of its own: uvicorn's h11 protocol, which reads the
certificate's URIs once per connection, when the handshake is done, and adds them to
the scope of every request on that connection.
"""

import asyncio
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol

# Where the identities go in the request's scope: a tuple of URIs, empty without a
# client certificate; and the certificate's serial number (hex), None without one.
SCOPE_KEY = "vaultgate.client_identities"
SERIAL_KEY = "vaultgate.client_serial"


def certificate_uris(certificate: dict[str, Any] | None) -> tuple[str, ...]:
    """The URIs in a certificate's subjectAltName, as ssl's getpeercert() returns it."""
    names = (certificate or {}).get("subjectAltName", ())
    return tuple(value for kind, value in names if kind == "URI")


class _WithIdentities:
    """The application, seeing the connection's client identities in each scope."""

    def __init__(self, app: Any, identities: tuple[str, ...], serial: str | None) -> None:
        self.app = app
        self.identities = identities
        self.serial = serial

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] in ("http", "websocket"):
            scope = {**scope, SCOPE_KEY: self.identities, SERIAL_KEY: self.serial}
        await self.app(scope, receive, send)


class ClientIdentityProtocol(H11Protocol):
    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert() if ssl_object is not None else None
        self.app = _WithIdentities(
            self.app, certificate_uris(certificate), (certificate or {}).get("serialNumber")
        )


def client_identities(scope: dict) -> tuple[str, ...]:
    return scope.get(SCOPE_KEY, ())


def client_serial(scope: dict) -> str | None:
    return scope.get(SERIAL_KEY)

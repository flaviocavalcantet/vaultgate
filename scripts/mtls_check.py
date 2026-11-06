"""Mutual TLS on the API's internal port (M10, ADR 0013), from the gateway's pod:
scripts/k3d.sh check runs it with
`kubectl exec deploy/vaultgate-gateway -- python - < scripts/mtls_check.py`.

With the gateway's own settings (its client certificate, its token, the trust bundle):
- its client certificate and token are accepted (an unknown intent is refused with 403,
  which only an authenticated caller gets);
- the same token over a connection with no client certificate is refused at the
  handshake;
- so is one with the gateway's server certificate: the same root, but not for clients.
"""

import http.client
import json
import ssl
import urllib.parse
import uuid

from vaultgate_gateway.settings import settings

URL = urllib.parse.urlsplit(settings.api_internal_url)
BODY = json.dumps({"token": "x", "kind": "upload", "file_id": str(uuid.uuid4()), "client_ip": None})


def status(cert: tuple[str, str] | None) -> int | None:
    """The API's answer, or None when the connection was refused."""
    context = ssl.create_default_context()
    if cert:
        context.load_cert_chain(*cert)
    conn = http.client.HTTPSConnection(URL.hostname, URL.port, context=context, timeout=10)
    try:
        conn.request(
            "POST",
            "/internal/intents/consume",
            BODY,
            {
                "Authorization": f"Bearer {settings.internal_token}",
                "Content-Type": "application/json",
            },
        )
        return conn.getresponse().status
    except (ssl.SSLError, ConnectionError):
        return None
    finally:
        conn.close()


def main() -> None:
    client = (settings.api_client_cert_file, settings.api_client_key_file)
    if not all(client):
        raise SystemExit("FAIL the gateway has no client certificate")
    if (got := status(client)) != 403:
        raise SystemExit(f"FAIL the gateway's certificate and token got {got}, not 403")
    if (got := status(None)) is not None:
        raise SystemExit(f"FAIL a connection without a client certificate got {got}")
    server = (settings.tls_cert_file, settings.tls_key_file)
    if (got := status(server)) is not None:
        raise SystemExit(f"FAIL a server certificate was accepted as a client's ({got})")
    print(
        "ok  the internal port takes the gateway's client certificate and token, and refuses "
        "connections with no client certificate or a server's"
    )


main()

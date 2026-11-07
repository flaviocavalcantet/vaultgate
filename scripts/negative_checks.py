"""Negative tests against the running system (M10, docs/security-scans.md): what the API,
the gateway and the cluster's services must refuse. `make k3d-check` runs it after the
end-to-end check, from the host, trusting the root (SSL_CERT_FILE).

1. Authentication: every route in the API's OpenAPI document but the public ones
   (health, and the share recipients' routes, which a link's token and an emailed code
   authorize) refuses no token, a token that isn't a JWT, alice's token with its
   payload changed (the signature no longer matches), and alice's claims re-signed with
   `alg: none`: 401, then, once this address has failed often enough, 429 with
   Retry-After (vaultgate_api.ratelimit), while a valid token from it still works.
2. Authorization: alice, who isn't an administrator, gets 403 on every /admin route;
   bob gets 404 on alice's file, its download, and its shares, as if it didn't exist.
3. Intent tokens at the gateway: none is 401; an unknown one, an upload intent for
   another file, and an upload intent used to download are refused, and the refusals
   leave it unspent: it then uploads, once.
4. Rate limits: bob, asking for /me as fast as he can, is refused with 429 and
   Retry-After once past his burst.
5. TLS: the API, the gateway, Keycloak and OpenBao speak TLS 1.3 and nothing older, and
   no plain HTTP.

    python3 scripts/negative_checks.py [--api URL] [--gateway URL] [--keycloak URL]
                                       [--openbao URL]

Standard library only. Needs the seeded allow policy (scripts/seed_policies.py), as
vault_e2e.py does.
"""

import argparse
import base64
import http.client
import json
import socket
import ssl
import sys
import urllib.parse
import uuid

from keycloak_smoke import login, wait_for

PUBLIC = ("/healthz", "/readyz", "/shares/access")


def request(
    base: str, method: str, path: str, token: str | None = None, body=None
) -> tuple[int, bytes]:
    status, body, _ = request_full(base, method, path, token, body)
    return status, body


def request_full(
    base: str, method: str, path: str, token: str | None = None, body=None
) -> tuple[int, bytes, http.client.HTTPMessage]:
    parts = urllib.parse.urlsplit(base)
    conn = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=30)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = body if isinstance(body, bytes) else json.dumps(body).encode() if body else None
    if data is not None:
        headers["Content-Length"] = str(len(data))
    try:
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        return response.status, response.read(), response.headers
    finally:
        conn.close()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forged(token: str) -> dict[str, str]:
    """Tokens a client could make from a real one, which the API must all refuse."""
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    changed = b64(json.dumps({**claims, "preferred_username": "admin"}).encode())
    unsigned = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    return {
        "none": None,
        "not a JWT": "not-a-jwt",
        "a changed payload": f"{header}.{changed}.{signature}",
        "alg none": f"{unsigned}.{payload}.",
    }


def routes(api: str) -> list[tuple[str, str]]:
    status, body = request(api, "GET", "/openapi.json")
    assert status == 200, status
    found = []
    for path, operations in json.loads(body)["paths"].items():
        concrete = path
        for name in [p[1:-1] for p in path.split("/") if p.startswith("{")]:
            concrete = concrete.replace("{" + name + "}", str(uuid.uuid4()))
        found += [(method.upper(), concrete) for method in operations]
    return found


def check_authentication(api: str, alice: str) -> None:
    protected = [(m, p) for m, p in routes(api) if not p.startswith(PUBLIC)]
    assert len(protected) > 20, protected  # the document lists them all
    statuses = []
    for what, token in forged(alice).items():
        for method, path in protected:
            status, _, headers = request_full(api, method, path, token, {})
            assert status in (401, 429), f"{method} {path} with {what}: {status}"
            if status == 429:
                assert int(headers["Retry-After"]) > 0, headers
            statuses.append(status)
    # 401 until the address has failed too often, then 429 for its failing requests.
    first = statuses.index(429) if 429 in statuses else len(statuses)
    assert first < len(statuses), "no 429 after so many failures"
    assert set(statuses[first:]) == {429}, "a failure got 401 again during the block"
    status, _ = request(api, "GET", "/me", alice)
    assert status == 200, f"alice's valid token got {status} from the blocked address"
    print(f"ok  {len(protected)} protected routes refuse no token, a non-JWT, a changed ", end="")
    print(f"payload and alg none: 401, then 429 after {first} failures; valid tokens still work")


def check_authorization(api: str, alice: str, bob: str) -> tuple[str, dict]:
    admin = [(m, p) for m, p in routes(api) if p.startswith("/admin")]
    for method, path in admin:
        status, _ = request(api, method, path, alice, {})
        assert status == 403, f"alice {method} {path}: {status}"
    print(f"ok  alice, not an administrator, gets 403 on all {len(admin)} /admin routes")

    status, body = request(api, "POST", "/files", alice, {"name": "negative.txt", "size": 5})
    assert status == 201, f"POST /files: {status} (403: run scripts/seed_policies.py first)"
    created = json.loads(body)
    file_id = created["file"]["id"]
    for method, path, payload in (
        ("GET", f"/files/{file_id}", None),
        ("POST", f"/files/{file_id}/download", {}),
        ("GET", f"/files/{file_id}/shares", None),
        ("POST", f"/files/{file_id}/shares", {"recipient_email": "bob@example.com"}),
    ):
        status, _ = request(api, method, path, bob, payload)
        assert status == 404, f"bob {method} {path}: {status}"
    print("ok  bob gets 404 on alice's file, its download and its shares")
    return file_id, created["upload"]


def check_intents(gateway: str, file_id: str, upload: dict) -> None:
    token, path = upload["token"], urllib.parse.urlsplit(upload["url"]).path
    assert path == f"/uploads/{file_id}", path
    refused = (
        ("no token", "PUT", path, None),
        ("an unknown token", "PUT", path, "not-an-intent"),
        ("the intent for another file", "PUT", f"/uploads/{uuid.uuid4()}", token),
        ("an upload intent to download", "GET", f"/downloads/{file_id}", token),
    )
    for what, method, target, credential in refused:
        status, _ = request(
            gateway, method, target, credential, b"hello" if method == "PUT" else None
        )
        expected = 401 if credential is None else 403
        assert status == expected, f"{what}: {status}, expected {expected}"
    status, _ = request(gateway, "PUT", path, token, b"hello")
    assert status == 201, f"the refusals spent the intent: {status}"
    status, _ = request(gateway, "PUT", path, token, b"hello")
    assert status == 403, f"the intent worked twice: {status}"
    print("ok  the gateway refuses no token, an unknown one, another file's and an upload ", end="")
    print("intent to download, and those refusals left the intent to upload once")


def check_rate_limit(api: str, bob: str) -> None:
    for sent in range(1, 301):
        status, _, headers = request_full(api, "GET", "/me", bob)
        if status == 429:
            assert int(headers["Retry-After"]) > 0, headers
            break
        assert status == 200, status
    else:
        raise AssertionError("bob was never limited in 300 requests")
    print(f"ok  bob, as fast as he can, gets 429 with Retry-After at request {sent}")


def handshake(host: str, port: int, version: ssl.TLSVersion) -> bool:
    context = ssl.create_default_context()
    context.minimum_version = context.maximum_version = version
    try:
        with (
            socket.create_connection((host, port), timeout=10) as sock,
            context.wrap_socket(sock, server_hostname=host),
        ):
            return True
    except ssl.SSLError:
        return False


def plain_http(host: str, port: int) -> bool:
    """Whether the port answers plain HTTP (a TLS port may answer with an error page)."""
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.request("GET", "/")
        return conn.getresponse().status < 400
    except (http.client.HTTPException, OSError):
        return False
    finally:
        conn.close()


def check_tls(services: dict[str, str]) -> None:
    for name, url in services.items():
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port
        assert handshake(host, port, ssl.TLSVersion.TLSv1_3), f"{name}: no TLS 1.3"
        assert not handshake(host, port, ssl.TLSVersion.TLSv1_2), f"{name} accepts TLS 1.2"
        assert not plain_http(host, port), f"{name} answers plain HTTP"
    print(f"ok  {', '.join(services)}: TLS 1.3 only, TLS 1.2 refused, no plain HTTP")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", default="https://localhost:8000")
    parser.add_argument("--gateway", default="https://localhost:8888")
    parser.add_argument("--keycloak", default="https://localhost:8080")
    parser.add_argument("--openbao", default="https://localhost:8200")
    args = parser.parse_args(argv)
    discovery = wait_for(args.keycloak)
    alice = login(discovery, "alice", "alice-dev-password")["access_token"]
    bob = login(discovery, "bob", "bob-dev-password")["access_token"]
    check_authentication(args.api, alice)
    file_id, upload = check_authorization(args.api, alice, bob)
    check_intents(args.gateway, file_id, upload)
    check_rate_limit(args.api, bob)
    check_tls(
        {
            "API": args.api,
            "gateway": args.gateway,
            "Keycloak": args.keycloak,
            "OpenBao": args.openbao,
        }
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

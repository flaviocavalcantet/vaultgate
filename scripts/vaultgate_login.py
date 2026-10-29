"""Log in to VaultGate from a terminal and print an access token.

Runs the same OAuth 2.0 authorization code flow with PKCE (S256) a browser app uses,
with this script acting as the public client `vaultgate-web`:

1. Listen on http://127.0.0.1:8765/callback (loopback only, one request).
2. Open the identity provider's login page in your browser.
3. After you sign in, the provider redirects to the callback with a one-time code.
4. Check `state`, exchange the code plus the PKCE verifier for tokens.
5. Print the access token on stdout; everything else goes to stderr.

    TOKEN=$(python3 scripts/vaultgate_login.py)
    curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/me

Nothing is written to disk. Access tokens live 5 minutes; run it again for a new one.
Standard library only.
"""

import argparse
import base64
import hashlib
import http.server
import json
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

DEFAULT_ISSUER = "http://localhost:8080/realms/vaultgate"
CLIENT_ID = "vaultgate-web"
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 8765
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}/callback"

PAGE = """<!doctype html><meta charset="utf-8"><title>VaultGate login</title>
<body style="font-family:sans-serif;margin:3rem"><h1>{title}</h1><p>{body}</p></body>"""


class LoginError(Exception):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def pkce_pair() -> tuple[str, str]:
    """A random code verifier and its S256 challenge (RFC 7636)."""
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def discover(issuer: str) -> dict:
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.load(response)


def authorization_url(discovery: dict, challenge: str, state: str) -> str:
    query = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "scope": "openid",
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{discovery['authorization_endpoint']}?{query}"


def wait_for_code(expected_state: str, timeout: float) -> str:
    """Serve exactly one /callback request on the loopback port and return its code."""
    result: dict[str, str] = {}
    done = threading.Event()

    class Callback(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            url = urllib.parse.urlparse(self.path)
            if url.path != "/callback":
                self.send_error(404)
                return
            params = urllib.parse.parse_qs(url.query)
            if params.get("state") != [expected_state]:
                # Not the response to our request (stale tab, or a forged redirect).
                self._reply(400, "Login failed", "The response did not match this login.")
                result["error"] = "state mismatch"
            elif "error" in params:
                self._reply(400, "Login failed", "The identity provider refused the login.")
                result["error"] = params["error"][0]
            elif "code" not in params:
                self._reply(400, "Login failed", "No authorization code was returned.")
                result["error"] = "no code"
            else:
                self._reply(200, "Logged in", "You can close this tab and return to the terminal.")
                result["code"] = params["code"][0]
            done.set()

        def _reply(self, status: int, title: str, body: str) -> None:
            content = PAGE.format(title=title, body=body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *args) -> None:
            pass  # keep the terminal clean; the URL carries the one-time code

    try:
        server = http.server.HTTPServer((CALLBACK_HOST, CALLBACK_PORT), Callback)
    except OSError as exc:
        raise LoginError(f"cannot listen on {REDIRECT_URI}: {exc}") from None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if not done.wait(timeout):
            raise LoginError(f"no login completed within {timeout:.0f}s")
    finally:
        server.shutdown()
        server.server_close()
    if "error" in result:
        raise LoginError(f"login failed: {result['error']}")
    return result["code"]


def exchange(discovery: dict, code: str, verifier: str) -> dict:
    data = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }
    ).encode()
    request = urllib.request.Request(discovery["token_endpoint"], data=data)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise LoginError(f"token exchange failed: {exc.code} {exc.read().decode()[:200]}") from None


def claims(token: str) -> dict:
    """Decode a JWT payload for display only. The API, not this script, verifies tokens."""
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Log in to VaultGate (authorization code + PKCE) and print an access token."
    )
    parser.add_argument(
        "--issuer", default=DEFAULT_ISSUER, help=f"OIDC issuer URL (default {DEFAULT_ISSUER})"
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="print the login URL instead of opening a browser",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the whole token response as JSON"
    )
    parser.add_argument("--timeout", type=float, default=180, help="seconds to wait for login")
    args = parser.parse_args(argv)

    try:
        discovery = discover(args.issuer)
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(16)
        url = authorization_url(discovery, challenge, state)
        print(f"Log in at: {url}", file=sys.stderr, flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        code = wait_for_code(state, args.timeout)
        tokens = exchange(discovery, code, verifier)
    except (LoginError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    info = claims(tokens["access_token"])
    print(
        f"Logged in as {info.get('preferred_username')} "
        f"(groups: {', '.join(info.get('groups', [])) or 'none'}); "
        f"token valid for {tokens.get('expires_in')}s",
        file=sys.stderr,
    )
    print(json.dumps(tokens) if args.json else tokens["access_token"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

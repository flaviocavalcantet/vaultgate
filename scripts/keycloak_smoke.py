"""End-to-end check of the local Keycloak realm (`infra/keycloak/vaultgate-realm.json`).

Logs in as a seeded user through the real authorization code + PKCE flow, the way a
browser would, and checks the access token the API will receive: issuer, audience,
expiry and the `groups` claim. Also checks that the insecure flows are refused.

    python3 scripts/keycloak_smoke.py [http://localhost:8080] [--api http://localhost:8000]

It also runs scripts/vaultgate_login.py (the developer login helper) headless and
completes its login as a browser would, checking the token it prints.

With --api, each user's access token is also sent to the API's GET /me, which must
accept it and return the provisioned user record with the same identity and groups,
and the ID token (wrong audience) must be refused. Then /admin/users must be refused
for non-admins and list every seed user for carol (vaultgate-admins): an end-to-end
check of the realm, token validation and user provisioning together.

Standard library only, so it runs in CI without installing anything. It drives
Keycloak's login form, so it is a test tool, not a client implementation.
"""

import argparse
import base64
import hashlib
import html
import http.cookiejar
import json
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HELPER = Path(__file__).resolve().parent / "vaultgate_login.py"
REALM = "vaultgate"
CLIENT_ID = "vaultgate-web"
REDIRECT_URI = "http://127.0.0.1:8765/callback"
AUDIENCE = "vaultgate-api"

EXPECTED_GROUPS = {
    "alice": ["/finance"],
    "bob": ["/legal"],
    "carol": ["/engineering", "/vaultgate-admins"],
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def post_form(url: str, data: dict) -> tuple[int, dict]:
    request = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode())
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def wait_for(base: str, timeout: float = 120) -> dict:
    url = f"{base}/realms/{REALM}/.well-known/openid-configuration"
    deadline = time.monotonic() + timeout
    while True:
        try:
            with urllib.request.urlopen(url) as response:
                return json.load(response)
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)


def browser_login(auth_url: str, username: str, password: str) -> str:
    """Do what a browser does with an authorization URL: show the login form, submit
    the credentials, and return the redirect Location carrying the code."""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)
    with opener.open(auth_url) as response:
        page = response.read().decode()
    # Keycloak marks its session cookies Secure even on http://localhost, which browsers
    # accept (localhost counts as a secure context) but Python's cookie jar does not.
    for cookie in jar:
        cookie.secure = False
    action = html.unescape(re.search(r'action="([^"]+)"', page).group(1))
    form = urllib.parse.urlencode({"username": username, "password": password}).encode()
    try:
        opener.open(action, data=form)
        raise AssertionError(f"login for {username} did not redirect (wrong password?)")
    except urllib.error.HTTPError as redirect:
        if redirect.code != 302:
            raise
        return redirect.headers["Location"]


def login(discovery: dict, username: str, password: str) -> dict:
    """Authorization code + PKCE through the login form; returns the token response."""
    verifier = b64url(secrets.token_bytes(32))
    state = secrets.token_urlsafe(16)
    query = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "scope": "openid",
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
        }
    )
    location = browser_login(f"{discovery['authorization_endpoint']}?{query}", username, password)
    params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    assert location.startswith(REDIRECT_URI), location
    assert params["state"] == [state], "state mismatch"
    status, tokens = post_form(
        discovery["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": params["code"][0],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    assert status == 200, tokens
    return tokens


def start_helper(issuer: str) -> tuple[subprocess.Popen, str]:
    """Start scripts/vaultgate_login.py headless; return it and the login URL it printed."""
    helper = subprocess.Popen(
        [sys.executable, str(HELPER), "--issuer", issuer, "--no-browser", "--timeout", "60"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = helper.stderr.readline()
    assert line.startswith("Log in at: "), f"unexpected helper output: {line!r}"
    time.sleep(0.5)  # let the callback listener bind before the redirect arrives
    return helper, line.removeprefix("Log in at: ").strip()


def check_login_helper(discovery: dict, api: str | None) -> None:
    """The CLI helper, driven as a person would: open its URL, log in, follow the redirect.

    A callback that does not answer this login's request (stale tab, forged redirect)
    arrives first: it must be refused without aborting the real login that follows.
    An idle connection (like a browser preconnect) stays open throughout and must not
    hold up the real redirect.
    """
    helper, url = start_helper(discovery["issuer"])
    idle = socket.create_connection(("127.0.0.1", 8765))
    forged = f"{REDIRECT_URI}?code=forged&state=not-the-one-we-sent"
    try:
        urllib.request.urlopen(forged)
        raise AssertionError("helper accepted a callback with the wrong state")
    except urllib.error.HTTPError as error:
        assert error.code == 400, error.code
    assert helper.poll() is None, "a forged callback ended the login"

    location = browser_login(url, "bob", "bob-dev-password")
    assert location.startswith(REDIRECT_URI), location
    with urllib.request.urlopen(location) as response:  # the browser following the redirect
        assert response.status == 200
    out, err = helper.communicate(timeout=30)
    idle.close()
    assert helper.returncode == 0, err
    token = out.strip()
    claims = jwt_claims(token)
    assert claims["preferred_username"] == "bob" and claims["azp"] == CLIENT_ID, claims
    if api:
        status, user = api_get(api, "/me", token)
        assert status == 200 and user["username"] == "bob", (status, user)
    print(
        "ok  login helper: forged callback refused, idle connection ignored, "
        "browser login yields a token the API accepts"
    )


def check_user(discovery: dict, username: str, api: str | None = None) -> dict:
    tokens = login(discovery, username, f"{username}-dev-password")
    claims = jwt_claims(tokens["access_token"])
    audience = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    assert claims["iss"] == discovery["issuer"], (claims["iss"], discovery["issuer"])
    assert AUDIENCE in audience, f"{AUDIENCE} missing from aud {audience}"
    assert claims["azp"] == CLIENT_ID, claims["azp"]
    assert claims["sub"], "no sub claim"
    assert 0 < claims["exp"] - claims["iat"] <= 300, "access token lives longer than 5 min"
    assert sorted(claims.get("groups", [])) == EXPECTED_GROUPS[username], claims.get("groups")
    print(f"ok  {username}: aud={audience} groups={claims['groups']}")
    if api:
        check_api(api, username, tokens)
    return tokens


def api_get(api: str, path: str, token: str) -> tuple[int, dict | None]:
    request = urllib.request.Request(f"{api}{path}", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, None


def check_api(api: str, username: str, tokens: dict) -> None:
    status, user = api_get(api, "/me", tokens["access_token"])
    assert status == 200, f"API refused {username}'s access token: {status}"
    assert user["username"] == username, user
    assert user["groups"] == EXPECTED_GROUPS[username], user
    assert user["id"] and user["is_active"], user
    status, _ = api_get(api, "/me", tokens["id_token"])
    assert status == 401, f"API accepted an ID token (audience vaultgate-web): {status}"
    print(f"ok  {username}: API /me returns user {user['id']}; ID token refused")


def check_admin(api: str, tokens_by_user: dict[str, dict]) -> None:
    status, _ = api_get(api, "/admin/users", tokens_by_user["alice"]["access_token"])
    assert status == 403, f"non-admin alice got {status} from /admin/users"
    status, page = api_get(api, "/admin/users?limit=100", tokens_by_user["carol"]["access_token"])
    assert status == 200, f"admin carol got {status} from /admin/users"
    listed = {u["username"] for u in page["items"]}
    assert set(EXPECTED_GROUPS) <= listed, listed
    print(f"ok  /admin/users: refused for alice, carol sees {sorted(listed)}")


def check_refusals(discovery: dict) -> None:
    status, body = post_form(
        discovery["token_endpoint"],
        {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "username": "alice",
            "password": "alice-dev-password",
        },
    )
    assert status in (400, 401), f"password grant was accepted: {status} {body}"
    print(f"ok  password grant refused ({body.get('error')})")

    query = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "scope": "openid",
            "redirect_uri": REDIRECT_URI,
        }
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(f"{discovery['authorization_endpoint']}?{query}")
        raise AssertionError("authorization request without PKCE was accepted")
    except urllib.error.HTTPError as error:
        location = error.headers.get("Location", "")
        assert "error=" in location, f"no error redirect without PKCE: {error.code} {location}"
    print("ok  authorization request without PKCE refused")

    query = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": "https://attacker.example/callback",
        }
    )
    try:
        opener.open(f"{discovery['authorization_endpoint']}?{query}")
        raise AssertionError("unregistered redirect URI was accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 400, error.code
    print("ok  unregistered redirect URI refused")


def wait_for_api(api: str, timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with urllib.request.urlopen(f"{api}/readyz"):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("keycloak", nargs="?", default="http://localhost:8080")
    parser.add_argument("--api", help="also check the API's /me at this base URL")
    args = parser.parse_args(argv)
    discovery = wait_for(args.keycloak.rstrip("/"))
    print(f"issuer {discovery['issuer']}")
    api = args.api.rstrip("/") if args.api else None
    if api:
        wait_for_api(api)
    tokens = {username: check_user(discovery, username, api) for username in EXPECTED_GROUPS}
    if api:
        check_admin(api, tokens)
    check_login_helper(discovery, api)
    check_refusals(discovery)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Seed the access policy that local development and CI run with.

Access is denied by default (ADR 0004), so a fresh stack refuses every file request
until a policy allows it. This logs in as carol, the local admin, and creates one
policy that lets every signed-in user read, upload and download, unless a policy with
that name exists already. Run it after `make up` (or `make vault-check` does).

    python3 scripts/seed_policies.py [--keycloak URL] [--api URL]

Never use this policy outside local development: it allows everything.
Standard library only.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

from keycloak_smoke import login, wait_for, wait_for_api

POLICY = {
    "name": "local development: signed-in users",
    "description": "Seeded by scripts/seed_policies.py. Allows everything; local use only.",
    "effect": "allow",
    "actions": ["read", "upload", "download"],
}


def call(api: str, method: str, path: str, token: str, body: dict | None = None):
    request = urllib.request.Request(
        f"{api}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        return error.code, None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keycloak", default="http://localhost:8080")
    parser.add_argument("--api", default="http://localhost:8000")
    args = parser.parse_args(argv)
    api = args.api.rstrip("/")

    discovery = wait_for(args.keycloak.rstrip("/"))
    wait_for_api(api)
    carol = login(discovery, "carol", "carol-dev-password")["access_token"]
    status, page = call(api, "GET", "/admin/policies?limit=100", carol)
    if status != 200:
        print(f"listing policies failed: {status}", file=sys.stderr)
        return 1
    if any(p["name"] == POLICY["name"] for p in page["items"]):
        print(f"ok  policy already present: {POLICY['name']}")
        return 0
    status, _ = call(api, "POST", "/admin/policies", carol, POLICY)
    if status != 201:
        print(f"creating the policy failed: {status}", file=sys.stderr)
        return 1
    print(f"ok  policy created: {POLICY['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

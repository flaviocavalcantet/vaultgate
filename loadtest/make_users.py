"""Writes infra/keycloak/vaultgate-users-0.json: the load test's users (M8, ADR 0011).

    python3 loadtest/make_users.py [--count 50]

Keycloak imports `<realm>-users-<n>.json` next to the realm file on start, in compose
and in the k3d cluster. The users are load-001 ... load-NNN in the /load group, with
verified addresses at example.com and one shared local password; they log in through the
local-only `vaultgate-load` client (password grant), never the web client. Local use only.
"""

import argparse
import json
from pathlib import Path

PASSWORD = "vaultgate-load-password"  # local-only test users
OUT = Path(__file__).resolve().parent.parent / "infra/keycloak/vaultgate-users-0.json"


def user(n: int) -> dict:
    name = f"load-{n:03d}"
    return {
        "username": name,
        "email": f"{name}@example.com",
        "firstName": "Load",
        "lastName": f"User {n:03d}",
        "enabled": True,
        "emailVerified": True,
        "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
        "groups": ["/load"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=50)
    args = parser.parse_args()
    body = {"realm": "vaultgate", "users": [user(n) for n in range(1, args.count + 1)]}
    OUT.write_text(json.dumps(body, indent=2) + "\n")
    print(f"wrote {args.count} users to {OUT}")


if __name__ == "__main__":
    main()

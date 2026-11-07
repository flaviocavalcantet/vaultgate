"""Egress network policy (M10, TM-1 in docs/threat-model.md), from the API's pod:
scripts/k3d.sh check runs it with
`kubectl exec deploy/vaultgate-api -- python - < scripts/egress_check.py`.

The API may reach what its network policy lists (PostgreSQL here, as the control: the
policy is in force and the probe itself works), and nothing else: not the Kubernetes
API, not another port of a pod it may reach (Alloy's UI, next to its OTLP port), and not
the internet.
"""

import socket

ALLOWED = [("postgres.vaultgate-deps.svc", 5432)]
REFUSED = [
    ("kubernetes.default.svc", 443),
    ("alloy.monitoring.svc", 12345),
    ("1.1.1.1", 443),
]


def reaches(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except OSError:  # refused, timed out (the policy drops it) or unresolvable
        return False


def main() -> None:
    for host, port in ALLOWED:
        if not reaches(host, port):
            raise SystemExit(f"FAIL the API cannot reach {host}:{port}, which it needs")
    for host, port in REFUSED:
        if reaches(host, port):
            raise SystemExit(f"FAIL the API reached {host}:{port}: egress is not restricted")
    print(
        "ok  the API reaches PostgreSQL, and not the Kubernetes API, Alloy's UI port or the "
        "internet: its egress is only what its network policy lists"
    )


main()

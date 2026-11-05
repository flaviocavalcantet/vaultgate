"""Checks of the local cluster's observability (scripts/k3d.sh check, ADR 0010).

    python3 scripts/k3d_checks.py targets       Prometheus scrapes the VaultGate services
                                                and Loki, Tempo and Alloy, all up
    python3 scripts/k3d_checks.py grafana       Grafana has the VaultGate dashboards and
                                                the Prometheus, Loki and Tempo data sources
    python3 scripts/k3d_checks.py alertmanager  Alertmanager mailed its Watchdog heartbeat
                                                to Mailpit: rules, routing and SMTP work

Exits 1 with the reason when a check does not hold yet (k3d.sh retries), 0 with an
`ok` line when it does. Standard library only.
"""

import base64
import json
import sys
import urllib.parse
import urllib.request

PROMETHEUS = "http://localhost:9090"
GRAFANA = "http://localhost:3000"
MAILPIT = "http://localhost:8025"

JOBS = {"api", "gateway", "scanner", "loki", "tempo", "alloy"}
DASHBOARDS = {"VaultGate / Service overview", "VaultGate / Gateway uploads"}
DATASOURCES = {"prometheus", "loki", "tempo"}  # UIDs, as the dashboards reference them


def get(url: str, headers: dict | None = None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def targets() -> str:
    active = get(f"{PROMETHEUS}/api/v1/targets?state=active")["data"]["activeTargets"]
    health = {}
    for target in active:
        job = target["labels"].get("job")
        if job in JOBS:
            health.setdefault(job, set()).add(target["health"])
    missing = sorted(JOBS - health.keys())
    down = sorted(job for job, states in health.items() if states != {"up"})
    if missing or down:
        raise AssertionError(f"targets missing: {missing}, not up: {down}")
    return f"Prometheus scrapes {', '.join(sorted(JOBS))}, all up"


def grafana() -> str:
    auth = {"Authorization": "Basic " + base64.b64encode(b"admin:admin").decode()}
    found = {d["title"] for d in get(f"{GRAFANA}/api/search?query=VaultGate", auth)}
    uids = {d["uid"] for d in get(f"{GRAFANA}/api/datasources", auth)}
    if not DASHBOARDS <= found or not DATASOURCES <= uids:
        raise AssertionError(
            f"dashboards missing: {sorted(DASHBOARDS - found)}, "
            f"data sources missing: {sorted(DATASOURCES - uids)}"
        )
    return "Grafana has the VaultGate dashboards and the Prometheus, Loki and Tempo sources"


def alertmanager() -> str:
    query = urllib.parse.urlencode({"query": "to:heartbeat@vaultgate.local"})
    found = get(f"{MAILPIT}/api/v1/search?{query}")
    if not found.get("messages_count"):
        raise AssertionError("no mail from Alertmanager in Mailpit yet")
    subject = found["messages"][0]["Subject"]
    return f"Alertmanager mailed its heartbeat to Mailpit ({subject!r})"


CHECKS = {"targets": targets, "grafana": grafana, "alertmanager": alertmanager}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in CHECKS:
        print(__doc__)
        return 2
    try:
        print(f"ok  {CHECKS[argv[0]]()}")
    except (AssertionError, OSError, ValueError, KeyError) as exc:
        print(f"not yet: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

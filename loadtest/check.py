"""Pass or fail a load run (M8, ADR 0011): `make load-smoke` runs it after Locust.

    python3 loadtest/check.py RESULTS_PREFIX [--prometheus URL] [--window 5m]

Reads Locust's RESULTS_PREFIX_stats.csv and asks the cluster's Prometheus about the same
minutes. The run fails when:

- any request failed (Locust counts timeouts, wrong status codes, short downloads and
  scans with no verdict as failures);
- a scenario did not do its work: Transfers no download, ControlPlane none of its API
  calls, Documents no document verdict (each checked by names only it produces);
- a gateway pod's resident memory came within 10% of its 256 MiB limit: streaming must
  keep it flat whatever the transfer sizes;
- a VaultGate pod restarted during the run (out of memory, failed probes).

Standard library only.
"""

import argparse
import csv
import json
import sys
import urllib.parse
import urllib.request

GATEWAY_LIMIT = 256 * 1024 * 1024
MEMORY_CEILING = 0.9 * GATEWAY_LIMIT
# What each scenario must have done, by request names only it produces: exact names, or
# a prefix (ending in a space) for the ones labelled by size or document type.
REQUIRED = {
    "Transfers": ["GET /downloads/{id} "],
    "ControlPlane": [
        "GET /me",
        "GET /files",
        "GET /files/{id}",
        "POST /files/{id}/download (intent only)",
    ],
    "Documents": ["upload → verdict document "],
}


def matches(name: str, wanted: str) -> bool:
    return name.startswith(wanted) if wanted.endswith(" ") else name == wanted


def query(prometheus: str, promql: str) -> float | None:
    url = f"{prometheus}/api/v1/query?{urllib.parse.urlencode({'query': promql})}"
    with urllib.request.urlopen(url, timeout=10) as response:
        result = json.loads(response.read())["data"]["result"]
    return max((float(r["value"][1]) for r in result), default=None)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("prefix")
    parser.add_argument("--prometheus", default="http://localhost:9090")
    parser.add_argument("--window", default="5m", help="how far back the run reaches")
    args = parser.parse_args(argv)

    with open(f"{args.prefix}_stats.csv", newline="") as f:
        rows = list(csv.DictReader(f))
    problems = []
    total = next(r for r in rows if r["Name"] == "Aggregated")
    failures, requests = int(total["Failure Count"]), int(total["Request Count"])
    if failures:
        problems.append(f"{failures} of {requests} requests failed")
    for scenario, names in REQUIRED.items():
        for wanted in names:
            done = sum(int(r["Request Count"]) for r in rows if matches(r["Name"], wanted))
            if not done:
                problems.append(f"{scenario}: no {wanted.strip()!r} request was made")

    try:
        memory = query(
            args.prometheus,
            f'max_over_time(process_resident_memory_bytes{{job="gateway"}}[{args.window}])',
        )
        restarts = query(
            args.prometheus,
            "sum(increase(kube_pod_container_status_restarts_total"
            f'{{namespace="vaultgate"}}[{args.window}]))',
        )
    except OSError as exc:
        print(f"FAIL Prometheus at {args.prometheus} did not answer: {exc}")
        return 1
    if memory is None:
        problems.append("no gateway memory samples in Prometheus")
    elif memory > MEMORY_CEILING:
        problems.append(f"gateway memory reached {memory / 2**20:.0f} MiB (limit 256 MiB)")
    if restarts:
        problems.append(f"VaultGate pods restarted {restarts:.0f} times")

    print(f"requests: {requests}, failed: {failures}")
    if memory is not None:
        print(f"gateway memory, highest: {memory / 2**20:.0f} MiB of 256 MiB")
    for problem in problems:
        print(f"FAIL {problem}")
    if not problems:
        print("ok  the load run passed")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

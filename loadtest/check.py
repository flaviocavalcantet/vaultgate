"""Pass or fail a load run (M8, ADR 0011): `make load-smoke` runs it after Locust.

    python3 loadtest/check.py RESULTS_PREFIX [--prometheus URL] [--window 5m]

Reads Locust's RESULTS_PREFIX_stats.csv and asks the cluster's Prometheus about the same
minutes. The run fails when:

- any request failed (Locust counts timeouts, wrong status codes, short downloads and
  scans with no verdict as failures);
- the scenario did not do its work: no upload, download, scan verdict or API read;
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
REQUIRED = ("PUT /uploads/", "GET /downloads/", "upload → verdict", "GET /files")


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
    for needed in REQUIRED:
        done = sum(int(r["Request Count"]) for r in rows if needed in r["Name"])
        if not done:
            problems.append(f"no {needed!r} request was made")

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

"""Write the load test report (M8, ADR 0011) from a full run: `make load-report`.

    python3 loadtest/report.py RESULTS_PREFIX [--prometheus URL] [--out docs]

Reads Locust's RESULTS_PREFIX_stats.csv and _stats_history.csv, asks the cluster's
Prometheus about the run's own minutes, and writes OUT/load-testing.md with its charts in
OUT/load-testing/*.svg (plain SVG, drawn here: no plotting library). The report states
where it was measured; it is regenerated, never edited by hand.

Standard library only.
"""

import argparse
import csv
import json
import math
import os
import platform
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check

MiB = 1024 * 1024
COLORS = ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2"]


# --- Prometheus ------------------------------------------------------------------------


def query_range(prometheus: str, promql: str, start: int, end: int, step: int = 15):
    """{series label: [(t, value), ...]} for a range query."""
    params = urllib.parse.urlencode({"query": promql, "start": start, "end": end, "step": step})
    with urllib.request.urlopen(f"{prometheus}/api/v1/query_range?{params}", timeout=30) as r:
        result = json.loads(r.read())["data"]["result"]
    series = {}
    for item in result:
        label = item["metric"].get("pod") or item["metric"].get("job") or "total"
        series[label] = [(float(t), float(v)) for t, v in item["values"]]
    return series


# --- SVG line charts -------------------------------------------------------------------


def nice_step(raw: float) -> float:
    """The smallest 1, 2 or 5 times a power of ten that is at least `raw`."""
    power = 10 ** math.floor(math.log10(raw))
    return next(m * power for m in (1, 2, 5, 10) if m * power >= raw)


def line_chart(title: str, series: dict, unit: str, start: float, ceiling: float | None = None):
    """A small, self-contained SVG line chart: minutes since the run's start on x."""
    width, height, left, right, top, bottom = 720, 260, 60, 170, 30, 40
    plot_w, plot_h = width - left - right, height - top - bottom
    points = [p for values in series.values() for p in values]
    end = max((t for t, _ in points), default=start + 60)
    step = nice_step(max([v for _, v in points] + ([ceiling] if ceiling else []) + [1e-9]) / 4)
    top_value = step * 5

    def x(t: float) -> float:
        return left + (t - start) / max(end - start, 1) * plot_w

    def y(v: float) -> float:
        return top + plot_h - v / top_value * plot_h

    out = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" font-family="sans-serif" font-size="11">'
        ),
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{left}" y="18" font-size="13" font-weight="bold">{title}</text>',
        (
            f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" '
            'stroke="#888"/>'
        ),
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#888"/>',
    ]
    for i in range(6):  # y grid and labels, on round numbers
        v = step * i
        out.append(
            f'<line x1="{left}" y1="{y(v):.1f}" x2="{left + plot_w}" y2="{y(v):.1f}" '
            'stroke="#eee"/>'
            f'<text x="{left - 6}" y="{y(v) + 4:.1f}" text-anchor="end">{v:.3g}</text>'
        )
    minutes = (end - start) / 60
    for i in range(int(minutes) + 1):  # x ticks every minute
        t = start + i * 60
        out.append(f'<text x="{x(t):.1f}" y="{top + plot_h + 16}" text-anchor="middle">{i}</text>')
    out.append(
        f'<text x="{left + plot_w / 2}" y="{height - 6}" text-anchor="middle">'
        f"minutes into the run</text>"
        f'<text x="14" y="{top + plot_h / 2}" transform="rotate(-90 14 {top + plot_h / 2})" '
        f'text-anchor="middle">{unit}</text>'
    )
    if ceiling:
        out.append(
            f'<line x1="{left}" y1="{y(ceiling):.1f}" x2="{left + plot_w}" y2="{y(ceiling):.1f}" '
            'stroke="#dc2626" stroke-dasharray="4 3"/>'
            f'<text x="{left + plot_w - 4}" y="{y(ceiling) - 4:.1f}" text-anchor="end" '
            f'fill="#dc2626">limit {ceiling:.3g}</text>'
        )
    for i, (label, values) in enumerate(sorted(series.items())):
        color = COLORS[i % len(COLORS)]
        path = " ".join(f"{x(t):.1f},{y(v):.1f}" for t, v in values)
        out.append(f'<polyline fill="none" stroke="{color}" stroke-width="1.5" points="{path}"/>')
        ly = top + 14 * i + 6
        out.append(
            f'<rect x="{left + plot_w + 12}" y="{ly - 8}" width="10" height="3" fill="{color}"/>'
            f'<text x="{left + plot_w + 26}" y="{ly - 4}">{label[:22]}</text>'
        )
    out.append("</svg>")
    return "\n".join(out) + "\n"


# --- the report ------------------------------------------------------------------------

CHARTS = [
    # file, title, unit, promql, scale, ceiling
    (
        "gateway-memory",
        "Gateway resident memory, per pod",
        "MiB",
        'process_resident_memory_bytes{job="gateway"}',
        1 / MiB,
        256,
    ),
    (
        "gateway-cpu",
        "Gateway CPU, per pod (request 200m, HPA target 70%)",
        "cores",
        (
            'sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="vaultgate",'
            'container="gateway"}[1m]))'
        ),
        1,
        None,
    ),
    (
        "gateway-replicas",
        "Gateway pods (autoscaler on CPU, 1 to 3)",
        "pods",
        (
            'kube_deployment_status_replicas_available{namespace="vaultgate",'
            'deployment="vaultgate-gateway"}'
        ),
        1,
        None,
    ),
    (
        "throughput",
        "Bytes through the gateway",
        "MiB/s",
        (
            'label_replace(sum(rate(vaultgate_gateway_upload_bytes_total[1m])), "job", "uploads",'
            ' "", "") or label_replace(sum(rate(vaultgate_gateway_download_bytes_total[1m])),'
            ' "job", "downloads", "", "")'
        ),
        1 / MiB,
        None,
    ),
    (
        "scanner",
        "Scans in progress (one scanner pod, two at once)",
        "scans",
        "sum(vaultgate_scanner_jobs_in_progress)",
        1,
        None,
    ),
]


def stats_rows(prefix: str) -> list[dict]:
    with open(f"{prefix}_stats.csv", newline="") as f:
        return list(csv.DictReader(f))


def ms(value: str) -> str:
    try:
        v = float(value)
    except ValueError:
        return value
    return f"{v / 1000:.2f} s" if v >= 1000 else f"{v:.0f} ms"


def table(rows: list[dict], kinds: set[str]) -> list[str]:
    lines = [
        "| Request | Count | Failed | Median | p95 | p99 | Max | Per second |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in sorted((r for r in rows if r["Type"] in kinds), key=lambda r: r["Name"]):
        lines.append(
            f"| {r['Type']} {r['Name'].replace('|', '/')} | {r['Request Count']} | "
            f"{r['Failure Count']} | {ms(r['50%'])} | {ms(r['95%'])} | {ms(r['99%'])} | "
            f"{ms(r['Max Response Time'])} | {float(r['Requests/s']):.2f} |"
        )
    return lines


def machine() -> str:
    cpus = os.cpu_count()
    try:
        with open("/proc/meminfo") as f:
            mem = next(int(line.split()[1]) // 1024**2 for line in f if line.startswith("MemTotal"))
        memory = f", {mem} GiB of memory"
    except (OSError, StopIteration):
        memory = ""
    runner = "a GitHub-hosted runner" if os.getenv("GITHUB_ACTIONS") else "a local machine"
    return f"{runner} ({platform.system()} {platform.machine()}, {cpus} CPUs{memory})"


def commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("prefix")
    parser.add_argument("--prometheus", default="http://localhost:9090")
    parser.add_argument("--out", default="docs")
    parser.add_argument("--profile", default="", help="the Locust profile, for the report")
    args = parser.parse_args(argv)

    rows = stats_rows(args.prefix)
    with open(f"{args.prefix}_stats_history.csv", newline="") as f:
        history = list(csv.DictReader(f))
    start = min(int(r["Timestamp"]) for r in history)
    # The run's own minutes: its last sample, plus a scrape interval for Prometheus.
    end = max(int(r["Timestamp"]) for r in history) + 15
    total = next(r for r in rows if r["Name"] == "Aggregated")

    charts_dir = Path(args.out) / "load-testing"
    charts_dir.mkdir(parents=True, exist_ok=True)
    peaks = {}
    for name, title, unit, promql, scale, ceiling in CHARTS:
        series = query_range(args.prometheus, promql, start, end)
        scaled = {k: [(t, v * scale) for t, v in vs] for k, vs in series.items()}
        peaks[name] = max((v for vs in scaled.values() for _, v in vs), default=0)
        if name == "throughput":
            peaks["uploads"] = max((v for _, v in scaled.get("uploads", [])), default=0)
        (charts_dir / f"{name}.svg").write_text(line_chart(title, scaled, unit, start, ceiling))

    sizes = {"256 KiB": 0.25, "4 MiB": 4, "32 MiB": 32, "128 MiB": 128}
    moved = sum(
        int(r["Request Count"]) * mib
        for r in rows
        for label, mib in sizes.items()
        if r["Name"] in (f"PUT /uploads/{{id}} {label}", f"GET /downloads/{{id}} {label}")
    )
    minutes = (end - start) / 60
    verdict = check.main([args.prefix, "--prometheus", args.prometheus]) == 0

    md = [
        "# Load test report",
        "",
        "<!-- Generated by loadtest/report.py from a `make load-report` run; do not edit. -->",
        "",
        (
            f"Measured on {machine()}, against the local k3d cluster (ADR 0009, 0010), at "
            f"commit `{commit()}`, on {datetime.fromtimestamp(start, UTC):%Y-%m-%d %H:%M} UTC. "
            f"Profile: {args.profile or 'see the Makefile'}. Everything (the cluster, "
            "PostgreSQL, LocalStack, Keycloak, Prometheus and Locust itself) shares that one "
            "machine, so the numbers describe VaultGate's behaviour, where it saturates and what "
            "stays flat, not what production hardware would do. How the scenarios and the "
            "thresholds work: [ADR 0011](adr/0011-load-testing.md)."
        ),
        "",
        "## Summary",
        "",
        (
            f"- **{total['Request Count']} requests in {minutes:.1f} minutes, "
            f"{total['Failure Count']} failed.** Thresholds (`loadtest/check.py`): "
            f"{'passed' if verdict else 'FAILED'}."
        ),
        (
            f"- **{moved / 1024:.1f} GiB through the gateway** (uploads and downloads), up to "
            f"{peaks['uploads']:.0f} MiB/s of uploads."
        ),
        (
            f"- **Gateway memory peaked at {peaks['gateway-memory']:.0f} MiB per pod** (limit "
            "256 MiB), whatever the transfer sizes."
        ),
        (
            f"- **The gateway ran on up to {peaks['gateway-replicas']:.0f} pods**, its CPU "
            f"autoscaler reacting to the load (peak {peaks['gateway-cpu']:.2f} cores in one pod)."
        ),
        f"- **Up to {peaks['scanner']:.0f} scans ran at once** in the one scanner pod.",
        "",
        "## Requests",
        "",
        (
            "HTTP requests, as Locust measured them (client side, so including the network "
            "inside the cluster):"
        ),
        "",
        *table(rows, {"GET", "POST", "PUT"}),
        "",
        "## Time to a scan verdict",
        "",
        (
            "From the end of the upload to the scan's verdict, as the API reports it: the "
            "queue, the scanner reading and decrypting the object, extraction and detection, "
            "and the report back (polled every 250 ms)."
        ),
        "",
        *table(rows, {"SCAN"}),
        "",
        "## The gateway under load",
        "",
        "![Gateway memory](load-testing/gateway-memory.svg)",
        "",
        "![Gateway CPU](load-testing/gateway-cpu.svg)",
        "",
        "![Gateway pods](load-testing/gateway-replicas.svg)",
        "",
        "![Throughput](load-testing/throughput.svg)",
        "",
        "## The scanner",
        "",
        "![Scans in progress](load-testing/scanner.svg)",
        "",
        "## Reproducing it",
        "",
        "```bash",
        "pip install -r loadtest/requirements.txt",
        "make k3d-up",
        "make load-report    # the full run, then this report in docs/",
        "```",
        "",
    ]
    (Path(args.out) / "load-testing.md").write_text("\n".join(md))
    print(f"wrote {Path(args.out) / 'load-testing.md'} and {len(CHARTS)} charts")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

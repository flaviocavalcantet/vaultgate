"""Sanity checks for the provisioned Grafana dashboards.

Grafana loads broken dashboards silently (or not at all), so CI checks what it can
without a running Grafana: valid JSON, unique UIDs and panel IDs, and that every
panel uses one of the provisioned data sources by its fixed UID.
"""

import json
import sys
from pathlib import Path

DATASOURCE_UIDS = {"prometheus", "loki"}


def check(path: Path, seen_uids: set[str]) -> list[str]:
    errors = []
    dashboard = json.loads(path.read_text())
    uid = dashboard.get("uid")
    if not uid:
        errors.append("missing uid")
    elif uid in seen_uids:
        errors.append(f"duplicate dashboard uid {uid!r}")
    seen_uids.add(uid)

    panel_ids = set()
    for panel in dashboard.get("panels", []):
        title = panel.get("title", "?")
        if panel["id"] in panel_ids:
            errors.append(f"duplicate panel id {panel['id']} ({title})")
        panel_ids.add(panel["id"])
        if panel.get("type") == "row":
            continue
        sources = [panel.get("datasource")] + [
            t.get("datasource") for t in panel.get("targets", [])
        ]
        for source in sources:
            if not source or source.get("uid") not in DATASOURCE_UIDS:
                errors.append(f"panel {title!r} uses unknown data source {source!r}")
        if not panel.get("targets"):
            errors.append(f"panel {title!r} has no queries")
    return [f"{path}: {e}" for e in errors]


def main(directory: str) -> int:
    paths = sorted(Path(directory).glob("*.json"))
    if not paths:
        print(f"no dashboards found in {directory}", file=sys.stderr)
        return 1
    seen: set[str] = set()
    errors = [e for path in paths for e in check(path, seen)]
    for error in errors:
        print(error, file=sys.stderr)
    print(f"checked {len(paths)} dashboards, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

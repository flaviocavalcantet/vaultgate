"""Play the scanner worker's part: report a scan result for one file through the API's
internal scanner routes, exactly as the worker will.

Local testing only, until the scanner worker exists. The internal port is never
published, so this runs inside the API container, which also has the scanner secret
and the database URL. Copy it in, then run it:

    docker compose cp scripts/play_scanner.py api:/tmp/play_scanner.py
    docker compose exec api python /tmp/play_scanner.py FILE_ID payment_card=1 email=2
    docker compose exec api python /tmp/play_scanner.py FILE_ID              # clean
    docker compose exec api python /tmp/play_scanner.py FILE_ID --unscannable "PDF is encrypted"

It looks up the file's current scan request, fetches the scan job (what the worker
needs to read the object) and posts the result. Prints each answer from the API.
"""

import argparse
import asyncio
import json
import urllib.error
import urllib.request
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from vaultgate_api.config import settings
from vaultgate_api.models import File


async def scan_id_of(file_id: uuid.UUID) -> uuid.UUID | None:
    engine = create_async_engine(settings.database_url)
    try:
        async with engine.connect() as connection:
            return await connection.scalar(select(File.scan_id).where(File.id == file_id))
    finally:
        await engine.dispose()


def call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    token = settings.scanner_token.get_secret_value() if settings.scanner_token else ""
    request = urllib.request.Request(
        f"http://localhost:{settings.internal_port}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def finding(value: str) -> dict:
    kind, _, count = value.partition("=")
    return {"kind": kind, "count": int(count or 1)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file_id", type=uuid.UUID)
    parser.add_argument(
        "findings", nargs="*", type=finding, help="kind=count, e.g. payment_card=1 br_cpf=2"
    )
    parser.add_argument("--unscannable", metavar="REASON", help="report the file unscannable")
    args = parser.parse_args()

    scan_id = asyncio.run(scan_id_of(args.file_id))
    if scan_id is None:
        raise SystemExit("no scan for this file: it is unknown or not uploaded yet")
    status, job = call("GET", f"/internal/scans/{scan_id}")
    job.pop("wrapped_key", None)
    print(f"scan job: {status} {json.dumps(job)}")
    result = {
        "outcome": "unscannable" if args.unscannable else "scanned",
        "findings": args.findings,
        "reason": args.unscannable,
    }
    status, answer = call("POST", f"/internal/scans/{scan_id}/result", result)
    print(f"result:   {status} {json.dumps(answer)}")


if __name__ == "__main__":
    main()

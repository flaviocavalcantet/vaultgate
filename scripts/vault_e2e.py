"""End-to-end check of the vault: real login, API, gateway, KMS and S3.

Logs in as alice and bob through Keycloak (the same PKCE flow as keycloak_smoke.py),
then, as alice:

1. registers a file with the API and streams it to the gateway with the upload token;
2. checks the API shows it uploaded with the right size and SHA-256;
3. reads the stored object straight from S3 and checks it is a VGE1 ciphertext of the
   expected size that does not contain the plaintext;
4. waits for the scanner worker's verdict (clean: random bytes hold no card or CPF),
   then asks for a download intent, streams the file back and compares bytes and digest;
5. checks that upload and download tokens are single use, that bob cannot get a
   download intent for alice's file, and that an upload with the wrong size is
   refused and marks the file failed;
6. as carol (admin), adds temporary deny policies and checks that the API refuses,
   that the gateway refuses an intent issued before the policy (and that the refused
   intent stays usable), that the gateway reports a known client address, and that
   deny wins over the seeded allow policy. The `e2e:` policies are always removed;
7. shares the file with an external address: the recipient gets a code by email
   (from Mailpit), verifies it, downloads the file through the gateway (counted against
   the share), and loses access when alice revokes the link; shares it with bob as a
   VaultGate user, who finds it under /shared-with-me and downloads it while carol
   can't; shares a folder with bob, who lists it and downloads a file inside it, until
   alice moves the file out. Then it checks the other
   verdicts and quarantine, and finally that the audit log holds the file's history and
   its hash chain verifies: a text with a test card number and CPFs
   is quarantined with those counts and cannot be downloaded until carol releases it,
   a rescan puts it back in quarantine, and an encrypted PDF is unscannable with the
   reason. Last, alice deletes a file: the API forgets it at once, and the gateway
   deletes its object from S3 and says so in the audit log;
8. finds the upload's trace in Tempo and checks that it runs from the gateway through
   the API and the scan queue to the scanner worker, and that Loki holds log lines
   from all three services under its trace_id.

    python3 scripts/vault_e2e.py [--keycloak URL] [--api URL] [--s3 URL] [--bucket NAME]
                                 [--mailpit URL] [--tempo URL] [--loki URL]
                                 [--skip-traces]

Needs the bucket, KMS key and scan queue from `make tf-local`, the scanner worker, and the seeded allow policy from
scripts/seed_policies.py (`make vault-check` does both). Standard library only, so it
runs in CI without installing anything. The S3 read is unsigned, which LocalStack accepts;
it is a test of the local stack, not something that works against AWS.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from keycloak_smoke import login, wait_for, wait_for_api

# Names are unique in a folder (ADR 0020): this run's files carry its own prefix, so a
# rerun against the same cluster doesn't clash with the last one's.
RUN = os.urandom(4).hex()

MiB = 1024 * 1024
ROOT = Path(__file__).resolve().parent.parent
E2E_POLICY = "e2e: "  # prefix of the temporary policies this check creates
# VGE1 framing (ADR 0003): 16-byte header, 64 KiB chunks, 16-byte tag per chunk.
VGE1_HEADER, VGE1_CHUNK, VGE1_TAG = 16, 64 * 1024, 16


def ciphertext_size(size: int) -> int:
    return VGE1_HEADER + size + max(1, -(-size // VGE1_CHUNK)) * VGE1_TAG


def api_call(api: str, method: str, path: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{api}{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        return error.code, None


def add_policy(api: str, admin: str, name: str, **fields) -> str:
    body = {"name": E2E_POLICY + name, "effect": "deny", "actions": ["download"]} | fields
    status, created = api_call(api, "POST", "/admin/policies", admin, body)
    assert status == 201, f"creating policy {name!r}: {status}"
    return created["id"]


def remove_policy(api: str, admin: str, policy_id: str) -> None:
    status, _ = api_call(api, "DELETE", f"/admin/policies/{policy_id}", admin)
    assert status in (204, 404), f"deleting policy: {status}"


def remove_e2e_policies(api: str, admin: str) -> None:
    status, page = api_call(api, "GET", "/admin/policies?limit=100", admin)
    assert status == 200, f"listing policies: {status}"
    for policy in page["items"]:
        if policy["name"].startswith(E2E_POLICY):
            remove_policy(api, admin, policy["id"])


def _connection(url: str) -> tuple[http.client.HTTPConnection, str]:
    """A connection for the gateway URL in an intent: https on the cluster (verified
    against the default trust store, which SSL_CERT_FILE replaces), http under compose."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return http.client.HTTPSConnection(parts.hostname, parts.port, timeout=60), parts.path
    return http.client.HTTPConnection(parts.hostname, parts.port, timeout=60), parts.path


def upload(url: str, token: str, pieces, size: int) -> tuple[int, dict | None]:
    """PUT the pieces as one body with a fixed Content-Length, streamed."""
    connection, path = _connection(url)
    connection.request(
        "PUT",
        path,
        body=pieces,
        headers={"Authorization": f"Bearer {token}", "Content-Length": str(size)},
    )
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, json.loads(body) if response.status == 201 else None


def download(url: str, token: str, form: bool = False) -> tuple[int, dict, str, int]:
    """GET and hash the body as it streams; returns status, headers, sha256, size.
    With `form`, as a browser's page does it (M12.5, ADR 0018): the token in a POSTed
    form, which the browser's own downloader follows."""
    connection, path = _connection(url)
    if form:
        connection.request(
            "POST",
            path,
            body=urllib.parse.urlencode({"token": token}),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    else:
        connection.request("GET", path, headers={"Authorization": f"Bearer {token}"})
    response = connection.getresponse()
    digest, size = hashlib.sha256(), 0
    while piece := response.read(MiB):
        digest.update(piece)
        size += len(piece)
    connection.close()
    return response.status, dict(response.getheaders()), digest.hexdigest(), size


def random_pieces(size: int, digest, first: list):
    """Random bytes in 1 MiB pieces, hashed as they are produced; keeps the first."""
    sent = 0
    while sent < size:
        piece = os.urandom(min(MiB, size - sent))
        digest.update(piece)
        if not first:
            first.append(piece)
        sent += len(piece)
        yield piece


def run(args) -> None:
    discovery = wait_for(args.keycloak)
    wait_for_api(args.api)
    alice = login(discovery, "alice", "alice-dev-password")["access_token"]
    bob = login(discovery, "bob", "bob-dev-password")["access_token"]
    carol = login(discovery, "carol", "carol-dev-password")["access_token"]
    size = args.size_mib * MiB
    remove_e2e_policies(args.api, carol)  # left over from an interrupted run

    # 1. Register and upload.
    status, created = api_call(
        args.api, "POST", "/files", alice, {"name": f"{RUN}-e2e-relatório.bin", "size": size}
    )
    assert status == 201, f"POST /files: {status} (403: run scripts/seed_policies.py first)"
    file_id, upload_intent = created["file"]["id"], created["upload"]
    digest, first = hashlib.sha256(), []
    started = time.monotonic()
    status, result = upload(
        upload_intent["url"], upload_intent["token"], random_pieces(size, digest, first), size
    )
    elapsed = time.monotonic() - started
    sha256 = digest.hexdigest()
    assert status == 201, f"upload: {status}"
    assert result == {"file_id": file_id, "size": size, "sha256": sha256}, result
    print(f"ok  upload: {args.size_mib} MiB in {elapsed:.1f}s")

    # 2. The API recorded it.
    status, file = api_call(args.api, "GET", f"/files/{file_id}", alice)
    assert status == 200 and file["status"] == "uploaded", (status, file)
    assert file["size"] == size and file["sha256"] == sha256, file
    print("ok  API shows the file uploaded with the right size and SHA-256")
    assert file["scan"]["verdict"] in ("pending", "clean"), file  # the worker may be done
    print("ok  the upload has a PII scan")

    # 3. What is in S3 is ciphertext.
    object_url = f"{args.s3}/{args.bucket}/files/{file_id}"
    with urllib.request.urlopen(object_url) as response:
        stored = response.read()
    assert stored[:4] == b"VGE1", stored[:16]
    assert len(stored) == ciphertext_size(size), (len(stored), ciphertext_size(size))
    assert first[0][:4096] not in stored, "plaintext found in the stored object"
    print(f"ok  S3 object is VGE1 ciphertext ({len(stored)} bytes), no plaintext")

    # 4. Download it back, once the scan says it is clean.
    scan = scan_result(args.api, alice, file_id)
    assert scan["verdict"] == "clean", scan
    print("ok  scan: the random file is clean")
    status, intent = api_call(args.api, "POST", f"/files/{file_id}/download", alice)
    assert status == 201, f"POST /files/{{id}}/download: {status}"
    started = time.monotonic()
    status, headers, got_sha256, got_size = download(intent["url"], intent["token"])
    elapsed = time.monotonic() - started
    assert status == 200, f"download: {status}"
    assert (got_size, got_sha256) == (size, sha256), "downloaded bytes differ"
    expected_digest = base64.b64encode(bytes.fromhex(sha256)).decode()
    assert headers["Repr-Digest"] == f"sha-256=:{expected_digest}:", headers
    assert headers["Content-Disposition"].startswith("attachment;"), headers
    assert "relat%C3%B3rio" in headers["Content-Disposition"], headers
    print(f"ok  download: identical bytes and Repr-Digest in {elapsed:.1f}s")

    # 5. Refusals.
    status, _ = upload(upload_intent["url"], upload_intent["token"], [b"x"], 1)
    assert status == 403, f"upload token reused: {status}"
    status, *_ = download(intent["url"], intent["token"])
    assert status == 403, f"download token reused: {status}"
    print("ok  upload and download tokens are single use")

    status, _ = api_call(args.api, "POST", f"/files/{file_id}/download", bob)
    assert status == 404, f"bob got a download intent for alice's file: {status}"
    print("ok  bob cannot download alice's file")

    body = {"name": f"{RUN}-short.bin", "size": 10}
    status, short = api_call(args.api, "POST", "/files", alice, body)
    assert status == 201, status
    connection, path = _connection(short["upload"]["url"])
    connection.request(
        "PUT",
        path,
        body=b"12345",
        headers={"Authorization": f"Bearer {short['upload']['token']}"},
    )
    response = connection.getresponse()
    response.read()
    assert response.status == 400, f"wrong-size upload: {response.status}"
    status, file = api_call(args.api, "GET", f"/files/{short['file']['id']}", alice)
    assert file["status"] == "failed", file
    print("ok  an upload with the wrong size is refused and the file marked failed")

    # 6. Access policies, on top of the seeded allow-everyone policy.
    try:
        check_policies(args, file_id, sha256, alice, bob, carol)
    finally:
        remove_e2e_policies(args.api, carol)

    # 7. Share links, PII scans by the worker, quarantine, and the audit log.
    check_shares(args, file_id, sha256, alice)
    check_internal_share(args.api, file_id, sha256, alice, bob, carol)
    check_folder_share(args.api, alice, bob)
    check_scans(args, alice, carol)
    check_audit(args.api, file_id, carol)
    check_deletion(args, alice, carol)

    # 8. Traces, linked to the logs.
    if args.skip_traces:
        print("--  traces not checked (--skip-traces)")
    else:
        check_traces(args, file_id)


# The upload's trace, hop by hop (ADR 0008).
UPLOAD_TRACE = {
    ("gateway", "PUT /uploads/{upload_id}"),
    ("gateway", "api consume upload"),
    ("api", "POST /internal/intents/consume"),
    ("gateway", "api complete"),
    ("api", "POST /internal/files/{file_id}/complete"),
    ("api", "scan request send"),
    ("scanner", "scan"),
    ("api", "GET /internal/scans/{scan_id}"),
    ("api", "POST /internal/scans/{scan_id}/result"),
}


def get_json(url: str, params: dict | None = None):
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read())


def eventually(check, timeout: float = 90, what: str = ""):
    """Retry check() until it returns something truthy: spans and log lines reach
    Tempo and Loki in batches, seconds after the fact."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            if result := check():
                return result
        except (OSError, ValueError, KeyError):
            pass
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(3)


def trace_spans(tempo: str, trace_id: str) -> set[tuple[str, str]]:
    found = set()
    for batch in get_json(f"{tempo}/api/v2/traces/{trace_id}")["trace"]["resourceSpans"]:
        attributes = {a["key"]: a["value"] for a in batch["resource"]["attributes"]}
        service = attributes["service.name"]["stringValue"]
        for scope in batch["scopeSpans"]:
            found |= {(service, span["name"]) for span in scope["spans"]}
    return found


def check_traces(args, file_id: str) -> None:
    now = int(time.time())
    # The upload that succeeded: step 5 also sent a PUT for this file (its spent token,
    # refused), which is a trace of its own that never reaches the scanner.
    query = (
        f'{{ resource.service.name = "gateway" && name = "PUT /uploads/{{upload_id}}" '
        f'&& span.vaultgate.file_id = "{file_id}" && span.http.response.status_code = 201 }}'
    )

    def upload_trace() -> str | None:
        found = get_json(
            f"{args.tempo}/api/search", {"q": query, "start": now - 3600, "end": now + 3600}
        )["traces"]
        # Tempo's search drops leading zeros from trace IDs; log lines carry all 32 hex
        # digits, and Loki matches them as text.
        return found[0]["traceID"].rjust(32, "0") if found else None

    trace_id = eventually(upload_trace, what="the upload's trace in Tempo")
    spans = eventually(
        lambda: (s := trace_spans(args.tempo, trace_id)) >= UPLOAD_TRACE and s,
        what=f"every hop of trace {trace_id}",
    )
    services = sorted({service for service, _ in spans})
    print(f"ok  trace {trace_id}: gateway -> API -> queue -> scanner ({len(spans)} span names)")
    assert services == ["api", "gateway", "scanner"], services

    def logged_services() -> set[str]:
        result = get_json(
            f"{args.loki}/loki/api/v1/query_range",
            {
                "query": f'{{service=~"api|gateway|scanner"}} | trace_id = "{trace_id}"',
                "start": (now - 3600) * 10**9,
                "end": (now + 3600) * 10**9,
                "limit": 1000,
            },
        )["data"]["result"]
        found = {stream["stream"]["service"] for stream in result}
        return found if found >= {"api", "gateway", "scanner"} else set()

    eventually(logged_services, what=f"log lines of all three services for trace {trace_id}")
    print("ok  Loki has log lines from the gateway, API and scanner under the trace's ID")


def check_audit(api: str, file_id: str, carol: str) -> None:
    status, page = api_call(api, "GET", f"/admin/audit?target_id={file_id}&limit=100", carol)
    assert status == 200, f"audit: {status}"
    actions = {e["action"] for e in page["items"]}
    expected = {
        "file.registered",
        "upload.completed",
        "scan.result",
        "download.started",
        "share.created",
        "share.downloaded",
        "share.revoked",
    }
    assert expected <= actions, sorted(expected - actions)
    status, verified = api_call(api, "POST", "/admin/audit/verify", carol)
    assert status == 200 and verified["ok"], verified
    print(
        f"ok  audit: the file's history is recorded and the chain of {verified['events']} events verifies"
    )


def check_deletion(args, alice: str, carol: str) -> None:
    """A deleted file is gone from the API at once, and its object from S3 once the
    gateway's deletion worker has run (every 30 s), which it records (ADR 0020)."""
    api = args.api
    file_id = upload_bytes(api, alice, f"{RUN}-deleted.bin", os.urandom(1024))
    object_url = f"{args.s3}/{args.bucket}/files/{file_id}"
    with urllib.request.urlopen(object_url) as response:
        assert response.status == 200
    status, _ = api_call(api, "DELETE", f"/files/{file_id}", alice)
    assert status == 204, f"DELETE /files: {status}"
    status, _ = api_call(api, "GET", f"/files/{file_id}", alice)
    assert status == 404, f"a deleted file is still listed: {status}"
    print("ok  a deleted file is gone from the API at once")

    def object_gone() -> bool:
        try:
            urllib.request.urlopen(object_url).close()
        except urllib.error.HTTPError as error:
            return error.code == 404
        return False

    def confirmed() -> bool:
        path = f"/admin/audit?target_id={file_id}&action=file.object_deleted"
        status, page = api_call(api, "GET", path, carol)
        return status == 200 and any(e["actor_kind"] == "gateway" for e in page["items"])

    deadline = time.monotonic() + 90
    while not (object_gone() and confirmed()):
        assert time.monotonic() < deadline, "the gateway did not delete the object in 90 s"
        time.sleep(3)
    print("ok  the gateway deleted its object from S3 and recorded it")


def upload_bytes(api: str, token: str, name: str, data: bytes) -> str:
    status, created = api_call(api, "POST", "/files", token, {"name": name, "size": len(data)})
    assert status == 201, status
    status, _ = upload(created["upload"]["url"], created["upload"]["token"], [data], len(data))
    assert status == 201, f"upload of {name}: {status}"
    return created["file"]["id"]


def scan_result(api: str, token: str, file_id: str, timeout: float = 120) -> dict:
    """The file's scan once it has a verdict other than pending."""
    deadline = time.monotonic() + timeout
    while True:
        status, file = api_call(api, "GET", f"/files/{file_id}", token)
        assert status == 200, status
        if file["scan"]["verdict"] != "pending":
            return file["scan"]
        assert time.monotonic() < deadline, f"no scan result after {timeout:.0f}s: {file}"
        time.sleep(1)


def mailpit_code(mailpit: str, to: str, after: set[str], timeout: float = 30) -> tuple[str, str]:
    """The newest code Mailpit caught for an address, from a message not in `after`."""
    deadline = time.monotonic() + timeout
    while True:
        with urllib.request.urlopen(f"{mailpit}/api/v1/messages?limit=50") as response:
            messages = json.load(response)["messages"]
        for m in messages:  # newest first
            if m["ID"] not in after and any(t["Address"] == to for t in m["To"]):
                return m["ID"], m["Subject"].rsplit(" ", 1)[-1]
        assert time.monotonic() < deadline, f"no email to {to} after {timeout:.0f}s"
        time.sleep(0.5)


def mailpit_ids(mailpit: str) -> set[str]:
    with urllib.request.urlopen(f"{mailpit}/api/v1/messages?limit=50") as response:
        return {m["ID"] for m in json.load(response)["messages"]}


def public_call(api: str, method: str, path: str, body: dict | None = None):
    """A call with no token: the share link's own token authorizes it."""
    request = urllib.request.Request(
        f"{api}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        return error.code, None


def check_shares(args, file_id: str, sha256: str, alice: str) -> None:
    api, recipient = args.api, "bob.external@example.com"
    status, created = api_call(
        api, "POST", f"/files/{file_id}/shares", alice, {"recipient_email": recipient}
    )
    assert status == 201, f"share: {status}"
    share, token = created["share"], created["token"]
    assert share["recipient_email"] == recipient and share["state"] == "active", share
    assert f"token={token}" in created["url"], created["url"]

    # The recipient: no account; the link and a code sent to the address.
    query = urllib.parse.urlencode({"token": token})
    status, described = public_call(api, "GET", f"/shares/access?{query}")
    assert status == 200 and described["recipient_hint"] == "b***@example.com", described
    seen = mailpit_ids(args.mailpit)
    status, _ = public_call(api, "POST", "/shares/access/code", {"token": token})
    assert status == 202, f"code: {status}"
    _, code = mailpit_code(args.mailpit, recipient, seen)
    status, _ = public_call(
        api,
        "POST",
        "/shares/access/verify",
        {"token": token, "code": "000000" if code != "000000" else "111111"},
    )
    assert status == 403, f"wrong code: {status}"
    status, verified = public_call(
        api, "POST", "/shares/access/verify", {"token": token, "code": code}
    )
    assert status == 200, f"verify: {status}"
    grant = verified["grant"]
    status, intent = public_call(
        api, "POST", "/shares/access/downloads", {"token": token, "grant": grant}
    )
    assert status == 201, f"share download intent: {status}"
    # The recipient's page would hand this to the browser: a form, not a header.
    status, headers, got_sha256, _ = download(intent["url"], intent["token"], form=True)
    assert (status, got_sha256) == (200, sha256), (status, got_sha256)
    assert headers.get("Content-Disposition", "").startswith("attachment;"), headers
    status, listed = api_call(api, "GET", f"/files/{file_id}/shares", alice)
    [counted] = [s for s in listed if s["id"] == share["id"]]
    assert counted["downloads"] == 1, counted
    print(
        "ok  shares: an external recipient proves the address by email code and downloads, "
        "as a browser does (the token in a form)"
    )

    path = f"/files/{file_id}/shares/{share['id']}"
    assert api_call(api, "DELETE", path, alice)[0] == 204, "revoke"
    status, _ = public_call(
        api, "POST", "/shares/access/downloads", {"token": token, "grant": grant}
    )
    assert status == 410, f"download after revoke: {status}"
    print("ok  shares: a revoked link stops working at once")


def check_internal_share(
    api: str, file_id: str, sha256: str, alice: str, bob: str, carol: str
) -> None:
    status, created = api_call(
        api,
        "POST",
        f"/files/{file_id}/shares",
        alice,
        {"recipient_email": "bob@example.com", "recipient_kind": "internal"},
    )
    assert status == 201, f"internal share: {status}"
    share_id = created["share"]["id"]
    status, listed = api_call(api, "GET", "/shared-with-me", bob)
    assert status == 200, f"shared-with-me: {status}"
    [item] = [i for i in listed if i["share_id"] == share_id]
    assert item["shared_by"] == "alice" and item["available"], item
    status, intent = api_call(api, "POST", f"/shared-with-me/{share_id}/download", bob)
    assert status == 201, f"internal share download intent: {status}"
    status, _, got_sha256, _ = download(intent["url"], intent["token"])
    assert (status, got_sha256) == (200, sha256), (status, got_sha256)
    status, listed = api_call(api, "GET", "/shared-with-me", carol)
    assert status == 200 and share_id not in {i["share_id"] for i in listed}, listed
    status, _ = api_call(api, "POST", f"/shared-with-me/{share_id}/download", carol)
    assert status == 404, f"carol downloaded bob's share: {status}"
    assert api_call(api, "DELETE", f"/files/{file_id}/shares/{share_id}", alice)[0] == 204
    print("ok  shares: bob, signed in with his verified email, downloads a file shared with him")


def check_folder_share(api: str, alice: str, bob: str) -> None:
    """A folder shared with bob: he lists it and downloads a file in a subfolder through
    the gateway; moved out of the folder, the file is no longer his (ADR 0020)."""
    status, top = api_call(api, "POST", "/folders", alice, {"name": f"{RUN}-shared"})
    assert status == 201, f"POST /folders: {status}"
    body = {"name": "inner", "parent_id": top["id"]}
    status, inner = api_call(api, "POST", "/folders", alice, body)
    assert status == 201, f"POST /folders (inner): {status}"
    data = os.urandom(2048)
    file_id = upload_bytes(api, alice, f"{RUN}-in-folder.bin", data)
    status, _ = api_call(api, "PATCH", f"/files/{file_id}", alice, {"folder_id": inner["id"]})
    assert status == 200, f"PATCH /files: {status}"
    assert scan_result(api, alice, file_id)["verdict"] == "clean"
    status, created = api_call(
        api,
        "POST",
        f"/folders/{top['id']}/shares",
        alice,
        {"recipient_email": "bob@example.com", "recipient_kind": "internal"},
    )
    assert status == 201, f"folder share: {status}"
    share_id = created["share"]["id"]
    status, listing = api_call(
        api, "GET", f"/shared-with-me/{share_id}/contents?folder_id={inner['id']}", bob
    )
    assert status == 200 and [f["id"] for f in listing["files"]] == [file_id], listing
    path = f"/shared-with-me/{share_id}/download?file_id={file_id}"
    status, intent = api_call(api, "POST", path, bob)
    assert status == 201, f"folder share download intent: {status}"
    status, _, got_sha256, _ = download(intent["url"], intent["token"])
    assert (status, got_sha256) == (200, hashlib.sha256(data).hexdigest()), status
    status, intent = api_call(api, "POST", path, bob)
    assert status == 201, f"second intent: {status}"
    status, _ = api_call(api, "PATCH", f"/files/{file_id}", alice, {"folder_id": None})
    assert status == 200, f"moving the file out: {status}"
    status, _, _, _ = download(intent["url"], intent["token"])
    assert status == 403, f"a file moved out of the folder was still served: {status}"
    assert api_call(api, "DELETE", f"/folders/{top['id']}", alice)[0] == 204
    print("ok  shares: bob downloads a file inside a folder shared with him, until it is moved out")


def check_scans(args, alice: str, carol: str) -> None:
    api = args.api
    # Well-known test values, valid by their check digits.
    text = b"Card 4111 1111 1111 1111, CPF 529.982.247-25 and 111.444.777-35.\n"
    pii = upload_bytes(api, alice, f"{RUN}-pii.txt", text)
    scan = scan_result(api, alice, pii)
    findings = {f["kind"]: f["count"] for f in scan["findings"]}
    assert scan["verdict"] == "quarantined", scan
    assert findings == {"payment_card": 1, "br_cpf": 2}, findings
    print("ok  scan: a card number and two CPFs quarantine the file")

    status, _ = api_call(api, "POST", f"/files/{pii}/download", alice)
    assert status == 409, f"download of a quarantined file: {status}"
    status, listed = api_call(api, "GET", "/admin/files?verdict=quarantined&limit=100", carol)
    assert status == 200 and pii in {f["id"] for f in listed["items"]}, status
    status, _ = api_call(api, "POST", f"/admin/files/{pii}/release", alice, {"reason": "mine"})
    assert status == 403, f"alice released her own file: {status}"
    status, released = api_call(
        api, "POST", f"/admin/files/{pii}/release", carol, {"reason": "e2e: test values"}
    )
    assert status == 200 and released["downloadable"], (status, released)
    status, intent = api_call(api, "POST", f"/files/{pii}/download", alice)
    assert status == 201, f"download after release: {status}"
    status, _, _, size = download(intent["url"], intent["token"])
    assert (status, size) == (200, len(text)), (status, size)
    print("ok  quarantine: no download until an admin releases the file, then it works")
    share = {"recipient_email": "e2e@example.com"}
    status, _ = api_call(api, "POST", f"/files/{pii}/shares", alice, share)
    assert status == 409, f"share of a file released for download only: {status}"
    print("ok  quarantine: a release for download does not let the file be shared")

    status, _ = api_call(api, "POST", f"/admin/files/{pii}/rescan", carol)
    assert status == 202, f"rescan: {status}"
    scan = scan_result(api, alice, pii)
    assert scan["verdict"] == "quarantined" and scan["releases"] == [], scan
    status, _ = api_call(api, "POST", f"/files/{pii}/download", alice)
    assert status == 409, f"download after a rescan: {status}"
    print("ok  quarantine: a rescan ends the release")

    encrypted = (ROOT / "scanner/internal/extract/testdata/encrypted.pdf").read_bytes()
    locked = upload_bytes(args.api, alice, f"{RUN}-locked.pdf", encrypted)
    scan = scan_result(args.api, alice, locked)
    assert scan["verdict"] == "unscannable" and scan["reason"] == "PDF is encrypted", scan
    print("ok  scan: an encrypted PDF is unscannable, with the reason")


def check_policies(args, file_id: str, sha256: str, alice: str, bob: str, carol: str) -> None:
    api, path = args.api, f"/files/{file_id}/download"

    deny = add_policy(api, carol, "no finance downloads", groups=["/finance"])
    status, _ = api_call(api, "POST", path, alice)
    assert status == 403, f"download intent despite a deny policy: {status}"
    remove_policy(api, carol, deny)
    print("ok  policies: the API refuses a download a deny policy covers")

    # An intent issued while allowed is refused by the gateway once a deny applies,
    # and stays usable: the refusal does not spend it.
    status, intent = api_call(api, "POST", path, alice)
    assert status == 201, status
    deny = add_policy(api, carol, "no finance downloads", groups=["/finance"])
    status, *_ = download(intent["url"], intent["token"])
    assert status == 403, f"gateway served a download a deny policy covers: {status}"
    remove_policy(api, carol, deny)
    status, _, got_sha256, _ = download(intent["url"], intent["token"])
    assert (status, got_sha256) == (200, sha256), status
    print("ok  policies: the gateway re-checks, and a refused intent stays usable")

    # Excluding every network denies only an unknown client address, so this passes
    # only if the gateway reports the address it saw.
    deny = add_policy(api, carol, "unknown address", excluded_networks=["0.0.0.0/0", "::/0"])
    status, intent = api_call(api, "POST", path, alice)
    assert status == 201, status
    status, *_ = download(intent["url"], intent["token"])
    assert status == 200, f"gateway did not report a client address: {status}"
    remove_policy(api, carol, deny)
    print("ok  policies: the gateway reports the client address it saw")

    add_policy(api, carol, "finance may not list", actions=["read"], groups=["/finance"])
    assert api_call(api, "GET", "/files", alice)[0] == 403, "deny did not win over allow"
    assert api_call(api, "GET", "/files", bob)[0] == 200, "a deny for /finance hit /legal"
    print("ok  policies: deny wins over allow, for the groups it names only")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keycloak", default="http://localhost:8080")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--s3", default="http://localhost:4566")
    parser.add_argument("--bucket", default="vaultgate-local-vault")
    parser.add_argument("--mailpit", default="http://localhost:8025")
    parser.add_argument("--tempo", default="http://localhost:3200")
    parser.add_argument("--loki", default="http://localhost:3100")
    parser.add_argument("--skip-traces", action="store_true", help="a stack without Tempo and Loki")
    parser.add_argument("--size-mib", type=int, default=20)
    args = parser.parse_args(argv)
    for name in ("keycloak", "api", "s3", "mailpit", "tempo", "loki"):
        setattr(args, name, getattr(args, name).rstrip("/"))
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

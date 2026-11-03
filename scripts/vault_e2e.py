"""End-to-end check of the vault: real login, API, gateway, KMS and S3.

Logs in as alice and bob through Keycloak (the same PKCE flow as keycloak_smoke.py),
then, as alice:

1. registers a file with the API and streams it to the gateway with the upload token;
2. checks the API shows it uploaded with the right size and SHA-256;
3. reads the stored object straight from S3 and checks it is a VGE1 ciphertext of the
   expected size that does not contain the plaintext;
4. asks for a download intent, streams the file back and compares bytes and digest;
5. checks that upload and download tokens are single use, that bob cannot get a
   download intent for alice's file, and that an upload with the wrong size is
   refused and marks the file failed;
6. as carol (admin), adds temporary deny policies and checks that the API refuses,
   that the gateway refuses an intent issued before the policy (and that the refused
   intent stays usable), that the gateway reports a known client address, and that
   deny wins over the seeded allow policy. The `e2e:` policies are always removed;
7. waits for the scanner worker's verdicts: the random file is clean, a text with a
   test card number and CPF is quarantined with those counts, and an encrypted PDF
   is unscannable with the reason.

    python3 scripts/vault_e2e.py [--keycloak URL] [--api URL] [--s3 URL] [--bucket NAME]

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
    parts = urllib.parse.urlsplit(url)
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


def download(url: str, token: str) -> tuple[int, dict, str, int]:
    """GET and hash the body as it streams; returns status, headers, sha256, size."""
    connection, path = _connection(url)
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
        args.api, "POST", "/files", alice, {"name": "e2e-relatório.bin", "size": size}
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

    # 4. Download it back.
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

    status, short = api_call(args.api, "POST", "/files", alice, {"name": "short.bin", "size": 10})
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

    # 7. PII scans by the worker.
    check_scans(args, file_id, alice)


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


def check_scans(args, random_file: str, alice: str) -> None:
    scan = scan_result(args.api, alice, random_file)
    assert scan["verdict"] == "clean", scan
    print("ok  scan: the random file is clean")

    # Well-known test values, valid by their check digits.
    text = b"Card 4111 1111 1111 1111, CPF 529.982.247-25 and 111.444.777-35.\n"
    scan = scan_result(args.api, alice, upload_bytes(args.api, alice, "pii.txt", text))
    findings = {f["kind"]: f["count"] for f in scan["findings"]}
    assert scan["verdict"] == "quarantined", scan
    assert findings == {"payment_card": 1, "br_cpf": 2}, findings
    print("ok  scan: a card number and two CPFs quarantine the file")

    encrypted = (ROOT / "scanner/internal/extract/testdata/encrypted.pdf").read_bytes()
    scan = scan_result(args.api, alice, upload_bytes(args.api, alice, "locked.pdf", encrypted))
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
    parser.add_argument("--size-mib", type=int, default=20)
    args = parser.parse_args(argv)
    for name in ("keycloak", "api", "s3"):
        setattr(args, name, getattr(args, name).rstrip("/"))
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

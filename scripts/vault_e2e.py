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
   refused and marks the file failed.

    python3 scripts/vault_e2e.py [--keycloak URL] [--api URL] [--s3 URL] [--bucket NAME]

Needs the bucket and KMS key from `make tf-local`. Standard library only, so it runs
in CI without installing anything. The S3 read is unsigned, which LocalStack accepts;
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

from keycloak_smoke import login, wait_for, wait_for_api

MiB = 1024 * 1024
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
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, None


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
    size = args.size_mib * MiB

    # 1. Register and upload.
    status, created = api_call(
        args.api, "POST", "/files", alice, {"name": "e2e-relatório.bin", "size": size}
    )
    assert status == 201, f"POST /files: {status}"
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

"""VaultGate load scenarios (M8, ADR 0011), run by `make load-test` and `make load-smoke`.

Three kinds of simulated user, each logged in as its own load user (load-001 ...)
through the local-only `vaultgate-load` client:

- Transfers: streams uploads of mixed sizes through the gateway, waits for the scan's
  verdict (reported as SCAN "upload → verdict"), then downloads the file back and
  checks its size. The gateway's throughput, latency and memory under concurrent
  transfers.
- ControlPlane: the API's small requests: who am I, list and read files, issue
  download intents (policy evaluation, quarantine check, intent written).
- Documents: uploads real documents (PDF, Office, OpenDocument) and large text files,
  and times them to their verdict: the scanner's throughput as its queue fills.

Every upload is real data the scanner reads: random bytes for Transfers (clean), the
extraction test documents and generated text for Documents (some contain test PII and
are quarantined; any verdict counts). Nothing here is cleaned up: run it against a
throwaway stack (the k3d cluster, `make k3d-down` afterwards).

Settings, from the environment (defaults: the local stack's ports):

    VAULTGATE_KEYCLOAK     http://localhost:8080
    VAULTGATE_LOAD_USERS   how many load users exist (50; see loadtest/make_users.py)
    VAULTGATE_SCAN_TIMEOUT seconds to wait for a verdict before counting a failure (300)
    VAULTGATE_LOAD_MAX_MIB largest Transfers upload, in MiB (128; the smoke run uses 32)
    VAULTGATE_LOAD_CLEANUP 1 to delete each Transfers object from LocalStack once its
                           download checked out (the make targets set it): VaultGate has
                           no delete yet, and a full run would otherwise keep gigabytes
                           of ciphertext in LocalStack, in the runner's memory and disk
    VAULTGATE_S3, VAULTGATE_BUCKET  where those objects are (http://localhost:4566,
                           vaultgate-local-vault)

The API is Locust's --host (https://localhost:8000 on the cluster, whose root CA
REQUESTS_CA_BUNDLE names); the gateway's address comes from the intents the API hands
out.
"""

import itertools
import os
import random
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import requests
from locust import HttpUser, between, events, task

KEYCLOAK = os.getenv("VAULTGATE_KEYCLOAK", "http://localhost:8080").rstrip("/")
TOKEN_URL = f"{KEYCLOAK}/realms/vaultgate/protocol/openid-connect/token"
CLIENT_ID = "vaultgate-load"
PASSWORD = "vaultgate-load-password"  # local-only test users
LOAD_USERS = int(os.getenv("VAULTGATE_LOAD_USERS", "50"))
SCAN_TIMEOUT = float(os.getenv("VAULTGATE_SCAN_TIMEOUT", "300"))
CLEANUP = os.getenv("VAULTGATE_LOAD_CLEANUP") == "1"
S3 = os.getenv("VAULTGATE_S3", "http://localhost:4566").rstrip("/")
BUCKET = os.getenv("VAULTGATE_BUCKET", "vaultgate-local-vault")

MiB = 1024 * 1024
# Upload sizes for Transfers, by weight: mostly documents, some large files.
MAX_SIZE = int(os.getenv("VAULTGATE_LOAD_MAX_MIB", "128")) * MiB
SIZES = [
    (size, weight)
    for size, weight in [(256 * 1024, 4), (4 * MiB, 4), (32 * MiB, 2), (128 * MiB, 1)]
    if size <= MAX_SIZE
]
CHUNK = os.urandom(MiB)  # random, so the scanner finds nothing and the file is clean

TESTDATA = Path(__file__).resolve().parent.parent / "scanner/internal/extract/testdata"
DOCUMENTS = [
    TESTDATA / name
    for name in ("report.pdf", "clean.docx", "report.docx", "clients.xlsx", "slides.pptx")
    if (TESTDATA / name).exists()
]

_accounts = itertools.count()
_accounts_lock = threading.Lock()


def next_username() -> str:
    """Each simulated user gets its own account, round robin over the load users."""
    with _accounts_lock:
        n = next(_accounts) % LOAD_USERS + 1
    return f"load-{n:03d}"


class RandomBody:
    """`size` bytes of random data, read in pieces of at most 1 MiB (constant memory here
    too). A file-like object with a length, not a generator: requests sends a generator
    with Transfer-Encoding: chunked, and a request with that and Content-Length is
    refused (the gateway takes a fixed length only)."""

    def __init__(self, size: int) -> None:
        self.size = size
        self.sent = 0

    def __len__(self) -> int:
        return self.size

    def read(self, n: int = -1) -> bytes:
        left = self.size - self.sent
        n = left if n is None or n < 0 else min(n, left)
        piece = CHUNK[: min(n, MiB)]
        self.sent += len(piece)
        return piece


def text_document(size: int) -> bytes:
    """Plain text without PII: words and numbers that no detector matches."""
    words = ["vault", "gateway", "scanner", "upload", "chunk", "policy", "share", "audit"]
    line = " ".join(random.choices(words, k=12)) + f" {random.randint(0, 999)}\n"
    return (line * (size // len(line) + 1))[:size].encode()


class VaultUser(HttpUser):
    abstract = True

    def on_start(self) -> None:
        self.username = next_username()
        self._login({"grant_type": "password", "username": self.username, "password": PASSWORD})

    def _login(self, form: dict) -> None:
        with self.client.post(
            TOKEN_URL, data={"client_id": CLIENT_ID, **form}, name="token", catch_response=True
        ) as response:
            if response.status_code != 200:
                response.failure(f"login {self.username}: {response.status_code}")
                raise RuntimeError(f"cannot log in as {self.username}")
            tokens = response.json()
        self.access = tokens["access_token"]
        self.refresh = tokens["refresh_token"]
        self.expires = time.monotonic() + tokens["expires_in"]

    @property
    def auth(self) -> dict:
        if time.monotonic() > self.expires - 60:  # access tokens last 5 minutes
            self._login({"grant_type": "refresh_token", "refresh_token": self.refresh})
        return {"Authorization": f"Bearer {self.access}"}

    # --- steps shared by the scenarios ---------------------------------------------

    def upload(self, name: str, size: int, data, label: str | None = None) -> str | None:
        """Register a file and stream it to the gateway; returns its ID. `label` names the
        upload in the results (the size by default)."""
        created = self.client.post(
            "/files", json={"name": name, "size": size}, headers=self.auth, name="POST /files"
        )
        if created.status_code != 201:
            return None
        file_id, intent = created.json()["file"]["id"], created.json()["upload"]
        with self.client.put(
            intent["url"],
            data=data,
            headers={"Authorization": f"Bearer {intent['token']}", "Content-Length": str(size)},
            name=f"PUT /uploads/{{id}} {label or size_label(size)}",
            catch_response=True,
        ) as response:
            if response.status_code != 201:
                response.failure(f"upload: {response.status_code}")
                return None
        return file_id

    def wait_for_verdict(self, file_id: str, label: str) -> str | None:
        """Poll the file until its scan has a verdict; reports the time from the end of
        the upload to the verdict as one SCAN request."""
        started = time.monotonic()
        while time.monotonic() - started < SCAN_TIMEOUT:
            file = self.client.get(
                f"/files/{file_id}", headers=self.auth, name="GET /files/{id} (poll scan)"
            )
            verdict = file.json()["scan"]["verdict"] if file.status_code == 200 else None
            if verdict not in (None, "pending"):
                events.request.fire(
                    request_type="SCAN",
                    name=f"upload → verdict {label}",
                    response_time=(time.monotonic() - started) * 1000,
                    response_length=0,
                    exception=None,
                    context={},
                )
                return verdict
            time.sleep(0.25)
        events.request.fire(
            request_type="SCAN",
            name=f"upload → verdict {label}",
            response_time=(time.monotonic() - started) * 1000,
            response_length=0,
            exception=TimeoutError(f"no verdict after {SCAN_TIMEOUT:.0f}s"),
            context={},
        )
        return None

    def download(self, file_id: str, size: int) -> None:
        intent = self.client.post(
            f"/files/{file_id}/download", headers=self.auth, name="POST /files/{id}/download"
        )
        if intent.status_code != 201:
            return
        url, token = intent.json()["url"], intent.json()["token"]
        with self.client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            stream=True,
            name=f"GET /downloads/{{id}} {size_label(size)}",
            catch_response=True,
        ) as response:
            got = sum(len(piece) for piece in response.iter_content(MiB))
            if response.status_code != 200 or got != size:
                response.failure(f"download: {response.status_code}, {got} of {size} bytes")


def delete_object(file_id: str) -> None:
    """Every version of the file's object, from LocalStack (the bucket is versioned):
    unsigned requests, which LocalStack accepts and real S3 never would. Outside the
    results: it is the test's housekeeping, not VaultGate's work."""
    key = f"files/{file_id}"
    listing = requests.get(f"{S3}/{BUCKET}", params={"versions": "", "prefix": key}, timeout=30)
    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    for entry in ET.fromstring(listing.content):
        if entry.tag.endswith(("}Version", "}DeleteMarker")):
            version = entry.find("s3:VersionId", ns)
            if entry.find("s3:Key", ns).text == key and version is not None:
                requests.delete(
                    f"{S3}/{BUCKET}/{key}", params={"versionId": version.text}, timeout=30
                )


def size_label(size: int) -> str:
    return f"{size // MiB} MiB" if size >= MiB else f"{size // 1024} KiB"


class Transfers(VaultUser):
    """Concurrent streaming uploads and downloads through the gateway."""

    weight = 3
    wait_time = between(1, 3)

    @task
    def upload_scan_download(self) -> None:
        size = random.choices([s for s, _ in SIZES], weights=[w for _, w in SIZES])[0]
        file_id = self.upload(f"load-{size_label(size)}.bin", size, RandomBody(size))
        if file_id and self.wait_for_verdict(file_id, size_label(size)) == "clean":
            self.download(file_id, size)
        if file_id and CLEANUP:
            delete_object(file_id)


class ControlPlane(VaultUser):
    """The API's small requests, as people browsing their files make them."""

    weight = 2
    wait_time = between(0.5, 1.5)

    def on_start(self) -> None:
        super().on_start()
        # One small clean file of its own, to read and to issue download intents for.
        self.file_id = self.upload(
            "control-plane.bin", 64 * 1024, RandomBody(64 * 1024), "control plane"
        )
        if self.file_id:
            self.wait_for_verdict(self.file_id, "control plane")

    @task(3)
    def me(self) -> None:
        self.client.get("/me", headers=self.auth, name="GET /me")

    @task(5)
    def list_files(self) -> None:
        self.client.get("/files?limit=20", headers=self.auth, name="GET /files")

    @task(3)
    def read_file(self) -> None:
        if self.file_id:
            self.client.get(f"/files/{self.file_id}", headers=self.auth, name="GET /files/{id}")

    @task(2)
    def download_intent(self) -> None:
        if self.file_id:
            self.client.post(
                f"/files/{self.file_id}/download",
                headers=self.auth,
                name="POST /files/{id}/download (intent only)",
            )


class Documents(VaultUser):
    """Real documents and large text files, timed from upload to verdict."""

    weight = 1
    wait_time = between(2, 5)

    @task(3)
    def office_or_pdf(self) -> None:
        path = random.choice(DOCUMENTS)
        data = path.read_bytes()
        label = f"document {path.suffix.lstrip('.')}"
        file_id = self.upload(path.name, len(data), data, label)
        if file_id:
            self.wait_for_verdict(file_id, label)

    @task(1)
    def large_text(self) -> None:
        data = text_document(8 * MiB)
        file_id = self.upload("notes.txt", len(data), data, "document text 8 MiB")
        if file_id:
            self.wait_for_verdict(file_id, "document text 8 MiB")

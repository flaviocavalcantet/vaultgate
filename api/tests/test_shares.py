"""Share links (M5) and what quarantine allows to be shared (ADR 0005)."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from tests.conftest import requires_db
from tests.test_files import as_user, consume_download
from tests.test_quarantine import CARD, admin, download, with_verdict
from tests.test_scans import file_of
from vaultgate_api.config import settings
from vaultgate_api.models import Policy, Share

pytestmark = requires_db


@pytest.fixture
async def sharing(scanner, session):
    """The scanner fixture's clients, with a policy that also allows sharing."""
    session.add(Policy(name="sharing", effect="allow", actions=["share"]))
    await session.flush()
    return scanner


def share(public, provider, file_id: str, sub: str = "alice", **body):
    payload = {"recipient_email": "Bob@Example.com"} | body
    return public.post(f"/files/{file_id}/shares", json=payload, headers=as_user(provider, sub))


async def test_owner_shares_a_clean_file(sharing, provider, queue, session):
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    before = datetime.now(UTC)
    response = await share(public, provider, file_id)
    assert response.status_code == 201, response.text
    body = response.json()
    created = body["share"]
    assert created["recipient_email"] == "bob@example.com"
    assert created["recipient_kind"] == "external"
    assert created["max_downloads"] == settings.share_default_downloads
    assert created["downloads"] == 0 and created["state"] == "active"
    expires = datetime.fromisoformat(created["expires_at"])
    assert (
        timedelta(days=7) - timedelta(minutes=1) < expires - before < timedelta(days=7, minutes=1)
    )
    assert body["url"].endswith(f"/shares/access?token={body['token']}")
    # Only the token's hash is stored.
    row = await session.scalar(select(Share).where(Share.id == created["id"]))
    assert row.token_hash == hashlib.sha256(body["token"].encode()).hexdigest()
    assert body["token"] not in (row.token_hash, row.recipient_email)


async def test_sharing_needs_the_share_action(scanner, provider, queue):
    public, _, _ = scanner  # only read, upload and download are allowed
    file_id, _ = await with_verdict(scanner, provider, queue)
    assert (await share(public, provider, file_id)).status_code == 403


async def test_only_the_owner_shares_an_uploaded_file(sharing, provider, queue):
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    assert (await share(public, provider, file_id, sub="bob")).status_code == 404
    created = await public.post(
        "/files", json={"name": "a.txt", "size": 1}, headers=as_user(provider)
    )
    assert (await share(public, provider, created.json()["file"]["id"])).status_code == 409


@pytest.mark.parametrize(
    ("outcome", "findings", "detail"),
    [
        ("pending", [], "File is waiting for its PII scan"),
        ("scanned", CARD, "File is quarantined: it contains personal data"),
        ("unscannable", [], "File could not be scanned for personal data"),
    ],
)
@pytest.mark.parametrize("blocks", ["download", "share"])
async def test_flagged_files_are_never_shared(
    sharing, provider, queue, monkeypatch, outcome, findings, detail, blocks
):
    """Whatever the quarantine scope: it only decides the owner's downloads."""
    monkeypatch.setattr(settings, "quarantine_blocks", blocks)
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue, outcome, findings)
    response = await share(public, provider, file_id)
    assert response.status_code == 409
    assert response.json()["detail"] == detail
    assert (await file_of(public, provider, file_id))["shareable"] is False


@pytest.mark.parametrize(("outcome", "findings"), [("pending", []), ("scanned", CARD)])
async def test_scope_share_lets_owners_download_flagged_files(
    sharing, provider, queue, monkeypatch, outcome, findings
):
    monkeypatch.setattr(settings, "quarantine_blocks", "share")
    public, internal, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue, outcome, findings)
    file = await file_of(public, provider, file_id)
    assert file["downloadable"] is True and file["shareable"] is False
    intent = await download(public, provider, file_id)
    assert intent.status_code == 201
    # The gateway's re-check follows the same scope.
    assert (await consume_download(internal, file_id, intent.json()["token"])).status_code == 200
    # Back to the default: the owner is blocked again.
    monkeypatch.setattr(settings, "quarantine_blocks", "download")
    assert (await download(public, provider, file_id)).status_code == 409


async def test_releases_are_scoped_by_purpose(sharing, provider, queue):
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue, findings=CARD)
    path = f"/admin/files/{file_id}/release"

    # Released for download: the owner downloads, nothing is shared.
    response = await public.post(path, json={"reason": "owner may"}, headers=admin(provider))
    assert response.status_code == 200
    assert (await download(public, provider, file_id)).status_code == 201
    assert (await share(public, provider, file_id)).status_code == 409

    # Released for sharing too: now it can be shared.
    response = await public.post(
        path, json={"reason": "client asked", "purpose": "share"}, headers=admin(provider)
    )
    assert response.status_code == 200, response.text
    assert set(response.json()["released_by"]) == {"download", "share"}
    file = await file_of(public, provider, file_id)
    assert [r["purpose"] for r in file["scan"]["releases"]] == ["download", "share"]
    assert file["downloadable"] is True and file["shareable"] is True
    assert (await share(public, provider, file_id)).status_code == 201
    # Each purpose is released once.
    again = await public.post(
        path, json={"reason": "x", "purpose": "share"}, headers=admin(provider)
    )
    assert again.status_code == 409

    # A rescan ends both.
    await public.post(f"/admin/files/{file_id}/rescan", headers=admin(provider))
    file = await file_of(public, provider, file_id)
    assert file["scan"]["releases"] == [] and not file["shareable"]


@pytest.mark.parametrize(
    "body",
    [
        {"recipient_email": "not-an-address"},
        {"recipient_email": "a@b"},
        {"recipient_email": "a b@example.com"},
        {"recipient_kind": "partner"},
        {"expires_in_days": 0},
        {"expires_in_days": 31},
        {"max_downloads": 0},
        {"max_downloads": 101},
    ],
)
async def test_share_requests_are_checked(sharing, provider, queue, body):
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    assert (await share(public, provider, file_id, **body)).status_code == 422


async def test_owners_choose_limits_within_bounds(sharing, provider, queue):
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    response = await share(
        public, provider, file_id, recipient_kind="internal", expires_in_days=1, max_downloads=1
    )
    assert response.status_code == 201
    created = response.json()["share"]
    assert created["recipient_kind"] == "internal" and created["max_downloads"] == 1


async def test_active_shares_per_file_are_capped(sharing, provider, queue, monkeypatch):
    monkeypatch.setattr(settings, "max_active_shares_per_file", 2)
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    first = (await share(public, provider, file_id)).json()["share"]
    assert (await share(public, provider, file_id)).status_code == 201
    assert (await share(public, provider, file_id)).status_code == 429
    # A revoked share no longer counts.
    await public.delete(f"/files/{file_id}/shares/{first['id']}", headers=as_user(provider))
    assert (await share(public, provider, file_id)).status_code == 201


async def test_owners_list_and_revoke_shares(sharing, provider, queue, session):
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    first = (await share(public, provider, file_id)).json()["share"]
    second = (await share(public, provider, file_id, recipient_email="carol@example.com")).json()
    path = f"/files/{file_id}/shares"

    listed = (await public.get(path, headers=as_user(provider))).json()
    # Newest first; here both have the same created_at (one test transaction).
    assert {s["id"] for s in listed} == {second["share"]["id"], first["id"]}

    revoke = f"{path}/{first['id']}"
    assert (await public.delete(revoke, headers=as_user(provider))).status_code == 204
    assert (await public.delete(revoke, headers=as_user(provider))).status_code == 204
    states = {
        s["id"]: s["state"] for s in (await public.get(path, headers=as_user(provider))).json()
    }
    assert states == {first["id"]: "revoked", second["share"]["id"]: "active"}

    # Expired and used-up shares say so.
    row = await session.get(Share, second["share"]["id"])
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.flush()
    states = {
        s["id"]: s["state"] for s in (await public.get(path, headers=as_user(provider))).json()
    }
    assert states[second["share"]["id"]] == "expired"

    # Someone else's file, or a share of another file: not found.
    assert (await public.get(path, headers=as_user(provider, "bob"))).status_code == 404
    assert (await public.delete(revoke, headers=as_user(provider, "bob"))).status_code == 404
    other, _ = await with_verdict(sharing, provider, queue, name="other.pdf")
    wrong = f"/files/{other}/shares/{first['id']}"
    assert (await public.delete(wrong, headers=as_user(provider))).status_code == 404


async def test_revoking_needs_no_share_permission(sharing, provider, queue, session):
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    created = (await share(public, provider, file_id)).json()["share"]
    policy = await session.scalar(select(Policy).where(Policy.name == "sharing"))
    await session.delete(policy)
    await session.flush()
    assert (await share(public, provider, file_id)).status_code == 403
    path = f"/files/{file_id}/shares/{created['id']}"
    assert (await public.delete(path, headers=as_user(provider))).status_code == 204

"""Sharing a folder (M12.6, ADR 0020): its live contents, downloadable files only, one
download limit across them, and every check again at the gateway."""

import uuid

from sqlalchemy import select

from tests.conftest import requires_db
from tests.test_audit import events
from tests.test_files import as_user, consume_download
from tests.test_folders import folder
from tests.test_quarantine import CARD, with_verdict
from tests.test_share_access import mailer, recipients, verified  # noqa: F401 (fixtures)
from tests.test_shared_with_me import person
from vaultgate_api.models import Share

pytestmark = requires_db


async def put(recipients, provider, queue, name, folder_id, outcome="scanned", findings=()):  # noqa: F811
    """A file with a verdict, moved into the folder; returns its id."""
    public = recipients[0]
    file_id, _ = await with_verdict(recipients, provider, queue, outcome, findings, name)
    moved = await public.patch(
        f"/files/{file_id}", json={"folder_id": folder_id}, headers=as_user(provider)
    )
    assert moved.status_code == 200, moved.text
    return file_id


async def tree(recipients, provider, queue):  # noqa: F811
    """projects/ (clean a.txt, quarantined card.txt) and projects/q3/ (clean b.txt,
    pending c.txt), plus other/ (clean x.txt) beside it."""
    public = recipients[0]
    root = await folder(public, provider, "projects")
    sub = await folder(public, provider, "q3", root["id"])
    other = await folder(public, provider, "other")
    ids = {
        "a": await put(recipients, provider, queue, "a.txt", root["id"]),
        "card": await put(recipients, provider, queue, "card.txt", root["id"], findings=CARD),
        "b": await put(recipients, provider, queue, "b.txt", sub["id"]),
        "c": await put(recipients, provider, queue, "c.txt", sub["id"], outcome="pending"),
        "x": await put(recipients, provider, queue, "x.txt", other["id"]),
    }
    return root, sub, other, ids


def share_folder(public, provider, folder_id, sub="alice", **body):
    payload = {"recipient_email": "Bob@Example.com"} | body
    return public.post(f"/folders/{folder_id}/shares", json=payload, headers=as_user(provider, sub))


def contents(public, token, grant, folder_id=None):
    body = {"token": token, "grant": grant, "folder_id": folder_id}
    return public.post("/shares/access/contents", json=body)


def download(public, token, grant, file_id=None):
    body = {"token": token, "grant": grant, "file_id": file_id}
    return public.post("/shares/access/downloads", json=body)


async def test_an_external_recipient_browses_and_downloads_a_folder(
    recipients,  # noqa: F811
    provider,
    queue,
    mailer,  # noqa: F811
    session,
) -> None:
    public, internal, _ = recipients
    root, sub, other, ids = await tree(recipients, provider, queue)
    created = await share_folder(public, provider, root["id"], max_downloads=2)
    assert created.status_code == 201, created.text
    shared = created.json()
    assert shared["share"]["folder_id"] == root["id"] and shared["share"]["file_id"] is None
    token = shared["token"]

    described = (await public.get("/shares/access", params={"token": token})).json()
    assert described["kind"] == "folder" and "projects" not in str(described)
    assert (await contents(public, token, "no grant")).status_code == 403
    grant = await verified(public, mailer, token)

    top = (await contents(public, token, grant)).json()
    assert top["folder"] == {"id": root["id"], "name": "projects"}
    assert top["path"] == [{"id": root["id"], "name": "projects"}]
    assert top["folders"] == [{"id": sub["id"], "name": "q3"}]
    # Only what can be downloaded now: the quarantined file isn't listed.
    assert [f["name"] for f in top["files"]] == ["a.txt"] and top["truncated"] is False
    inner = (await contents(public, token, grant, sub["id"])).json()
    assert [p["name"] for p in inner["path"]] == ["projects", "q3"]
    assert [f["name"] for f in inner["files"]] == ["b.txt"]  # c.txt is still being scanned
    assert (await contents(public, token, grant, other["id"])).status_code == 404

    # Any file in it, at any level, against one limit; nothing else.
    assert (await download(public, token, grant)).status_code == 422
    assert (await download(public, token, grant, ids["x"])).status_code == 404
    assert (await download(public, token, grant, ids["card"])).status_code == 409
    assert (await download(public, token, grant, ids["c"])).status_code == 409
    for name in ("b", "a"):
        intent = await download(public, token, grant, ids[name])
        assert intent.status_code == 201, intent.text
        consumed = await consume_download(internal, ids[name], intent.json()["token"])
        assert consumed.status_code == 200, consumed.text
    assert (await download(public, token, grant, ids["a"])).status_code == 410  # used up

    downloaded = await events(session, action="share.downloaded")
    assert {e.target_id for e in downloaded} == {uuid.UUID(ids["a"]), uuid.UUID(ids["b"])}
    assert all(e.details["folder_id"] == root["id"] for e in downloaded)


async def test_a_file_moved_out_after_its_intent_is_refused_at_the_gateway(
    recipients,  # noqa: F811
    provider,
    queue,
    mailer,  # noqa: F811
) -> None:
    public, internal, _ = recipients
    root, _, other, ids = await tree(recipients, provider, queue)
    token = (await share_folder(public, provider, root["id"])).json()["token"]
    grant = await verified(public, mailer, token)
    intent = (await download(public, token, grant, ids["b"])).json()
    moved = await public.patch(
        f"/files/{ids['b']}", json={"folder_id": other["id"]}, headers=as_user(provider)
    )
    assert moved.status_code == 200
    refused = await consume_download(internal, ids["b"], intent["token"])
    assert refused.status_code == 403
    assert refused.json()["detail"] == "File is no longer in the shared folder"
    # Moved back, the same intent (left unspent) works.
    await public.patch(
        f"/files/{ids['b']}", json={"folder_id": root["id"]}, headers=as_user(provider)
    )
    assert (await consume_download(internal, ids["b"], intent["token"])).status_code == 200


async def test_owners_list_and_revoke_folder_shares(
    recipients,  # noqa: F811
    provider,
    session,
) -> None:
    public, _, _ = recipients
    root = await folder(public, provider, "projects")
    path = f"/folders/{root['id']}/shares"
    me = as_user(provider)
    assert (await share_folder(public, provider, root["id"], sub="bob")).status_code == 404
    first = (await share_folder(public, provider, root["id"])).json()
    second = (
        await share_folder(public, provider, root["id"], recipient_email="carol@example.com")
    ).json()
    listed = (await public.get(path, headers=me)).json()
    assert {s["id"] for s in listed} == {first["share"]["id"], second["share"]["id"]}
    assert (await public.get(path, headers=as_user(provider, "bob"))).status_code == 404

    revoke = f"{path}/{first['share']['id']}"
    assert (await public.delete(revoke, headers=as_user(provider, "bob"))).status_code == 404
    assert (await public.delete(revoke, headers=me)).status_code == 204
    gone = await public.get("/shares/access", params={"token": first["token"]})
    assert gone.status_code == 410
    # A folder's share isn't revoked through a file's route, nor the other way round.
    other = await public.delete(f"/files/{uuid.uuid4()}/shares/{second['share']['id']}", headers=me)
    assert other.status_code == 404

    [created, _] = await events(session, action="share.created")
    assert (created.target_kind, created.target_id) == ("folder", uuid.UUID(root["id"]))
    [revoked] = await events(session, action="share.revoked")
    assert revoked.target_kind == "folder"


async def test_deleting_the_folder_ends_its_shares(
    recipients,  # noqa: F811
    provider,
    session,
) -> None:
    public, _, _ = recipients
    root = await folder(public, provider, "projects")
    created = (await share_folder(public, provider, root["id"])).json()
    me = as_user(provider)
    assert (await public.delete(f"/folders/{root['id']}", headers=me)).status_code == 204
    gone = await public.get("/shares/access", params={"token": created["token"]})
    assert gone.status_code == 404
    left = await session.scalar(select(Share).where(Share.folder_id == uuid.UUID(root["id"])))
    assert left is None


async def test_a_signed_in_recipient_browses_and_downloads_a_folder(
    recipients,  # noqa: F811
    provider,
    queue,
) -> None:
    public, internal, _ = recipients
    root, sub, other, ids = await tree(recipients, provider, queue)
    created = await share_folder(public, provider, root["id"], recipient_kind="internal")
    share_id = created.json()["share"]["id"]
    bob = person(provider, "bob", "Bob@Example.com")
    carol = person(provider, "carol", "carol@example.com")

    [item] = (await public.get("/shared-with-me", headers=bob)).json()
    assert item["kind"] == "folder" and item["folder_id"] == root["id"]
    assert item["name"] == "projects" and item["file_id"] is None and item["available"]
    assert (await public.get("/shared-with-me", headers=carol)).json() == []

    listing = await public.get(f"/shared-with-me/{share_id}/contents", headers=bob)
    assert [f["name"] for f in listing.json()["files"]] == ["a.txt"]
    inner = await public.get(
        f"/shared-with-me/{share_id}/contents", params={"folder_id": sub["id"]}, headers=bob
    )
    assert [f["name"] for f in inner.json()["files"]] == ["b.txt"]
    outside = await public.get(
        f"/shared-with-me/{share_id}/contents", params={"folder_id": other["id"]}, headers=bob
    )
    assert outside.status_code == 404
    assert (
        await public.get(f"/shared-with-me/{share_id}/contents", headers=carol)
    ).status_code == 404

    path = f"/shared-with-me/{share_id}/download"
    assert (await public.post(path, headers=bob)).status_code == 422
    assert (await public.post(path, params={"file_id": ids["x"]}, headers=bob)).status_code == 404
    assert (
        await public.post(path, params={"file_id": ids["card"]}, headers=bob)
    ).status_code == 409
    intent = await public.post(path, params={"file_id": ids["b"]}, headers=bob)
    assert intent.status_code == 201, intent.text
    consumed = await consume_download(internal, ids["b"], intent.json()["token"])
    assert consumed.status_code == 200


async def test_a_file_share_has_no_contents(
    recipients,  # noqa: F811
    provider,
    queue,
    mailer,  # noqa: F811
) -> None:
    public, _, _ = recipients
    file_id, _ = await with_verdict(recipients, provider, queue)
    created = await public.post(
        f"/files/{file_id}/shares",
        json={"recipient_email": "bob@example.com"},
        headers=as_user(provider),
    )
    token = created.json()["token"]
    assert (await public.get("/shares/access", params={"token": token})).json()["kind"] == "file"
    grant = await verified(public, mailer, token)
    assert (await contents(public, token, grant)).status_code == 409
    # Naming another file through a file's share finds nothing.
    assert (await download(public, token, grant, str(uuid.uuid4()))).status_code == 404
    assert (await download(public, token, grant, file_id)).status_code == 201

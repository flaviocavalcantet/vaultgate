"""Deleting files and folders (M12.6, ADR 0020): rows and keys at once, objects queued
for the gateway, which claims and confirms them."""

import base64
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update

from tests.conftest import requires_db
from tests.test_audit import events
from tests.test_files import as_user, consume, create, uploaded
from tests.test_folders import folder
from tests.test_quarantine import download, with_verdict
from tests.test_shares import share, sharing  # noqa: F401 (fixture)
from vaultgate_api.models import File, ObjectDeletion, Share, TransferIntent

pytestmark = requires_db


async def queued(session) -> dict[str, ObjectDeletion]:
    rows = await session.scalars(select(ObjectDeletion).execution_options(populate_existing=True))
    return {r.storage_key: r for r in rows}


def claim(internal, limit: int = 100):
    return internal.post("/internal/deletions/claim", json={"limit": limit})


async def test_a_deleted_file_is_gone_at_once_and_its_object_queued(
    sharing,  # noqa: F811
    provider,
    queue,
    session,
) -> None:
    public, internal, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    assert (await share(public, provider, file_id)).status_code == 201
    intent = (await download(public, provider, file_id)).json()
    path = f"/files/{file_id}"

    assert (await public.delete(path, headers=as_user(provider, "bob"))).status_code == 404
    assert (await public.delete(path, headers=as_user(provider))).status_code == 204
    assert (await public.get(path, headers=as_user(provider))).status_code == 404
    assert (await public.delete(path, headers=as_user(provider))).status_code == 404

    # The row, its wrapped key, shares and intents are gone; the object waits.
    session.expire_all()
    assert await session.get(File, uuid.UUID(file_id)) is None
    for model in (Share, TransferIntent):
        count = await session.scalar(
            select(func.count()).select_from(model).where(model.file_id == uuid.UUID(file_id))
        )
        assert count == 0, model.__name__
    assert set(await queued(session)) == {f"files/{file_id}"}
    # A download intent issued before can't be used any more.
    spent = await internal.post(
        "/internal/intents/consume",
        json={"token": intent["token"], "kind": "download", "file_id": file_id},
    )
    assert spent.status_code == 403

    [deleted] = await events(session, action="file.deleted")
    assert deleted.target_id == uuid.UUID(file_id) and deleted.actor_kind == "user"
    assert deleted.details == {
        "name": "report.pdf",
        "folder_id": None,
        "status": "uploaded",
        "size": 1234,
    }
    # The name is free again.
    assert (await create(public, provider, name="report.pdf"))["file"]["name"] == "report.pdf"


async def test_an_upload_still_streaming_is_refused_when_it_completes(
    clients, provider, session
) -> None:
    public, internal = clients
    created = await create(public, provider)
    file_id = created["file"]["id"]
    assert (await consume(internal, created)).status_code == 200  # uploading
    assert (await public.delete(f"/files/{file_id}", headers=as_user(provider))).status_code == 204
    done = await internal.post(
        f"/internal/files/{file_id}/complete",
        json={
            "size": 1234,
            "sha256": "ab" * 32,
            "wrapped_key": base64.b64encode(b"key").decode(),
            "kms_key_id": "alias/test",
        },
    )
    # The gateway takes a 409 as "not recorded" and deletes the object it wrote.
    assert done.status_code == 409
    assert set(await queued(session)) == {f"files/{file_id}"}


async def test_a_folder_goes_with_everything_in_it(clients, provider, session) -> None:
    public, internal = clients
    me = as_user(provider)
    a = await folder(public, provider, "a")
    b = await folder(public, provider, "b", a["id"])
    c = await folder(public, provider, "c", b["id"])
    kept = await folder(public, provider, "kept")
    in_a = await uploaded(public, internal, provider, name="in-a.txt")
    move = await public.patch(
        f"/files/{in_a['file']['id']}", json={"folder_id": a["id"]}, headers=me
    )
    assert move.status_code == 200
    in_c = (await create(public, provider, name="in-c.txt", folder_id=c["id"]))["file"]
    in_b = (await create(public, provider, name="in-b.txt", folder_id=b["id"]))["file"]
    outside = (await create(public, provider, name="outside.txt", folder_id=kept["id"]))["file"]

    totals = await public.get(f"/folders/{a['id']}/totals", headers=me)
    assert totals.json() == {"folders": 2, "files": 3, "bytes": 1234}
    other = as_user(provider, "bob")
    assert (await public.get(f"/folders/{a['id']}/totals", headers=other)).status_code == 404
    assert (await public.delete(f"/folders/{a['id']}", headers=other)).status_code == 404

    assert (await public.delete(f"/folders/{a['id']}", headers=me)).status_code == 204
    for gone in (a, b, c):
        assert (await public.get(f"/folders/{gone['id']}", headers=me)).status_code == 404
    for gone in (in_a["file"], in_b, in_c):
        assert (await public.get(f"/files/{gone['id']}", headers=me)).status_code == 404
    assert (await public.get(f"/files/{outside['id']}", headers=me)).status_code == 200
    assert (await public.get(f"/folders/{kept['id']}", headers=me)).status_code == 200
    assert set(await queued(session)) == {f"files/{f['id']}" for f in (in_a["file"], in_b, in_c)}

    [deleted] = await events(session, action="folder.deleted")
    assert deleted.target_id == uuid.UUID(a["id"])
    assert deleted.details == {
        "name": "a",
        "parent_id": None,
        "folders": 2,
        "files": 3,
        "bytes": 1234,
    }
    reasons = {e.details["reason"] for e in await events(session, action="file.deleted")}
    assert reasons == {f"folder {a['id']} deleted"}
    assert (await folder(public, provider, "A"))["name"] == "A"  # the name is free again


async def test_an_empty_folder_is_deleted(clients, provider) -> None:
    public, _ = clients
    me = as_user(provider)
    empty = await folder(public, provider, "empty")
    assert (await public.get(f"/folders/{empty['id']}/totals", headers=me)).json() == {
        "folders": 0,
        "files": 0,
        "bytes": 0,
    }
    assert (await public.delete(f"/folders/{empty['id']}", headers=me)).status_code == 204


async def test_the_gateway_claims_deletes_and_confirms(clients, provider, session) -> None:
    public, internal = clients
    me = as_user(provider)
    ids = []
    for n in range(3):
        file_id = (await create(public, provider, name=f"{n}.txt"))["file"]["id"]
        assert (await public.delete(f"/files/{file_id}", headers=me)).status_code == 204
        ids.append(file_id)

    first = (await claim(internal, limit=2)).json()
    assert [i["storage_key"] for i in first["items"]] == [f"files/{i}" for i in ids[:2]]
    assert first["pending"] == 3
    second = (await claim(internal)).json()
    assert [i["storage_key"] for i in second["items"]] == [f"files/{ids[2]}"]
    assert (await claim(internal)).json()["items"] == []  # all held

    done = await internal.post(
        "/internal/deletions/done", json={"ids": [i["id"] for i in first["items"]]}
    )
    assert done.json() == {"confirmed": 2}
    again = await internal.post(
        "/internal/deletions/done", json={"ids": [i["id"] for i in first["items"]]}
    )
    assert again.json() == {"confirmed": 0}  # confirmed once only
    assert set(await queued(session)) == {f"files/{ids[2]}"}
    confirmed = await events(session, action="file.object_deleted")
    assert {(e.target_id, e.actor_kind) for e in confirmed} == {
        (uuid.UUID(i), "gateway") for i in ids[:2]
    }

    # A claim not confirmed in time is claimed again, and counted.
    await session.execute(
        update(ObjectDeletion).values(claimed_until=datetime.now(UTC) - timedelta(seconds=1))
    )
    retried = (await claim(internal)).json()
    assert [i["storage_key"] for i in retried["items"]] == [f"files/{ids[2]}"]
    assert (await queued(session))[f"files/{ids[2]}"].attempts == 2


async def test_deletion_routes_are_the_gateways_only(clients) -> None:
    _, internal = clients
    for path, body in [
        ("/internal/deletions/claim", {}),
        ("/internal/deletions/done", {"ids": [1]}),
    ]:
        refused = await internal.post(path, json=body, headers={"Authorization": "Bearer nope"})
        assert refused.status_code == 401
    assert (await claim(internal, limit=0)).status_code == 422
    assert (await claim(internal, limit=501)).status_code == 422

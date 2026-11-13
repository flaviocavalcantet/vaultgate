"""Folders (M12.6, ADR 0020): nesting, names unique in a folder, moves and renames."""

import importlib.util
import uuid

from sqlalchemy import select, text, update

from tests.conftest import API_ROOT, requires_db
from tests.test_audit import events
from tests.test_files import as_user, create
from vaultgate_api import audit
from vaultgate_api.folders import MAX_DEPTH
from vaultgate_api.models import File, User

pytestmark = requires_db


async def folder(public, provider, name, parent_id=None, sub="alice") -> dict:
    response = await public.post(
        "/folders", json={"name": name, "parent_id": parent_id}, headers=as_user(provider, sub)
    )
    assert response.status_code == 201, response.text
    return response.json()


def new_folder(public, provider, name, parent_id=None, sub="alice"):
    return public.post(
        "/folders", json={"name": name, "parent_id": parent_id}, headers=as_user(provider, sub)
    )


def new_file(public, provider, name, folder_id=None, sub="alice"):
    body = {"name": name, "size": 1, "folder_id": folder_id}
    return public.post("/files", json=body, headers=as_user(provider, sub))


async def test_folders_nest_and_list_with_their_path(clients, provider) -> None:
    public, _ = clients
    work = await folder(public, provider, "Work")
    reports = await folder(public, provider, "reports", work["id"])
    q3 = await folder(public, provider, "Q3", reports["id"])
    await folder(public, provider, "archive")

    top = (await public.get("/folders", headers=as_user(provider))).json()
    assert [f["name"] for f in top["items"]] == ["archive", "Work"]  # by name, any case
    inside = await public.get(
        "/folders", params={"parent_id": work["id"]}, headers=as_user(provider)
    )
    assert [f["id"] for f in inside.json()["items"]] == [reports["id"]]

    detail = (await public.get(f"/folders/{q3['id']}", headers=as_user(provider))).json()
    assert detail["parent_id"] == reports["id"]
    assert [p["name"] for p in detail["path"]] == ["Work", "reports", "Q3"]


async def test_another_users_folder_is_not_found(clients, provider) -> None:
    public, _ = clients
    mine = await folder(public, provider, "Private")
    bob = as_user(provider, "bob")
    assert (await public.get(f"/folders/{mine['id']}", headers=bob)).status_code == 404
    listed = await public.get("/folders", params={"parent_id": mine["id"]}, headers=bob)
    assert listed.status_code == 404
    assert (await new_folder(public, provider, "in", mine["id"], sub="bob")).status_code == 404
    assert (await new_file(public, provider, "in.txt", mine["id"], sub="bob")).status_code == 404
    listed = await public.get("/files", params={"folder_id": mine["id"]}, headers=bob)
    assert listed.status_code == 404
    rename = await public.patch(f"/folders/{mine['id']}", json={"name": "x"}, headers=bob)
    assert rename.status_code == 404
    # Bob's files can't be moved into it, nor his folders.
    theirs = (await new_file(public, provider, "b.txt", sub="bob")).json()["file"]
    move = await public.patch(f"/files/{theirs['id']}", json={"folder_id": mine["id"]}, headers=bob)
    assert move.status_code == 404
    unknown = await public.get(f"/folders/{uuid.uuid4()}", headers=as_user(provider))
    assert unknown.status_code == 404


async def test_names_are_unique_in_a_folder_across_files_and_folders(clients, provider) -> None:
    public, _ = clients
    docs = await folder(public, provider, "Docs")
    assert (await new_folder(public, provider, "docs")).status_code == 409
    clash = await new_file(public, provider, "DOCS")
    assert clash.status_code == 409
    assert clash.json()["detail"] == "Something named “DOCS” is already here; choose another name"

    assert (await new_file(public, provider, "Report.pdf")).status_code == 201
    assert (await new_file(public, provider, "report.PDF")).status_code == 409
    assert (await new_folder(public, provider, "REPORT.pdf")).status_code == 409

    # The same name elsewhere, or another user's, is fine.
    assert (await new_file(public, provider, "report.pdf", docs["id"])).status_code == 201
    assert (await new_folder(public, provider, "Docs", docs["id"])).status_code == 201
    assert (await new_file(public, provider, "report.pdf", sub="bob")).status_code == 201
    assert (await new_folder(public, provider, "docs", sub="bob")).status_code == 201


async def test_a_failed_upload_holds_no_name(clients, provider, session) -> None:
    public, _ = clients
    first = (await new_file(public, provider, "data.csv")).json()["file"]
    await session.execute(update(File).where(File.id == first["id"]).values(status="failed"))
    assert (await new_file(public, provider, "data.csv")).status_code == 201


async def test_names_must_be_plain(clients, provider) -> None:
    public, _ = clients
    for name in ["a/b", "a\\b", "..", ".", " lead", "trail ", "tab\there", ""]:
        assert (await new_folder(public, provider, name)).status_code == 422, name
        assert (await new_file(public, provider, name)).status_code == 422, name


async def test_files_go_into_folders_and_are_listed_there(clients, provider) -> None:
    public, _ = clients
    docs = await folder(public, provider, "Docs")
    inside = (await new_file(public, provider, "in.txt", docs["id"])).json()["file"]
    top = (await new_file(public, provider, "top.txt")).json()["file"]
    assert inside["folder_id"] == docs["id"] and top["folder_id"] is None

    listed = (await public.get("/files", headers=as_user(provider))).json()
    assert [f["id"] for f in listed["items"]] == [top["id"]] and listed["total"] == 1
    listed = (
        await public.get("/files", params={"folder_id": docs["id"]}, headers=as_user(provider))
    ).json()
    assert [f["id"] for f in listed["items"]] == [inside["id"]]


async def test_files_are_renamed_and_moved(clients, provider, session) -> None:
    public, _ = clients
    docs = await folder(public, provider, "Docs")
    file = (await create(public, provider, name="draft.txt"))["file"]
    path = f"/files/{file['id']}"
    me = as_user(provider)

    renamed = await public.patch(path, json={"name": "final.txt"}, headers=me)
    assert renamed.status_code == 200 and renamed.json()["name"] == "final.txt"
    moved = await public.patch(path, json={"folder_id": docs["id"]}, headers=me)
    assert moved.json()["folder_id"] == docs["id"] and moved.json()["name"] == "final.txt"
    # Unchanged when nothing changes; null moves it back to the top level.
    assert (await public.patch(path, json={}, headers=me)).json()["folder_id"] == docs["id"]
    back = await public.patch(path, json={"folder_id": None, "name": "v2.txt"}, headers=me)
    assert back.json()["folder_id"] is None and back.json()["name"] == "v2.txt"
    # Its own name in another case is fine; another item's is not.
    assert (await public.patch(path, json={"name": "V2.txt"}, headers=me)).status_code == 200
    await new_file(public, provider, "taken.txt", docs["id"])
    clash = await public.patch(
        path, json={"folder_id": docs["id"], "name": "TAKEN.txt"}, headers=me
    )
    assert clash.status_code == 409
    assert (await public.patch(path, json={"name": "a/b"}, headers=me)).status_code == 422
    assert (
        await public.patch(path, json={"name": "x"}, headers=as_user(provider, "bob"))
    ).status_code == 404

    trail = [(e.action, e.details) for e in await events(session, target_id=uuid.UUID(file["id"]))][
        1:
    ]
    assert trail == [
        ("file.renamed", {"from": "draft.txt", "to": "final.txt"}),
        ("file.moved", {"from_folder_id": None, "to_folder_id": docs["id"]}),
        (
            "file.moved",
            {
                "from_folder_id": docs["id"],
                "to_folder_id": None,
                "from": "final.txt",
                "to": "v2.txt",
            },
        ),
        ("file.renamed", {"from": "v2.txt", "to": "V2.txt"}),
    ]


async def test_folders_are_renamed_and_moved_but_never_into_themselves(
    clients, provider, session
) -> None:
    public, _ = clients
    me = as_user(provider)
    a = await folder(public, provider, "a")
    b = await folder(public, provider, "b", a["id"])
    c = await folder(public, provider, "c", b["id"])
    other = await folder(public, provider, "other")

    for target in [a, b, c]:
        into = await public.patch(
            f"/folders/{a['id']}", json={"parent_id": target["id"]}, headers=me
        )
        assert into.status_code == 409, target["name"]
        assert into.json()["detail"] == "A folder can't be moved into itself"

    moved = await public.patch(f"/folders/{b['id']}", json={"parent_id": other["id"]}, headers=me)
    assert moved.status_code == 200 and moved.json()["parent_id"] == other["id"]
    path = (await public.get(f"/folders/{c['id']}", headers=me)).json()["path"]
    assert [p["name"] for p in path] == ["other", "b", "c"]  # its contents went with it

    await new_file(public, provider, "c.txt", other["id"])
    clash = await public.patch(f"/folders/{b['id']}", json={"name": "C.TXT"}, headers=me)
    assert clash.status_code == 409
    renamed = await public.patch(
        f"/folders/{b['id']}", json={"name": "B", "parent_id": None}, headers=me
    )
    assert renamed.json() | {"created_at": None} == {
        "id": b["id"],
        "name": "B",
        "parent_id": None,
        "created_at": None,
    }
    actions = [e.action for e in await events(session, target_id=uuid.UUID(b["id"]))]
    assert actions == ["folder.created", "folder.moved", "folder.moved"]


async def test_folders_nest_at_most_max_depth(clients, provider) -> None:
    public, _ = clients
    me = as_user(provider)
    parent = None
    chain = []
    for level in range(MAX_DEPTH):
        parent = (await folder(public, provider, f"level {level}", parent))["id"]
        chain.append(parent)
    too_deep = await new_folder(public, provider, "one more", parent)
    assert too_deep.status_code == 409
    assert too_deep.json()["detail"] == f"Folders nest at most {MAX_DEPTH} deep"

    # A tree two deep can't move under the 15th level, but fits under the 14th.
    tree = await folder(public, provider, "tree")
    await folder(public, provider, "leaf", tree["id"])
    deep = await public.patch(
        f"/folders/{tree['id']}", json={"parent_id": chain[MAX_DEPTH - 2]}, headers=me
    )
    assert deep.status_code == 409
    fits = await public.patch(
        f"/folders/{tree['id']}", json={"parent_id": chain[MAX_DEPTH - 3]}, headers=me
    )
    assert fits.status_code == 200


def _migration():
    path = API_ROOT / "migrations" / "versions" / "0016_folders.py"
    spec = importlib.util.spec_from_file_location("migration_0016", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_the_migration_renames_duplicates_and_records_it(clients, provider, session) -> None:
    """Names that clashed before 0016 get a number, oldest first, each rename audited.
    Run inside the test's transaction (the index dropped and the rows rolled back)."""
    public, _ = clients
    await public.get("/me", headers=as_user(provider))
    await public.get("/me", headers=as_user(provider, "bob"))
    users = {u.username: u.id for u in await session.scalars(select(User))}
    await session.execute(text("DROP INDEX uq_files_owner_folder_name"))

    def add(owner: str, name: str, *, status="uploaded", age=0) -> uuid.UUID:
        file_id = uuid.uuid4()
        session.add(
            File(
                id=file_id,
                owner_id=users[owner],
                name=name,
                content_type="text/plain",
                declared_size=1,
                storage_key=f"files/{file_id}",
                status=status,
                created_at=text(f"now() - interval '{age} minutes'"),
            )
        )
        return file_id

    oldest = add("alice", "report.pdf", age=3)
    second = add("alice", "Report.pdf", age=2)
    third = add("alice", "REPORT.PDF", age=1)
    taken = add("alice", "report (2).pdf", age=5)  # the first number is already used
    failed = add("alice", "report.pdf", status="failed")
    bobs = add("bob", "report.pdf")
    plain = add("alice", "notes", age=2)
    plain_dup = add("alice", "notes", age=1)
    await session.flush()

    migration = _migration()
    await session.run_sync(lambda s: migration._rename_duplicates(s.connection()))
    await session.execute(
        text(
            "CREATE UNIQUE INDEX uq_files_owner_folder_name ON files "
            "(owner_id, folder_id, lower(name)) NULLS NOT DISTINCT WHERE status <> 'failed'"
        )
    )

    names = {
        f.id: f.name
        for f in await session.scalars(
            select(File)
            .where(File.owner_id.in_(users.values()))
            .execution_options(populate_existing=True)
        )
    }
    assert names[oldest] == "report.pdf"
    assert names[second] == "Report (3).pdf"
    assert names[third] == "REPORT (4).PDF"
    assert names[taken] == "report (2).pdf"
    assert names[failed] == "report.pdf" and names[bobs] == "report.pdf"
    assert names[plain] == "notes" and names[plain_dup] == "notes (2)"

    renamed = await events(session, action="file.renamed", actor_kind="system")
    assert {(e.target_id, e.details["from"], e.details["to"]) for e in renamed} == {
        (second, "Report.pdf", "Report (3).pdf"),
        (third, "REPORT.PDF", "REPORT (4).PDF"),
        (plain_dup, "notes", "notes (2)"),
    }
    assert all(e.details["owner_id"] == str(users["alice"]) for e in renamed)
    assert (await audit.verify(session)).ok


def test_numbered_names_keep_their_extension_and_fit() -> None:
    numbered = _migration()._numbered
    assert numbered("report.pdf", 2) == "report (2).pdf"
    assert numbered("archive.tar.gz", 3) == "archive.tar (3).gz"
    assert numbered(".env", 2) == ".env (2)"
    long = numbered("x" * 250 + ".pdf", 12)
    assert len(long) == 255 and long.endswith(" (12).pdf")

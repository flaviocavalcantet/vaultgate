"""The audit log (ADR 0007): security events, append-only, hash-chained."""

import uuid
from itertools import pairwise

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from tests.conftest import requires_db
from tests.test_files import as_user, consume_download
from tests.test_quarantine import CARD, admin, download, with_verdict
from tests.test_share_access import mailer, recipients, shared  # noqa: F401 (fixtures)
from tests.test_shares import share, sharing  # noqa: F401 (fixture)
from vaultgate_api import audit
from vaultgate_api.models import AuditEvent, Policy

pytestmark = requires_db


async def events(session, **where) -> list[AuditEvent]:
    query = select(AuditEvent).order_by(AuditEvent.id).execution_options(populate_existing=True)
    for column, value in where.items():
        query = query.where(getattr(AuditEvent, column) == value)
    return list((await session.scalars(query)).all())


async def test_an_upload_and_download_leave_a_trail(sharing, provider, queue, session):  # noqa: F811
    public, internal, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    intent = (await download(public, provider, file_id)).json()
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 200

    trail = [
        (e.action, e.outcome, e.actor_kind)
        for e in await events(session, target_id=uuid.UUID(file_id))
    ]
    assert trail == [
        ("file.registered", "ok", "user"),
        ("upload.started", "ok", "user"),
        ("upload.completed", "ok", "gateway"),
        ("scan.result", "clean", "scanner"),
        ("download.issued", "ok", "user"),
        ("download.started", "ok", "user"),
    ]
    registered = (await events(session, action="file.registered", target_id=uuid.UUID(file_id)))[0]
    assert registered.details == {"name": "report.pdf", "declared_size": 1234}
    assert registered.request_id  # ties the event to the access log line
    assert (await audit.verify(session)).ok


async def test_refusals_are_kept_although_the_attempt_rolls_back(sharing, provider, queue, session):  # noqa: F811
    public, internal, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    # A forged token names nothing real: logged, not audited (anyone can send one).
    rejected = await consume_download(internal, file_id, "forged")
    assert rejected.status_code == 403
    assert await events(session, action="intent.rejected") == []

    # A policy refusal at the API.
    session.add(Policy(name="no downloads", effect="deny", actions=["download"]))
    await session.flush()
    assert (await download(public, provider, file_id)).status_code == 403
    [denied] = await events(session, action="access.denied")
    assert denied.outcome == "denied"
    assert denied.details["action"] == "download"
    assert denied.details["deny_policies"] == ["no downloads"]
    assert (await audit.verify(session)).ok


async def test_shares_and_quarantine_decisions_are_recorded(sharing, provider, queue, session):  # noqa: F811
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue, findings=CARD)
    await public.post(
        f"/admin/files/{file_id}/release",
        json={"reason": "client contract", "purpose": "share"},
        headers=admin(provider),
    )
    created = (await share(public, provider, file_id)).json()["share"]
    await public.delete(f"/files/{file_id}/shares/{created['id']}", headers=as_user(provider))

    by_action = {e.action: e for e in await events(session, target_id=uuid.UUID(file_id))}
    assert by_action["scan.result"].outcome == "quarantined"
    assert by_action["scan.result"].details["findings"] == {"payment_card": 1}
    assert by_action["quarantine.released"].details == {
        "verdict": "quarantined",
        "purpose": "share",
        "reason": "client contract",
    }
    # An audit log has to say who received a file.
    assert by_action["share.created"].details["recipient_email"] == "bob@example.com"
    assert by_action["share.revoked"].details["share_id"] == created["id"]


async def test_policy_changes_keep_the_policy_as_it_was(sharing, provider, session):  # noqa: F811
    public, _, _ = sharing
    body = {"name": "weekdays", "effect": "allow", "actions": ["read"], "days": [1, 2, 3, 4, 5]}
    created = (await public.post("/admin/policies", json=body, headers=admin(provider))).json()
    await public.delete(f"/admin/policies/{created['id']}", headers=admin(provider))
    trail = await events(session, target_id=uuid.UUID(created["id"]))
    assert [e.action for e in trail] == ["policy.created", "policy.deleted"]
    assert trail[1].details["days"] == [1, 2, 3, 4, 5]  # what was deleted


async def test_events_chain_to_each_other(sharing, provider, queue, session):  # noqa: F811
    await with_verdict(sharing, provider, queue)
    chain = await events(session)
    assert chain[0].prev_hash == audit.GENESIS
    for before, after in pairwise(chain):
        assert after.prev_hash == before.hash
    assert all(audit.event_hash(e) == e.hash for e in chain)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET outcome = 'ok'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ],
)
async def test_the_log_is_append_only(sharing, provider, queue, session, statement):  # noqa: F811
    await with_verdict(sharing, provider, queue)
    with pytest.raises(DBAPIError, match="append-only"):
        async with session.begin_nested():
            await session.execute(text(statement))


async def _tamper(session, sql: str) -> None:
    """What someone with the table owner's rights could do: switch the guard off."""
    await session.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
    await session.execute(text(sql))
    await session.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))


async def test_verification_finds_a_changed_event(sharing, provider, queue, session):  # noqa: F811
    await with_verdict(sharing, provider, queue)
    chain = await events(session)
    victim = chain[2]
    await _tamper(session, f"UPDATE audit_events SET outcome = 'nothing' WHERE id = {victim.id}")
    result = await audit.verify(session)
    assert not result.ok
    assert result.first_broken_id == victim.id and "changed" in result.reason
    assert result.events == 2


async def test_verification_finds_a_removed_event(sharing, provider, queue, session):  # noqa: F811
    await with_verdict(sharing, provider, queue)
    chain = await events(session)
    await _tamper(session, f"DELETE FROM audit_events WHERE id = {chain[1].id}")
    result = await audit.verify(session)
    assert not result.ok
    assert result.first_broken_id == chain[2].id and "removed" in result.reason


async def test_admins_read_and_verify_the_log(sharing, provider, queue):  # noqa: F811
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    page = (
        await public.get("/admin/audit", params={"target_id": file_id}, headers=admin(provider))
    ).json()
    assert [e["action"] for e in page["items"]][:1] == ["scan.result"]  # newest first
    assert page["total"] == 4
    uploads = await public.get(
        "/admin/audit", params={"action": "upload."}, headers=admin(provider)
    )
    assert {e["action"] for e in uploads.json()["items"]} == {"upload.started", "upload.completed"}
    verified = (await public.post("/admin/audit/verify", headers=admin(provider))).json()
    assert verified["ok"] is True and verified["events"] >= 4 and verified["head_hash"]
    # Not for anyone else.
    assert (await public.get("/admin/audit", headers=as_user(provider))).status_code == 403
    assert (await public.post("/admin/audit/verify", headers=as_user(provider))).status_code == 403


async def test_an_outside_recipient_leaves_a_trail(recipients, provider, queue, mailer, session):  # noqa: F811
    public, internal, _ = recipients
    file_id, share_id, token = await shared(recipients, provider, queue)
    await public.post("/shares/access/code", json={"token": token})
    await public.post(
        "/shares/access/verify",
        json={"token": token, "code": "000000" if mailer.last_code() != "000000" else "111111"},
    )
    grant = (
        await public.post(
            "/shares/access/verify", json={"token": token, "code": mailer.last_code()}
        )
    ).json()["grant"]
    intent = (
        await public.post("/shares/access/downloads", json={"token": token, "grant": grant})
    ).json()
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 200
    trail = [
        (e.action, e.outcome, e.actor_kind)
        for e in await events(session, target_id=uuid.UUID(file_id))
        if e.action.startswith("share.")
    ]
    assert trail == [
        ("share.created", "ok", "user"),
        ("share.code_sent", "ok", "recipient"),
        ("share.verification_failed", "denied", "recipient"),
        ("share.verified", "ok", "recipient"),
        ("share.download_issued", "ok", "recipient"),
        ("share.downloaded", "ok", "recipient"),
    ]
    downloaded = (await events(session, action="share.downloaded"))[0]
    assert downloaded.details == {"share_id": share_id, "recipient_email": "bob@example.com"}
    assert (await audit.verify(session)).ok

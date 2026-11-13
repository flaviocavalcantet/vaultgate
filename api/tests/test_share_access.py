"""External share recipients: code by email, grant, download through the gateway."""

import re
from datetime import UTC, datetime, timedelta

import pytest
from prometheus_client import REGISTRY
from sqlalchemy import select, update

from tests.conftest import requires_db
from tests.test_files import as_user, consume_download
from tests.test_quarantine import CARD, admin, with_verdict
from tests.test_shares import share
from vaultgate_api import mail
from vaultgate_api.config import settings
from vaultgate_api.main import app
from vaultgate_api.models import File, Policy, Share, ShareVerification, User

pytestmark = requires_db


class FakeMailer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []
        self.failing = False

    async def send(self, to: str, subject: str, body: str) -> None:
        if self.failing:
            raise mail.MailUnavailable("down")
        self.sent.append((to, subject, body))

    def last_code(self) -> str:
        return re.search(r"\b(\d{6})\b", self.sent[-1][2]).group(1)


@pytest.fixture
def mailer() -> FakeMailer:
    return FakeMailer()


@pytest.fixture
async def recipients(scanner, session, mailer):
    """The scanner fixture's clients, sharing allowed, and email caught by `mailer`."""
    session.add(Policy(name="sharing", effect="allow", actions=["share"]))
    await session.flush()
    app.dependency_overrides[mail.get_mailer] = lambda: mailer
    return scanner


async def shared(
    recipients, provider, queue, findings=(), name="report.pdf", **body
) -> tuple[str, str, str]:
    """A clean (or flagged) file shared with bob; returns its id, the share id, the token."""
    file_id, _ = await with_verdict(recipients, provider, queue, findings=findings, name=name)
    if findings:
        await recipients[0].post(
            f"/admin/files/{file_id}/release",
            json={"reason": "test", "purpose": "share"},
            headers=admin(provider),
        )
    response = await share(recipients[0], provider, file_id, **body)
    assert response.status_code == 201, response.text
    created = response.json()
    return file_id, created["share"]["id"], created["token"]


async def verified(public, mailer, token: str) -> str:
    assert (await public.post("/shares/access/code", json={"token": token})).status_code == 202
    response = await public.post(
        "/shares/access/verify", json={"token": token, "code": mailer.last_code()}
    )
    assert response.status_code == 200, response.text
    return response.json()["grant"]


def downloads(public, token: str, grant: str):
    return public.post("/shares/access/downloads", json={"token": token, "grant": grant})


async def test_a_recipient_proves_the_address_and_downloads(
    recipients, provider, queue, mailer, session
):
    public, internal, _ = recipients
    file_id, share_id, token = await shared(recipients, provider, queue)

    described = await public.get("/shares/access", params={"token": token})
    assert described.status_code == 200
    assert described.json()["recipient_hint"] == "b***@example.com"
    assert described.json()["downloads_left"] == settings.share_default_downloads
    assert "report.pdf" not in described.text  # nothing about the file before the proof

    sent = await public.post("/shares/access/code", json={"token": token})
    assert sent.status_code == 202 and sent.json()["sent_to"] == "b***@example.com"
    [(to, subject, body)] = mailer.sent
    code = mailer.last_code()
    assert to == "bob@example.com" and code in subject and code in body
    # Nothing a user typed goes into the mail.
    assert "report.pdf" not in body and "alice" not in body
    # Only a salted hash of the code is stored.
    row = await session.get(ShareVerification, share_id)
    assert row.code_hash and code not in (row.code_hash, row.code_salt)

    grant = (
        await public.post("/shares/access/verify", json={"token": token, "code": code})
    ).json()["grant"]
    intent = await downloads(public, token, grant)
    assert intent.status_code == 201, intent.text
    assert intent.json()["url"].endswith(f"/downloads/{file_id}")

    before = REGISTRY.get_sample_value("vaultgate_api_share_downloads_total") or 0
    consumed = await consume_download(internal, file_id, intent.json()["token"])
    assert consumed.status_code == 200, consumed.text
    assert consumed.json()["name"] == "report.pdf"
    # A recipient's downloads count against the share, not the owner.
    assert consumed.json()["limit_key"] == f"share:{share_id}"
    assert REGISTRY.get_sample_value("vaultgate_api_share_downloads_total") == before + 1
    row = await session.get(Share, share_id)
    await session.refresh(row)
    assert row.downloads == 1
    # The grant keeps working for further downloads, each counted.
    assert (await downloads(public, token, grant)).status_code == 201


async def test_unknown_links_are_not_found(recipients):
    public, _, _ = recipients
    for method, path, body in [
        ("GET", "/shares/access?token=nope", None),
        ("POST", "/shares/access/code", {"token": "nope"}),
        ("POST", "/shares/access/verify", {"token": "nope", "code": "123456"}),
        ("POST", "/shares/access/downloads", {"token": "nope", "grant": "x"}),
    ]:
        assert (await public.request(method, path, json=body)).status_code == 404


async def test_codes_are_for_external_recipients_only(recipients, provider, queue, mailer):
    public, _, _ = recipients
    _, _, token = await shared(recipients, provider, queue, recipient_kind="internal")
    response = await public.post("/shares/access/code", json={"token": token})
    assert response.status_code == 409 and "sign in" in response.json()["detail"]
    assert mailer.sent == []


async def test_wrong_codes_use_up_the_code(recipients, provider, queue, mailer):
    public, _, _ = recipients
    _, _, token = await shared(recipients, provider, queue)
    await public.post("/shares/access/code", json={"token": token})
    code = mailer.last_code()
    wrong = "000000" if code != "000000" else "111111"
    for left in range(settings.share_code_attempts - 1, 0, -1):
        response = await public.post("/shares/access/verify", json={"token": token, "code": wrong})
        assert response.status_code == 403 and f"{left} tries left" in response.json()["detail"]
    last = await public.post("/shares/access/verify", json={"token": token, "code": wrong})
    assert "Too many" in last.json()["detail"]
    # The right code no longer works either.
    late = await public.post("/shares/access/verify", json={"token": token, "code": code})
    assert late.status_code == 403


async def test_a_code_works_once_and_expires(recipients, provider, queue, mailer, session):
    public, _, _ = recipients
    _, share_id, token = await shared(recipients, provider, queue)
    await verified(public, mailer, token)
    again = await public.post(
        "/shares/access/verify", json={"token": token, "code": mailer.last_code()}
    )
    assert again.status_code == 403

    await session.execute(
        update(ShareVerification)
        .where(ShareVerification.share_id == share_id)
        .values(last_sent_at=None)
    )
    await public.post("/shares/access/code", json={"token": token})
    await session.execute(
        update(ShareVerification)
        .where(ShareVerification.share_id == share_id)
        .values(code_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    expired = await public.post(
        "/shares/access/verify", json={"token": token, "code": mailer.last_code()}
    )
    assert expired.status_code == 403 and "expired" in expired.json()["detail"]


@pytest.mark.parametrize("code", ["12345", "1234567", "abcdef", ""])
async def test_codes_are_six_digits(recipients, provider, queue, code):
    public, _, _ = recipients
    _, _, token = await shared(recipients, provider, queue)
    response = await public.post("/shares/access/verify", json={"token": token, "code": code})
    assert response.status_code == 422


async def test_codes_are_rate_limited(recipients, provider, queue, mailer, session, monkeypatch):
    public, _, _ = recipients
    _, share_id, token = await shared(recipients, provider, queue)
    assert (await public.post("/shares/access/code", json={"token": token})).status_code == 202
    soon = await public.post("/shares/access/code", json={"token": token})
    assert soon.status_code == 429 and soon.headers["Retry-After"]

    monkeypatch.setattr(settings, "share_code_resend_seconds", 0)
    for _ in range(settings.share_code_sends_per_hour - 1):
        assert (await public.post("/shares/access/code", json={"token": token})).status_code == 202
    over = await public.post("/shares/access/code", json={"token": token})
    assert over.status_code == 429
    assert len(mailer.sent) == settings.share_code_sends_per_hour
    # A new hour, new codes.
    await session.execute(
        update(ShareVerification)
        .where(ShareVerification.share_id == share_id)
        .values(window_started_at=datetime.now(UTC) - timedelta(hours=1, seconds=1))
    )
    assert (await public.post("/shares/access/code", json={"token": token})).status_code == 202


async def test_a_mail_failure_sends_nothing_and_stores_no_code(
    recipients, provider, queue, mailer, session
):
    public, _, _ = recipients
    _, share_id, token = await shared(recipients, provider, queue)
    mailer.failing = True
    response = await public.post("/shares/access/code", json={"token": token})
    assert response.status_code == 503
    row = await session.scalar(
        select(ShareVerification)
        .where(ShareVerification.share_id == share_id)
        .execution_options(populate_existing=True)
    )
    assert row is None or (row.code_hash is None and row.sends == 0 and row.last_sent_at is None)
    # No wait imposed by a send that did not happen.
    mailer.failing = False
    assert (await public.post("/shares/access/code", json={"token": token})).status_code == 202


async def test_no_lock_is_held_while_the_mail_is_sent(recipients, provider, queue, session):
    """Sending waits on a mail server; the share's row must be free meanwhile."""
    public, _, _ = recipients
    _, _, token = await shared(recipients, provider, queue)
    # The test's transaction holds everything until the test ends, so this only checks
    # that the route commits before sending: the share row is unlocked by then.
    sent = []

    async def send(to, subject, body):
        sent.append(session.in_transaction())

    probe = type("Probe", (), {"send": staticmethod(send)})()
    app.dependency_overrides[mail.get_mailer] = lambda: probe
    assert (await public.post("/shares/access/code", json={"token": token})).status_code == 202
    assert sent == [False]


async def test_grants_must_be_right_and_current(recipients, provider, queue, mailer, session):
    public, _, _ = recipients
    _, share_id, token = await shared(recipients, provider, queue)
    assert (await downloads(public, token, "no grant yet")).status_code == 403
    grant = await verified(public, mailer, token)
    assert (await downloads(public, token, grant + "x")).status_code == 403
    _, _, other = await shared(recipients, provider, queue, name="other.pdf")
    assert (await downloads(public, other, grant)).status_code == 403  # another share's
    await session.execute(
        update(ShareVerification)
        .where(ShareVerification.share_id == share_id)
        .values(grant_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    assert (await downloads(public, token, grant)).status_code == 403


async def test_a_revoke_ends_everything_at_once(recipients, provider, queue, mailer):
    public, internal, _ = recipients
    file_id, share_id, token = await shared(recipients, provider, queue)
    grant = await verified(public, mailer, token)
    intent = (await downloads(public, token, grant)).json()
    revoked = await public.delete(f"/files/{file_id}/shares/{share_id}", headers=as_user(provider))
    assert revoked.status_code == 204
    assert (await public.get("/shares/access", params={"token": token})).status_code == 410
    assert (await downloads(public, token, grant)).status_code == 410
    # An intent handed out before the revoke is refused by the gateway's consume.
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 403


async def test_downloads_stop_at_the_limit(recipients, provider, queue, mailer):
    public, internal, _ = recipients
    file_id, _, token = await shared(recipients, provider, queue, max_downloads=1)
    grant = await verified(public, mailer, token)
    first = (await downloads(public, token, grant)).json()
    second = (await downloads(public, token, grant)).json()  # issued, not yet counted
    assert (await consume_download(internal, file_id, first["token"])).status_code == 200
    assert (await consume_download(internal, file_id, second["token"])).status_code == 403
    described = await public.get("/shares/access", params={"token": token})
    assert described.status_code == 410 and described.json()["detail"] == "Share is used"


async def test_a_rescan_into_quarantine_stops_share_downloads(recipients, provider, queue, mailer):
    public, internal, scanner_client = recipients
    file_id, _, token = await shared(recipients, provider, queue, findings=CARD)
    grant = await verified(public, mailer, token)
    intent = (await downloads(public, token, grant)).json()
    # The rescan drops the release for sharing; the verdict is quarantined again.
    await public.post(f"/admin/files/{file_id}/rescan", headers=admin(provider))
    [(_, scan_id)] = queue.sent[-1:]
    await scanner_client.post(
        f"/internal/scans/{scan_id}/result", json={"outcome": "scanned", "findings": CARD}
    )
    refused = await consume_download(internal, file_id, intent["token"])
    assert refused.status_code == 409
    assert (await downloads(public, token, grant)).status_code == 409
    assert (await public.post("/shares/access/code", json={"token": token})).status_code == 409


async def test_a_deactivated_owner_ends_their_shares(recipients, provider, queue, mailer, session):
    public, internal, _ = recipients
    file_id, _, token = await shared(recipients, provider, queue)
    grant = await verified(public, mailer, token)
    intent = (await downloads(public, token, grant)).json()
    owner = await session.scalar(select(User).where(User.subject == "alice"))
    owner.is_active = False
    await session.flush()
    assert (await public.get("/shares/access", params={"token": token})).status_code == 410
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 403


async def test_the_owners_policies_do_not_govern_recipients(
    recipients, provider, queue, mailer, session
):
    """The owner decided by sharing; their own download restrictions (say, office
    networks only) are not the recipient's."""
    public, internal, _ = recipients
    file_id, _, token = await shared(recipients, provider, queue)
    session.add(Policy(name="no downloads", effect="deny", actions=["download"]))
    await session.flush()
    grant = await verified(public, mailer, token)
    intent = (await downloads(public, token, grant)).json()
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 200
    # The owner, meanwhile, is denied.
    assert (
        await public.post(f"/files/{file_id}/download", headers=as_user(provider))
    ).status_code == 403


async def test_a_file_gone_from_the_vault_is_not_served(
    recipients, provider, queue, mailer, session
):
    public, _, _ = recipients
    file_id, _, token = await shared(recipients, provider, queue)
    await session.execute(update(File).where(File.id == file_id).values(status="failed"))
    assert (await public.get("/shares/access", params={"token": token})).status_code == 410


async def test_codes_are_capped_per_owner(recipients, provider, queue, mailer, monkeypatch):
    """Code emails go to addresses the owner chose: one owner can't send many."""
    monkeypatch.setattr(settings, "share_codes_per_owner_per_hour", 2)
    public, _, _ = recipients
    tokens = [(await shared(recipients, provider, queue, name=f"{n}.pdf"))[2] for n in range(3)]
    for token in tokens[:2]:
        assert (await public.post("/shares/access/code", json={"token": token})).status_code == 202
    capped = await public.post("/shares/access/code", json={"token": tokens[2]})
    assert capped.status_code == 429
    assert len(mailer.sent) == 2

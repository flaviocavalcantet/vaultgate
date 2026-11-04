"""Internal share recipients: signed-in users whose verified email a share names."""

from sqlalchemy import select

from tests.conftest import requires_db
from tests.fake_oidc import FakeProvider
from tests.test_files import consume_download
from tests.test_quarantine import CARD, admin, with_verdict
from tests.test_shares import share, sharing  # noqa: F401 (fixture)
from vaultgate_api.models import Policy, Share, User

pytestmark = requires_db


def person(provider: FakeProvider, sub: str, email: str, verified: bool = True, groups=("/legal",)):
    token = provider.token(
        sub=sub,
        preferred_username=sub,
        email=email,
        email_verified=verified,
        groups=list(groups),
    )
    return {"Authorization": f"Bearer {token}"}


async def internal_share(sharing, provider, queue, findings=(), **body) -> tuple[str, str]:  # noqa: F811
    file_id, _ = await with_verdict(sharing, provider, queue, findings=findings)
    response = await share(sharing[0], provider, file_id, recipient_kind="internal", **body)
    assert response.status_code == 201, response.text
    return file_id, response.json()["share"]["id"]


async def test_the_named_user_lists_and_downloads(sharing, provider, queue, session):  # noqa: F811
    public, internal, _ = sharing
    file_id, share_id = await internal_share(sharing, provider, queue, max_downloads=2)
    bob = person(provider, "bob", "Bob@Example.com")

    [item] = (await public.get("/shared-with-me", headers=bob)).json()
    assert item["share_id"] == share_id and item["file_id"] == file_id
    assert item["name"] == "report.pdf" and item["shared_by"] == "alice"
    assert item["downloads_left"] == 2 and item["available"] is True

    intent = await public.post(f"/shared-with-me/{share_id}/download", headers=bob)
    assert intent.status_code == 201, intent.text
    consumed = await consume_download(internal, file_id, intent.json()["token"])
    assert consumed.status_code == 200
    row = await session.get(Share, share_id)
    await session.refresh(row)
    assert row.downloads == 1


async def test_only_a_verified_matching_email_sees_the_share(sharing, provider, queue):  # noqa: F811
    public, _, _ = sharing
    _, share_id = await internal_share(sharing, provider, queue)
    for headers in (
        person(provider, "bob", "bob@example.com", verified=False),
        person(provider, "carol", "carol@example.com"),
        person(provider, "nomail", None),
    ):
        assert (await public.get("/shared-with-me", headers=headers)).json() == []
        response = await public.post(f"/shared-with-me/{share_id}/download", headers=headers)
        assert response.status_code == 404


async def test_external_shares_are_not_for_signed_in_users(sharing, provider, queue):  # noqa: F811
    public, _, _ = sharing
    file_id, _ = await with_verdict(sharing, provider, queue)
    created = (await share(public, provider, file_id)).json()["share"]  # external, to bob
    bob = person(provider, "bob", "bob@example.com")
    assert (await public.get("/shared-with-me", headers=bob)).json() == []
    response = await public.post(f"/shared-with-me/{created['id']}/download", headers=bob)
    assert response.status_code == 404


async def test_a_revoke_ends_the_share_and_intents_already_issued(sharing, provider, queue):  # noqa: F811
    public, internal, _ = sharing
    file_id, share_id = await internal_share(sharing, provider, queue)
    bob = person(provider, "bob", "bob@example.com")
    intent = (await public.post(f"/shared-with-me/{share_id}/download", headers=bob)).json()
    alice = {"Authorization": f"Bearer {provider.token(sub='alice', preferred_username='alice')}"}
    assert (
        await public.delete(f"/files/{file_id}/shares/{share_id}", headers=alice)
    ).status_code == 204
    assert (await public.get("/shared-with-me", headers=bob)).json() == []
    assert (
        await public.post(f"/shared-with-me/{share_id}/download", headers=bob)
    ).status_code == 410
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 403


async def test_the_recipients_own_policies_apply(sharing, provider, queue, session):  # noqa: F811
    """Unlike an outside recipient, a VaultGate user stays under their own policies,
    at the API and at the gateway."""
    public, internal, _ = sharing
    file_id, share_id = await internal_share(sharing, provider, queue)
    bob = person(provider, "bob", "bob@example.com", groups=("/legal",))
    intent = (await public.post(f"/shared-with-me/{share_id}/download", headers=bob)).json()
    session.add(
        Policy(name="legal no downloads", effect="deny", actions=["download"], groups=["/legal"])
    )
    await session.flush()
    # The API first: the gateway's refusal rolls back the test's shared session, policy
    # included.
    assert (
        await public.post(f"/shared-with-me/{share_id}/download", headers=bob)
    ).status_code == 403
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 403


async def test_an_email_change_ends_access(sharing, provider, queue):  # noqa: F811
    public, internal, _ = sharing
    file_id, share_id = await internal_share(sharing, provider, queue)
    intent = (
        await public.post(
            f"/shared-with-me/{share_id}/download",
            headers=person(provider, "bob", "bob@example.com"),
        )
    ).json()
    # Bob's next token carries another address: his user record follows it.
    moved = person(provider, "bob", "bob@elsewhere.example")
    assert (await public.get("/shared-with-me", headers=moved)).json() == []
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 403


async def test_a_rescan_into_quarantine_makes_it_unavailable(sharing, provider, queue):  # noqa: F811
    public, internal, scanner_client = sharing
    file_id, _ = await with_verdict(sharing, provider, queue, findings=CARD)
    await public.post(
        f"/admin/files/{file_id}/release",
        json={"reason": "test", "purpose": "share"},
        headers=admin(provider),
    )
    share_id = (await share(public, provider, file_id, recipient_kind="internal")).json()["share"][
        "id"
    ]
    bob = person(provider, "bob", "bob@example.com")
    intent = (await public.post(f"/shared-with-me/{share_id}/download", headers=bob)).json()
    await public.post(f"/admin/files/{file_id}/rescan", headers=admin(provider))
    [(_, scan_id)] = queue.sent[-1:]
    await scanner_client.post(
        f"/internal/scans/{scan_id}/result", json={"outcome": "scanned", "findings": CARD}
    )
    [item] = (await public.get("/shared-with-me", headers=bob)).json()
    assert item["available"] is False
    assert (
        await public.post(f"/shared-with-me/{share_id}/download", headers=bob)
    ).status_code == 409
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 409


async def test_a_deactivated_owner_ends_their_shares(sharing, provider, queue, session):  # noqa: F811
    public, internal, _ = sharing
    file_id, share_id = await internal_share(sharing, provider, queue)
    bob = person(provider, "bob", "bob@example.com")
    intent = (await public.post(f"/shared-with-me/{share_id}/download", headers=bob)).json()
    owner = await session.scalar(select(User).where(User.subject == "alice"))
    owner.is_active = False
    await session.flush()
    assert (await public.get("/shared-with-me", headers=bob)).json() == []
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 403

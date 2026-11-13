"""Quarantine (ADR 0005): only a clean file, or one an admin released, is downloaded."""

import uuid

import pytest
from prometheus_client import REGISTRY

from tests.conftest import requires_db
from tests.fake_oidc import FakeProvider
from tests.test_files import as_user, consume_download
from tests.test_scans import file_of, report, scanned_upload
from vaultgate_api.config import settings

pytestmark = requires_db

CARD = [{"kind": "payment_card", "count": 1}]
EMAIL = [{"kind": "email", "count": 1}]


def admin(provider: FakeProvider) -> dict[str, str]:
    token = provider.token(sub="carol", preferred_username="carol", groups=["/vaultgate-admins"])
    return {"Authorization": f"Bearer {token}"}


def download(public, provider, file_id: str, sub: str = "alice"):
    return public.post(f"/files/{file_id}/download", headers=as_user(provider, sub))


async def with_verdict(scanner, provider, queue, outcome="scanned", findings=(), name="report.pdf"):
    public, internal, scanner_client = scanner
    file_id, scan_id = await scanned_upload(public, internal, provider, queue, name)
    if outcome != "pending":
        response = await report(scanner_client, scan_id, outcome, findings=list(findings))
        assert response.status_code == 200
    return file_id, scan_id


def counter(name: str, **labels) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


@pytest.mark.parametrize(
    ("outcome", "findings", "detail"),
    [
        ("pending", [], "File is waiting for its PII scan"),
        ("scanned", CARD, "File is quarantined: it contains personal data"),
        (
            "scanned",
            [{"kind": "br_cpf", "count": 3}],
            "File is quarantined: it contains personal data",
        ),
        ("unscannable", [], "File could not be scanned for personal data"),
    ],
)
async def test_only_clean_files_are_downloaded(scanner, provider, queue, outcome, findings, detail):
    public, _, _ = scanner
    file_id, _ = await with_verdict(scanner, provider, queue, outcome, findings)
    verdict = (
        "pending"
        if outcome == "pending"
        else (await file_of(public, provider, file_id))["scan"]["verdict"]
    )
    before = counter("vaultgate_api_downloads_blocked_total", verdict=verdict, checked_by="api")
    response = await download(public, provider, file_id)
    assert response.status_code == 409
    assert response.json() == {"detail": detail}
    assert (await file_of(public, provider, file_id))["downloadable"] is False
    after = counter("vaultgate_api_downloads_blocked_total", verdict=verdict, checked_by="api")
    assert after == before + 1


@pytest.mark.parametrize("findings", [[], EMAIL])
async def test_clean_files_are_downloaded(scanner, provider, queue, findings):
    public, _, _ = scanner
    file_id, _ = await with_verdict(scanner, provider, queue, findings=findings)
    assert (await file_of(public, provider, file_id))["downloadable"] is True
    assert (await download(public, provider, file_id)).status_code == 201


async def test_the_gateway_rechecks_and_a_refused_intent_stays_unspent(
    scanner, provider, queue, monkeypatch
):
    public, internal, _ = scanner
    file_id, _ = await with_verdict(scanner, provider, queue, findings=EMAIL)
    intent = (await download(public, provider, file_id)).json()
    # Emails quarantine now: the intent issued while the file was clean is refused...
    monkeypatch.setattr(settings, "quarantine_kinds", ["email"])
    refused = await consume_download(internal, file_id, intent["token"])
    assert refused.status_code == 409
    assert refused.json()["detail"] == "File is quarantined: it contains personal data"
    # ...and still usable once the file is allowed again.
    monkeypatch.setattr(settings, "quarantine_kinds", ["payment_card"])
    assert (await consume_download(internal, file_id, intent["token"])).status_code == 200


@pytest.mark.parametrize(("outcome", "findings"), [("scanned", CARD), ("unscannable", [])])
async def test_an_admin_release_lets_the_owner_download(
    scanner, provider, queue, outcome, findings
):
    public, _, _ = scanner
    file_id, _ = await with_verdict(scanner, provider, queue, outcome, findings)
    before = counter("vaultgate_api_quarantine_releases_total", purpose="download")
    response = await public.post(
        f"/admin/files/{file_id}/release",
        json={"reason": "Customer contract, checked with the DPO"},
        headers=admin(provider),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["downloadable"] is True
    assert body["released_by"]["download"] is not None
    assert counter("vaultgate_api_quarantine_releases_total", purpose="download") == before + 1

    file = await file_of(public, provider, file_id)
    assert file["scan"]["verdict"] in ("quarantined", "unscannable")  # the verdict stands
    [release] = file["scan"]["releases"]
    assert release["purpose"] == "download"
    assert release["reason"] == "Customer contract, checked with the DPO"
    assert file["downloadable"] is True
    assert (await download(public, provider, file_id)).status_code == 201
    # Still only the owner's file.
    assert (await download(public, provider, file_id, sub="bob")).status_code == 404


@pytest.mark.parametrize(
    ("outcome", "findings"), [("pending", []), ("scanned", []), ("scanned", EMAIL)]
)
async def test_only_quarantined_or_unscannable_files_are_released(
    scanner, provider, queue, outcome, findings
):
    public, _, _ = scanner
    file_id, _ = await with_verdict(scanner, provider, queue, outcome, findings)
    response = await public.post(
        f"/admin/files/{file_id}/release", json={"reason": "x"}, headers=admin(provider)
    )
    assert response.status_code == 409


async def test_a_release_needs_a_reason_and_happens_once(scanner, provider, queue):
    public, _, _ = scanner
    file_id, _ = await with_verdict(scanner, provider, queue, findings=CARD)
    path = f"/admin/files/{file_id}/release"
    for body in ({}, {"reason": ""}, {"reason": "x" * 501}):
        assert (await public.post(path, json=body, headers=admin(provider))).status_code == 422
    assert (
        await public.post(path, json={"reason": "ok"}, headers=admin(provider))
    ).status_code == 200
    assert (
        await public.post(path, json={"reason": "ok"}, headers=admin(provider))
    ).status_code == 409


async def test_a_rescan_drops_the_findings_and_the_release(scanner, provider, queue):
    public, _, scanner_client = scanner
    file_id, old_scan = await with_verdict(scanner, provider, queue, findings=CARD)
    await public.post(
        f"/admin/files/{file_id}/release", json={"reason": "ok"}, headers=admin(provider)
    )
    queue.sent.clear()
    response = await public.post(f"/admin/files/{file_id}/rescan", headers=admin(provider))
    assert response.status_code == 202, response.text
    assert response.json()["scan"]["verdict"] == "pending"

    [(sent_file, new_scan)] = queue.sent
    assert str(sent_file) == file_id and str(new_scan) != old_scan
    file = await file_of(public, provider, file_id)
    assert file["scan"] == {
        "verdict": "pending",
        "findings": [],
        "reason": None,
        "scanned_at": None,
        "releases": [],
    }
    assert (await download(public, provider, file_id)).status_code == 409
    # A late result for the old scan does not count; the new one does.
    assert (await report(scanner_client, old_scan, findings=[])).status_code == 404
    assert (await report(scanner_client, str(new_scan), findings=CARD)).status_code == 200
    assert (await file_of(public, provider, file_id))["scan"]["verdict"] == "quarantined"
    assert (await download(public, provider, file_id)).status_code == 409


async def test_a_pending_file_is_not_rescanned(scanner, provider, queue):
    public, _, _ = scanner
    file_id, _ = await with_verdict(scanner, provider, queue, "pending")
    response = await public.post(f"/admin/files/{file_id}/rescan", headers=admin(provider))
    assert response.status_code == 409


async def test_admins_list_files_by_verdict(scanner, provider, queue, monkeypatch):
    public, _, _ = scanner
    ids = {
        verdict: (await with_verdict(scanner, provider, queue, outcome, found, f"{verdict}.pdf"))[0]
        for verdict, outcome, found in [
            ("pending", "pending", ()),
            ("clean", "scanned", EMAIL),
            ("quarantined", "scanned", CARD),
            ("unscannable", "unscannable", ()),
        ]
    }

    async def listed(verdict: str | None = None) -> set[str]:
        params = {"verdict": verdict, "limit": 100} if verdict else {"limit": 100}
        response = await public.get("/admin/files", params=params, headers=admin(provider))
        assert response.status_code == 200, response.text
        items = response.json()["items"]
        assert all(i["owner_username"] == "alice" for i in items if i["id"] in ids.values())
        return {i["id"] for i in items}

    for verdict, file_id in ids.items():
        found = await listed(verdict)
        assert file_id in found
        assert not {other for v, other in ids.items() if v != verdict} & found
    assert set(ids.values()) <= await listed()
    # The filter follows the quarantine kinds as configured now.
    monkeypatch.setattr(settings, "quarantine_kinds", ["email"])
    assert ids["clean"] in await listed("quarantined")
    assert ids["quarantined"] in await listed("clean")
    response = await public.get("/admin/files", params={"verdict": "x"}, headers=admin(provider))
    assert response.status_code == 422


async def test_admin_file_routes_are_for_admins_only(scanner, provider, queue):
    public, _, _ = scanner
    file_id, _ = await with_verdict(scanner, provider, queue, findings=CARD)
    alice = as_user(provider)
    for method, path, body in [
        ("GET", "/admin/files", None),
        ("GET", f"/admin/files/{file_id}", None),
        ("POST", f"/admin/files/{file_id}/release", {"reason": "mine"}),
        ("POST", f"/admin/files/{file_id}/rescan", None),
    ]:
        response = await public.request(method, path, json=body, headers=alice)
        assert response.status_code == 403, (method, path)
    for path in (f"/admin/files/{uuid.uuid4()}", f"/admin/files/{uuid.uuid4()}/rescan"):
        method = "GET" if path.count("/") == 3 else "POST"
        assert (await public.request(method, path, headers=admin(provider))).status_code == 404

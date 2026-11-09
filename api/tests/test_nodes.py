"""Node enrollment (M11, ADR 0014): a node's request, an admin's approval, the one-time
code, renewal on the nodes' port, revocation; with a fake signer for OpenBao."""

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import requires_db
from tests.fake_oidc import make_validator
from vaultgate_api import nodes, tpm
from vaultgate_api.config import settings
from vaultgate_api.db import get_session
from vaultgate_api.main import app
from vaultgate_api.models import AuditEvent, Node, NodeEnrollment, NodeEnrollmentToken, Policy
from vaultgate_api.mtls import _WithIdentities
from vaultgate_api.nodes_app import nodes_app


def csr_for(key=None, names: list[x509.GeneralName] | None = None) -> tuple[str, str]:
    """A CSR (PEM) and its key's fingerprint."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode(), nodes.fingerprint(
        key.public_key()
    )


# --- pure helpers ----------------------------------------------------------------------


def test_csr_checks() -> None:
    pem, fingerprint = csr_for()
    assert nodes.check_csr(pem) == fingerprint
    assert fingerprint.startswith("SHA256:") and len(fingerprint) == 50
    # Names a CSR asks for don't matter (the signer gives the identity), but it's valid.
    asking, _ = csr_for(names=[x509.UniformResourceIdentifier("spiffe://vaultgate/ns/x")])
    nodes.check_csr(asking)
    for bad, message in [
        ("not a csr", "not a PEM"),
        (csr_for(rsa.generate_private_key(65537, 2048))[0], "ECDSA P-256"),
        (csr_for(ec.generate_private_key(ec.SECP384R1()))[0], "ECDSA P-256"),
        ("x" * 5000, "too large"),
    ]:
        with pytest.raises(nodes.InvalidCSR, match=message):
            nodes.check_csr(bad)


def test_a_csr_signed_by_another_key_is_refused() -> None:
    key, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(key, hashes.SHA256())
    )
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    # Swap in the other key: the signature no longer matches the key it carries.
    mine = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    theirs = other.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    swapped = bytes(der).replace(mine, theirs)
    pem = x509.load_der_x509_csr(swapped).public_bytes(serialization.Encoding.PEM).decode()
    with pytest.raises(nodes.InvalidCSR, match="signature"):
        nodes.check_csr(pem)


def test_names_identities_serials_codes() -> None:
    assert nodes.identity("edge-1") == "spiffe://nodes.vaultgate/node/edge-1"
    assert nodes.name_of(("spiffe://nodes.vaultgate/node/edge-1",)) == "edge-1"
    for uris in [
        ("spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway",),
        ("spiffe://nodes.vaultgate/node/Edge_1",),
        ("spiffe://nodes.vaultgate/node/a/b",),
        (),
    ]:
        assert nodes.name_of(uris) is None
    assert nodes.serial_int("00:1b:2e") == nodes.serial_int("1B2E") == 0x1B2E
    code = nodes.new_code()
    assert len(code) == 11 and code[5] == "-"
    assert set(code.replace("-", "")) <= set(nodes.CODE_ALPHABET)
    salt = "s"
    assert nodes.code_matches(f" {code.lower()} ", salt, nodes.hash_code(code, salt))
    assert not nodes.code_matches("AAAAA-AAAAA", salt, nodes.hash_code(code, salt))


# --- the routes, with a database --------------------------------------------------------


class FakeSigner:
    def __init__(self) -> None:
        self.signed: list[tuple[str, str]] = []
        self.revoked: list[str] = []
        self.failing = False

    async def sign(self, csr: str, identity: str) -> nodes.Issued:
        if self.failing:
            raise nodes.SignerError("down")
        self.signed.append((csr, identity))
        n = len(self.signed)
        return nodes.Issued(
            certificate=f"CERT-{n}",
            chain=["NODES-CA", "ROOT"],
            serial=f"0a:{n:02x}",
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )

    async def revoke(self, serial: str) -> None:
        if self.failing:
            raise nodes.SignerError("down")
        self.revoked.append(serial)


ADMIN = {"sub": "admin-1", "preferred_username": "root", "groups": ["/vaultgate-admins"]}


@pytest.fixture
async def env(clients, provider, session: AsyncSession, monkeypatch):
    """(public client, admin headers, signer, session); enrolling allowed by a policy."""
    public, _ = clients
    session.add(Policy(name="nodes may enroll", effect="allow", actions=["enroll"]))
    # Committed (a savepoint of the test's transaction): a route's rollback before it
    # records a refusal must not take the policy with it.
    await session.commit()
    signer = FakeSigner()
    monkeypatch.setattr(app.state, "node_signer", signer, raising=False)
    admin = {"Authorization": f"Bearer {provider.token(**ADMIN)}"}
    yield public, admin, signer, session
    nodes_app.dependency_overrides.clear()


def node_client(session: AsyncSession, identities: tuple[str, ...], serial: str | None):
    """A client of the nodes' port, presenting a certificate with these URIs and serial."""

    async def test_session():
        yield session

    nodes_app.dependency_overrides[get_session] = test_session
    wrapped = _WithIdentities(nodes_app, identities, serial)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=wrapped), base_url="https://nodes")


async def enroll(public, admin, name: str = "edge-1") -> tuple[dict, str]:
    """A node enrolled through the whole flow: its certificate's answer, and its key."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr, fingerprint = csr_for(key)
    asked = await public.post("/nodes/enrollments", json={"name": name, "csr": csr})
    assert asked.status_code == 202, asked.text
    enrollment = asked.json()
    approved = await public.post(
        f"/admin/nodes/enrollments/{enrollment['id']}/approve",
        json={"key_fingerprint": fingerprint},
        headers=admin,
    )
    assert approved.status_code == 200, approved.text
    done = await public.post(
        f"/nodes/enrollments/{enrollment['id']}/complete", json={"code": approved.json()["code"]}
    )
    assert done.status_code == 200, done.text
    return done.json(), key


async def actions(session: AsyncSession) -> list[tuple[str, str]]:
    rows = await session.execute(
        select(AuditEvent.action, AuditEvent.outcome)
        .where(AuditEvent.action.like("node.%"))
        .order_by(AuditEvent.id)
    )
    return [tuple(r) for r in rows]


@requires_db
async def test_enrollment_by_admin_approval(env) -> None:
    public, admin, signer, session = env
    csr, fingerprint = csr_for()
    asked = await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})
    assert asked.status_code == 202
    enrollment = asked.json()
    assert enrollment["status"] == "pending"
    assert enrollment["key_fingerprint"] == fingerprint
    assert enrollment["identity"] == "spiffe://nodes.vaultgate/node/edge-1"
    eid = enrollment["id"]

    waiting = (await public.get("/admin/nodes/enrollments", headers=admin)).json()
    assert [e["id"] for e in waiting["items"]] == [eid]
    assert waiting["items"][0]["client_ip"] == "127.0.0.1"

    # Not the node's key: refused, and recorded.
    _, other = csr_for()
    wrong = await public.post(
        f"/admin/nodes/enrollments/{eid}/approve", json={"key_fingerprint": other}, headers=admin
    )
    assert wrong.status_code == 409
    assert (await public.get(f"/nodes/enrollments/{eid}")).json()["status"] == "pending"

    approved = await public.post(
        f"/admin/nodes/enrollments/{eid}/approve",
        json={"key_fingerprint": fingerprint},
        headers=admin,
    )
    assert approved.status_code == 200
    code = approved.json()["code"]
    assert (await public.get(f"/nodes/enrollments/{eid}")).json()["status"] == "approved"

    bad = await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": "AAAAA-AAAAA"})
    assert bad.status_code == 403 and "4 tries left" in bad.json()["detail"]
    done = await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": code.lower()})
    assert done.status_code == 200
    issued = done.json()
    assert issued["certificate"] == "CERT-1" and issued["chain"] == ["NODES-CA", "ROOT"]
    assert issued["identity"] == "spiffe://nodes.vaultgate/node/edge-1"
    # The stored CSR is what was signed: the code is good for the request's key only.
    assert signer.signed == [(csr, "spiffe://nodes.vaultgate/node/edge-1")]

    again = await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": code})
    assert again.status_code == 409  # single use
    assert (await public.get(f"/nodes/enrollments/{eid}")).json()["status"] == "completed"
    listed = (await public.get("/admin/nodes", headers=admin)).json()["items"]
    assert [(n["name"], n["status"], n["cert_serial"]) for n in listed] == [
        ("edge-1", "active", "0a:01")
    ]
    assert await actions(session) == [
        ("node.enrollment_requested", "ok"),
        ("node.enrollment_approved", "denied"),
        ("node.enrollment_approved", "ok"),
        ("node.enrollment_completed", "denied"),
        ("node.enrollment_completed", "ok"),
    ]


@requires_db
async def test_enrolling_needs_a_policy(env) -> None:
    public, _, _, session = env
    for policy in await session.scalars(select(Policy).where(Policy.name == "nodes may enroll")):
        await session.delete(policy)
    await session.flush()
    csr, _ = csr_for()
    refused = await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})
    assert refused.status_code == 403
    assert await actions(session) == [("node.enrollment_requested", "denied")]
    assert await session.scalar(select(NodeEnrollment)) is None


@requires_db
async def test_a_deny_policy_by_network_refuses_completion(env) -> None:
    public, admin, signer, session = env
    csr, fingerprint = csr_for()
    eid = (await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})).json()[
        "id"
    ]
    code = (
        await public.post(
            f"/admin/nodes/enrollments/{eid}/approve",
            json={"key_fingerprint": fingerprint},
            headers=admin,
        )
    ).json()["code"]
    session.add(
        Policy(name="not from here", effect="deny", actions=["enroll"], networks=["127.0.0.0/8"])
    )
    await session.flush()
    done = await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": code})
    assert done.status_code == 403
    assert signer.signed == []


@requires_db
async def test_request_checks(env) -> None:
    public, admin, _, _ = env
    csr, _ = csr_for()
    for body, code in [
        ({"name": "Edge_1", "csr": csr}, 422),
        ({"name": "-edge", "csr": csr}, 422),
        ({"name": "edge-1", "csr": "junk"}, 422),
        ({"name": "edge-1", "csr": csr_for(rsa.generate_private_key(65537, 2048))[0]}, 422),
    ]:
        assert (await public.post("/nodes/enrollments", json=body)).status_code == code, body
    await enroll(public, admin, "edge-1")
    taken = await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})
    assert taken.status_code == 409


@requires_db
async def test_too_many_waiting(env, monkeypatch) -> None:
    public, _, _, _ = env
    monkeypatch.setattr(settings, "node_max_pending_enrollments", 2)
    codes = [
        (
            await public.post("/nodes/enrollments", json={"name": f"n{i}", "csr": csr_for()[0]})
        ).status_code
        for i in range(3)
    ]
    assert codes == [202, 202, 429]


@requires_db
async def test_too_many_waiting_from_one_address(env, monkeypatch) -> None:
    """One client can't take every waiting place: others still get theirs."""
    public, _, _, session = env
    monkeypatch.setattr(settings, "node_max_pending_per_address", 2)
    codes = [
        (
            await public.post("/nodes/enrollments", json={"name": f"n{i}", "csr": csr_for()[0]})
        ).status_code
        for i in range(3)
    ]
    assert codes == [202, 202, 429]
    # The same requests from elsewhere don't count against this address.
    for enrollment in await session.scalars(select(NodeEnrollment)):
        enrollment.client_ip = "192.0.2.7"
    await session.flush()
    again = await public.post("/nodes/enrollments", json={"name": "n9", "csr": csr_for()[0]})
    assert again.status_code == 202


@requires_db
async def test_a_code_has_a_few_tries_and_a_short_life(env, monkeypatch) -> None:
    public, admin, signer, session = env
    monkeypatch.setattr(settings, "node_code_attempts", 3)
    csr, fingerprint = csr_for()
    eid = (await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})).json()[
        "id"
    ]

    async def approve() -> str:
        answer = await public.post(
            f"/admin/nodes/enrollments/{eid}/approve",
            json={"key_fingerprint": fingerprint},
            headers=admin,
        )
        return answer.json()["code"]

    code = await approve()
    enrollment = await session.get(NodeEnrollment, uuid.UUID(eid))
    enrollment.code_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.flush()
    expired = await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": code})
    assert expired.status_code == 403 and "expired" in expired.json()["detail"]

    code = await approve()  # a new code
    for _ in range(3):
        wrong = await public.post(
            f"/nodes/enrollments/{eid}/complete", json={"code": "ZZZZZ-ZZZZZ"}
        )
    assert wrong.status_code == 403 and "Too many" in wrong.json()["detail"]
    late = await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": code})
    assert late.status_code == 409  # rejected: the node asks again
    assert (await public.get(f"/nodes/enrollments/{eid}")).json()["status"] == "rejected"
    assert signer.signed == []


@requires_db
async def test_expired_requests_and_rejection(env) -> None:
    public, admin, _, session = env
    csr, fingerprint = csr_for()
    eid = (await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})).json()[
        "id"
    ]
    enrollment = await session.get(NodeEnrollment, uuid.UUID(eid))
    enrollment.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.flush()
    assert (await public.get(f"/nodes/enrollments/{eid}")).json()["status"] == "expired"
    late = await public.post(
        f"/admin/nodes/enrollments/{eid}/approve",
        json={"key_fingerprint": fingerprint},
        headers=admin,
    )
    assert late.status_code == 409
    assert (await public.get("/admin/nodes/enrollments", headers=admin)).json()["total"] == 0

    eid = (await public.post("/nodes/enrollments", json={"name": "edge-2", "csr": csr})).json()[
        "id"
    ]
    rejected = await public.post(f"/admin/nodes/enrollments/{eid}/reject", headers=admin)
    assert rejected.status_code == 204
    assert (await public.get(f"/nodes/enrollments/{eid}")).json()["status"] == "rejected"


@requires_db
async def test_only_admins_decide(env, provider) -> None:
    public, _, _, _ = env
    csr, fingerprint = csr_for()
    eid = (await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})).json()[
        "id"
    ]
    user = {"Authorization": f"Bearer {provider.token()}"}
    for method, path, body in [
        ("GET", "/admin/nodes/enrollments", None),
        ("POST", f"/admin/nodes/enrollments/{eid}/approve", {"key_fingerprint": fingerprint}),
        ("POST", f"/admin/nodes/enrollments/{eid}/reject", None),
        ("GET", "/admin/nodes", None),
    ]:
        answer = await public.request(method, path, json=body, headers=user)
        assert answer.status_code == 403, path
    assert (await public.post(f"/admin/nodes/enrollments/{eid}/reject")).status_code == 401


@requires_db
async def test_without_a_signer_enrollment_is_unavailable(env) -> None:
    public, admin, signer, _ = env
    signer.failing = True
    csr, fingerprint = csr_for()
    eid = (await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})).json()[
        "id"
    ]
    code = (
        await public.post(
            f"/admin/nodes/enrollments/{eid}/approve",
            json={"key_fingerprint": fingerprint},
            headers=admin,
        )
    ).json()["code"]
    assert (
        await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": code})
    ).status_code == 503
    # Nothing was used up: once OpenBao is back, the same code completes.
    signer.failing = False
    assert (
        await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": code})
    ).status_code == 200
    app.state.node_signer = None  # enrollment off (env's teardown removes it)
    csr, _ = csr_for()
    eid = (await public.post("/nodes/enrollments", json={"name": "edge-2", "csr": csr})).json()[
        "id"
    ]
    assert (
        await public.post(f"/nodes/enrollments/{eid}/complete", json={"code": "x"})
    ).status_code == 503


@requires_db
async def test_renewal_with_the_current_certificate(env, monkeypatch) -> None:
    public, admin, signer, session = env
    monkeypatch.setattr(nodes_app.state, "node_signer", signer, raising=False)
    issued, _ = await enroll(public, admin)
    me = (issued["identity"],)
    async with node_client(session, me, "0A01") as node:
        assert (await node.get("/whoami")).json()["name"] == "edge-1"
        csr, fingerprint = csr_for()  # a new key
        renewed = await node.post("/renew", json={"csr": csr})
        assert renewed.status_code == 200, renewed.text
        assert renewed.json()["serial"] == "0a:02"
    assert signer.revoked == ["0a:01"]  # the presented certificate renews once
    row = await session.scalar(select(Node).where(Node.name == "edge-1"))
    assert (row.cert_serial, row.key_fingerprint) == ("0a:02", fingerprint)
    async with node_client(session, me, "0A01") as stale:
        assert (await stale.post("/renew", json={"csr": csr})).status_code == 403
        assert (await stale.get("/whoami")).status_code == 403
    async with node_client(session, me, "0a02") as current:
        assert (await current.get("/whoami")).status_code == 200
    assert ("node.renewed", "ok") in await actions(session)
    assert ("node.authenticated", "denied") in await actions(session)


@requires_db
async def test_the_nodes_port_wants_a_node(env) -> None:
    public, admin, _, session = env
    await enroll(public, admin)
    for identities, serial in [
        (("spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway",), "0a01"),  # a service
        (("spiffe://nodes.vaultgate/node/edge-2",), "0a01"),  # not enrolled
        ((), None),  # no certificate
    ]:
        async with node_client(session, identities, serial) as client:
            assert (await client.get("/whoami")).status_code == 403, identities


@requires_db
async def test_revocation(env, monkeypatch) -> None:
    public, admin, signer, session = env
    monkeypatch.setattr(nodes_app.state, "node_signer", signer, raising=False)
    issued, _ = await enroll(public, admin)
    revoked = await public.post(f"/admin/nodes/{issued['node_id']}/revoke", headers=admin)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert signer.revoked == ["0a:01"]
    async with node_client(session, (issued["identity"],), "0a01") as node:
        assert (await node.post("/renew", json={"csr": csr_for()[0]})).status_code == 403
    again = await public.post(f"/admin/nodes/{issued['node_id']}/revoke", headers=admin)
    assert again.status_code == 409
    # The name may be enrolled again, with a new key.
    await enroll(public, admin)
    statuses = (await public.get("/admin/nodes?status=all", headers=admin)).json()["items"]
    assert sorted(n["status"] for n in statuses) == ["active", "revoked"]


@requires_db
async def test_revocation_waits_for_openbao(env) -> None:
    public, admin, signer, _ = env
    issued, _ = await enroll(public, admin)
    signer.failing = True
    assert (
        await public.post(f"/admin/nodes/{issued['node_id']}/revoke", headers=admin)
    ).status_code == 503
    signer.failing = False
    nodes_ = (await public.get("/admin/nodes", headers=admin)).json()["items"]
    assert nodes_[0]["status"] == "active"  # not marked revoked while OpenBao said no


@requires_db
async def test_an_enroll_policy_made_by_an_admin_allows_enrolling(env) -> None:
    """Through the admin API, as scripts/seed_policies.py makes it: `enroll` is kept."""
    public, admin, _, session = env
    for policy in await session.scalars(select(Policy).where(Policy.name == "nodes may enroll")):
        await session.delete(policy)
    await session.flush()
    made = await public.post(
        "/admin/policies",
        json={"name": "anyone, anything", "effect": "allow",
              "actions": ["read", "upload", "download", "share", "enroll"]},
        headers=admin,
    )  # fmt: skip
    assert made.status_code == 201, made.text
    assert made.json()["actions"] == ["read", "upload", "download", "share", "enroll"]
    csr, _ = csr_for()
    asked = await public.post("/nodes/enrollments", json={"name": "edge-1", "csr": csr})
    assert asked.status_code == 202, asked.text


# --- first trust by a Keycloak client ----------------------------------------------------


def node_token(provider, name: str = "edge-1", **overrides) -> dict:
    """Headers with a node client's token, as Keycloak issues it for client credentials."""
    claims = {
        "aud": ["vaultgate-nodes", "account"],
        "azp": f"node-{name}",
        "sub": f"sa-{name}",
        "preferred_username": f"service-account-node-{name}",
        "realm_access": {"roles": ["default-roles-vaultgate", "vaultgate-node-enroll"]},
        "groups": None,
        "email": None,
        "name": None,
    } | overrides
    return {"Authorization": f"Bearer {provider.token(**claims)}"}


@pytest.fixture
async def by_client(env, provider, monkeypatch):
    monkeypatch.setattr(
        app.state, "node_token_validator", make_validator(provider, audience="vaultgate-nodes"),
        raising=False,
    )  # fmt: skip
    yield env


@requires_db
async def test_enrollment_by_a_keycloak_client(by_client, provider) -> None:
    public, admin, signer, session = by_client
    csr, fingerprint = csr_for()
    done = await public.post(
        "/nodes/enrollments/by-client", json={"csr": csr}, headers=node_token(provider)
    )
    assert done.status_code == 201, done.text
    assert done.json()["identity"] == "spiffe://nodes.vaultgate/node/edge-1"
    assert signer.signed == [(csr, "spiffe://nodes.vaultgate/node/edge-1")]
    node = await session.scalar(select(Node).where(Node.name == "edge-1"))
    assert node.key_fingerprint == fingerprint and node.status == "active"
    node_id = node.id  # the refusals below roll the shared session back
    listed = (await public.get("/admin/nodes/enrollments?status=all", headers=admin)).json()
    assert [(e["method"], e["client_id"], e["status"]) for e in listed["items"]] == [
        ("keycloak_client", "node-edge-1", "completed")
    ]
    # The client enrolls one node, ever: again, even once the node is revoked, it's refused.
    again = await public.post(
        "/nodes/enrollments/by-client", json={"csr": csr_for()[0]}, headers=node_token(provider)
    )
    assert again.status_code == 409
    await public.post(f"/admin/nodes/{node_id}/revoke", headers=admin)
    after = await public.post(
        "/nodes/enrollments/by-client", json={"csr": csr_for()[0]}, headers=node_token(provider)
    )
    assert after.status_code == 409
    # A new client (a new service account), even of the same name, is a new credential.
    fresh = await public.post(
        "/nodes/enrollments/by-client",
        json={"csr": csr_for()[0]},
        headers=node_token(provider, sub="sa-edge-1-new"),
    )
    assert fresh.status_code == 201
    assert (await actions(session)).count(("node.enrollment_completed", "denied")) == 2


@requires_db
async def test_only_a_node_clients_token_with_the_role(by_client, provider) -> None:
    public, _, signer, _ = by_client
    csr, _ = csr_for()
    url = "/nodes/enrollments/by-client"
    for headers, code in [
        ({}, 401),
        ({"Authorization": f"Bearer {provider.token()}"}, 401),  # a user's token: aud vaultgate-api
        (node_token(provider, aud="vaultgate-api"), 401),
        (node_token(provider, azp="vaultgate-web"), 403),  # not a node's client
        (node_token(provider, azp="node-Bad_Name"), 403),
        (node_token(provider, realm_access={"roles": ["default-roles-vaultgate"]}), 403),
    ]:
        answer = await public.post(url, json={"csr": csr}, headers=headers)
        assert answer.status_code == code, (headers, answer.text)
    assert signer.signed == []
    # And a node client's token opens no user route.
    assert (await public.get("/me", headers=node_token(provider))).status_code == 401


@requires_db
async def test_by_client_under_the_policies_and_names(by_client, provider) -> None:
    public, admin, signer, session = by_client
    await enroll(public, admin, "edge-1")  # by approval
    taken = await public.post(
        "/nodes/enrollments/by-client", json={"csr": csr_for()[0]}, headers=node_token(provider)
    )
    assert taken.status_code == 409
    for policy in await session.scalars(select(Policy).where(Policy.name == "nodes may enroll")):
        await session.delete(policy)
    await session.flush()
    refused = await public.post(
        "/nodes/enrollments/by-client",
        json={"csr": csr_for()[0]},
        headers=node_token(provider, "edge-2"),
    )
    assert refused.status_code == 403
    assert len(signer.signed) == 1  # the approval's only


# --- first trust by an admin's enrollment token ------------------------------------------


async def issue(public, admin, name: str = "edge-1", **body) -> dict:
    answer = await public.post("/admin/nodes/tokens", json={"name": name, **body}, headers=admin)
    assert answer.status_code == 201, answer.text
    return answer.json()


@requires_db
async def test_enrollment_by_token(env) -> None:
    public, admin, signer, session = env
    issued = await issue(public, admin)
    token = issued["token"]
    assert token.startswith("vgn_") and len(token) > 40
    assert issued["state"] == "usable" and issued["identity"].endswith("/node/edge-1")
    row = await session.scalar(select(NodeEnrollmentToken))
    assert row.token_hash == nodes.hash_token(token) and token not in str(row.__dict__)

    csr, fingerprint = csr_for()
    done = await public.post("/nodes/enrollments/by-token", json={"token": token, "csr": csr})
    assert done.status_code == 201, done.text
    assert done.json()["identity"] == "spiffe://nodes.vaultgate/node/edge-1"
    assert signer.signed == [(csr, "spiffe://nodes.vaultgate/node/edge-1")]

    again = await public.post(
        "/nodes/enrollments/by-token", json={"token": token, "csr": csr_for()[0]}
    )
    assert again.status_code == 403  # single use
    listed = (await public.get("/admin/nodes/tokens?status=all", headers=admin)).json()
    assert [t["state"] for t in listed["items"]] == ["used"]
    assert (await public.get("/admin/nodes/tokens", headers=admin)).json()["total"] == 0
    enrollments = (await public.get("/admin/nodes/enrollments?status=all", headers=admin)).json()
    assert [(e["method"], e["status"]) for e in enrollments["items"]] == [
        ("enrollment_token", "completed")
    ]
    node = await session.scalar(select(Node).where(Node.name == "edge-1"))
    assert node.key_fingerprint == fingerprint
    assert await actions(session) == [
        ("node.enrollment_token_issued", "ok"),
        ("node.enrollment_completed", "ok"),
        ("node.enrollment_completed", "denied"),
    ]


@requires_db
async def test_a_token_expires_and_can_be_revoked(env) -> None:
    public, admin, signer, session = env
    expiring = await issue(public, admin, "edge-1", ttl_seconds=60)
    row = await session.get(NodeEnrollmentToken, uuid.UUID(expiring["id"]))
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.flush()
    url = "/nodes/enrollments/by-token"
    assert (
        await public.post(url, json={"token": expiring["token"], "csr": csr_for()[0]})
    ).status_code == 403

    revoked = await issue(public, admin, "edge-2")
    gone = await public.post(f"/admin/nodes/tokens/{revoked['id']}/revoke", headers=admin)
    assert gone.status_code == 204
    assert (
        await public.post(url, json={"token": revoked["token"], "csr": csr_for()[0]})
    ).status_code == 403
    again = await public.post(f"/admin/nodes/tokens/{revoked['id']}/revoke", headers=admin)
    assert again.status_code == 409

    assert (
        await public.post(url, json={"token": "vgn_guess", "csr": csr_for()[0]})
    ).status_code == 403
    assert signer.signed == []
    results = await session.scalars(
        select(AuditEvent.details["result"].astext).where(AuditEvent.outcome == "denied")
    )
    assert sorted(results) == ["token expired", "token revoked"]  # an unknown token: not


@requires_db
async def test_token_limits_and_checks(env, monkeypatch) -> None:
    public, admin, _, _ = env
    monkeypatch.setattr(settings, "node_token_max_ttl_seconds", 600)
    long = await issue(public, admin, "edge-1", ttl_seconds=86400)
    lasts = datetime.fromisoformat(long["expires_at"]) - datetime.fromisoformat(long["created_at"])
    assert lasts == timedelta(seconds=600)
    for body in [{"name": "Bad_Name"}, {"name": "edge-2", "ttl_seconds": 5}]:
        answer = await public.post("/admin/nodes/tokens", json=body, headers=admin)
        assert answer.status_code == 422, body
    # A bad CSR leaves the token usable.
    url = "/nodes/enrollments/by-token"
    assert (await public.post(url, json={"token": long["token"], "csr": "junk"})).status_code == 422
    assert (
        await public.post(url, json={"token": long["token"], "csr": csr_for()[0]})
    ).status_code == 201
    # A name with an active node gets no token.
    taken = await public.post("/admin/nodes/tokens", json={"name": "edge-1"}, headers=admin)
    assert taken.status_code == 409


@requires_db
async def test_tokens_are_for_admins(env, provider) -> None:
    public, _, _, _ = env
    user = {"Authorization": f"Bearer {provider.token()}"}
    for method, path, body in [
        ("POST", "/admin/nodes/tokens", {"name": "edge-1"}),
        ("GET", "/admin/nodes/tokens", None),
        ("POST", f"/admin/nodes/tokens/{uuid.uuid4()}/revoke", None),
    ]:
        assert (await public.request(method, path, json=body, headers=user)).status_code == 403


@requires_db
async def test_token_enrollment_under_the_policies(env) -> None:
    public, admin, signer, session = env
    issued = await issue(public, admin)
    for policy in await session.scalars(select(Policy).where(Policy.name == "nodes may enroll")):
        await session.delete(policy)
    await session.flush()
    url = "/nodes/enrollments/by-token"
    refused = await public.post(url, json={"token": issued["token"], "csr": csr_for()[0]})
    assert refused.status_code == 403 and signer.signed == []
    still = (await public.get("/admin/nodes/tokens", headers=admin)).json()["items"]
    assert [t["state"] for t in still] == ["usable"]  # refused, not used up


# --- first trust by cloud instance identity (AWS) ----------------------------------------


class FakeAWS:
    """A stand-in for AWS's signing key, and its certificate in a PEM file."""

    def __init__(self, tmp_path) -> None:
        self.key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Fake AWS")])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(self.key, hashes.SHA256())
        )
        self.file = tmp_path / "aws.pem"
        self.file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def document(self, **fields) -> dict:
        document = json.dumps({
            "accountId": "123456789012", "instanceId": "i-0abc123def4567890",
            "region": "ap-northeast-1", "pendingTime": datetime.now(UTC).isoformat(),
            "instanceType": "t3.micro", "imageId": "ami-0123",
        } | fields)  # fmt: skip
        signature = self.key.sign(document.encode(), padding.PKCS1v15(), hashes.SHA256())
        return {"provider": "aws", "document": document,
                "signature": base64.b64encode(signature).decode()}  # fmt: skip


@pytest.fixture
async def by_cloud(env, tmp_path, monkeypatch):
    aws = FakeAWS(tmp_path)
    monkeypatch.setattr(settings, "node_aws_certificates_file", str(aws.file))
    monkeypatch.setattr(settings, "node_aws_accounts", ["123456789012"])
    yield (*env, aws)


@requires_db
async def test_enrollment_by_cloud_identity(by_cloud) -> None:
    public, admin, signer, session, aws = by_cloud
    url = "/nodes/enrollments/by-cloud"
    csr, fingerprint = csr_for()
    done = await public.post(url, json=aws.document() | {"csr": csr})
    assert done.status_code == 201, done.text
    assert done.json()["identity"] == "spiffe://nodes.vaultgate/node/aws-i-0abc123def4567890"
    node = await session.scalar(select(Node).where(Node.name == "aws-i-0abc123def4567890"))
    assert node.key_fingerprint == fingerprint
    node_id = node.id
    listed = (await public.get("/admin/nodes/enrollments?status=all", headers=admin)).json()
    assert [(e["method"], e["client_id"]) for e in listed["items"]] == [("cloud_identity", "aws")]
    # The document isn't secret: the instance enrolls once, ever, revoked or not.
    again = await public.post(url, json=aws.document() | {"csr": csr_for()[0]})
    assert again.status_code == 409
    await public.post(f"/admin/nodes/{node_id}/revoke", headers=admin)
    after = await public.post(url, json=aws.document() | {"csr": csr_for()[0]})
    assert after.status_code == 409
    other = await public.post(url, json=aws.document(instanceId="i-0fff") | {"csr": csr_for()[0]})
    assert other.status_code == 201
    assert len(signer.signed) == 2


@requires_db
async def test_only_a_signed_document(by_cloud, tmp_path) -> None:
    public, _, signer, session, aws = by_cloud
    url = "/nodes/enrollments/by-cloud"
    csr, _ = csr_for()
    forger = FakeAWS(tmp_path / "..")  # another key: not AWS's
    tampered = aws.document()
    tampered["document"] = tampered["document"].replace("123456789012", "999999999999")
    for body in [
        forger.document(),
        tampered,
        aws.document() | {"signature": "not base64!"},
        aws.document() | {"document": "{}", "signature": aws.document()["signature"]},
    ]:
        answer = await public.post(url, json=body | {"csr": csr})
        assert answer.status_code == 403, answer.text
    assert signer.signed == []
    assert await actions(session) == []  # unsigned input: refused, not recorded


@requires_db
async def test_cloud_accounts_regions_and_age(by_cloud, monkeypatch) -> None:
    public, _, _, session, aws = by_cloud
    url = "/nodes/enrollments/by-cloud"
    other_account = await public.post(
        url, json=aws.document(accountId="210987654321") | {"csr": csr_for()[0]}
    )
    assert other_account.status_code == 403
    monkeypatch.setattr(settings, "node_aws_regions", ["us-east-1"])
    wrong_region = await public.post(url, json=aws.document() | {"csr": csr_for()[0]})
    assert wrong_region.status_code == 403
    monkeypatch.setattr(settings, "node_aws_regions", [])
    monkeypatch.setattr(settings, "node_cloud_max_launch_age_seconds", 600)
    old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    too_old = await public.post(url, json=aws.document(pendingTime=old) | {"csr": csr_for()[0]})
    assert too_old.status_code == 403
    fresh = await public.post(url, json=aws.document() | {"csr": csr_for()[0]})
    assert fresh.status_code == 201
    results = await session.scalars(
        select(AuditEvent.details["result"].astext).where(AuditEvent.outcome == "denied")
    )
    assert sorted(results) == ["account", "launched too long ago", "region"]


@requires_db
async def test_cloud_identity_off_and_under_the_policies(by_cloud, monkeypatch) -> None:
    public, _, signer, session, aws = by_cloud
    url = "/nodes/enrollments/by-cloud"
    for policy in await session.scalars(select(Policy).where(Policy.name == "nodes may enroll")):
        await session.delete(policy)
    await session.flush()
    assert (await public.post(url, json=aws.document() | {"csr": csr_for()[0]})).status_code == 403
    monkeypatch.setattr(settings, "node_aws_accounts", [])
    assert (await public.post(url, json=aws.document() | {"csr": csr_for()[0]})).status_code == 404
    assert signer.signed == []


def test_cloud_identity_document_parsing(tmp_path) -> None:
    from vaultgate_api import cloud

    aws = FakeAWS(tmp_path)
    body = aws.document()
    instance = cloud.aws_instance(body["document"], body["signature"], str(aws.file))
    assert (instance.account, instance.instance, instance.region) == (
        "123456789012", "i-0abc123def4567890", "ap-northeast-1"
    )  # fmt: skip
    assert instance.subject == "aws:123456789012:i-0abc123def4567890"
    for fields in [{"accountId": "12"}, {"instanceId": "vm-1"}, {"pendingTime": "yesterday"}]:
        body = aws.document(**fields)
        with pytest.raises(cloud.InvalidIdentity):
            cloud.aws_instance(body["document"], body["signature"], str(aws.file))


# --- first trust by TPM attestation --------------------------------------------------------


async def register_tpm(public, admin, fake, name: str = "edge-1"):
    answer = await public.post(
        "/admin/nodes/tpms",
        json={"name": name, "ek_fingerprint": fake.ek_fingerprint()},
        headers=admin,
    )
    assert answer.status_code == 201, answer.text
    return answer.json()


@requires_db
async def test_enrollment_by_tpm_attestation(env) -> None:
    from tests.test_tpm import FakeTPM

    public, admin, signer, session = env
    fake = FakeTPM()
    registered = await register_tpm(public, admin, fake)
    assert registered["state"] == "usable"
    body = fake.body()
    started = await public.post("/nodes/enrollments/by-tpm", json=body)
    assert started.status_code == 202, started.text
    challenge = started.json()
    assert challenge["identity"] == "spiffe://nodes.vaultgate/node/edge-1"
    secret = fake.activate(base64.b64decode(challenge["credential"]))
    url = f"/nodes/enrollments/by-tpm/{challenge['id']}/complete"
    wrong = await public.post(url, json={"secret": base64.b64encode(b"x" * 32).decode()})
    assert wrong.status_code == 403
    done = await public.post(url, json={"secret": base64.b64encode(secret).decode()})
    assert done.status_code == 201, done.text
    assert signer.signed == [(body["csr"], "spiffe://nodes.vaultgate/node/edge-1")]
    # The registration is used: the TPM enrolls this one node.
    again = await public.post("/nodes/enrollments/by-tpm", json=fake.body())
    assert again.status_code == 403
    listed = (await public.get("/admin/nodes/tpms?status=all", headers=admin)).json()
    assert [t["state"] for t in listed["items"]] == ["used"]
    assert await actions(session) == [
        ("node.tpm_registered", "ok"),
        ("node.enrollment_requested", "ok"),
        ("node.enrollment_completed", "denied"),
        ("node.enrollment_completed", "ok"),
    ]


@requires_db
async def test_tpm_attestation_refusals(env) -> None:
    from tests.test_tpm import KEY_ATTRS, FakeTPM

    public, admin, signer, session = env
    url = "/nodes/enrollments/by-tpm"
    stranger = FakeTPM()
    assert (await public.post(url, json=stranger.body())).status_code == 403  # not registered
    assert await actions(session) == []  # unregistered: not recorded

    exportable = FakeTPM(key_attrs=KEY_ATTRS & ~tpm.FIXED_TPM)
    await register_tpm(public, admin, exportable, "edge-2")
    refused = await public.post(url, json=exportable.body())
    assert refused.status_code == 403 and "never leave" in refused.json()["detail"]

    fake = FakeTPM()
    await register_tpm(public, admin, fake, "edge-3")
    other_key = fake.csr(ec.generate_private_key(ec.SECP256R1()))
    refused = await public.post(url, json=fake.body(csr=other_key))
    assert refused.status_code == 403 and "CSR" in refused.json()["detail"]

    # Three wrong secrets end the attempt; the registration stays for another.
    started = (await public.post(url, json=fake.body())).json()
    for _ in range(3):
        wrong = await public.post(f"{url}/{started['id']}/complete", json={"secret": "AAAA"})
    assert wrong.status_code == 403
    secret = fake.activate(base64.b64decode(started["credential"]))
    late = await public.post(
        f"{url}/{started['id']}/complete", json={"secret": base64.b64encode(secret).decode()}
    )
    assert late.status_code == 409
    restarted = (await public.post(url, json=fake.body())).json()
    secret = fake.activate(base64.b64decode(restarted["credential"]))
    done = await public.post(
        f"{url}/{restarted['id']}/complete", json={"secret": base64.b64encode(secret).decode()}
    )
    assert done.status_code == 201
    assert len(signer.signed) == 1


@requires_db
async def test_tpm_enrollments_are_not_approved_by_admins(env) -> None:
    from tests.test_tpm import FakeTPM

    public, admin, _, _ = env
    fake = FakeTPM()
    await register_tpm(public, admin, fake)
    started = (await public.post("/nodes/enrollments/by-tpm", json=fake.body())).json()
    approve = await public.post(
        f"/admin/nodes/enrollments/{started['id']}/approve",
        json={"key_fingerprint": "SHA256:" + "A" * 43},
        headers=admin,
    )
    assert approve.status_code == 409
    complete = await public.post(
        f"/nodes/enrollments/{started['id']}/complete", json={"code": "AAAAA-AAAAA"}
    )
    assert complete.status_code == 409


@requires_db
async def test_tpm_registrations(env, provider) -> None:
    from tests.test_tpm import FakeTPM

    public, admin, _, _ = env
    fake = FakeTPM()
    registered = await register_tpm(public, admin, fake)
    twice = await public.post(
        "/admin/nodes/tpms",
        json={"name": "edge-9", "ek_fingerprint": fake.ek_fingerprint()},
        headers=admin,
    )
    assert twice.status_code == 409  # one usable registration per TPM
    bad = await public.post(
        "/admin/nodes/tpms", json={"name": "edge-9", "ek_fingerprint": "nope"}, headers=admin
    )
    assert bad.status_code == 422
    gone = await public.post(f"/admin/nodes/tpms/{registered['id']}/revoke", headers=admin)
    assert gone.status_code == 204
    assert (await public.post("/nodes/enrollments/by-tpm", json=fake.body())).status_code == 403
    user = {"Authorization": f"Bearer {provider.token()}"}
    assert (await public.get("/admin/nodes/tpms", headers=user)).status_code == 403


@requires_db
async def test_a_tpm_node_renews_for_its_attested_key_only(env, monkeypatch) -> None:
    from tests.test_tpm import FakeTPM

    public, admin, signer, session = env
    monkeypatch.setattr(nodes_app.state, "node_signer", signer, raising=False)
    fake = FakeTPM()
    await register_tpm(public, admin, fake)
    started = (await public.post("/nodes/enrollments/by-tpm", json=fake.body())).json()
    secret = fake.activate(base64.b64decode(started["credential"]))
    done = (
        await public.post(
            f"/nodes/enrollments/by-tpm/{started['id']}/complete",
            json={"secret": base64.b64encode(secret).decode()},
        )
    ).json()
    async with node_client(session, (done["identity"],), done["serial"]) as node:
        other = await node.post("/renew", json={"csr": csr_for()[0]})
        assert other.status_code == 409  # a key the TPM never vouched for
        same = await node.post("/renew", json={"csr": fake.csr()})
        assert same.status_code == 200, same.text


@requires_db
async def test_an_expired_tpm_registration_gives_way(env, session) -> None:
    from tests.test_tpm import FakeTPM
    from vaultgate_api.models import NodeTpm

    public, admin, _, _ = env
    fake = FakeTPM()
    first = await register_tpm(public, admin, fake)
    row = await session.get(NodeTpm, uuid.UUID(first["id"]))
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.commit()
    second = await register_tpm(public, admin, fake, "edge-2")
    assert second["state"] == "usable"
    listed = (await public.get("/admin/nodes/tpms?status=all", headers=admin)).json()["items"]
    assert sorted(t["state"] for t in listed) == ["revoked", "usable"]


@requires_db
async def test_one_open_registration_per_tpm_is_a_constraint(session) -> None:
    """Two admins registering one TPM at once: the database keeps one."""
    from sqlalchemy.exc import IntegrityError

    from vaultgate_api.models import NodeTpm

    later = datetime.now(UTC) + timedelta(hours=1)
    for name in ("edge-1", "edge-2"):
        session.add(NodeTpm(name=name, ek_fingerprint="SHA256:" + "E" * 43, expires_at=later))
    with pytest.raises(IntegrityError):
        await session.flush()

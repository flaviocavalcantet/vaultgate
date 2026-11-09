"""Node enrollment (M11, ADR 0014): a node's request, an admin's approval, the one-time
code, renewal on the nodes' port, revocation; with a fake signer for OpenBao."""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import requires_db
from tests.fake_oidc import make_validator
from vaultgate_api import nodes
from vaultgate_api.config import settings
from vaultgate_api.db import get_session
from vaultgate_api.main import app
from vaultgate_api.models import AuditEvent, Node, NodeEnrollment, Policy
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
    await session.flush()
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

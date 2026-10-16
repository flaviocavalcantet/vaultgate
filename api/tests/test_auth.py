import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from vaultgate_api.auth import JwksCache, KeySetUnavailable, TokenError, TokenValidator
from vaultgate_api.main import PUBLIC_PATHS, app

ISSUER = "http://localhost:8080/realms/vaultgate"
DISCOVERY_URL = "http://keycloak:8080/realms/vaultgate/.well-known/openid-configuration"
JWKS_URI = "http://keycloak:8080/realms/vaultgate/protocol/openid-connect/certs"
AUDIENCE = "vaultgate-api"


class FakeProvider:
    """An identity provider: signing keys, a JWKS endpoint and a token factory."""

    def __init__(self) -> None:
        self.keys: dict[str, rsa.RSAPrivateKey] = {}
        self.requests: list[str] = []
        self.down = False
        self.jwks_override = None  # a raw JSON body served instead of the real JWKS
        self.add_key("key-1")

    def add_key(self, kid: str) -> None:
        self.keys[kid] = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwks(self) -> dict:
        keys = []
        for kid, private in self.keys.items():
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
            keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": keys}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if self.down:
            return httpx.Response(503)
        if str(request.url) == DISCOVERY_URL:
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        if str(request.url) == JWKS_URI:
            if self.jwks_override is not None:
                return httpx.Response(200, content=self.jwks_override)
            return httpx.Response(200, json=self.jwks())
        return httpx.Response(404)

    def token(self, kid: str = "key-1", headers: dict | None = None, **overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": [AUDIENCE],
            "sub": "user-123",
            "iat": now,
            "exp": now + 300,
            "preferred_username": "alice",
            "email": "alice@example.com",
            "name": "Alice Finance",
            "groups": ["/finance"],
            "azp": "vaultgate-web",
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(
            claims, self.keys[kid], algorithm="RS256", headers={"kid": kid, **(headers or {})}
        )


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def validator(provider: FakeProvider, clock: Clock) -> TokenValidator:
    client = httpx.AsyncClient(transport=httpx.MockTransport(provider.handler))
    keys = JwksCache(client, DISCOVERY_URL, ttl_seconds=300, min_refresh_interval=30, clock=clock)
    return TokenValidator(keys, issuer=ISSUER, audience=AUDIENCE, algorithms=["RS256"])


@pytest.fixture
def api(validator: TokenValidator):
    app.state.token_validator = validator
    yield TestClient(app)
    del app.state.token_validator


# --- validation rules ---------------------------------------------------------


async def test_valid_token_gives_principal(provider, validator) -> None:
    principal = await validator.validate(provider.token(groups=["/legal", "/finance"]))
    assert principal.subject == "user-123"
    assert principal.issuer == ISSUER
    assert principal.username == "alice"
    assert principal.groups == ("/finance", "/legal")


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"exp": int(time.time()) - 120}, "expired"),
        ({"nbf": int(time.time()) + 600}, "not_yet_valid"),
        ({"aud": ["account"]}, "wrong_audience"),
        ({"iss": "http://localhost:8080/realms/other"}, "wrong_issuer"),
        ({"sub": None}, "missing_claim"),
        ({"exp": None}, "missing_claim"),
        ({"groups": "/finance"}, "invalid_groups"),
    ],
)
async def test_rejected_claims(provider, validator, overrides, reason) -> None:
    with pytest.raises(TokenError) as exc:
        await validator.validate(provider.token(**overrides))
    assert exc.value.reason == reason


async def test_small_clock_skew_is_tolerated(provider, validator) -> None:
    await validator.validate(provider.token(exp=int(time.time()) - 10))


async def test_tampered_payload_fails_signature(provider, validator) -> None:
    header, _, signature = provider.token().split(".")
    other = provider.token(sub="admin").split(".")[1]
    with pytest.raises(TokenError) as exc:
        await validator.validate(f"{header}.{other}.{signature}")
    assert exc.value.reason == "bad_signature"


async def test_token_signed_by_unknown_key_is_rejected(provider, validator) -> None:
    attacker = FakeProvider()
    with pytest.raises(TokenError) as exc:
        await validator.validate(attacker.token())  # same kid, different key
    assert exc.value.reason == "bad_signature"


async def test_alg_none_is_rejected(validator) -> None:
    token = jwt.encode({"sub": "admin"}, None, algorithm="none", headers={"kid": "key-1"})
    with pytest.raises(TokenError) as exc:
        await validator.validate(token)
    assert exc.value.reason == "algorithm_not_allowed"


async def test_hmac_with_public_key_is_rejected(provider, validator) -> None:
    """Algorithm confusion: an HS256 token keyed with the provider's public key."""
    public_pem = (
        provider.keys["key-1"]
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "admin", "iat": now, "exp": now + 60}
    # Built by hand: PyJWT itself refuses to use a PEM public key as an HMAC secret.
    token = _hs256(claims, public_pem)
    with pytest.raises(TokenError) as exc:
        await validator.validate(token)
    assert exc.value.reason == "algorithm_not_allowed"


def _hs256(claims: dict, secret: bytes) -> str:
    import base64
    import hashlib
    import hmac
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing_input = (
        f"{b64(json.dumps({'alg': 'HS256', 'typ': 'JWT', 'kid': 'key-1'}).encode())}."
        f"{b64(json.dumps(claims).encode())}"
    )
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64(signature)}"


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c", "eyJhbGciOiJSUzI1NiJ9.e30.x"])
async def test_garbage_is_rejected(validator, token) -> None:
    with pytest.raises(TokenError):
        await validator.validate(token)


async def test_missing_kid_is_rejected(provider, validator) -> None:
    token = jwt.encode({"sub": "x"}, provider.keys["key-1"], algorithm="RS256")
    with pytest.raises(TokenError) as exc:
        await validator.validate(token)
    assert exc.value.reason == "missing_key_id"


def test_symmetric_algorithms_cannot_be_configured(validator) -> None:
    for algorithms in (["HS256"], ["RS256", "none"], []):
        with pytest.raises(ValueError):
            TokenValidator(validator._keys, issuer=ISSUER, audience=AUDIENCE, algorithms=algorithms)


# --- key handling -------------------------------------------------------------


async def test_keys_are_cached(provider, validator) -> None:
    for _ in range(5):
        await validator.validate(provider.token())
    assert provider.requests == [DISCOVERY_URL, JWKS_URI]


async def test_rotated_key_is_picked_up(provider, validator, clock) -> None:
    await validator.validate(provider.token())
    provider.add_key("key-2")
    clock.now += 31  # past the minimum refresh interval
    principal = await validator.validate(provider.token(kid="key-2"))
    assert principal.subject == "user-123"
    assert provider.requests.count(JWKS_URI) == 2


async def test_unknown_kids_cannot_force_refreshes(provider, validator, clock) -> None:
    await validator.validate(provider.token())
    for i in range(20):
        with pytest.raises(TokenError) as exc:
            await validator.validate(provider.token(headers={"kid": f"random-{i}"}))
        assert exc.value.reason == "unknown_key"
    assert provider.requests.count(JWKS_URI) == 1


async def test_keys_expire_after_ttl(provider, validator, clock) -> None:
    await validator.validate(provider.token())
    clock.now += 301
    await validator.validate(provider.token())
    assert provider.requests.count(JWKS_URI) == 2


async def test_provider_down_at_first_use(provider, validator) -> None:
    provider.down = True
    with pytest.raises(KeySetUnavailable):
        await validator.validate(provider.token())


async def test_provider_down_is_not_retried_on_every_request(provider, validator, clock) -> None:
    provider.down = True
    for _ in range(10):
        with pytest.raises(KeySetUnavailable):
            await validator.validate(provider.token())
    assert len(provider.requests) == 1
    clock.now += 31
    provider.down = False
    await validator.validate(provider.token())


@pytest.mark.parametrize(
    "body", [b'["not", "a", "jwks"]', b'{"keys": null}', b'{"keys": ["x"]}', b"<html>"]
)
async def test_malformed_jwks_is_unavailable_not_a_crash(provider, validator, body) -> None:
    provider.jwks_override = body
    with pytest.raises(KeySetUnavailable):
        await validator.validate(provider.token())


async def test_malformed_jwks_later_keeps_cached_keys(provider, validator, clock) -> None:
    await validator.validate(provider.token())
    provider.jwks_override = b'["proxy", "error"]'
    clock.now += 301
    await validator.validate(provider.token())


async def test_provider_down_later_keeps_cached_keys(provider, validator, clock) -> None:
    await validator.validate(provider.token())
    provider.down = True
    clock.now += 301
    await validator.validate(provider.token())  # served from the previous key set


# --- HTTP behaviour -----------------------------------------------------------


def test_me_returns_identity(provider, api) -> None:
    response = api.get("/me", headers={"Authorization": f"Bearer {provider.token()}"})
    assert response.status_code == 200
    assert response.json() == {
        "issuer": ISSUER,
        "subject": "user-123",
        "username": "alice",
        "email": "alice@example.com",
        "name": "Alice Finance",
        "groups": ["/finance"],
    }


def test_missing_token_is_401_with_challenge(api) -> None:
    response = api.get("/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer realm="vaultgate"'


def test_invalid_token_is_401_and_counted(provider, api) -> None:
    labels = {"reason": "expired"}
    before = REGISTRY.get_sample_value("vaultgate_auth_failures_total", labels) or 0
    token = provider.token(exp=int(time.time()) - 120)
    response = api.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert 'error="invalid_token"' in response.headers["www-authenticate"]
    assert REGISTRY.get_sample_value("vaultgate_auth_failures_total", labels) == before + 1


def test_token_is_never_logged(provider, api, caplog) -> None:
    token = provider.token(exp=int(time.time()) - 120)
    with caplog.at_level("DEBUG"):
        api.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert token not in caplog.text
    assert token.split(".")[2] not in caplog.text


def test_provider_unavailable_is_503(provider, api) -> None:
    provider.down = True
    response = api.get("/me", headers={"Authorization": f"Bearer {provider.token()}"})
    assert response.status_code == 503


def test_every_route_requires_a_token_unless_public(api) -> None:
    """Deny by default: a new route is protected unless listed in PUBLIC_PATHS."""
    for route in app.routes:
        if not isinstance(route, APIRoute) or route.path in PUBLIC_PATHS:
            continue
        for method in route.methods:
            response = api.request(method, route.path)
            assert response.status_code == 401, f"{method} {route.path} answered without a token"


async def test_algorithm_key_mismatch_is_rejected_not_crash(provider) -> None:
    """With several algorithm families allowed, an ES256 header naming an RSA key is a 401."""
    client = httpx.AsyncClient(transport=httpx.MockTransport(provider.handler))
    validator = TokenValidator(
        JwksCache(client, DISCOVERY_URL),
        issuer=ISSUER,
        audience=AUDIENCE,
        algorithms=["RS256", "ES256"],
    )
    _, payload, signature = provider.token().split(".")
    es256_header = jwt.utils.base64url_encode(b'{"alg":"ES256","kid":"key-1"}').decode()
    with pytest.raises(TokenError) as exc:
        await validator.validate(f"{es256_header}.{payload}.{signature}")
    assert exc.value.reason == "algorithm_key_mismatch"

"""A fake OIDC provider for tests: signing keys, a JWKS endpoint and a token factory."""

import time

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from vaultgate_api.auth import JwksCache, TokenValidator

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


def make_validator(provider: "FakeProvider", clock=None) -> TokenValidator:
    client = httpx.AsyncClient(transport=httpx.MockTransport(provider.handler))
    kwargs = {"clock": clock} if clock else {}
    keys = JwksCache(client, DISCOVERY_URL, ttl_seconds=300, min_refresh_interval=30, **kwargs)
    return TokenValidator(keys, issuer=ISSUER, audience=AUDIENCE, algorithms=["RS256"])


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

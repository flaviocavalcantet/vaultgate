"""Bearer token validation against the organization's OIDC provider.

The API is a pure resource server: clients obtain access tokens from the identity
provider (authorization code + PKCE) and send them as `Authorization: Bearer`. Every
request is checked here; nothing is cached in a session.

A token is accepted only if all of these hold:
- its header names an allowed asymmetric algorithm (never `none` or HMAC, which would
  let an attacker sign with the public key) and a key ID published in the JWKS;
- the signature verifies with that key;
- `iss` equals the configured issuer and `aud` contains this API's audience;
- `exp`, `iat` and `sub` are present, and `exp`/`nbf` hold (small clock leeway).

Keys come from the provider's JWKS, found through its discovery document. They are
cached; an unknown key ID triggers one refresh (key rotation) but refreshes are rate
limited, so random key IDs cannot be used to hammer the provider.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Annotated, Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import Counter

from vaultgate_api.config import settings

logger = logging.getLogger(__name__)

AUTH_FAILURES = Counter(
    "vaultgate_auth_failures_total",
    "Requests rejected by bearer token validation, by reason",
    ["reason"],
)

REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]

# Asymmetric signatures only. `none` and HMAC (HS*) are never accepted: with HMAC a
# token "signed" using the provider's public key would verify.
ASYMMETRIC_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)


@dataclass(frozen=True)
class Principal:
    """The authenticated caller, as vouched for by the identity provider."""

    issuer: str
    subject: str
    username: str | None
    email: str | None
    name: str | None
    groups: tuple[str, ...]


class TokenError(Exception):
    """The token is not acceptable. `reason` is a short, log- and metric-safe code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class KeySetUnavailable(Exception):
    """The provider's discovery document or JWKS could not be fetched."""


class JwksCache:
    """Fetches and caches the provider's signing keys."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        discovery_url: str,
        *,
        ttl_seconds: float = 300,
        min_refresh_interval: float = 30,
        clock=time.monotonic,
    ) -> None:
        self._client = client
        self._discovery_url = discovery_url
        self._ttl = ttl_seconds
        self._min_refresh_interval = min_refresh_interval
        self._clock = clock
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._jwks_uri: str | None = None
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> jwt.PyJWK:
        # An unknown key ID may be a rotated key, so it also triggers a refresh;
        # _refresh itself is rate limited, so random IDs cannot hammer the provider.
        if self._is_stale() or kid not in self._keys:
            await self._refresh()
        try:
            return self._keys[kid]
        except KeyError:
            raise TokenError("unknown_key") from None

    def _is_stale(self) -> bool:
        return self._fetched_at is None or self._clock() - self._fetched_at > self._ttl

    async def _refresh(self) -> None:
        async with self._lock:
            now = self._clock()
            if (
                self._last_attempt is not None
                and now - self._last_attempt <= self._min_refresh_interval
            ):
                # Attempted moments ago (maybe by a concurrent request): use what we have.
                if not self._keys:
                    raise KeySetUnavailable("signing keys not available yet")
                return
            self._last_attempt = now
            try:
                if self._jwks_uri is None:
                    discovery = await self._get_json(self._discovery_url)
                    self._jwks_uri = discovery["jwks_uri"]
                keys = _signing_keys(await self._get_json(self._jwks_uri))
            except (httpx.HTTPError, KeyError, ValueError, TypeError, AttributeError) as exc:
                # Unreachable provider, bad status, or a response that is not the JSON
                # shape we expect (e.g. a proxy error page): all mean "no fresh keys".
                if not self._keys:
                    raise KeySetUnavailable(str(exc)) from exc
                # Keep serving with the cached keys; retry after the interval.
                logger.warning("jwks refresh failed, using cached keys", extra={"error": str(exc)})
                return
            self._keys = keys
            self._fetched_at = now
            logger.info("jwks refreshed", extra={"keys": len(self._keys)})

    async def _get_json(self, url: str) -> dict[str, Any]:
        response = await self._client.get(url)
        response.raise_for_status()
        return response.json()


def _signing_keys(jwks: Any) -> dict[str, jwt.PyJWK]:
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise TypeError("JWKS document has no keys list")
    keys = {}
    for data in jwks["keys"]:
        if not isinstance(data, dict) or data.get("use", "sig") != "sig" or "kid" not in data:
            continue  # encryption keys and keys without an ID are never used here
        try:
            keys[data["kid"]] = jwt.PyJWK(data)
        except jwt.PyJWKError:
            continue  # unsupported key type
    if not keys:
        # Treated like an outage: keep any cached keys rather than drop them all.
        raise ValueError("JWKS document has no usable signing keys")
    return keys


class TokenValidator:
    def __init__(
        self,
        keys: JwksCache,
        *,
        issuer: str,
        audience: str,
        algorithms: list[str],
        leeway_seconds: int = 30,
    ) -> None:
        if not algorithms or not set(algorithms) <= ASYMMETRIC_ALGORITHMS:
            raise ValueError(f"only asymmetric JWT algorithms are allowed, got {algorithms}")
        self._keys = keys
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms
        self._leeway = leeway_seconds

    async def validate(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.DecodeError:
            raise TokenError("malformed") from None
        if header.get("alg") not in self._algorithms:
            raise TokenError("algorithm_not_allowed")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise TokenError("missing_key_id")
        key = await self._keys.get_key(kid)
        # The header's algorithm must be the one the key is for. Otherwise, with several
        # algorithm families allowed, an ES256 header naming an RSA key would reach the
        # crypto library with a key of the wrong type.
        if header["alg"] != key.algorithm_name:
            raise TokenError("algorithm_key_mismatch")
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=[key.algorithm_name],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.ExpiredSignatureError:
            raise TokenError("expired") from None
        except jwt.ImmatureSignatureError:
            raise TokenError("not_yet_valid") from None
        except jwt.InvalidAudienceError:
            raise TokenError("wrong_audience") from None
        except jwt.InvalidIssuerError:
            raise TokenError("wrong_issuer") from None
        except jwt.MissingRequiredClaimError:
            raise TokenError("missing_claim") from None
        except jwt.InvalidSignatureError:
            raise TokenError("bad_signature") from None
        except jwt.PyJWTError:
            raise TokenError("invalid") from None
        return _principal(claims)


def _principal(claims: dict[str, Any]) -> Principal:
    groups = claims.get("groups") or []
    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        raise TokenError("invalid_groups")
    return Principal(
        issuer=claims["iss"],
        subject=claims["sub"],
        username=claims.get("preferred_username"),
        email=claims.get("email"),
        name=claims.get("name"),
        groups=tuple(sorted(groups)),
    )


def build_validator(client: httpx.AsyncClient) -> TokenValidator:
    discovery_url = settings.oidc_discovery_url or (
        f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
    )
    return TokenValidator(
        JwksCache(client, discovery_url, ttl_seconds=settings.oidc_jwks_ttl_seconds),
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        algorithms=settings.oidc_algorithms,
        leeway_seconds=settings.oidc_leeway_seconds,
    )


_bearer = HTTPBearer(auto_error=False, description="Access token from the identity provider")


def _unauthorized(reason: str) -> HTTPException:
    AUTH_FAILURES.labels(reason).inc()
    header = 'Bearer realm="vaultgate"'
    if reason != "missing_token":
        header += ', error="invalid_token"'
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": header},
    )


async def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    """FastAPI dependency: the authenticated caller, or 401."""
    if credentials is None:
        raise _unauthorized("missing_token")
    validator: TokenValidator = request.app.state.token_validator
    try:
        return await validator.validate(credentials.credentials)
    except TokenError as exc:
        # The reason is logged; the token itself never is.
        logger.info("token rejected", extra={"reason": exc.reason})
        raise _unauthorized(exc.reason) from None
    except KeySetUnavailable:
        AUTH_FAILURES.labels("keys_unavailable").inc()
        logger.error("cannot validate tokens: identity provider keys unavailable")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity provider unavailable"
        ) from None


PrincipalDep = Annotated[Principal, Depends(get_principal)]

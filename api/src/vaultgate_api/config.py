from typing import Annotated

from pydantic import IPvAnyNetwork, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from vaultgate_api.clientip import parse_networks


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables prefixed with VAULTGATE_."""

    model_config = SettingsConfigDict(env_prefix="VAULTGATE_")

    # SQLAlchemy URL; the asyncpg driver is required because the API is fully async.
    database_url: str = "postgresql+asyncpg://vaultgate:vaultgate@localhost:5432/vaultgate"
    database_echo: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    # Reverse proxies whose X-Forwarded-For is believed, as a comma-separated list of
    # networks ("10.0.0.0/8, 192.0.2.10/32"). Proxy addresses only, never client
    # networks; empty means the TCP peer is the client (see vaultgate_api.clientip).
    trusted_proxies: Annotated[list[IPvAnyNetwork], NoDecode] = []
    # Prometheus scrape endpoint; kept off the public port on purpose.
    metrics_port: int = 9100
    log_level: str = "INFO"
    # "json" for machines (default, what the log pipeline expects); "text" for reading locally.
    log_format: str = "json"
    # Must equal the `iss` claim of the provider's tokens exactly.
    oidc_issuer: str = "http://localhost:8080/realms/vaultgate"
    oidc_audience: str = "vaultgate-api"
    # Where the API itself fetches discovery and JWKS. Defaults to the issuer's
    # well-known URL; set it when the API reaches the provider under another address
    # than the public issuer (e.g. keycloak:8080 inside docker compose).
    oidc_discovery_url: str | None = None
    oidc_algorithms: list[str] = ["RS256"]
    oidc_leeway_seconds: int = 30
    oidc_jwks_ttl_seconds: int = 300
    # Members of any of these identity-provider groups may use the /admin endpoints.
    admin_groups: list[str] = ["/vaultgate-admins"]

    # Internal API for the gateway (validate and consume transfer intents, report
    # results). Served on its own port, never routed publicly, and every request must
    # carry this shared secret. Unset means the internal API refuses everything.
    internal_port: int = 8001
    internal_token: SecretStr | None = None

    # Files
    gateway_public_url: str = "http://localhost:8888"
    max_upload_bytes: int = 5 * 1024**3
    upload_intent_ttl_seconds: int = 900
    # A download intent is used right away by the client that asked for it.
    download_intent_ttl_seconds: int = 300
    # Live uploads a user may have at once; more get 429. Abandoned ones do not count:
    # a pending file whose intent expired, or an upload started longer ago than
    # upload_stale_after_seconds.
    max_open_uploads_per_user: int = 20
    upload_stale_after_seconds: int = 6 * 3600
    # How often abandoned uploads are marked failed (see vaultgate_api.uploads); 0 = off.
    upload_sweep_interval_seconds: int = 300

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def split_networks(cls, value):
        return parse_networks(value) if isinstance(value, str) else value


settings = Settings()

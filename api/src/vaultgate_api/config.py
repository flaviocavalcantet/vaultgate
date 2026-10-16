from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables prefixed with VAULTGATE_."""

    model_config = SettingsConfigDict(env_prefix="VAULTGATE_")

    # SQLAlchemy URL; the asyncpg driver is required because the API is fully async.
    database_url: str = "postgresql+asyncpg://vaultgate:vaultgate@localhost:5432/vaultgate"
    database_echo: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
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


settings = Settings()

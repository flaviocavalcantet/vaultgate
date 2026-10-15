from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables prefixed with VAULTGATE_."""

    model_config = SettingsConfigDict(env_prefix="VAULTGATE_")

    # SQLAlchemy URL; the asyncpg driver is required because the API is fully async.
    database_url: str = "postgresql+asyncpg://vaultgate:vaultgate@localhost:5432/vaultgate"
    database_echo: bool = False
    oidc_issuer: str = "http://localhost:8080/realms/vaultgate"
    oidc_audience: str = "vaultgate-api"


settings = Settings()

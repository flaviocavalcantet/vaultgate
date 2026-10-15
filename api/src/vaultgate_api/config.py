from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables prefixed with VAULTGATE_."""

    model_config = SettingsConfigDict(env_prefix="VAULTGATE_")

    database_url: str = "postgresql://vaultgate:vaultgate@localhost:5432/vaultgate"
    oidc_issuer: str = "http://localhost:8080/realms/vaultgate"
    oidc_audience: str = "vaultgate-api"


settings = Settings()

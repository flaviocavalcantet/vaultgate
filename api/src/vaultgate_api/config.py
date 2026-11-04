from typing import Annotated, Literal

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

    # Scanning uploaded files for personal data (vaultgate_api.scans). The scanner
    # worker uses the internal API with its own secret; unset refuses it everything.
    scanner_token: SecretStr | None = None
    # SQS queue the scan requests go to. Unset: nothing is sent and files stay pending.
    scan_queue_url: str | None = None
    aws_region: str = "ap-northeast-1"
    # LocalStack locally; unset in AWS.
    aws_endpoint_url: str | None = None
    # What quarantine blocks (ADR 0005): "download" (default) blocks the owner's
    # downloads and sharing alike; "share" lets the owner download any verdict and
    # blocks sharing only. Files are never shared before a clean verdict or a release.
    quarantine_blocks: Literal["download", "share"] = "download"
    # Finding kinds that quarantine a file; other kinds (email) are only recorded.
    # Comma-separated, like trusted_proxies ("payment_card,br_cpf").
    quarantine_kinds: Annotated[list[str], NoDecode] = ["payment_card", "br_cpf"]
    # A pending scan with no result after this long is sent again, up to
    # scan_max_attempts sends; then it is marked unscannable. Keep it above the
    # queue's visibility timeout so a scan still running is not sent twice.
    scan_resend_after_seconds: int = 900
    scan_max_attempts: int = 5
    # How often stuck scans are looked for; 0 = off.
    scan_resend_interval_seconds: int = 60

    # Sharing (M5). Links last share_default_days (at most share_max_days) and allow
    # share_default_downloads downloads (at most share_max_downloads); the owner may
    # choose within those bounds.
    public_api_url: str = "http://localhost:8000"
    share_default_days: int = 7
    share_max_days: int = 30
    share_default_downloads: int = 5
    share_max_downloads: int = 100
    # Shares of one file that are still usable at once; more get 429.
    max_active_shares_per_file: int = 50
    # External recipients prove their address with a code sent to it: 6 digits, valid
    # share_code_ttl_seconds, share_code_attempts tries; at most share_code_sends_per_hour
    # codes per share, share_code_resend_seconds apart. A right code gives a grant that
    # lasts share_grant_ttl_seconds, to ask for download intents with.
    share_code_ttl_seconds: int = 600
    share_code_attempts: int = 5
    share_code_sends_per_hour: int = 5
    share_code_resend_seconds: int = 60
    # Codes one owner's shares may send in an hour, all shares together: the code email
    # goes to addresses the owner chose, so it must not become a way to mail anyone.
    share_codes_per_owner_per_hour: int = 50
    share_grant_ttl_seconds: int = 1800

    # Outgoing email (verification codes). Mailpit locally; unset means no email can be
    # sent, and external recipients cannot verify.
    smtp_host: str | None = None
    smtp_port: int = 25
    smtp_starttls: bool = False
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "VaultGate <no-reply@vaultgate.local>"

    # How often the head of the audit chain is logged (vaultgate_api.audit); 0 = off.
    audit_anchor_interval_seconds: int = 300

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def split_networks(cls, value):
        return parse_networks(value) if isinstance(value, str) else value

    @field_validator("quarantine_kinds", mode="before")
    @classmethod
    def split_kinds(cls, value):
        if isinstance(value, str):
            return [kind.strip() for kind in value.split(",") if kind.strip()]
        return value


settings = Settings()

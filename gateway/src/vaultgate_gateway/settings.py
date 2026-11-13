"""Gateway configuration, read once from VAULTGATE_* environment variables."""

import os
from dataclasses import dataclass, field

from vaultgate_gateway.clientip import IPNetwork, parse_networks
from vaultgate_gateway.cors import parse_origins


def _env(name: str, default: str | None = None) -> str | None:
    return os.getenv(f"VAULTGATE_{name}", default)


def _secret(name: str) -> str | None:
    """A credential: VAULTGATE_<name>, or else the file vaultgate_<name> in
    VAULTGATE_SECRETS_DIR, where they arrive from OpenBao on the cluster (M9, ADR 0012)
    on a memory-backed volume rather than in the environment."""
    value = _env(name)
    directory = _env("SECRETS_DIR")
    if value is None and directory:
        path = os.path.join(directory, f"vaultgate_{name.lower()}")
        if os.path.isfile(path):
            with open(path) as f:
                value = f.read().strip()
    return value


@dataclass(frozen=True)
class Settings:
    port: int = int(_env("GATEWAY_PORT", "8888"))
    # TLS (M9, ADR 0012): a PEM certificate (with its chain) and key; both unset means
    # plain HTTP, as under docker compose. Renewed files are loaded without a restart.
    tls_cert_file: str | None = _env("TLS_CERT_FILE")
    tls_key_file: str | None = _env("TLS_KEY_FILE")
    tls_reload_interval_seconds: int = int(_env("TLS_RELOAD_INTERVAL_SECONDS", "60"))
    metrics_port: int = int(_env("METRICS_PORT", "9100"))
    max_upload_bytes: int = int(_env("MAX_UPLOAD_BYTES", str(5 * 1024**3)))
    # Transfer limits (vaultgate_gateway.limits; M10): at once per user and per client
    # address, and how many refused intents a minute block an address, for how long.
    # 0 turns a limit off.
    uploads_per_user: int = int(_env("UPLOADS_PER_USER", "4"))
    downloads_per_user: int = int(_env("DOWNLOADS_PER_USER", "8"))
    transfers_per_client: int = int(_env("TRANSFERS_PER_CLIENT", "16"))
    refused_intents_per_minute: int = int(_env("REFUSED_INTENTS_PER_MINUTE", "10"))
    refused_intents_block_seconds: int = int(_env("REFUSED_INTENTS_BLOCK_SECONDS", "300"))
    # How long a connection may send nothing before it is closed (Tornado: an hour), and
    # how long a transfer may move no bytes before it is aborted (0: never).
    idle_connection_timeout_seconds: int = int(_env("IDLE_CONNECTION_TIMEOUT_SECONDS", "60"))
    transfer_stall_timeout_seconds: int = int(_env("TRANSFER_STALL_TIMEOUT_SECONDS", "60"))
    # Reverse proxies whose X-Forwarded-For is believed, comma-separated networks.
    # Proxy addresses only, never client networks (see vaultgate_gateway.clientip).
    trusted_proxies: tuple[IPNetwork, ...] = tuple(parse_networks(_env("TRUSTED_PROXIES", "")))
    # Web origins whose pages may upload and download (CORS, vaultgate_gateway.cors),
    # comma-separated ("https://vault.example.com"). Empty: none, the default.
    cors_origins: frozenset[str] = parse_origins(_env("CORS_ORIGINS", ""))
    # The API's internal endpoint (never the public one) and the shared secret for it.
    # Over https, the API's certificate is verified against the system's trust store,
    # which SSL_CERT_FILE replaces (the cluster's trust bundle).
    api_internal_url: str = _env("API_INTERNAL_URL", "http://localhost:8001")
    internal_token: str | None = field(default=_secret("INTERNAL_TOKEN"), repr=False)
    # The gateway's client certificate for that port, when it wants one (mutual TLS,
    # M10, ADR 0013): a PEM certificate (with its chain) and key, reloaded when renewed.
    api_client_cert_file: str | None = _env("API_CLIENT_CERT_FILE")
    api_client_key_file: str | None = _env("API_CLIENT_KEY_FILE")
    # Object storage and KMS. An endpoint URL points both at LocalStack locally.
    bucket: str = _env("BUCKET", "vaultgate-local-vault")
    kms_key_id: str = _env("KMS_KEY_ID", "alias/vaultgate-local")
    aws_region: str = _env("AWS_REGION", "ap-northeast-1")
    aws_endpoint_url: str | None = _env("AWS_ENDPOINT_URL")
    # Encrypted bytes buffered before each S3 part upload (S3 minimum is 5 MiB).
    part_size: int = int(_env("PART_SIZE", str(8 * 1024 * 1024)))
    # How much ciphertext a download reads from S3 at a time.
    read_size: int = int(_env("READ_SIZE", str(256 * 1024)))
    # Deleting the objects of deleted files (vaultgate_gateway.deletions, ADR 0020): how
    # often to ask the API for more when the queue was drained (0: never), and how many
    # at a time.
    deletion_interval_seconds: float = float(_env("DELETION_INTERVAL_SECONDS", "30"))
    deletion_batch: int = int(_env("DELETION_BATCH", "100"))


settings = Settings()

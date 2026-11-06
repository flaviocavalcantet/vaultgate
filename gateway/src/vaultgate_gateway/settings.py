"""Gateway configuration, read once from VAULTGATE_* environment variables."""

import os
from dataclasses import dataclass, field

from vaultgate_gateway.clientip import IPNetwork, parse_networks


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
    # Reverse proxies whose X-Forwarded-For is believed, comma-separated networks.
    # Proxy addresses only, never client networks (see vaultgate_gateway.clientip).
    trusted_proxies: tuple[IPNetwork, ...] = tuple(parse_networks(_env("TRUSTED_PROXIES", "")))
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


settings = Settings()

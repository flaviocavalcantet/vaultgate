"""Gateway configuration, read once from VAULTGATE_* environment variables."""

import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None) -> str | None:
    return os.getenv(f"VAULTGATE_{name}", default)


@dataclass(frozen=True)
class Settings:
    port: int = int(_env("GATEWAY_PORT", "8888"))
    metrics_port: int = int(_env("METRICS_PORT", "9100"))
    max_upload_bytes: int = int(_env("MAX_UPLOAD_BYTES", str(5 * 1024**3)))
    # The API's internal endpoint (never the public one) and the shared secret for it.
    api_internal_url: str = _env("API_INTERNAL_URL", "http://localhost:8001")
    internal_token: str | None = field(default=_env("INTERNAL_TOKEN"), repr=False)
    # Object storage and KMS. An endpoint URL points both at LocalStack locally.
    bucket: str = _env("BUCKET", "vaultgate-local-vault")
    kms_key_id: str = _env("KMS_KEY_ID", "alias/vaultgate-local")
    aws_region: str = _env("AWS_REGION", "ap-northeast-1")
    aws_endpoint_url: str | None = _env("AWS_ENDPOINT_URL")
    # Encrypted bytes buffered before each S3 part upload (S3 minimum is 5 MiB).
    part_size: int = int(_env("PART_SIZE", str(8 * 1024 * 1024)))


settings = Settings()

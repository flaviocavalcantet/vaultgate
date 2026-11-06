"""Entry point: `python -m vaultgate_api`.

Starts uvicorn with logging already configured, so uvicorn's own messages come out
in the same JSON format as the application's instead of its default text format.
Two servers run in one process: the public API and, on its own port, the internal
API the gateway and the scanner use; next to them, a periodic sweep of abandoned
uploads and the resender of stuck scan requests. With a TLS certificate configured, both
servers and the metrics port speak TLS only, and a renewed certificate is loaded without a
restart.
"""

import asyncio
import ssl

import uvicorn

from vaultgate_api.audit import run_anchor
from vaultgate_api.config import settings
from vaultgate_api.db import get_sessionmaker
from vaultgate_api.logs import configure_logging
from vaultgate_api.scans import get_scan_queue, run_resender
from vaultgate_api.tls import CertificateReloader, start_metrics_server
from vaultgate_api.tracing import configure_tracing
from vaultgate_api.uploads import run_sweeper


def _server(app: str, port: int) -> uvicorn.Server:
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=port,
        log_config=None,
        access_log=False,
        # Off: ClientAddressMiddleware resolves the client against trusted_proxies
        # (uvicorn's own handling would trust 127.0.0.1 implicitly).
        proxy_headers=False,
        ssl_certfile=settings.tls_cert_file,
        ssl_keyfile=settings.tls_key_file,
    )
    config.load()  # builds the SSLContext now, so the reloader can renew it in place
    return uvicorn.Server(config)


async def serve(metrics_context: ssl.SSLContext | None = None) -> None:
    if bool(settings.tls_cert_file) != bool(settings.tls_key_file):
        raise SystemExit("set both VAULTGATE_TLS_CERT_FILE and VAULTGATE_TLS_KEY_FILE, or neither")
    public = _server("vaultgate_api.main:app", settings.port)
    internal = _server("vaultgate_api.internal:internal_app", settings.internal_port)
    tasks = [public.serve(), internal.serve()]
    if settings.tls_cert_file and settings.tls_key_file:
        reloader = CertificateReloader(
            settings.tls_cert_file,
            settings.tls_key_file,
            [public.config.ssl, internal.config.ssl, *filter(None, [metrics_context])],
        )
        tasks.append(reloader.run(settings.tls_reload_interval_seconds))
    if settings.upload_sweep_interval_seconds > 0:
        tasks.append(run_sweeper(get_sessionmaker(), settings.upload_sweep_interval_seconds))
    if settings.audit_anchor_interval_seconds > 0:
        tasks.append(run_anchor(get_sessionmaker(), settings.audit_anchor_interval_seconds))
    if settings.scan_resend_interval_seconds > 0:
        tasks.append(
            run_resender(
                get_sessionmaker(), get_scan_queue(), settings.scan_resend_interval_seconds
            )
        )
    await asyncio.gather(*tasks)


def main() -> None:
    configure_logging(settings.log_level, settings.log_format)
    configure_tracing()
    metrics_context = start_metrics_server(
        settings.metrics_port, settings.tls_cert_file, settings.tls_key_file
    )
    asyncio.run(serve(metrics_context))


if __name__ == "__main__":
    main()

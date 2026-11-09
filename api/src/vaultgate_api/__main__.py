"""Entry point: `python -m vaultgate_api`.

Starts uvicorn with logging already configured, so uvicorn's own messages come out
in the same JSON format as the application's instead of its default text format.
Two servers run in one process: the public API and, on its own port, the internal
API the gateway and the scanner use; next to them, a periodic sweep of abandoned
uploads and the resender of stuck scan requests. With a TLS certificate configured, both
servers and the metrics port speak TLS only, and a renewed certificate is loaded without a
restart. With a client CA as well, the internal server wants a client certificate from it
(mutual TLS, vaultgate_api.mtls). With a nodes' client CA, a third server, the nodes' port,
wants a node's certificate (M11, vaultgate_api.nodes_app).
"""

import asyncio
import ssl

import uvicorn

from vaultgate_api.audit import run_anchor
from vaultgate_api.config import settings
from vaultgate_api.db import get_sessionmaker
from vaultgate_api.logs import configure_logging
from vaultgate_api.mtls import ClientIdentityProtocol
from vaultgate_api.scans import get_scan_queue, run_resender
from vaultgate_api.tls import CertificateReloader, start_metrics_server
from vaultgate_api.tracing import configure_tracing
from vaultgate_api.uploads import run_sweeper


def _server(app: str, port: int, **mtls) -> uvicorn.Server:
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
        # No server name or version in the responses (M10, docs/security-scans.md).
        server_header=False,
        **mtls,
    )
    config.load()  # builds the SSLContext now, so the reloader can renew it in place
    if config.ssl is not None:
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3  # as every hop (ADR 0012)
    return uvicorn.Server(config)


async def serve(metrics_context: ssl.SSLContext | None = None) -> None:
    if bool(settings.tls_cert_file) != bool(settings.tls_key_file):
        raise SystemExit("set both VAULTGATE_TLS_CERT_FILE and VAULTGATE_TLS_KEY_FILE, or neither")
    mtls = {}
    if settings.internal_client_ca_file:
        if not settings.tls_cert_file:
            raise SystemExit("VAULTGATE_INTERNAL_CLIENT_CA_FILE needs TLS on (a certificate)")
        mtls = {
            "ssl_ca_certs": settings.internal_client_ca_file,
            "ssl_cert_reqs": ssl.CERT_REQUIRED,
            "http": ClientIdentityProtocol,
        }
    public = _server("vaultgate_api.main:app", settings.port)
    internal = _server("vaultgate_api.internal:internal_app", settings.internal_port, **mtls)
    servers = [public, internal]
    if settings.nodes_client_ca_file:
        if not settings.tls_cert_file:
            raise SystemExit("VAULTGATE_NODES_CLIENT_CA_FILE needs TLS on (a certificate)")
        servers.append(
            _server(
                "vaultgate_api.nodes_app:nodes_app",
                settings.nodes_port,
                ssl_ca_certs=settings.nodes_client_ca_file,
                ssl_cert_reqs=ssl.CERT_REQUIRED,
                http=ClientIdentityProtocol,
            )
        )
    tasks = [server.serve() for server in servers]
    if settings.tls_cert_file and settings.tls_key_file:
        reloader = CertificateReloader(
            settings.tls_cert_file,
            settings.tls_key_file,
            [*(s.config.ssl for s in servers), *filter(None, [metrics_context])],
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


def migrate(config_file: str = "alembic.ini") -> None:
    """`alembic upgrade head`, in-process. Its environment runs its own event loop, so
    this comes before the servers'."""
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config(config_file), "head")


def main() -> None:
    configure_logging(settings.log_level, settings.log_format)
    if settings.migrate_on_start:
        migrate()
    configure_tracing()
    metrics_context = start_metrics_server(
        settings.metrics_port, settings.tls_cert_file, settings.tls_key_file
    )
    asyncio.run(serve(metrics_context))


if __name__ == "__main__":
    main()

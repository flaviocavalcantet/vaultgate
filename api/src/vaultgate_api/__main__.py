"""Entry point: `python -m vaultgate_api`.

Starts uvicorn with logging already configured, so uvicorn's own messages come out
in the same JSON format as the application's instead of its default text format.
Two servers run in one process: the public API and, on its own port, the internal
API the gateway and the scanner use; next to them, a periodic sweep of abandoned
uploads and the resender of stuck scan requests.
"""

import asyncio

import uvicorn
from prometheus_client import start_http_server

from vaultgate_api.audit import run_anchor
from vaultgate_api.config import settings
from vaultgate_api.db import get_sessionmaker
from vaultgate_api.logs import configure_logging
from vaultgate_api.scans import get_scan_queue, run_resender
from vaultgate_api.tracing import configure_tracing
from vaultgate_api.uploads import run_sweeper


def _server(app: str, port: int) -> uvicorn.Server:
    return uvicorn.Server(
        uvicorn.Config(
            app,
            host=settings.host,
            port=port,
            log_config=None,
            access_log=False,
            # Off: ClientAddressMiddleware resolves the client against trusted_proxies
            # (uvicorn's own handling would trust 127.0.0.1 implicitly).
            proxy_headers=False,
        )
    )


async def serve() -> None:
    public = _server("vaultgate_api.main:app", settings.port)
    internal = _server("vaultgate_api.internal:internal_app", settings.internal_port)
    tasks = [public.serve(), internal.serve()]
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
    start_http_server(settings.metrics_port)
    asyncio.run(serve())


if __name__ == "__main__":
    main()

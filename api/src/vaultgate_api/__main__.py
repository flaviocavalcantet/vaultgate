"""Entry point: `python -m vaultgate_api`.

Starts uvicorn with logging already configured, so uvicorn's own messages come out
in the same JSON format as the application's instead of its default text format.
Two servers run in one process: the public API and, on its own port, the internal
API the gateway uses; next to them, a periodic sweep of abandoned uploads.
"""

import asyncio

import uvicorn
from prometheus_client import start_http_server

from vaultgate_api.config import settings
from vaultgate_api.db import get_sessionmaker
from vaultgate_api.logs import configure_logging
from vaultgate_api.uploads import run_sweeper


def _server(app: str, port: int, *, proxy_headers: bool) -> uvicorn.Server:
    return uvicorn.Server(
        uvicorn.Config(
            app,
            host=settings.host,
            port=port,
            log_config=None,
            access_log=False,
            proxy_headers=proxy_headers,
        )
    )


async def serve() -> None:
    public = _server("vaultgate_api.main:app", settings.port, proxy_headers=True)
    internal = _server(
        "vaultgate_api.internal:internal_app", settings.internal_port, proxy_headers=False
    )
    tasks = [public.serve(), internal.serve()]
    if settings.upload_sweep_interval_seconds > 0:
        tasks.append(run_sweeper(get_sessionmaker(), settings.upload_sweep_interval_seconds))
    await asyncio.gather(*tasks)


def main() -> None:
    configure_logging(settings.log_level, settings.log_format)
    start_http_server(settings.metrics_port)
    asyncio.run(serve())


if __name__ == "__main__":
    main()

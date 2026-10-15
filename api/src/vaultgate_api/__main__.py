"""Entry point: `python -m vaultgate_api`.

Starts uvicorn with logging already configured, so uvicorn's own messages come out
in the same JSON format as the application's instead of its default text format.
"""

import uvicorn
from prometheus_client import start_http_server

from vaultgate_api.config import settings
from vaultgate_api.logs import configure_logging


def main() -> None:
    configure_logging(settings.log_level, settings.log_format)
    start_http_server(settings.metrics_port)
    uvicorn.run(
        "vaultgate_api.main:app",
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=False,
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()

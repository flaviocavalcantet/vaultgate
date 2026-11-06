"""TLS certificates that renew while the servers run (M9, ADR 0012).

cert-manager renews the API's certificate long before it expires (they last a day)
and Kubernetes swaps the mounted files in place. The servers keep their SSLContext,
so this loads the new certificate and key into it: connections made after that get the
new certificate, open ones keep theirs. A pair that doesn't load (a key that doesn't
match, a half-written file) is skipped and tried again, and the old one stays in use.
"""

import asyncio
import logging
import os
import ssl

logger = logging.getLogger(__name__)


class CertificateReloader:
    def __init__(self, cert_file: str, key_file: str, contexts: list[ssl.SSLContext]) -> None:
        self.cert_file = cert_file
        self.key_file = key_file
        self.contexts = contexts
        self._loaded = self._signature()

    def _signature(self) -> tuple:
        # stat follows the symlinks of a mounted Secret, so a swap shows as a new file.
        return tuple(
            (s.st_ino, s.st_mtime_ns, s.st_size)
            for s in (os.stat(self.cert_file), os.stat(self.key_file))
        )

    def check(self) -> bool:
        """Loads the certificate again if its files changed; True when it did."""
        try:
            current = self._signature()
        except OSError as exc:
            logger.warning("tls certificate unreadable, keeping the loaded one: %s", exc)
            return False
        if current == self._loaded:
            return False
        try:
            # Tried on a scratch context first: a failed load_cert_chain can leave the
            # certificate loaded without its key, and the context unable to serve.
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(self.cert_file, self.key_file)
            for context in self.contexts:
                context.load_cert_chain(self.cert_file, self.key_file)
        except (OSError, ssl.SSLError) as exc:
            logger.warning("tls certificate not reloaded, keeping the loaded one: %s", exc)
            return False
        self._loaded = current
        logger.info("tls certificate reloaded", extra={"cert_file": self.cert_file})
        return True

    async def run(self, interval_seconds: float) -> None:
        while True:
            await asyncio.sleep(interval_seconds)
            self.check()

"""Outgoing email, for share verification codes.

SMTP through the standard library, in a thread so the event loop keeps serving.
Locally the server is Mailpit (in compose), which catches every message and shows it
at http://localhost:8025. Without VAULTGATE_SMTP_HOST nothing can be sent, and the
routes that need email answer 503.
"""

import asyncio
import smtplib
from email.message import EmailMessage
from email.utils import make_msgid
from functools import lru_cache
from typing import Annotated, Protocol

from fastapi import Depends

from vaultgate_api.config import settings


class MailUnavailable(Exception):
    """The message could not be handed to the mail server."""


class Mailer(Protocol):
    async def send(self, to: str, subject: str, body: str) -> None: ...


class SmtpMailer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    def _send(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self.host, self.port, timeout=10) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_username and settings.smtp_password:
                smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            smtp.send_message(message)

    async def send(self, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = to
        message["Subject"] = subject
        message["Message-ID"] = make_msgid(domain="vaultgate.local")
        message.set_content(body)
        try:
            await asyncio.to_thread(self._send, message)
        except (OSError, smtplib.SMTPException) as exc:
            raise MailUnavailable(type(exc).__name__) from None


class NoMailer:
    async def send(self, to: str, subject: str, body: str) -> None:
        raise MailUnavailable("VAULTGATE_SMTP_HOST is not set")


@lru_cache
def get_mailer() -> Mailer:
    if settings.smtp_host:
        return SmtpMailer(settings.smtp_host, settings.smtp_port)
    return NoMailer()


MailerDep = Annotated[Mailer, Depends(get_mailer)]

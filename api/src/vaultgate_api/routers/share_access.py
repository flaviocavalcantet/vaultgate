"""The recipient's side of a share link (M5), for external recipients.

No account and no OIDC token: the link's token names the share, and the recipient
proves they hold its address with a code sent there.

1. `GET /shares/access?token=...` says what the link is (never the file name before
   the address is proven).
2. `POST /shares/access/code` emails a 6-digit code to the share's address.
3. `POST /shares/access/verify` takes the code and returns a grant, shown once.
4. `POST /shares/access/downloads` takes the grant and returns a download intent for
   the gateway, like an owner's download.

Every step re-checks that the share is active and that the file's scan lets it be
shared (ADR 0005), and the gateway's consume checks again and counts the download
against the share, so a revoke, an expiry or a rescan into quarantine applies at
once, also to grants and intents already handed out. Codes and grants are stored
hashed; tokens travel in request bodies, or in the link's query string, which is never
logged. Logs name the share, never the recipient's address.
"""

import hashlib
import hmac
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from vaultgate_api import intents, metrics, scans
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.mail import MailerDep, MailUnavailable
from vaultgate_api.models import File, Share, ShareVerification, User
from vaultgate_api.routers.files import TransferOut
from vaultgate_api.routers.shares import hash_token, state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/shares/access", tags=["share access"])

Token = Field(min_length=1, max_length=256)


class AccessOut(BaseModel):
    recipient_kind: Literal["external", "internal"]
    # The address with most of its local part hidden, so the recipient knows which
    # inbox to look in without the link revealing it.
    recipient_hint: str
    expires_at: datetime
    downloads_left: int


class TokenIn(BaseModel):
    token: str = Token


class VerifyIn(BaseModel):
    token: str = Token
    code: str = Field(pattern=r"^[0-9]{6}$")


class GrantOut(BaseModel):
    grant: str
    expires_at: datetime


class DownloadIn(BaseModel):
    token: str = Token
    grant: str = Token


def _hint(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


async def _share(session, token: str, *, lock: bool = False) -> tuple[Share, File]:
    """The active share the token names, and its file, or a refusal."""
    query = select(Share).where(Share.token_hash == hash_token(token))
    share = await session.scalar(query.with_for_update() if lock else query)
    if share is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Share not found")
    if (current := state(share)) != "active":
        raise HTTPException(status.HTTP_410_GONE, detail=f"Share is {current}")
    file = await session.get(File, share.file_id)
    owner = await session.get(User, share.created_by)
    if file is None or file.status != "uploaded" or owner is None or not owner.is_active:
        raise HTTPException(status.HTTP_410_GONE, detail="File is not available")
    return share, file


def _shareable(file: File) -> None:
    if reason := scans.check(file, "share", checked_by="api"):
        raise HTTPException(status.HTTP_409_CONFLICT, detail=reason)


def _external(share: Share) -> None:
    if share.recipient_kind != "external":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="This share is for a VaultGate user: sign in to download it",
        )


async def _verification(session, share: Share) -> ShareVerification:
    """The share's verification row, locked; created on first use."""
    await session.execute(
        insert(ShareVerification).values(share_id=share.id).on_conflict_do_nothing()
    )
    return await session.scalar(
        select(ShareVerification)
        .where(ShareVerification.share_id == share.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def _hash(secret: str, salt: str = "") -> str:
    return hashlib.sha256((salt + secret).encode()).hexdigest()


@router.get("")
async def describe_share(
    session: SessionDep, token: str = Query(min_length=1, max_length=256)
) -> AccessOut:
    """What the link is for: the kind of recipient, a hint of the address, and how long
    and how many downloads it has left."""
    share, _ = await _share(session, token)
    return AccessOut(
        recipient_kind=share.recipient_kind,
        recipient_hint=_hint(share.recipient_email),
        expires_at=share.expires_at,
        downloads_left=share.max_downloads - share.downloads,
    )


@router.post("/code", status_code=status.HTTP_202_ACCEPTED)
async def send_code(body: TokenIn, session: SessionDep, mailer: MailerDep) -> dict:
    """Email a 6-digit code to the share's address. A new code replaces the last one."""
    share, file = await _share(session, body.token, lock=True)
    share_id = str(share.id)  # for logs; share is expired by a rollback
    _external(share)
    _shareable(file)
    v = await _verification(session, share)
    now = datetime.now(UTC)
    if v.last_sent_at and now - v.last_sent_at < timedelta(
        seconds=settings.share_code_resend_seconds
    ):
        await session.rollback()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="A code was just sent; wait before asking for another",
            headers={"Retry-After": str(settings.share_code_resend_seconds)},
        )
    if v.window_started_at is None or now - v.window_started_at >= timedelta(hours=1):
        v.window_started_at, v.sends = now, 0
    if v.sends >= settings.share_code_sends_per_hour:
        await session.rollback()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many codes for this share; try later"
        )
    owner_sends = await session.scalar(
        select(func.coalesce(func.sum(ShareVerification.sends), 0))
        .join(Share, Share.id == ShareVerification.share_id)
        .where(
            Share.created_by == share.created_by,
            ShareVerification.window_started_at > now - timedelta(hours=1),
        )
    )
    if owner_sends >= settings.share_codes_per_owner_per_hour:
        await session.rollback()
        logger.warning("share codes capped for an owner", extra={"share_id": share_id})
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many codes sent; try later"
        )
    previous = (v.sends, v.window_started_at, v.last_sent_at)
    code = f"{secrets.randbelow(10**6):06d}"
    v.code_salt = secrets.token_hex(16)
    v.code_hash = _hash(code, v.code_salt)
    v.code_expires_at = now + timedelta(seconds=settings.share_code_ttl_seconds)
    v.code_attempts = 0
    v.sends += 1
    v.last_sent_at = now
    code_hash = v.code_hash
    to, hint = share.recipient_email, _hint(share.recipient_email)
    # Committed before the mail goes out: the share's lock must not wait on a slow mail
    # server, or downloads, revokes and checks of this share would wait with it.
    await session.commit()
    minutes = settings.share_code_ttl_seconds // 60
    try:
        # Fixed text only: nothing a user typed (file name, display name) goes into a
        # message sent from VaultGate to an address they chose.
        await mailer.send(
            to,
            f"Your VaultGate code: {code}",
            "Someone used a VaultGate share link sent to this address and asked for a "
            f"code to open it.\n\nYour code is {code}. It expires in {minutes} minutes.\n\n"
            "If you did not ask for it, ignore this message: nothing is shared without it.\n",
        )
    except MailUnavailable:
        # Nothing was sent: the code goes, and the send does not count.
        v = await session.scalar(
            select(ShareVerification)
            .where(ShareVerification.share_id == share.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if v is not None and v.code_hash == code_hash:  # not replaced since
            v.code_hash = v.code_salt = v.code_expires_at = None
            v.sends, v.window_started_at, v.last_sent_at = previous
            await session.commit()
        logger.warning("share code not sent", extra={"share_id": share_id})
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="The code could not be sent; try later"
        ) from None
    metrics.SHARE_CODES_SENT.inc()
    logger.info("share code sent", extra={"share_id": share_id})
    return {"sent_to": hint, "expires_in": settings.share_code_ttl_seconds}


@router.post("/verify")
async def verify_code(body: VerifyIn, session: SessionDep) -> GrantOut:
    """Check the code; the right one gives a grant to ask for downloads with."""
    share, file = await _share(session, body.token, lock=True)
    share_id = str(share.id)  # for logs; share is expired by a rollback
    _external(share)
    _shareable(file)
    v = await _verification(session, share)
    now = datetime.now(UTC)

    def refuse(result: str, detail: str) -> HTTPException:
        metrics.SHARE_VERIFICATIONS.labels(result).inc()
        logger.info("share code refused", extra={"share_id": share_id, "result": result})
        return HTTPException(status.HTTP_403_FORBIDDEN, detail=detail)

    if v.code_hash is None:
        await session.rollback()
        raise refuse("exhausted", "No code to check; ask for a new one")
    if v.code_expires_at <= now:
        v.code_hash = v.code_salt = None
        await session.commit()
        raise refuse("expired", "The code has expired; ask for a new one")
    if not hmac.compare_digest(_hash(body.code, v.code_salt), v.code_hash):
        v.code_attempts += 1
        left = settings.share_code_attempts - v.code_attempts
        if left <= 0:
            v.code_hash = v.code_salt = None  # one code, a few tries
        await session.commit()
        if left <= 0:
            raise refuse("exhausted", "Too many wrong codes; ask for a new one")
        raise refuse("wrong", f"Wrong code; {left} tries left")
    grant = secrets.token_urlsafe(32)
    v.code_hash = v.code_salt = None  # single use
    v.grant_hash = _hash(grant)
    v.grant_expires_at = now + timedelta(seconds=settings.share_grant_ttl_seconds)
    await session.commit()
    metrics.SHARE_VERIFICATIONS.labels("ok").inc()
    logger.info("share recipient verified", extra={"share_id": share_id})
    return GrantOut(grant=grant, expires_at=v.grant_expires_at)


@router.post("/downloads", status_code=status.HTTP_201_CREATED)
async def create_share_download(body: DownloadIn, session: SessionDep) -> TransferOut:
    """A single-use download intent for the shared file. The gateway counts it against
    the share's downloads when it starts."""
    share, file = await _share(session, body.token)
    _external(share)
    v = await session.get(ShareVerification, share.id)
    now = datetime.now(UTC)
    if (
        v is None
        or v.grant_hash is None
        or v.grant_expires_at <= now
        or not hmac.compare_digest(_hash(body.grant), v.grant_hash)
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Grant not valid; verify again")
    _shareable(file)
    token, expires_at = await intents.issue(
        session,
        file=file,
        kind="download",
        user_id=share.created_by,
        ttl=timedelta(seconds=settings.download_intent_ttl_seconds),
        share_id=share.id,
    )
    await session.commit()
    url = f"{settings.gateway_public_url.rstrip('/')}/downloads/{file.id}"
    return TransferOut(url=url, token=token, expires_at=expires_at)

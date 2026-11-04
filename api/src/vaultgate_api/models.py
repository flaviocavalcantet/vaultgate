"""Relational schema for the control plane.

Identity comes from the organization's OIDC provider. A user row is a local record of
a person the provider has vouched for, keyed by (issuer, subject) because `sub` is
only unique within one issuer. Groups mirror the provider's group paths and drive
access policies (see vaultgate_api.policies and ADR 0004).
"""

import uuid
from datetime import datetime, time

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    LargeBinary,
    MetaData,
    SmallInteger,
    String,
    Table,
    Text,
    Time,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Deterministic constraint names keep Alembic migrations stable across databases.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True, index=True),
)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_users_issuer_subject"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(255))
    # The provider's login name (Keycloak: preferred_username). Display only: it can
    # change, so identity is always (issuer, subject).
    username: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320))
    # Whether the provider vouched for the email in the last token (email_verified).
    email_verified: Mapped[bool] = mapped_column(default=False, server_default="false")
    display_name: Mapped[str | None] = mapped_column(String(255))
    # Local kill switch: an inactive user is refused even with a valid token.
    is_active: Mapped[bool] = mapped_column(default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    groups: Mapped[list["Group"]] = relationship(
        secondary=user_groups, back_populates="members", lazy="selectin"
    )


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # Full group path as the identity provider reports it, e.g. "/finance/payroll".
    name: Mapped[str] = mapped_column(String(255), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Never loaded implicitly: a large group would pull in every member row. Code that
    # needs members asks for them (selectinload) or counts them with a join.
    members: Mapped[list[User]] = relationship(
        secondary=user_groups, back_populates="groups", lazy="raise"
    )


FILE_STATUSES = ("pending", "uploading", "uploaded", "failed")
SCAN_STATUSES = ("pending", "scanned", "unscannable")


class File(Base):
    """A file in the vault. Bytes live in object storage, encrypted by the gateway.

    Lifecycle: pending (metadata created, upload intent issued) -> uploading (the
    gateway consumed the intent and is receiving bytes) -> uploaded | failed.

    An uploaded file is scanned for personal data (vaultgate_api.scans): scan_status
    is pending until the scanner reports, then scanned (with findings) or unscannable.
    """

    __tablename__ = "files"
    __table_args__ = (
        CheckConstraint(f"status IN {FILE_STATUSES}", name="status"),
        CheckConstraint("declared_size >= 0", name="declared_size"),
        CheckConstraint(f"scan_status IN {SCAN_STATUSES}", name="scan_status"),
        CheckConstraint("(scan_status IS NULL) = (scan_id IS NULL)", name="scan_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(255))
    # What the client announced; the gateway refuses to accept more than this.
    declared_size: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    # Object key in the vault bucket; derived from the id, never from the file name.
    storage_key: Mapped[str] = mapped_column(String(512), unique=True)
    # Set when the upload completes.
    size: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    # The per-file data key, encrypted by KMS. Plaintext keys are never stored.
    wrapped_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    kms_key_id: Mapped[str | None] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Scan state; all NULL until the upload completes.
    scan_status: Mapped[str | None] = mapped_column(String(16))
    # Names one scan request. Queue messages and results carry it, so a result for an
    # older request (before a rescan) cannot overwrite the current one.
    scan_id: Mapped[uuid.UUID | None] = mapped_column(unique=True)
    # When the request was last sent to the queue, and how many times it was sent.
    scan_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scan_attempts: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Why a file is unscannable, e.g. "PDF is encrypted". Never contains file content.
    scan_reason: Mapped[str | None] = mapped_column(String(500))

    findings: Mapped[list["ScanFinding"]] = relationship(
        lazy="selectin", cascade="all, delete-orphan", order_by="ScanFinding.kind"
    )
    releases: Mapped[list["ScanRelease"]] = relationship(
        lazy="selectin", cascade="all, delete-orphan", order_by="ScanRelease.purpose"
    )


class ScanFinding(Base):
    """How many matches of one kind of personal data the scanner found in a file.

    Only the kind and the count are kept: matched values and their positions never
    leave the scanner.
    """

    __tablename__ = "scan_findings"
    __table_args__ = (CheckConstraint("count > 0", name="count"),)

    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    count: Mapped[int] = mapped_column(BigInteger)


RELEASE_PURPOSES = ("download", "share")


class ScanRelease(Base):
    """An admin's release of a quarantined or unscannable file for one purpose: its
    owner may download it, or it may be shared. It covers the scan it was given for
    (scan_id) only: after a rescan it no longer applies (ADR 0005)."""

    __tablename__ = "scan_releases"
    __table_args__ = (CheckConstraint(f"purpose IN {RELEASE_PURPOSES}", name="purpose"),)

    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), primary_key=True
    )
    purpose: Mapped[str] = mapped_column(String(16), primary_key=True)
    scan_id: Mapped[uuid.UUID]
    released_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    released_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reason: Mapped[str] = mapped_column(String(500))


SHARE_KINDS = ("external", "internal")


class Share(Base):
    """A link to one file for one recipient, named by email address.

    An external recipient proves they hold the address with a code sent to it; an
    internal one signs in, with a verified email equal to the address. The link's token
    is shown to the owner once; only its SHA-256 is stored. A share ends when it
    expires, when its downloads are used up, or when the owner revokes it.
    """

    __tablename__ = "shares"
    __table_args__ = (
        CheckConstraint(f"recipient_kind IN {SHARE_KINDS}", name="recipient_kind"),
        CheckConstraint("max_downloads > 0", name="max_downloads"),
        CheckConstraint("downloads >= 0 AND downloads <= max_downloads", name="downloads"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # Lower case; the address the recipient must prove.
    recipient_email: Mapped[str] = mapped_column(String(320))
    recipient_kind: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_downloads: Mapped[int] = mapped_column(SmallInteger)
    downloads: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ShareVerification(Base):
    """An external recipient's proof of their address, for one share.

    A code is sent to the share's address; only its salted hash is kept, with a few
    attempts and a short life. A right code gives a grant (a token shown once, hashed
    here) with which the recipient asks for download intents for a while.
    """

    __tablename__ = "share_verifications"

    share_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("shares.id", ondelete="CASCADE"), primary_key=True
    )
    code_hash: Mapped[str | None] = mapped_column(String(64))
    code_salt: Mapped[str | None] = mapped_column(String(32))
    code_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    code_attempts: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    # Codes sent in the current hour, from window_started_at.
    sends: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    window_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    grant_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    grant_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TransferIntent(Base):
    """A short-lived, single-use permission to move one file's bytes through the gateway.

    The token is shown to the client once; only its SHA-256 is stored, so a database
    leak does not yield usable tokens.
    """

    __tablename__ = "transfer_intents"
    __table_args__ = (CheckConstraint("kind IN ('upload', 'download')", name="kind"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set for a recipient's download through a share; created_by is then the owner.
    share_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("shares.id", ondelete="CASCADE"))


POLICY_EFFECTS = ("allow", "deny")
POLICY_ACTIONS = ("read", "upload", "download", "share")


class Policy(Base):
    """An access rule. Nothing is allowed unless an enabled allow policy matches, and a
    matching deny policy always wins (ADR 0004).

    A policy matches a request when the action is one of `actions` and every condition
    that is set holds; an empty list or a missing time window means "any".
    """

    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint(f"effect IN {POLICY_EFFECTS}", name="effect"),
        CheckConstraint("cardinality(actions) > 0", name="actions"),
        CheckConstraint(f"actions <@ ARRAY{list(POLICY_ACTIONS)}::varchar[]", name="known_actions"),
        CheckConstraint("days <@ ARRAY[1, 2, 3, 4, 5, 6, 7]::smallint[]", name="days"),
        CheckConstraint("(start_time IS NULL) = (end_time IS NULL)", name="time_window"),
        CheckConstraint("start_time <> end_time", name="time_window_length"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    effect: Mapped[str] = mapped_column(String(8))
    actions: Mapped[list[str]] = mapped_column(ARRAY(String(16)))
    # Group paths; a policy for "/finance" also covers members of "/finance/payroll".
    groups: Mapped[list[str]] = mapped_column(ARRAY(String(255)), default=list, server_default="{}")
    # The client must be in one of `networks` (if any) and in none of `excluded_networks`.
    networks: Mapped[list] = mapped_column(ARRAY(CIDR), default=list, server_default="{}")
    excluded_networks: Mapped[list] = mapped_column(ARRAY(CIDR), default=list, server_default="{}")
    # ISO weekdays, 1 = Monday ... 7 = Sunday.
    days: Mapped[list[int]] = mapped_column(ARRAY(SmallInteger), default=list, server_default="{}")
    # Local wall-clock times in `timezone`, start inclusive, end exclusive. A window
    # that ends before it starts runs overnight and belongs to the day it starts.
    start_time: Mapped[time | None] = mapped_column(Time)
    end_time: Mapped[time | None] = mapped_column(Time)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", server_default="UTC")
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


AUDIT_ACTOR_KINDS = ("user", "recipient", "gateway", "scanner", "system")


class AuditEvent(Base):
    """One security event (ADR 0007): who did what to which object, with what outcome.

    Append-only: a trigger refuses UPDATE, DELETE and TRUNCATE for every role. Rows form
    a hash chain: each one's `hash` is a SHA-256 over its own fields and the previous
    row's hash (`prev_hash`), so a row changed or removed around the trigger breaks the
    chain from there on (vaultgate_api.audit.verify). No foreign keys: the record must
    outlive the users, files and shares it names.
    """

    __tablename__ = "audit_events"
    __table_args__ = (CheckConstraint(f"actor_kind IN {AUDIT_ACTOR_KINDS}", name="actor_kind"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor_kind: Mapped[str] = mapped_column(String(16))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    # Dotted name, e.g. share.created, access.denied (see vaultgate_api.audit).
    action: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16))
    target_kind: Mapped[str | None] = mapped_column(String(16))
    target_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    client_ip: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)

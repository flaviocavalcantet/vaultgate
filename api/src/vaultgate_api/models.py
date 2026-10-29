"""Relational schema for the control plane.

Identity comes from the organization's OIDC provider. A user row is a local record of
a person the provider has vouched for, keyed by (issuer, subject) because `sub` is
only unique within one issuer. Groups mirror the provider's group paths and drive
access policies from M3 onwards.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    func,
)
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

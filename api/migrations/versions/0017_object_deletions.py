"""Deleting files and folders (M12.6, ADR 0020): the queue of stored objects the
gateway deletes.

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "object_deletions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("storage_key", sa.String(length=512), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("claimed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.SmallInteger(), server_default="0", nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_object_deletions")),
    )
    op.create_index(
        op.f("ix_object_deletions_claimed_until"), "object_deletions", ["claimed_until"]
    )


def downgrade() -> None:
    op.drop_table("object_deletions")

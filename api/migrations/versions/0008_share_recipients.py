"""External share recipients: verification codes and grants; intents for shares.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "share_verifications",
        sa.Column("share_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=True),
        sa.Column("code_salt", sa.String(length=32), nullable=True),
        sa.Column("code_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("code_attempts", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("sends", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("grant_hash", sa.String(length=64), nullable=True),
        sa.Column("grant_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["share_id"],
            ["shares.id"],
            name=op.f("fk_share_verifications_share_id_shares"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("share_id", name=op.f("pk_share_verifications")),
        sa.UniqueConstraint("grant_hash", name=op.f("uq_share_verifications_grant_hash")),
    )
    op.add_column("transfer_intents", sa.Column("share_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_transfer_intents_share_id_shares"),
        "transfer_intents",
        "shares",
        ["share_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_transfer_intents_share_id_shares"), "transfer_intents", type_="foreignkey"
    )
    op.drop_column("transfer_intents", "share_id")
    op.drop_table("share_verifications")

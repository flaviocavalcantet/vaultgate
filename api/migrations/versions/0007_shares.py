"""Shares, the share action, and releases by purpose.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIONS_BEFORE = "ARRAY['read', 'upload', 'download']::varchar[]"
ACTIONS_AFTER = "ARRAY['read', 'upload', 'download', 'share']::varchar[]"


def upgrade() -> None:
    # Existing policies keep their actions: sharing is denied until an admin allows it.
    op.drop_constraint(op.f("ck_policies_known_actions"), "policies", type_="check")
    op.create_check_constraint(
        op.f("ck_policies_known_actions"), "policies", f"actions <@ {ACTIONS_AFTER}"
    )

    op.create_table(
        "scan_releases",
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column(
            "released_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("released_by", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('download', 'share')", name=op.f("ck_scan_releases_purpose")
        ),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["files.id"],
            name=op.f("fk_scan_releases_file_id_files"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["released_by"],
            ["users.id"],
            name=op.f("fk_scan_releases_released_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("file_id", "purpose", name=op.f("pk_scan_releases")),
    )
    # M4's releases allowed downloads.
    op.execute(
        "INSERT INTO scan_releases (file_id, purpose, scan_id, released_at, released_by, reason) "
        "SELECT id, 'download', scan_id, released_at, released_by, release_reason FROM files "
        "WHERE released_at IS NOT NULL AND scan_id IS NOT NULL"
    )
    op.drop_constraint(op.f("ck_files_release"), "files", type_="check")
    op.drop_constraint(op.f("fk_files_released_by_users"), "files", type_="foreignkey")
    for column in ("release_reason", "released_by", "released_at"):
        op.drop_column("files", column)

    op.create_table(
        "shares",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("recipient_email", sa.String(length=320), nullable=False),
        sa.Column("recipient_kind", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_downloads", sa.SmallInteger(), nullable=False),
        sa.Column("downloads", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "recipient_kind IN ('external', 'internal')", name=op.f("ck_shares_recipient_kind")
        ),
        sa.CheckConstraint("max_downloads > 0", name=op.f("ck_shares_max_downloads")),
        sa.CheckConstraint(
            "downloads >= 0 AND downloads <= max_downloads", name=op.f("ck_shares_downloads")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_shares_created_by_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["file_id"], ["files.id"], name=op.f("fk_shares_file_id_files"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_shares")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_shares_token_hash")),
    )
    op.create_index(op.f("ix_shares_file_id"), "shares", ["file_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_shares_file_id"), table_name="shares")
    op.drop_table("shares")
    op.add_column("files", sa.Column("released_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("files", sa.Column("released_by", sa.Uuid(), nullable=True))
    op.add_column("files", sa.Column("release_reason", sa.String(length=500), nullable=True))
    op.execute(
        "UPDATE files SET released_at = r.released_at, released_by = r.released_by, "
        "release_reason = r.reason FROM scan_releases r "
        "WHERE r.file_id = files.id AND r.purpose = 'download' AND r.scan_id = files.scan_id"
    )
    op.create_foreign_key(
        op.f("fk_files_released_by_users"),
        "files",
        "users",
        ["released_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        op.f("ck_files_release"), "files", "(released_at IS NULL) = (release_reason IS NULL)"
    )
    op.drop_table("scan_releases")
    # Policies only about sharing go; the others lose the share action.
    op.execute("DELETE FROM policies WHERE actions <@ ARRAY['share']::varchar[]")
    op.execute("UPDATE policies SET actions = array_remove(actions, 'share')")
    op.drop_constraint(op.f("ck_policies_known_actions"), "policies", type_="check")
    op.create_check_constraint(
        op.f("ck_policies_known_actions"), "policies", f"actions <@ {ACTIONS_BEFORE}"
    )

"""Sharing a folder (M12.6, ADR 0020): a share names a file or a folder.

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("shares", sa.Column("folder_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_shares_folder_id_folders"),
        "shares",
        "folders",
        ["folder_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(op.f("ix_shares_folder_id"), "shares", ["folder_id"])
    op.alter_column("shares", "file_id", existing_type=sa.Uuid(), nullable=True)
    op.create_check_constraint(
        op.f("ck_shares_target"), "shares", "(file_id IS NULL) <> (folder_id IS NULL)"
    )


def downgrade() -> None:
    # Folder shares can't be kept without a file: they go.
    op.execute("DELETE FROM shares WHERE folder_id IS NOT NULL")
    op.drop_constraint(op.f("ck_shares_target"), "shares", type_="check")
    op.alter_column("shares", "file_id", existing_type=sa.Uuid(), nullable=False)
    op.drop_index(op.f("ix_shares_folder_id"), table_name="shares")
    op.drop_constraint(op.f("fk_shares_folder_id_folders"), "shares", type_="foreignkey")
    op.drop_column("shares", "folder_id")

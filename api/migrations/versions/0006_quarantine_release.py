"""Admin release of quarantined files.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("files", sa.Column("released_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("files", sa.Column("released_by", sa.Uuid(), nullable=True))
    op.add_column("files", sa.Column("release_reason", sa.String(length=500), nullable=True))
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


def downgrade() -> None:
    op.drop_constraint(op.f("ck_files_release"), "files", type_="check")
    op.drop_constraint(op.f("fk_files_released_by_users"), "files", type_="foreignkey")
    for column in ("release_reason", "released_by", "released_at"):
        op.drop_column("files", column)

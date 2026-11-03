"""Scan state of files and scan findings.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("files", sa.Column("scan_status", sa.String(length=16), nullable=True))
    op.add_column("files", sa.Column("scan_id", sa.Uuid(), nullable=True))
    op.add_column(
        "files", sa.Column("scan_requested_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "files",
        sa.Column("scan_attempts", sa.SmallInteger(), server_default="0", nullable=False),
    )
    op.add_column("files", sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("files", sa.Column("scan_reason", sa.String(length=500), nullable=True))
    op.create_unique_constraint(op.f("uq_files_scan_id"), "files", ["scan_id"])
    # Files uploaded before scanning existed wait for a scan like new ones; with no
    # attempts yet, the resender sends them on its first round.
    op.execute(
        "UPDATE files SET scan_status = 'pending', scan_id = gen_random_uuid(), "
        "scan_requested_at = now() WHERE status = 'uploaded'"
    )
    op.create_check_constraint(
        op.f("ck_files_scan_status"),
        "files",
        "scan_status IN ('pending', 'scanned', 'unscannable')",
    )
    op.create_check_constraint(
        op.f("ck_files_scan_id"), "files", "(scan_status IS NULL) = (scan_id IS NULL)"
    )
    op.create_table(
        "scan_findings",
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("count", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("count > 0", name=op.f("ck_scan_findings_count")),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["files.id"],
            name=op.f("fk_scan_findings_file_id_files"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("file_id", "kind", name=op.f("pk_scan_findings")),
    )


def downgrade() -> None:
    op.drop_table("scan_findings")
    op.drop_constraint(op.f("ck_files_scan_id"), "files", type_="check")
    op.drop_constraint(op.f("ck_files_scan_status"), "files", type_="check")
    op.drop_constraint(op.f("uq_files_scan_id"), "files", type_="unique")
    for column in (
        "scan_reason",
        "scanned_at",
        "scan_attempts",
        "scan_requested_at",
        "scan_id",
        "scan_status",
    ):
        op.drop_column("files", column)

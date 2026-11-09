"""Node enrollment by an admin's enrollment token (M11, ADR 0014).

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "node_enrollment_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=63), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enrollment_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_node_enrollment_tokens_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["enrollment_id"],
            ["node_enrollments.id"],
            name=op.f("fk_node_enrollment_tokens_enrollment_id_node_enrollments"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_node_enrollment_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_node_enrollment_tokens_token_hash")),
    )
    op.create_index(op.f("ix_node_enrollment_tokens_name"), "node_enrollment_tokens", ["name"])
    op.drop_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", type_="check")
    op.create_check_constraint(
        op.f("ck_node_enrollments_method"),
        "node_enrollments",
        "method IN ('admin_approval', 'keycloak_client', 'enrollment_token')",
    )


def downgrade() -> None:
    op.drop_table("node_enrollment_tokens")
    op.execute("DELETE FROM node_enrollments WHERE method = 'enrollment_token'")
    op.drop_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", type_="check")
    op.create_check_constraint(
        op.f("ck_node_enrollments_method"),
        "node_enrollments",
        "method IN ('admin_approval', 'keycloak_client')",
    )

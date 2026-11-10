"""Node enrollment by TPM attestation (M11, ADR 0014): admins' TPM registrations, and the
method.

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BEFORE = "method IN ('admin_approval', 'keycloak_client', 'enrollment_token', 'cloud_identity')"
AFTER = (
    "method IN ('admin_approval', 'keycloak_client', 'enrollment_token', 'cloud_identity', 'tpm')"
)


def upgrade() -> None:
    op.create_table(
        "node_tpms",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=63), nullable=False),
        sa.Column("ek_fingerprint", sa.String(length=64), nullable=False),
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
            name=op.f("fk_node_tpms_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["enrollment_id"],
            ["node_enrollments.id"],
            name=op.f("fk_node_tpms_enrollment_id_node_enrollments"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_node_tpms")),
    )
    op.create_index(op.f("ix_node_tpms_name"), "node_tpms", ["name"])
    op.create_index(op.f("ix_node_tpms_ek_fingerprint"), "node_tpms", ["ek_fingerprint"])
    # One open registration per TPM, whatever runs at once.
    op.create_index(
        "uq_node_tpms_open_ek",
        "node_tpms",
        ["ek_fingerprint"],
        unique=True,
        postgresql_where=sa.text("used_at IS NULL AND revoked_at IS NULL"),
    )
    op.drop_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", type_="check")
    op.create_check_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", AFTER)


def downgrade() -> None:
    op.drop_table("node_tpms")
    op.execute("DELETE FROM node_enrollments WHERE method = 'tpm'")
    op.drop_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", type_="check")
    op.create_check_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", BEFORE)

"""Node enrollment by a Keycloak client (M11, ADR 0014): the method, and the client that
enrolled, once.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("node_enrollments", sa.Column("client_id", sa.String(length=255), nullable=True))
    op.add_column(
        "node_enrollments", sa.Column("client_subject", sa.String(length=255), nullable=True)
    )
    # A client's service account enrolls one node, ever.
    op.create_index(
        "uq_node_enrollments_client_subject", "node_enrollments", ["client_subject"],
        unique=True, postgresql_where=sa.text("client_subject IS NOT NULL"),
    )  # fmt: skip
    op.drop_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", type_="check")
    op.create_check_constraint(
        op.f("ck_node_enrollments_method"),
        "node_enrollments",
        "method IN ('admin_approval', 'keycloak_client')",
    )


def downgrade() -> None:
    op.execute("DELETE FROM node_enrollments WHERE method = 'keycloak_client'")
    op.drop_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", type_="check")
    op.create_check_constraint(
        op.f("ck_node_enrollments_method"), "node_enrollments", "method IN ('admin_approval')"
    )
    op.drop_index("uq_node_enrollments_client_subject", table_name="node_enrollments")
    op.drop_column("node_enrollments", "client_subject")
    op.drop_column("node_enrollments", "client_id")

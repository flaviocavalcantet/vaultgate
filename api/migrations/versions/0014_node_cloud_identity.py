"""Node enrollment by cloud instance identity (M11, ADR 0014): the method. The instance
is recorded as the client (client_id: the provider; client_subject:
provider:account:instance), under the same single-use index.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-09
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BEFORE = "method IN ('admin_approval', 'keycloak_client', 'enrollment_token')"
AFTER = "method IN ('admin_approval', 'keycloak_client', 'enrollment_token', 'cloud_identity')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", type_="check")
    op.create_check_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", AFTER)


def downgrade() -> None:
    op.execute("DELETE FROM node_enrollments WHERE method = 'cloud_identity'")
    op.drop_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", type_="check")
    op.create_check_constraint(op.f("ck_node_enrollments_method"), "node_enrollments", BEFORE)

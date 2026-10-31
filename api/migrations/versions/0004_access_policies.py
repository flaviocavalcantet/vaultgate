"""Access policies.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # No policies are created: with none, everything except /admin is denied (ADR 0004).
    op.create_table(
        "policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("effect", sa.String(length=8), nullable=False),
        sa.Column("actions", postgresql.ARRAY(sa.String(length=16)), nullable=False),
        sa.Column(
            "groups", postgresql.ARRAY(sa.String(length=255)), server_default="{}", nullable=False
        ),
        sa.Column(
            "networks", postgresql.ARRAY(postgresql.CIDR()), server_default="{}", nullable=False
        ),
        sa.Column(
            "excluded_networks",
            postgresql.ARRAY(postgresql.CIDR()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("days", postgresql.ARRAY(sa.SmallInteger()), server_default="{}", nullable=False),
        sa.Column("start_time", sa.Time(), nullable=True),
        sa.Column("end_time", sa.Time(), nullable=True),
        sa.Column("timezone", sa.String(length=64), server_default="UTC", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("effect IN ('allow', 'deny')", name=op.f("ck_policies_effect")),
        sa.CheckConstraint("cardinality(actions) > 0", name=op.f("ck_policies_actions")),
        sa.CheckConstraint(
            "actions <@ ARRAY['read', 'upload', 'download']::varchar[]",
            name=op.f("ck_policies_known_actions"),
        ),
        sa.CheckConstraint(
            "days <@ ARRAY[1, 2, 3, 4, 5, 6, 7]::smallint[]", name=op.f("ck_policies_days")
        ),
        sa.CheckConstraint(
            "(start_time IS NULL) = (end_time IS NULL)", name=op.f("ck_policies_time_window")
        ),
        sa.CheckConstraint("start_time <> end_time", name=op.f("ck_policies_time_window_length")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policies")),
        sa.UniqueConstraint("name", name=op.f("uq_policies_name")),
    )


def downgrade() -> None:
    op.drop_table("policies")

"""Nodes and their enrollments (M11, ADR 0014); the enroll action; nodes as audit actors.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIONS_BEFORE = "ARRAY['read', 'upload', 'download', 'share']::varchar[]"
ACTIONS_AFTER = "ARRAY['read', 'upload', 'download', 'share', 'enroll']::varchar[]"
ACTORS_BEFORE = "('user', 'recipient', 'gateway', 'scanner', 'system')"
ACTORS_AFTER = "('user', 'recipient', 'gateway', 'scanner', 'system', 'node')"


def upgrade() -> None:
    # Existing policies keep their actions: enrolling nodes is denied until an admin
    # allows it.
    op.drop_constraint(op.f("ck_policies_known_actions"), "policies", type_="check")
    op.create_check_constraint(
        op.f("ck_policies_known_actions"), "policies", f"actions <@ {ACTIONS_AFTER}"
    )
    # A constraint change, not a row change: the audit log's append-only trigger fires
    # on rows only.
    op.drop_constraint(op.f("ck_audit_events_actor_kind"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_actor_kind"), "audit_events", f"actor_kind IN {ACTORS_AFTER}"
    )

    op.create_table(
        "nodes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=63), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("key_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("cert_serial", sa.String(length=64), nullable=False),
        sa.Column("cert_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "enrolled_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("enrolled_by", sa.Uuid(), nullable=True),
        sa.Column("renewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.CheckConstraint("status IN ('active', 'revoked')", name=op.f("ck_nodes_status")),
        sa.ForeignKeyConstraint(
            ["enrolled_by"],
            ["users.id"],
            name=op.f("fk_nodes_enrolled_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by"],
            ["users.id"],
            name=op.f("fk_nodes_revoked_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_nodes")),
        sa.UniqueConstraint("cert_serial", name=op.f("uq_nodes_cert_serial")),
    )
    op.create_index(op.f("ix_nodes_name"), "nodes", ["name"])
    # One active node per name; revoked ones stay, for the record.
    op.create_index(
        "uq_nodes_active_name", "nodes", ["name"], unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )  # fmt: skip

    op.create_table(
        "node_enrollments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=63), nullable=False),
        sa.Column("method", sa.String(length=32), nullable=False),
        sa.Column("csr", sa.Text(), nullable=False),
        sa.Column("key_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("client_ip", postgresql.INET(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("code_hash", sa.String(length=64), nullable=True),
        sa.Column("code_salt", sa.String(length=32), nullable=True),
        sa.Column("code_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("code_attempts", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("node_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'completed', 'rejected')",
            name=op.f("ck_node_enrollments_status"),
        ),
        sa.CheckConstraint("method IN ('admin_approval')", name=op.f("ck_node_enrollments_method")),
        sa.ForeignKeyConstraint(
            ["decided_by"],
            ["users.id"],
            name=op.f("fk_node_enrollments_decided_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_node_enrollments_node_id_nodes"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_node_enrollments")),
    )
    op.create_index(op.f("ix_node_enrollments_name"), "node_enrollments", ["name"])
    op.create_index(op.f("ix_node_enrollments_status"), "node_enrollments", ["status"])


def downgrade() -> None:
    op.drop_table("node_enrollments")
    op.drop_index("uq_nodes_active_name", table_name="nodes")
    op.drop_table("nodes")
    # NOT VALID: events by nodes stay (the log is append-only); new ones can't be added.
    op.drop_constraint(op.f("ck_audit_events_actor_kind"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_actor_kind"), "audit_events", f"actor_kind IN {ACTORS_BEFORE}",
        postgresql_not_valid=True,
    )  # fmt: skip
    op.execute("DELETE FROM policies WHERE actions = ARRAY['enroll']::varchar[]")
    op.execute("UPDATE policies SET actions = array_remove(actions, 'enroll')")
    op.drop_constraint(op.f("ck_policies_known_actions"), "policies", type_="check")
    op.create_check_constraint(
        op.f("ck_policies_known_actions"), "policies", f"actions <@ {ACTIONS_BEFORE}"
    )

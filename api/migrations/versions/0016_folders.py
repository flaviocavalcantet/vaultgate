"""Folders (M12.6, ADR 0020): folders, files in them, and names unique in a folder.

Files that already share a name (case-insensitively, failed uploads aside) are renamed
before the unique index is made: the oldest keeps its name, the others become
"name (2).ext", "name (3).ext"... Each rename is recorded in the audit log, chained like
any other event, so the change to a user's file names is accounted for.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-13
"""

import hashlib
import ipaddress
import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The audit chain's lock and hash form (vaultgate_api.audit), copied so this migration
# keeps working whatever later code does with them.
CHAIN_LOCK = 0x5641554C54
GENESIS = "0" * 64
MAX_NAME = 255


def _canonical_ip(value):
    if value is None:
        return None
    address = ipaddress.ip_interface(str(value)).ip
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _event_hash(fields: dict) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _numbered(name: str, n: int) -> str:
    """ "report.pdf" -> "report (2).pdf"; a name without an extension gets the number at
    its end. Shortened to fit, extension kept."""
    dot = name.rfind(".")
    stem, ext = (name[:dot], name[dot:]) if dot > 0 else (name, "")
    suffix = f" ({n})"
    room = MAX_NAME - len(suffix) - len(ext)
    return stem[: max(room, 1)] + suffix + ext


def _rename_duplicates(bind) -> None:
    rows = bind.execute(
        sa.text(
            "SELECT id, owner_id, name FROM files WHERE status <> 'failed' "
            "ORDER BY owner_id, lower(name), created_at, id"
        )
    ).all()
    taken: dict[uuid.UUID, set[str]] = {}
    for row in rows:
        taken.setdefault(row.owner_id, set()).add(row.name.lower())
    seen: set[tuple[uuid.UUID, str]] = set()
    renames = []
    for row in rows:
        key = (row.owner_id, row.name.lower())
        if key not in seen:
            seen.add(key)
            continue
        n = 2
        while _numbered(row.name, n).lower() in taken[row.owner_id]:
            n += 1
        new = _numbered(row.name, n)
        taken[row.owner_id].add(new.lower())
        renames.append((row.id, row.owner_id, row.name, new))
    if not renames:
        return
    bind.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": CHAIN_LOCK})
    prev = bind.scalar(sa.text("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1"))
    for file_id, owner_id, old, new in renames:
        bind.execute(
            sa.text("UPDATE files SET name = :name WHERE id = :id"), {"name": new, "id": file_id}
        )
        event = {
            "occurred_at": datetime.now(UTC).isoformat(),
            "actor_kind": "system",
            "actor_id": None,
            "action": "file.renamed",
            "outcome": "ok",
            "target_kind": "file",
            "target_id": str(file_id),
            "client_ip": _canonical_ip(None),
            "request_id": None,
            "details": {
                "from": old,
                "to": new,
                "owner_id": str(owner_id),
                "reason": "names are unique in a folder (migration 0016)",
            },
            "prev_hash": prev or GENESIS,
        }
        digest = _event_hash(event)
        bind.execute(
            sa.text(
                "INSERT INTO audit_events (occurred_at, actor_kind, actor_id, action, outcome, "
                "target_kind, target_id, client_ip, request_id, details, prev_hash, hash) "
                "VALUES (:occurred_at, :actor_kind, NULL, :action, :outcome, :target_kind, "
                ":target_id, NULL, NULL, CAST(:details AS jsonb), :prev_hash, :hash)"
            ),
            {
                **{k: event[k] for k in ("actor_kind", "action", "outcome", "target_kind")},
                "occurred_at": datetime.fromisoformat(event["occurred_at"]),
                "target_id": file_id,
                "details": json.dumps(event["details"]),
                "prev_hash": event["prev_hash"],
                "hash": digest,
            },
        )
        prev = digest


def upgrade() -> None:
    op.create_table(
        "folders",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("parent_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name=op.f("fk_folders_owner_id_users"), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["folders.id"],
            name=op.f("fk_folders_parent_id_folders"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_folders")),
    )
    op.create_index(op.f("ix_folders_owner_id"), "folders", ["owner_id"])
    op.create_index(op.f("ix_folders_parent_id"), "folders", ["parent_id"])
    op.create_index(
        "uq_folders_owner_parent_name",
        "folders",
        ["owner_id", "parent_id", sa.text("lower(name)")],
        unique=True,
        postgresql_nulls_not_distinct=True,
    )

    op.add_column("files", sa.Column("folder_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_files_folder_id_folders"),
        "files",
        "folders",
        ["folder_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(op.f("ix_files_folder_id"), "files", ["folder_id"])

    _rename_duplicates(op.get_bind())
    op.create_index(
        "uq_files_owner_folder_name",
        "files",
        ["owner_id", "folder_id", sa.text("lower(name)")],
        unique=True,
        postgresql_nulls_not_distinct=True,
        postgresql_where=sa.text("status <> 'failed'"),
    )


def downgrade() -> None:
    # Renamed files keep their new names: the audit log records the old ones.
    op.drop_index("uq_files_owner_folder_name", table_name="files")
    op.drop_index(op.f("ix_files_folder_id"), table_name="files")
    op.drop_constraint(op.f("fk_files_folder_id_folders"), "files", type_="foreignkey")
    op.drop_column("files", "folder_id")
    op.drop_table("folders")

# ADR 0020: Folders

**Status:** Accepted (folders, names, moves and renames); deletion and folder sharing
follow in the same milestone (M12.6)

## Context

Every file a user uploaded sat in one flat list, newest first. That is enough for a
handful of files and no more: people file by project, client or month, and a web
frontend needs a structure to show. Users also have no way to remove a file, and can
only share files one at a time.

Three things have to hold whatever the structure:

- A file's stored object, its key and its scan are what the security model rests on
  (ADR 0003, ADR 0005). Organising files must never touch them.
- Another user's file or folder is reported as not found, so IDs can't be probed.
- Least privilege (each service's IAM policy, ADR 0012): the API can't read or delete objects; only the gateway
  writes and deletes them.

## Decision

**Folders are metadata only: a `folders` table (owner, parent, name) and a `folder_id`
on each file.** Moving or renaming a file or folder changes rows, never an object key
(`files/<id>` stays) or a scan.

- **One owner per folder.** A folder sits in another folder of the same user's, or at
  the top level (`parent_id` NULL). Files sit in a folder or at the top level. A
  folder of another user's is a `404` wherever it is named: listing it, creating or
  moving into it.
- **Names unique in a folder, case-insensitively, across files and folders.**
  "Report.pdf" can't sit beside "report.pdf", nor a folder beside a file of the same
  name: two items a person can't tell apart in a listing, or in a download that keeps
  the name, are a mistake waiting to happen. Each table has a unique index on
  `(owner, parent, lower(name))` with `NULLS NOT DISTINCT`, so the top level counts as
  one folder; the check across the two tables runs under a transaction-scoped advisory
  lock on the folder, so two requests can't both take a name. A clash is a `409` that
  names it. A failed upload holds no name (the files index is partial), so a retry
  can use it again.
- **Existing duplicates are renamed by the migration.** Before the index, files with
  the same name (case-insensitively, failed ones aside) were allowed; the oldest
  keeps its name and the others become "name (2).ext", "name (3).ext"... skipping
  numbers already in use. Each rename is a `file.renamed` audit event by `system`,
  chained like any other, with the owner and the reason, so the change to a user's
  names is accounted for. The downgrade keeps the new names: the audit log has the
  old ones.
- **Names stay plain:** no path separators, no control characters, no leading or
  trailing spaces, not `.` or `..`. They are display names; nothing is built from them.
- **At most 16 levels.** Deep enough for any filing scheme, and it bounds every walk up
  or down a tree. A move is refused if the folder would land inside itself or one of
  its own subfolders, or if the deepest folder it holds would end up deeper than 16.
  Placing a folder (creating it in another, or moving it) takes a lock on the owner's
  whole tree first, so two moves that each pass alone (A into B, B into A) can't
  together make a cycle or a tree too deep.
- **Listings by folder.** `GET /files` lists the top level, `?folder_id=` a folder;
  `GET /folders` likewise with `parent_id`, by name. `GET /folders/{id}` returns the
  path from the top level for breadcrumbs.
- **The same access actions.** Looking needs `read`; creating, renaming and moving need
  `upload`, the action that already lets a user add to their files. No new action:
  organising one's own files grants nothing new.
- **Audited:** `folder.created`, `folder.moved`, `folder.renamed`, `file.moved` and
  `file.renamed`, with the before and after.

### Deletion (next step)

Deleting a file or a folder (with everything in it) removes the rows at once, wrapped
data keys included: without its key the object can't be decrypted, whatever copies of
it remain (crypto-shredding). The objects themselves go too, without giving the API
delete rights: the API adds their keys to a deletion queue table in the same
transaction, and the gateway, which already holds `DeleteObject`, drains it through its
internal mTLS endpoint. The bucket is versioned, so a lifecycle rule expires noncurrent
versions and removes the delete markers left behind. Shares of deleted files end at
once. An upload still streaming when its file is deleted is refused when it completes,
and the gateway deletes an object the API refuses to record, as it does today.

### Folder sharing (after deletion)

A share can be of a folder: the recipient sees its live contents, subfolders included,
and only the files they can download now (clean, or released for sharing); files being
scanned or held are hidden from them, and shown to the owner as they are. One download
limit covers the whole share. The gateway's consume checks that the file asked for is
inside the shared folder, along with the scan and the count it checks today.

## Consequences

- The API's files listing changes meaning: it lists the top level, not every file.
  Existing files all sit at the top level after the migration, so nothing moves.
- Creating a file now takes a short lock on its folder and two lookups; uploads into
  different folders don't wait on each other.
- Users whose names clashed see some renamed, with the reason in the audit log.
- A folder tree is walked by recursive queries bounded by the depth limit.

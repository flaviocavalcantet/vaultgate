# ADR 0020: Folders

**Status:** Accepted (folders, names, moves, renames and deletion); folder sharing
follows in the same milestone (M12.6)

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

### Deletion

**A deleted file is unreadable from the moment its deletion commits; its object goes
soon after, deleted by the gateway.**

- **Rows and keys at once.** Deleting a file removes its row in one transaction, and
  with it (by cascade) its scan findings, releases, shares, share verifications and
  intents. The wrapped data key was in the row: without it the object can't be
  decrypted, whatever copies of it remain (crypto-shredding). Shares end at once, and
  an intent issued before can't be consumed.
- **Objects by the gateway, from a queue.** The API has no S3 rights (least privilege)
  and keeps none for this: the same transaction adds the object's key to
  `object_deletions`. Each gateway, which already holds `DeleteObject`, claims a batch
  through its internal mTLS endpoint (`FOR UPDATE SKIP LOCKED`, so replicas never take
  the same rows), deletes the objects and confirms them; the confirmation is audited
  (`file.object_deleted`, by the gateway). A claim lasts 5 minutes: one not confirmed
  by then (the gateway died, S3 refused) is claimed again.
- **Only files' keys.** The gateway deletes only `files/<uuid>` keys and refuses, counts
  and logs anything else: a compromised API could otherwise use the queue to have the
  gateway delete objects it has no business with.
- **Old versions by a lifecycle rule.** The bucket is versioned, so a delete leaves a
  delete marker over the object's version. A rule on `files/` expires noncurrent
  versions after a day (`deleted_object_days`) and then removes the expired delete
  marker. File keys are never written twice, so only deleted files have noncurrent
  versions. Deleting versions directly would need `ListBucketVersions` too, for no gain:
  the content is already unreadable.
- **A folder with everything in it.** `DELETE /folders/{id}` deletes every file in it
  at every level, as above, then its folders, deepest first. It takes the owner's tree
  lock (no folder can be created in it or moved into it meanwhile) and locks the
  folders' rows, which adding or moving a file into one of them waits on; such a
  request then finds the folder gone (`404`). `GET /folders/{id}/totals` counts what
  would go, for a client to show before asking.
- **The same action.** Deleting needs `upload`, like every change to one's own files.
- **Uploads in flight.** An upload still streaming when its file is deleted is refused
  when it completes (the row is gone), and the gateway deletes the object it wrote, as
  it does for any upload the API refuses.
- **Audited:** `file.deleted` (with the name, folder, state and size, and the folder's
  deletion as the reason when it was one) and `folder.deleted` (with what it held).

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
- Deletion can't be undone: there is no bin. The key is gone at once, so even a restore
  of the bucket's versions brings back nothing readable; a database backup taken before
  the deletion still holds the key, for as long as backups are kept.
- A backlog of objects waiting for the gateway shows in
  `vaultgate_gateway_object_deletions_pending`, and refused keys in
  `vaultgate_gateway_object_deletions_total{outcome="refused"}`.

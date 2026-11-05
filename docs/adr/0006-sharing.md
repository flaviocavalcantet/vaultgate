# ADR 0006: Sharing (links for one recipient, proven by email or by sign-in)

**Status:** Accepted

## Context

Owners need to hand a file to someone else: a colleague with a VaultGate account, or a
person outside the organization who has none. A share must not become a way around
the controls on the vault: access policies (ADR 0004), quarantine (ADR 0005) and the
gateway's encryption (ADR 0003). It has to be limited in time and in downloads, and
its owner must be able to end it at once.

## Decision

**A share is a link to one file for one recipient, named by email address.**

- Only the owner of an uploaded file shares it. That needs the `share` policy action,
  which existing policies do not have until an admin adds it, and a file the scan
  allows to be shared. Sharing always needs a clean verdict or an admin's release for
  sharing, whatever `VAULTGATE_QUARANTINE_BLOCKS` says about the owner's own downloads.
- The link carries a random token, shown to the owner once; only its SHA-256 is
  stored, as for transfer intents. Links expire (7 days by default, 30 at most) and
  allow a number of downloads (5 by default, 100 at most). The owner lists and
  revokes them; revoking needs only ownership, so someone who may no longer share can
  still take a link back.

**The recipient proves the address, in one of two ways:**

- **External** (no account): a 6-digit code is emailed to the address. It lasts 10
  minutes and allows 5 tries; a share sends at most 5 codes an hour, an owner 50
  across their shares. A right code gives a grant, valid 30 minutes, to ask for
  download intents with. Codes and grants are stored as hashes. The email is fixed
  text with only the code: nothing a user typed goes into a message VaultGate sends
  to an address they chose. The owner's own access policies do not govern the
  recipient; the owner decided when sharing.
- **Internal** (a VaultGate user): they sign in, and a share is theirs when its
  address is the verified email in their token. They stay under their own access
  policies (`read` to list, `download` to download), at the API and at the gateway.

The token alone never grants a download: it names the share, and the proof of the
address does the rest.

**The gateway decides last.** A recipient's download is an ordinary download intent
that names its share. When the gateway consumes it, the API checks again that the
share is active, the owner active, the scan allows sharing (and, for an internal
recipient, their policies and verified address), then counts the download with an
atomic `UPDATE ... WHERE downloads < max_downloads`. A revoke, an expiry, the last
download, a rescan into quarantine or a deactivated owner therefore applies at once,
also to grants and intents already handed out.

## Consequences

- Sharing is opt-in per organization (the `share` action) and never reaches flagged
  files. Agents (M14) will count as sharing too.
- External sharing depends on email delivery. Without an SMTP server codes cannot be
  sent and external recipients cannot download; locally Mailpit catches every message.
- An internal share depends on the identity provider vouching for email addresses. An
  address that is not verified matches nothing.
- A leaked link is not enough on its own: the address still has to be proven. A
  compromised mailbox is: shares are as safe as the recipient's email, which is why
  they expire, count downloads and can be revoked at once.
- The download count is exact even with several intents issued at once; an intent
  issued but never used costs nothing.
- Logs and metrics name shares, never recipients' addresses. The append-only audit
  log (M6) will record shares, codes and downloads.

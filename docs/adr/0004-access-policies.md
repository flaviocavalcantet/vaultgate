# ADR 0004: Access policies (deny by default, deny wins)

**Status:** Accepted

## Context

Signing in proves who a user is (ADR 0002). Organizations also need to limit what a
signed-in user may do, depending on:

- **who:** group membership from the identity provider;
- **where from:** the client's IP address (office network, VPN, blocked ranges);
- **when:** days of the week and hours, in the organization's local time.

The rules must be easy to reason about, safe when nobody has configured anything yet,
and take effect at once when changed: a user who leaves the office network or whose
group is removed loses access on their next request, not when a session expires.

## Decision

**Policies** are rows in PostgreSQL, managed by admins through the API:

| Field | Meaning |
|---|---|
| `effect` | `allow` or `deny` |
| `actions` | any of `read` (list and view own files), `upload`, `download`; `share` joins in M5 |
| `groups` | the user is in one of them, or a subgroup (`/finance` covers `/finance/payroll`) |
| `networks` / `excluded_networks` | the client address is in one of `networks` and in none of `excluded_networks` |
| `days`, `start_time`, `end_time`, `timezone` | ISO weekdays and a local time window, `[start, end)` |
| `enabled` | disabled policies are ignored |

A policy matches when the action is one of its actions and every condition it sets
holds. An unset condition (empty list, no window) matches anything.

**Evaluation:** a request is allowed only if **at least one allow policy matches and
no deny policy matches**. Deny always wins, so restrictions can be added without
editing every allow rule. For example, "deny everything from outside 10.0.0.0/8" is one
deny policy with `excluded_networks: ["10.0.0.0/8"]`.

- **Deny by default.** With no matching allow policy, the answer is no. A new
  installation has no policies, so it allows nothing until an admin creates one. Local
  development and CI seed a permissive policy.
- **Admins are exempt.** The `/admin` endpoints are never subject to policies; access
  to them comes from the identity provider's admin group alone. Admins therefore can't
  lock themselves out by writing a bad policy. `/me` is also exempt, so users can
  always see who they are and which groups they are in.
- **Evaluated on every request, never cached.** Policies are read fresh for each
  decision, by action. The table holds tens of rows, not thousands, so this is one
  cheap query; caching would delay revocations.
- **Checked at both ends of a transfer.** The API evaluates `upload` or `download`
  when it issues an intent, and again when the gateway consumes the intent, with the
  client address the gateway sees. A token obtained from an allowed network is
  therefore useless from elsewhere, and a window that closes in between stops it. A
  transfer already in progress is not cut off.
- **Time windows** are local wall-clock times in an IANA timezone, so they follow
  daylight saving time. A window that ends before it starts (`22:00`-`06:00`) runs
  overnight and belongs to the day it starts: Friday's night shift covers Saturday
  03:00, and Sunday's does not cover Monday 03:00 unless Sunday is selected.
- **Failing closed.** A policy that cannot be evaluated (a timezone missing from the
  system's database, say) counts as matching if it denies and as not matching if it
  allows.
- **Refusals don't explain themselves to the caller.** The API answers `403` with a
  generic message and logs the matching policy names; the admin dry-run shows the full
  decision.

## Client addresses

IP conditions are only as good as the address they check. Behind a reverse proxy or
ingress, the TCP peer is the proxy, and `X-Forwarded-For` is whatever the client
claims. Both services therefore take the client address from `X-Forwarded-For` only
when the peer is a configured trusted proxy, reading the header from the right and
skipping trusted hops. Otherwise they use the peer address. IPv4-mapped IPv6 addresses
are treated as IPv4.

## Consequences

- Upgrading an installation without policies stops all transfers and file listing
  until an admin adds an allow policy. The release notes and the README say so.
- Every protected file request costs one extra query.
- Rules are flat, with no priorities or ordering to get wrong. The price is that some
  intents need two policies, for example "outside office hours" as a deny for the
  evenings plus one for the weekend.
- Device posture (managed laptop, disk encryption) is out of scope. It would need a
  signal the identity provider does not give us today.

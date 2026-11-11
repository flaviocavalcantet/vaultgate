# ADR 0017: Cross-origin requests for the web frontend

**Status:** Accepted

## Context

VaultGate gets a web frontend, in its own repository and served from its own origin.
A browser lets a page call another origin only when that origin allows it (CORS).
Until now neither the API nor the gateway answered any cross-origin page, which was
right while their only clients were scripts and services. The frontend needs the
API (JSON, with the user's bearer token) and the gateway (uploads and downloads, with
an intent token).

Two ways to let it in:

- **Same origin:** serve the frontend, the API and the gateway behind one host, by
  path. No CORS at all, but it ties the three to one ingress and one hostname, and the
  chart publishes the API and the gateway on their own hosts.
- **An allow-list of origins:** the API and the gateway name the frontend's origin.

## Decision

**An exact allow-list of web origins, on the API and the gateway, empty by default.**

- **One setting for both:** `VAULTGATE_CORS_ORIGINS` (the chart's `corsOrigins`), a
  list of `scheme://host[:port]`. No wildcard, pattern, path or `null`: anything else
  stops the service at start, so a typo isn't a silent hole.
- **Empty means off.** No origin is named in any answer and a preflight is refused, as
  before this ADR. Compose and the local cluster list `http://localhost:5173`, the
  frontend's development server.
- **No credentials.** `Access-Control-Allow-Credentials` is never sent. Neither service
  has cookies: a request carries a bearer token the page itself holds, or it carries
  nothing. So a page of another origin has nothing of the user's to ride on, whatever
  the list says.
- **What a listed origin gets** is the right for its JavaScript to read answers,
  errors included (the frontend must tell a 401 from a 429). Every route still checks
  its token and the access policies exactly as before.
- **Preflights cost nothing.** They carry no token. The API answers them before any
  route runs, so they don't count against a user's rate limit; on the gateway they
  spend no intent and hold no transfer slot. They are logged, counted and traced like
  any request.
- **Methods and headers** are the ones the frontend uses: `GET`, `POST`, `PUT` and
  `DELETE` on the API, `PUT` on uploads and `GET` on downloads; `Authorization` and
  `Content-Type`. A page may read `Retry-After` and `X-Request-ID`, and on a download
  its name, length and digest.
- **Only the public ports.** The API's internal port and the nodes' port are for
  services and nodes, not browsers, and get no CORS.

`Cross-Origin-Resource-Policy: same-origin` (M10) stays on every answer: it stops other
sites embedding one (`<img>`, `<script>`), and doesn't affect a CORS request.

## Consequences

- A deployment lists its frontend's origin once, for both services.
- A wrong origin on the list lets that site's JavaScript read answers for a user whose
  token it already holds. It still can't get a token: sign-in redirects only to the
  addresses the identity provider's client allows.
- The cluster's negative checks cover it: the listed origin passes a preflight on both
  services, other origins (and one that only starts like it) are refused and never
  named, and the listed origin still gets a 401 without a token.
- An unhandled error's 500 carries no CORS header (it is written outside the CORS
  layer), so the frontend sees it as a network error. The request ID is in the logs.
- Large downloads still can't be handed to the browser as a plain link, since the
  gateway wants its token in a header: the next M12.5 step.

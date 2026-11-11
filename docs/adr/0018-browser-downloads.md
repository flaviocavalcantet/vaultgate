# ADR 0018: Downloads a browser can follow

**Status:** Accepted

## Context

A download goes in two steps: the API issues a single-use intent (a token and the
gateway's address, valid five minutes), and the gateway streams the decrypted file to
whoever presents the token. Until now the token went in an `Authorization` header.

A web page can't hand that to the browser. A link or a navigation carries no header,
and a `fetch` with the header gets the whole file into the page's memory before it
can be saved: fine for a small file, not for the gateway's 5 GiB. The browser's own
downloader, which streams to disk and shows its progress, only follows navigations.

Two ways to make a navigation carry the token:

- **In the address** (`/downloads/{id}?token=...`): the simplest, but the address is
  kept in the browser's history, written by proxies and load balancers to their logs,
  and can leave in a `Referer`. The token is single use and short-lived, but it is
  still the credential to one file.
- **In a submitted form:** the page builds a form with the token as a field and submits
  it to the gateway. The browser sends it as the body of a POST, a navigation, and its
  downloader takes the response (always an attachment).

## Decision

**`POST /downloads/{file_id}` takes the token as the only field of an HTML form
(`application/x-www-form-urlencoded`). The header form stays for programs. The token is
never accepted in the address.**

- **The same download:** the same intent consumption, transfer limits, decryption,
  streaming, headers (attachment, `nosniff`, sandboxing CSP, `no-store`,
  `Repr-Digest`) and failure handling as the header form. Only where the token comes
  from differs.
- **A small, exact form.** Another content type is refused (415) before the body is
  read. The body is capped at 4 KiB (the gateway's own limit is the upload size, 5 GiB,
  which a download form must never get near). Anything but exactly one non-empty
  `token` field is a 401, and spends nothing.
- **No CORS needed.** A form submission is a navigation: the page never reads the
  response, the browser saves it. The gateway's CORS answers (ADR 0017) stay for the
  uploads and the header downloads a page makes with `fetch`.
- **Cross-site forms gain nothing.** Any site can make a browser POST a form to the
  gateway, but the gateway has no cookies: the form carries only the token the page
  put in it. A site that has a valid token can already use it.
- **Share recipients too.** The recipients' download intents (ADR 0006) are the same
  intents, so the recipients' page downloads the same way.

## Consequences

- The frontend downloads by submitting a hidden form to the intent's `url` with its
  `token`. Its Content-Security-Policy must allow the gateway in `form-action`.
- The browser shows its own download progress; the page doesn't. A page that wants
  its own progress, for a small file, can still `fetch` with the header.
- A failed download (an expired or spent token, the file's scan state having changed)
  is an error page in the browser's download list, a JSON body, rather than an answer
  the page reads. The frontend asks for the intent just before submitting the form, so
  the window for that is short.
- The address never carries a credential, so access logs, which already record the
  path only, have nothing to leave out.

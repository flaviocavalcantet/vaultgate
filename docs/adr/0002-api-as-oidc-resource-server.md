# ADR 0002: The API is an OIDC resource server; users are provisioned from tokens

**Status:** Accepted

## Context

VaultGate authenticates users through the organization's identity provider (Keycloak
locally). Two common designs:

1. **Backend for frontend (BFF):** the API runs the login flow itself, keeps tokens on
   the server and gives the browser a session cookie.
2. **Resource server:** clients (web app, CLI) run the login flow with the identity
   provider and call the API with bearer access tokens; the API only validates them.

The API also needs a local record of each user (to own files, appear in policies and
the audit log), while the identity provider remains the source of truth.

## Decision

- **The API is a pure resource server.** Clients are public OIDC clients using the
  authorization code flow with PKCE (S256); the password grant and implicit flow are
  disabled in the realm. The API holds no sessions and no client secret.
- **Every request is authenticated independently** from its access token: signature
  against the realm's JWKS, algorithm allow-list bound to the key, issuer, audience
  and expiry. Access tokens are short-lived (5 minutes), so revocation in the identity
  provider takes effect quickly without the API keeping state.
- **Deny by default:** every router is mounted under one authenticated router; public
  routes are an explicit list, enforced by a test.
- **Just-in-time provisioning:** the first authenticated request creates the local
  user, keyed by `(issuer, subject)`; later requests sync profile and group
  memberships from the token. Group membership in the identity provider is
  authoritative, including for admin rights. A local `is_active` flag can still lock
  a user out without touching the identity provider.

## Consequences

- No CSRF surface and no server-side session store; the API scales horizontally as-is.
- Browser clients must hold tokens in memory and refresh them; the future web app
  needs care (in-memory storage, refresh token rotation, which the realm enables).
- Users appear in VaultGate only after their first request; there is no directory
  sync. Admin views list people who have used VaultGate, not everyone in the provider.
- Group changes reach VaultGate within one token lifetime (at most 5 minutes).

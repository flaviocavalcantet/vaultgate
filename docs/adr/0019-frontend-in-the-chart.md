# ADR 0019: The web frontend in the chart

**Status:** Accepted

## Context

The web frontend lives in its own repository (`vaultgate-frontend`), which publishes its
image to GHCR by commit. Without a place in VaultGate's deployment, whoever deploys it
writes their own manifests, sets its addresses by hand, and has to remember that the
same addresses must be in the API's and the gateway's CORS list and in the identity
provider's client. The frontend's Content-Security-Policy, its main defence against an
injected script reading the tokens it keeps in memory, depends on those addresses too.

## Decision

**The chart deploys the frontend as an optional component (`frontend.enabled`), from the
frontend's own image at a pinned commit, and gives it the addresses the chart already
knows.**

- **Its own image and tag.** `frontend.image.repository` and `frontend.image.tag`, not
  VaultGate's `image.tag`: the two repositories release separately, so the chart pins
  the frontend commit it runs and a bump is a reviewed change. The tag is required
  when the component is on.
- **One source for the addresses.** The frontend is told `api.publicUrl`,
  `api.gatewayPublicUrl` and `api.oidc.issuer`, the values the API already uses for
  intents and token checks. The image writes its `/config.json` and its
  Content-Security-Policy from them at start (connections to those three only, forms
  to the gateway only, no inline code, no frames).
- **TLS like the rest.** With `tls.enabled`, the chart issues the frontend a
  short-lived certificate from the cluster's issuer, as it does the API and the gateway,
  and the image serves HTTPS, TLS 1.3 only, reloading the certificate when cert-manager
  renews it. The files are public, but their integrity isn't optional: the JavaScript
  holds the user's tokens and decides where they go, so a plain-HTTP hop, even inside
  the cluster, would let anyone on the pod network serve a modified app.
- **Hardened like the rest:** non-root, read-only root filesystem, all capabilities
  dropped, a disruption budget, and a network policy that lets anyone reach its port and
  lets it reach nothing (not even DNS): it serves files, and the browser makes every
  call.
- **The ingress** gets a third host (`ingress.frontendHost`), on the same certificate.
- **The local cluster** runs it on https://localhost:5174 (trusted through the cluster's
  root, like the API), and lists that origin in
  `corsOrigins` and in Keycloak's `vaultgate-web` client (redirect, web origin,
  post-logout). The cluster check confirms the app is served with this cluster's
  settings and policy, and that the API allows its origin.
- **Not wired automatically:** the frontend's own public address in `corsOrigins` and
  in the identity provider's client. Those are the deployment's decisions; the README
  lists them next to `frontend.enabled`.

## Consequences

- A deployment turns on one option and pins one tag to get the app, with its
  Content-Security-Policy matching the deployment's addresses.
- Updating the frontend in a VaultGate deployment is a change of
  `frontend.image.tag` here, after the frontend's own CI has built, checked and scanned
  that commit.
- Every hop to the frontend is TLS, as for the API and the gateway: the browser to the
  Ingress, and the Ingress to the pod (the controller verifying the pod's certificate
  with the trust bundle, as `ingress.serviceAnnotations` describes for the others).
- The frontend's image is scanned in its own repository, so this repository's
  third-party image scan leaves it out, as it does VaultGate's own.

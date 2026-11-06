# ADR 0013: Service identity on the API's internal port

**Status:** Accepted

## Context

The API's internal port is where the gateway and the scanner are trusted:

- the gateway spends intent tokens there and gets back the wrapped data keys of the
  files it serves;
- the scanner gets the keys of the files it scans and reports what it found.

Until M10, two things stood between that port and anyone else:

- **the network policy:** only the gateway's and the scanner's pods reach the port;
- **a shared token per caller:** `VAULTGATE_INTERNAL_TOKEN` and
  `VAULTGATE_SCANNER_TOKEN`, from OpenBao since M9.

Everything is TLS since M9 (ADR 0012), but only the server proves who it is. A caller
proves itself with the token alone: a bearer secret that works from anywhere it leaks
to.

## Decision

**The gateway and the scanner present client certificates naming them, and the
internal port wants both the certificate and the token.**

- **The identity is a URI in the certificate:**
  `spiffe://vaultgate/ns/<namespace>/sa/<service account>`, for example
  `spiffe://vaultgate/ns/vaultgate/sa/vaultgate-gateway`.
  - The certificate holds nothing else: no DNS name or IP address, and no server use
    (its only extended key usage is client authentication).
  - The URI follows SPIFFE's shape, so SPIRE can issue the same identities later
    without the API changing.
- **OpenBao signs them** under a role of their own (`pki/roles/vaultgate-client`), from
  the same intermediate as the server certificates. The role allows:
  - URIs under `spiffe://vaultgate/ns/vaultgate/sa/` and nothing else, so no common
    name, DNS name, IP address or localhost;
  - client use only;
  - a day by default, three days at most.
- **The namespace is the trust boundary.**
  - The certificates come from a namespaced cert-manager `Issuer` in VaultGate's
    namespace, not a `ClusterIssuer`: only a `Certificate` in that namespace can ask
    for one.
  - The Issuer logs in to OpenBao as that namespace's `vaultgate-client-issuer` service
    account, with an audience naming the Issuer (`vault://vaultgate/vaultgate-clients`).
  - OpenBao's `cert-manager-clients` role accepts only that account, and may sign under
    the client role only.
  - The `ClusterIssuer`, open to every namespace, signs server certificates only. Its
    role allows no URIs and no client use, so it can't mint an identity.
- **The API checks, in order:**
  1. **The TLS handshake.** The internal port requires a client certificate that
     chains to VaultGate's root. It is verified against the root alone
     (`VAULTGATE_INTERNAL_CLIENT_CA_FILE`), never against the trust bundle's public
     CAs.
  2. **The identity.** The gateway's routes want the gateway's URI
     (`VAULTGATE_INTERNAL_GATEWAY_IDENTITY`), and the scanner's routes want the
     scanner's. An identity left unset refuses its routes.
  3. **The token**, as before. A certificate alone opens nothing, nor does a token
     alone.

  A failed identity or token check answers 401. The gateway reports that as the API
  being unavailable, never as a refused intent.
- **How the API sees the certificate.** uvicorn does not pass the client certificate to
  the application, so the internal server runs a subclass of uvicorn's h11 protocol
  (`vaultgate_api.mtls`). Once per connection, after the handshake, it reads the
  certificate's URIs and adds them to the scope of every request on that connection.
  The public port is unchanged.
- **Renewal.** The client certificates are renewed by cert-manager like the server
  certificates, and reloaded by the clients as they run. The gateway reuses
  `CertificateReloader` on its client `SSLContext`. The scanner gets the certificate
  from `tlsreload` through `GetClientCertificate`.

## Consequences

- **A leaked token is no longer enough.** It also needs the caller's key, which
  cert-manager generates in the cluster and keeps in that caller's Secret.
- **A leaked key alone isn't enough either.** It also needs the token.
- **Anyone who may create a `Certificate` in VaultGate's namespace can get any
  VaultGate identity.** That is no more than they could already do: they could read the
  services' Secrets anyway. Binding identities to service accounts more tightly would
  take cert-manager's CSI driver or approver-policy, or SPIRE; that is left for later
  (M11 plans SPIRE as an option).
- **Revocation is by expiry.** The certificates last a day, the same as the server
  certificates.
- **The root reaches VaultGate's namespace as a Secret** (`vaultgate-root-ca`, created
  by `make k3d-up` after the ceremony, like the one in `cert-manager`). The Issuer
  verifies OpenBao with it, and the API verifies clients with it.
- **Rotating the root needs a restart of the API.** The API reads the client CA file
  when it starts.
- **OpenBao's new roles exist only on a fresh OpenBao.** Self-initialization runs only
  on empty storage, so an existing local cluster needs `make k3d-down` and `make
  k3d-up`.
- **Docker compose is unchanged.** It runs without TLS, so without client certificates:
  the token alone.
- **The check:** `make k3d-check` (`scripts/mtls_check.py`, run in the gateway's pod)
  confirms that:
  - the gateway's certificate and token are accepted;
  - a connection without a client certificate is refused at the handshake;
  - so is one with a server certificate from the same root.

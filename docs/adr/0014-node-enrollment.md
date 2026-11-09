# ADR 0014: Node enrollment

**Status:** Accepted (M11, in steps: the nodes' CA first; enrollment and its first-trust
methods follow, and extend this record)

## Context

M11 gives external nodes (machines outside the cluster, such as an on-premises agent)
certificates through VaultGate's API. Each node generates its key, VaultGate signs it
once the node has passed a first-trust check, and the node then proves who it is with
that certificate.

M9's PKI (ADR 0012) has one intermediate CA, for the cluster's services: server
certificates for cluster names, and since M10 the services' client identities, URIs
`spiffe://vaultgate/ns/<namespace>/sa/<account>` (ADR 0013). The API's internal port
verifies client certificates against the root, then authorizes by URI.

A node's certificate signed by that same intermediate would share its fate:
- a mistake in a node role, or a compromised signing path, could mint a service's
  identity, which the internal port would accept;
- the cluster's CA would have to answer revocation for machines outside the cluster.

## Decision

**Nodes get their own intermediate CA, from the offline root, which can sign node
identities and nothing else.**

### The nodes' CA

- **A second PKI mount in OpenBao**, `pki-nodes`, with its own issuer, revocation lists,
  OCSP responder and policies. Its key is generated inside OpenBao and never leaves it,
  like the services' intermediate's.
- **Signed by the offline root, in the same ceremony** (`scripts/pki.py intermediate`):
  one passphrase prompt installs or renews both intermediates. The `pki-ceremony`
  account's policy now covers the same calls on the second mount.
- **Constrained to node identities.** Its critical name constraints permit:
  - URIs on the host `nodes.vaultgate`: a node's identity is
    `spiffe://nodes.vaultgate/node/<id>`, its own SPIFFE trust domain;
  - no DNS name, email or IP address: each type is limited to a name that can't exist
    (the reserved `invalid` domain, the unspecified addresses), so any real one fails.

  Its extended key usage is client authentication only, so its certificates can't serve
  TLS. And `pathlen:0`: it signs leaves only.
- **The services' intermediate is constrained the other way.** It now permits only URIs
  on the host `vaultgate`, so it can't mint a node's identity. The constraint takes
  effect when the intermediate is next issued: a new cluster, or the yearly renewal.
- **Why constraints, beyond OpenBao's roles.** The roles already refuse those names, but
  a constraint holds even if OpenBao is compromised: every verifier rejects what the
  CA had no right to sign. `scripts/pki.py check-constraints` proves it on a throwaway
  root and intermediates made from the same extensions. They sign what they may not,
  and OpenSSL and a TLS handshake like the internal port's reject it:
  - the nodes' CA: a service's URI, a DNS name, an IP or email address, a server
    certificate;
  - the services' CA: a node's URI.

### Node certificates

- **The `node` role** (`pki-nodes/roles/node`):
  - a URI under `spiffe://nodes.vaultgate/node/` and nothing else;
  - client use only;
  - ECDSA P-256 keys;
  - a day by default, a week at most.
- **The identity comes from the signer, never from the CSR.** The role ignores the
  names a CSR asks for (`use_csr_sans` and `use_csr_common_name` off): a node chooses
  its key, and VaultGate its name. Without this, OpenBao's `sign` takes the CSR's names
  and ignores the ones given.
- **Who signs:** the enrollment API, in the next step. Until then only `make
  k3d-check` signs, as its own short-lived login (`pki-nodes-check`), local cluster
  only.

### Revocation

- **OCSP**, from OpenBao's responder: it answers from the revocations as they are, so
  a revoked certificate shows as revoked at once.
- **Revocation lists:**
  - the full list lasts two days and is rebuilt half a day before it expires;
  - a delta list carries the revocations since, rebuilt every 5 minutes.
- **Published by the API.** Nodes, and whoever checks their certificates, are outside
  the cluster and can't reach OpenBao. So the certificates name the API's public routes
  as their CA Issuers, CRL distribution point and OCSP URLs, and the API serves them
  from OpenBao (`/pki/nodes/ca`, `/ca/pem`, `/crl`, `/crl/delta`, `/ocsp`).
  - They need no token: a CA certificate, signed lists and signed responses are public
    by nature. They are limited per client address instead (120 a minute).
  - The certificate and the lists are cached for a minute, so a flood doesn't reach
    OpenBao. OCSP answers are not cached.
  - The API reaches OpenBao over TLS, verified with the trust bundle, through the egress
    its network policy already allowed (its OpenBao agent's).
  - The chart's `api.nodesCa.enabled` turns them on; off, they answer 404.

### Alternatives considered

- **Nodes under the services' intermediate, with a role of their own:** one CA less,
  but a role is all that separates a node from a service, and the internal port trusts
  the whole root.
- **A second root for nodes:** full separation, but a second offline key and ceremony,
  and every verifier configured with two roots. Two constrained intermediates under one
  root separate them as well.
- **Pinning the internal port to the services' intermediate instead of the root:** it
  would also keep node certificates out, but it breaks on each yearly renewal unless
  both intermediates are trusted during the change. The name constraints need no
  change at renewal.
- **OpenBao's CRL and OCSP exposed directly** (an ingress to OpenBao): the nodes' CA's
  public endpoints would then open the secret store itself to the outside.

## Consequences

- **Two intermediates to renew,** in one ceremony. `scripts/pki.py check` checks both,
  and each one's constraints.
- **A node certificate can't pass for a service's,** nor the reverse, whatever OpenBao
  signs. A node's identity is told apart by its trust domain, `nodes.vaultgate`.
- **Revocation needs the API to be up** for OCSP, and lists at most a minute old. Short
  certificates bound the rest: a day by default.
- **The local cluster's nodes' CA names `https://localhost:8000`,** the local API, in
  its certificates (`pki-nodes/config/urls`, in `openbao.hcl`). A deployment names its
  own public address.
- **OpenBao's new mount, role and logins exist only on a fresh OpenBao.**
  Self-initialization runs only on empty storage, so an existing local cluster needs
  `make k3d-down` and `make k3d-up`.
- **The check:** `make k3d-check`:
  - confirms both intermediates' constraints (`check-constraints`);
  - signs a 10-minute node certificate under the node role, which refuses a service's
    identity and a DNS name;
  - verifies it as a client's and not a server's;
  - asks the API's OCSP: good, then, after revoking it, revoked;
  - checks that the API's list is signed by the nodes' CA (`check-nodes`).

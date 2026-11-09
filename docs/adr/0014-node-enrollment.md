# ADR 0014: Node enrollment

**Status:** Accepted (M11, in steps: the nodes' CA; then enrollment, with admin approval
as its first first-trust method; the other methods follow, and extend this record)

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
- **Who signs:** the API, for enrollment and renewal (below), through its OpenBao agent.
  `make k3d-check` also signs one, as its own short-lived login (`pki-nodes-check`),
  local cluster only.

### Enrollment

**A node generates its key, asks with a CSR, and gets its certificate once it passes a
first-trust check. Then it renews with that certificate, never with the first-trust
credential again.**

- **The request** (`POST /nodes/enrollments`, public port): the name the node wants (a
  DNS label) and a CSR.
  - The API checks that the CSR's signature verifies with its key (the node holds it)
    and that the key is ECDSA P-256 (the role's), and keeps the CSR.
  - The answer is the request's ID and the key's fingerprint: SHA-256 over the
    SubjectPublicKeyInfo, as `SHA256:<base64>` (OpenSSH's form). The node also shows its
    operator this fingerprint, computed from its own key.
  - A request waits a day at most. At most 100 wait at once, and a name with an active
    node can't be asked for.
- **No credential yet, so no token.** The node's routes (request, status, complete) are
  limited per client address. They are also under the access policies, through a new
  action, `enroll`, evaluated with the node's address and the time, and no groups (a
  node is no user). Policies deny by default, so no node enrolls until an admin allows
  it, from the networks they choose. The local cluster's seeded policy allows it.
- **First trust by admin approval** (`/admin/nodes/enrollments`, public port, admins
  only):
  1. The admin compares the request's fingerprint with the one the node's operator reads
     them, out of band, and approves with it. A different fingerprint is refused and
     audited: the request's key isn't that node's.
  2. The approval answers with a one-time code (10 characters from an alphabet without
     look-alikes, about 50 bits), shown once. Only its salted SHA-256 is kept. It lasts
     15 minutes and 5 tries, after which the request is rejected. Approving again gives
     a new code.
  3. The operator gives the code to the node, which completes the enrollment with it
     (`POST /nodes/enrollments/{id}/complete`).

  The stored CSR is what gets signed, so the code is good for that key only. Whoever
  intercepts the code gets a certificate for a key they don't hold.
- **Completion** signs the CSR under the node role, with the identity
  `spiffe://nodes.vaultgate/node/<name>`, and records the node: its key's fingerprint
  and its certificate's serial. The answer is the certificate and its chain. One active
  node per name, enforced by a partial unique index; a race signs, then revokes the
  loser's certificate.
- **Signing through the API's OpenBao agent.** The agent, already the API's sidecar,
  serves an API proxy on the pod's loopback that adds its own token. The API's OpenBao
  policy gains three paths: signing under the node role, revoking, and rotating the
  delta list. The API process never holds an OpenBao token. `make k3d-check` checks
  that the API may make exactly these calls on the nodes' CA, and the gateway and the
  scanner none.

### The nodes' port

**Enrolled nodes call the API on a port of their own, with their certificates.**

- **A third API server** (8002, `api.nodes` in the chart), TLS with a required client
  certificate from the root. The routes then want the certificate to name a node,
  which only the nodes' CA can do (its constraints; a service's certificate names no
  node), and to be that node's current one:
  - the node active (not revoked);
  - the certificate's serial the one on record.
- **Renewal** (`POST /renew`): a CSR, for the same key or a new one. The new certificate
  replaces the old one on record, and the old one is revoked in OpenBao. So each
  certificate renews once, a copied one can't renew alongside the node, and the
  first-trust code is never used again. `GET /whoami` shows the node.
- **No token.** The certificate is the node's credential, and the port is for machines.
  People and the future frontend stay on the public port, with the identity provider's
  tokens. Browsers don't hold SPIFFE identities, and never need to.
- **Revocation by an admin** (`POST /admin/nodes/{id}/revoke`): the certificate is
  revoked in OpenBao first (OCSP and the lists show it), then the node is marked
  revoked, so it can't renew. If OpenBao refuses, nothing changes. The name is free to
  enroll again.
- **Audited:** each request, approval (or refused fingerprint), rejection, completion
  (or refused code), renewal, revocation, and each certificate refused on the nodes'
  port. Nodes are a new kind of actor in the audit log (`node`).

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

- **Polling for the certificate after approval, without a code:** a certificate for the
  node's own key is useless to anyone else, but the code also proves that the person
  who spoke to the admin is at the node. The roadmap's admin approval has it.
- **Renewal on the public port, with optional client certificates:** one port fewer,
  but every TLS handshake on the public port would ask for a certificate, and browsers
  may then prompt their users.
- **Through the gateway:** it would terminate the node's TLS and pass its identity on,
  and the API would have to trust the gateway's word for it.

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
- **The enrollment check:** `make k3d-check` runs `scripts/node_check.py`, with
  `scripts/vaultgate_node.py` as the node and carol as the admin:
  - an approval naming another key is refused, and the right one gives a code;
  - a wrong code and the code a second time are refused;
  - the certificate names the node, for clients, from the nodes' CA;
  - the nodes' port answers the node, and refuses a connection without a certificate;
  - after renewal with a new key, the previous certificate is refused and revoked;
  - after carol revokes the node, the port refuses it and OCSP says revoked.
- **The CA check:** `make k3d-check`:
  - confirms both intermediates' constraints (`check-constraints`);
  - signs a 10-minute node certificate under the node role, which refuses a service's
    identity and a DNS name;
  - verifies it as a client's and not a server's;
  - asks the API's OCSP: good, then, after revoking it, revoked;
  - checks that the API's list is signed by the nodes' CA (`check-nodes`).

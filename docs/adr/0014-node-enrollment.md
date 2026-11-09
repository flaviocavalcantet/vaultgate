# ADR 0014: Node enrollment

**Status:** Accepted (M11, in steps: the nodes' CA; then enrollment, with admin approval
as its first first-trust method; then first trust by a Keycloak client, and by an
admin's enrollment token, and by cloud instance identity (AWS); the other methods
follow, and extend this record)

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
  - A request waits a day at most. At most 100 wait at once, and 10 from one client
    address, so one client can't take every place. A name with an active node can't be
    asked for. Names aren't limited: whoever knows a node's name could then keep its
    real request out.
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

### First trust by an admin's enrollment token

**An admin issues a token for one node name, and the node enrolls with it, at once and
once.**

- **Issued by an admin** (`POST /admin/nodes/tokens`, with the name and, optionally, a
  shorter life):
  - 256 random bits, prefixed `vgn_` so that secret scanners, and people, recognize it;
  - shown once, with only its SHA-256 kept;
  - an hour by default, a day at most;
  - not issued for a name with an active node.

  Admins list tokens (`GET /admin/nodes/tokens`) and revoke unused ones.
- **Used by the node** (`POST /nodes/enrollments/by-token`, the token and a CSR, in the
  body, never a URL): the token names the node, and the certificate comes back at once.
  - The token's row is locked, and marked used in the same transaction that records the
    node and the enrollment. Two concurrent uses can't both succeed, and a failed
    signing uses nothing up.
  - A bad CSR or a policy refusal doesn't use it up either.
  - The `enroll` policies apply, as to every method.
- **Refusals:** a token that was used, revoked or expired is refused (403) and audited.
  An unknown string is refused without an audit record: anyone can send one, as often as
  the per-address limit allows, and a record of each would fill the log.
- **The node's client** reads the token from `VAULTGATE_ENROLLMENT_TOKEN`, or asks for
  it, and never takes it as a command-line argument, which shell history would keep.

### First trust by cloud instance identity

**An instance of an allowed cloud account enrolls with the identity document its cloud
signs, once per instance.** AWS first; GCP's and Azure's documents would be further
providers behind the same route.

- **The document:** an EC2 instance reads it from the instance metadata service
  (IMDSv2):
  - JSON naming its account, instance, region and launch time;
  - AWS's RSA-SHA256 signature over it (base64).

  The node sends both, with a CSR, to `POST /nodes/enrollments/by-cloud`.
- **What VaultGate checks:**
  - **The signature**, against the certificates the operator configures: AWS's
    published ones, for the regions in use (`api.nodes.aws.certificatesSecret`). There
    is no other trust anchor: a document that verifies against none is refused.
  - **The account**, which must be allowed (`accounts`; none, and the method is off).
  - **The region**, if any are listed (`regions`).
  - **The launch time**, optionally: at most `maxLaunchAgeSeconds` ago.
  - **The `enroll` policies**, as for every method.
- **The node's name is its instance's** (`aws-<instance ID>`). Nothing the node sends
  chooses it.
- **Once per instance, because the document isn't secret.** Any process on the instance
  can read it, and it never changes. So VaultGate records the instance
  (`aws:<account>:<instance>`, under the same unique index as Keycloak clients) and
  accepts its first enrollment only, even after that node is revoked.
  - If something else on the instance enrolled first, the real node is refused, and the
    admin sees both in the audit log.
  - The launch-time limit narrows that window to the instance's first minutes, for
    fleets that enroll at boot.
- **Refusals:** a document whose signature doesn't verify is refused without an audit
  record (anyone can send one). A signed document from the wrong account, region or
  launch time, or an instance used already, is refused and audited.
- **Locally:** k3d has no EC2. `make k3d-up` makes a stand-in for AWS's signing key next
  to the root (`local-aws-iid.key`), and the cluster's API trusts its certificate for a
  made-up account. `scripts/node_check.py` serves a document signed with it from a fake
  metadata service.

### First trust by a Keycloak client

**A node with its own confidential Keycloak client enrolls with that client's token, at
once and once.**

- **The client** (`node-<name>`, made by an admin: `scripts/keycloak_node_client.py
  create`):
  - **Authentication:** a JWT signed by the node's own key (`private_key_jwt`, RFC 7523).
    Keycloak holds only the key's certificate, which the node makes
    (`vaultgate_node.py credential`). There is no client secret to leak or share.
  - **Its tokens** are for the audience `vaultgate-nodes`, never the API's
    (`vaultgate-api`). Every user route refuses them, and the enrollment route refuses
    users' tokens.
  - **Its service account** has the realm role `vaultgate-node-enroll`.
- **Enrollment** (`POST /nodes/enrollments/by-client`, with the token and a CSR): the API
  validates the token against the node audience, wants the role, and names the node
  after the client (`node-<name>` is `<name>`). Then the CSR is checked and signed as by
  approval, under the same `enroll` policies, and the certificate comes back at once.
  There is no admin step at enrollment time: the admin's trust went into making the
  client.
- **Once, by VaultGate.** The enrollment records the client's service account (the
  token's `sub`), and a unique index keeps it to one node ever. A second request with
  the same client is refused (409, audited), even after its node is revoked.
  - **VaultGate never writes to Keycloak.** The roadmap had the role removed once the
    node has its certificate. That would give the API write access to Keycloak's users.
    The single-use record protects as well, so the API's credentials stay read-only.
    Removing the role (`unassign`) or the client (`delete`) afterwards is the admin's
    tidying. Recreating a client makes a new service account, so enrolling again is
    always a deliberate admin act.
- **Its failures are plain 401s**, not counted towards the address's authentication
  block as the user routes' are. The route is limited per address already, a signed
  token can't be guessed, and ZAP, scanning with a user's token, would otherwise be
  blocked partway through a scan.
- **Locally:** `scripts/keycloak_node_client.py` signs in as Keycloak's bootstrap admin
  (TM-12). Elsewhere it uses an admin's credentials.

### Alternatives considered

- **The API removing the role in Keycloak itself:** faithful to the roadmap, but it needs
  a Keycloak credential that can change users' role mappings. Keycloak's fine-grained
  admin permissions could narrow it to the nodes' service accounts. The single-use
  record already makes a second enrollment impossible, so the credential wasn't worth
  adding.

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
- **The token check:** `scripts/node_check.py` also has carol issue a token. The node
  enrolls with it, and then:
  - the token is refused a second time;
  - a token carol revoked enrolls nothing.
- **The cloud identity check:** `scripts/node_check.py` also enrolls a fourth node, from
  a fake metadata service, with the stand-in's signature. Then:
  - the instance can't enroll a second node;
  - a document changed after signing is refused.
- **The Keycloak client check:** `scripts/node_check.py` also makes a node client with
  its certificate. The node enrolls with a token got by `private_key_jwt`, and checks
  that:
  - the client can't enroll a second node;
  - its token opens no user route;
  - a user's token isn't a node client's.

  The client is deleted afterwards.
- **The CA check:** `make k3d-check`:
  - confirms both intermediates' constraints (`check-constraints`);
  - signs a 10-minute node certificate under the node role, which refuses a service's
    identity and a DNS name;
  - verifies it as a client's and not a server's;
  - asks the API's OCSP: good, then, after revoking it, revoked;
  - checks that the API's list is signed by the nodes' CA (`check-nodes`).

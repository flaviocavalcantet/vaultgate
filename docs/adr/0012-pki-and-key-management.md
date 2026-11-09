# ADR 0012: PKI and key management

**Status:** Accepted

## Context

Until M9, VaultGate has keys but no PKI:

- files are encrypted with per-file data keys that a KMS key wraps (ADR 0003);
- inside the cluster, the services talk plain HTTP and prove who they are with shared
  tokens;
- the credentials (database URL, internal tokens, AWS keys) sit in one Kubernetes
  Secret, which outside the local cluster is created by hand.

M9 adds a certificate authority whose private keys are kept safe, certificates on every
hop, and the services' secrets delivered from a secret store instead of from values. M10
then builds service identity (client certificates) and the trust between nodes on top of
it, and M11 enrolls external nodes through VaultGate's API, with a second intermediate.

## Decision

**OpenBao is the CA and the secret store. Its intermediate CA is signed by a root whose
key never enters the cluster.**

- **OpenBao** (the open-source fork of HashiCorp Vault, MPL-2.0) runs in the cluster:
  - one pod, with integrated storage (`deploy/k3d/openbao`);
  - TLS only, TLS 1.3;
  - plain manifests synced by Argo CD, like Loki and Tempo.

  It holds the intermediate CA, in the `pki` mount, and in the later M9 steps the
  services' secrets. One component then covers both jobs. Its policies and audit log
  apply to certificates and to secrets alike.
- **Configured from git, with no root token ever handed out.** On first start, OpenBao
  initializes itself (the `initialize` blocks in `openbao.hcl`):
  - the `pki` mount and its URLs;
  - Kubernetes logins;
  - the policies and roles.

  The root token it does this with is revoked at the end. The audit log is declared in
  the same file and goes to stdout, so into Loki. Every later change is either a request
  made by a role allowed to make it, or a new cluster.
- **An offline root** (`scripts/pki.py`):
  - **Where it lives:** an EC P-384 root, valid ten years, created and kept on the
    operator's machine, in `~/.vaultgate/pki`. Its key is encrypted with a passphrase
    (AES-256) and handled by OpenSSL only.
  - **What it signs:** two things, and nothing else.
    - **The intermediate CA**, in a ceremony:
      1. OpenBao generates the intermediate's key (type `internal`, so it can never be
         read back) and a CSR.
      2. The root signs the CSR on the operator's machine.
      3. OpenBao installs the certificate.

      The ceremony logs in as the `pki-ceremony` service account, with a 10-minute
      token. Its policy allows exactly those calls.
    - **OpenBao's own server certificate.** OpenBao can't issue its own before it holds
      the intermediate. It is valid one year and renewed by running the command again;
      OpenBao reloads it without a restart.
- **The intermediate CA is constrained:**
  - **Leaves only:** `pathlen:0`, so it can't create another CA.
  - **Cluster and loopback names only:** critical name constraints permit DNS names
    under `svc` and `cluster.local`, `localhost`, and loopback addresses. A verifying
    client rejects anything else it issues, even if OpenBao is compromised.
  - **Valid one year.** The ceremony renews it when fewer than 30 days remain.
- **The seal, locally:** a static key, in a Secret that `make k3d-up` creates (never in
  git).
  - **What that means:** the local cluster unseals itself after a restart. Anyone who
    can read Secrets in the `openbao` namespace can therefore decrypt its storage.
  - **Why that is enough here:** the local cluster is its own root of trust anyway.
  - **Elsewhere:** the seal would be a cloud KMS (`awskms`). Unsealing then needs the
    KMS, and the storage alone is useless.
- **CI:** each job creates a root of its own, with a random passphrase. Its key is
  deleted once the ceremony is done, so nothing can be signed by it afterwards.

### Alternatives considered

- **cert-manager's CA issuer**, with the intermediate's key in a Kubernetes Secret: the
  simplest, but then the CA key is only as safe as the Secret (and etcd), and anyone
  who reads it can issue anything. With OpenBao, the key never leaves OpenBao.
- **step-ca:** a good dedicated CA (ACME, short-lived certificates), but a second
  component for the secrets that M9 also needs.
- **The root inside OpenBao:** simpler to set up and to rotate, but whoever compromises
  OpenBao could then mint a new intermediate. With an offline root, the cluster can lose
  its intermediate, never its root.
- **The root in SoftHSM (PKCS#11):** shows HSM-style key handling, but adds tooling and
  is still a file on disk. Production would use a real HSM or an air-gapped machine.

### Certificates for the services

**cert-manager signs through OpenBao, trust-manager hands out the root, and the services
load renewed certificates as they run.**

- **Issuing** (`deploy/k3d/pki`):
  - cert-manager 1.21 and trust-manager 0.25 are installed from their upstream charts,
    at pinned versions.
  - The `vaultgate-ca` ClusterIssuer sends each certificate's CSR to OpenBao's
    `vaultgate-service` role. The key stays with cert-manager in the cluster; OpenBao
    only signs.
  - cert-manager logs in as the `openbao-issuer` service account, with a token it mints
    for that issuer's audience. The account's OpenBao policy allows that one signing
    path.
- **The `vaultgate-service` role:**
  - DNS names under `svc` and `cluster.local`, and `localhost`, so services are named
    by their Service's full name (`vaultgate-api.vaultgate.svc`), never a short name;
  - no IP addresses, wildcards or client certificates (M10 brings those);
  - ECDSA P-256 keys;
  - valid one day by default, three at most.

  The intermediate's name constraints would reject anything else anyway.
- **Short-lived certificates, reloaded in place.**
  - The API's and the gateway's certificates last a day, and cert-manager renews them
    with a third of their life left.
  - The services check the mounted files every minute and load a renewed pair into their
    running TLS context, so they need no restart. A pair that doesn't load, such as a key
    that doesn't match, is skipped and the old one stays in use.
  - A revoked or stolen certificate is therefore useful for a day at most. Revocation
    lists are left for the node certificates of M11.
- **Trust:** trust-manager writes one bundle into every namespace, a ConfigMap
  `vaultgate-ca` holding the root and the public CAs.
  - The services read it as their trust store (`SSL_CERT_FILE`, which Python's `ssl` and
    Go's `crypto/x509` both honour). Their clients verify without any VaultGate-specific
    code: the gateway and the scanner calling the API, and later the API calling
    PostgreSQL and Keycloak.
  - The host trusts `root-ca.crt` from `~/.vaultgate/pki`.
- **Ordering:** cert-manager waits a long time after a failed issuance: an hour, then
  longer. `make k3d-up` therefore creates the root's Secret, which the issuer and the
  bundle need, only after the ceremony has installed the intermediate. Until then the
  issuer isn't ready, and certificate requests wait instead of failing.
- **The chart:** `tls.enabled` turns it all on (`values-k3d.yaml` does).
  - The public and the internal ports both speak TLS only, with probes over HTTPS.
  - The metrics ports speak TLS as well (below).
  - Off, the chart serves plain HTTP as before.
- **The dependencies:**
  - **PostgreSQL** serves TLS 1.3 with its own day-long certificate, and its `pg_hba`
    rejects any connection without TLS. It reads a renewed certificate on a reload, which
    the pod triggers every hour.
  - **The API** connects with `ssl=verify-full`, checking the server's name and chain.
    asyncpg reads the trust bundle from `PGSSLROOTCERT`.
  - **Keycloak** serves TLS 1.3 only, on its public port and its management port
    (health), and reloads its certificate every hour. Its issuer becomes
    `https://localhost:8080/realms/vaultgate`, and the API fetches discovery and keys
    from `keycloak.vaultgate-deps.svc` over TLS.
- **Metrics:** the API's, gateway's and scanner's metrics ports serve TLS with the
  same certificates, which are renewed in place like the others (the scanner's in Go,
  by `internal/tlsreload`). The ServiceMonitors scrape over https and verify against the
  trust bundle and the Service's name, and `k3d-check` fails on a target scraped over
  plain HTTP.
- **Traces:** Alloy's OTLP receiver serves TLS with its own certificate, reloaded
  hourly. The services' exporters verify it (`OTEL_EXPORTER_OTLP_CERTIFICATE`).
  Inside the `monitoring` namespace, Alloy to Tempo and Prometheus to Loki and Tempo
  stay plain HTTP: they carry no tokens or file data.
- **The ingress (optional in the chart; the local cluster uses NodePorts):** with TLS
  on and no `ingress.tls` given, cert-manager issues the ingress's certificate for both
  hosts. The backends then speak HTTPS only, so the controller must too, and verify them
  with the bundle. That setting belongs to each controller, so it is passed through
  `ingress.serviceAnnotations`. Traefik's ServersTransport is one example. This is
  checked against the schemas only, since the local cluster has no ingress controller.
- **What a production cluster would change:** this role lets any namespace's Certificate
  name any Service. A shared cluster would give each namespace its own role, limited to
  `*.<namespace>.svc`, or add cert-manager's approver-policy.

### The services' credentials

**OpenBao holds them, each service reads only its own, and they reach the pods as
files in memory.**

- **Stored** in a key-value mount (`secret/`): `secret/vaultgate/<name>`, the value in
  its `value` field. The secrets are the internal token, the scanner token and, since
  M10, each service's own AWS credentials file (`aws-api`, `aws-gateway`,
  `aws-scanner`), from its own IAM user with a least-privilege policy
  (`infra/terraform/modules/access`; TM-2 in docs/threat-model.md). The database
  credentials are not stored at all (below).
- **Seeded by `make k3d-up`** with random tokens (`scripts/service_secrets.py seed`),
  and with each service's AWS key from Terraform's output (`seed-aws`).
  - It runs as the `secrets-seed` service account. Its policy has `create` on the
    secrets and `read` on their metadata. It can create a secret and see that one
    exists, but never read or overwrite one, so a second run keeps every value, and a
    refused write fails instead of passing for "exists".
  - None of them is ever in git, in Helm values or in a Kubernetes Secret.
  - Compose keeps its fixed development tokens.
- **Read by each service with its own identity.** The chart gives the API, the gateway
  and the scanner a service account each, and OpenBao has a matching Kubernetes role
  and policy for each:
  - the API reads the three secrets and its database credentials;
  - the gateway reads the internal token and the AWS file;
  - the scanner reads the scanner token and the AWS file.

  `k3d-check` logs in as each one and asks OpenBao what that login may read
  (`sys/capabilities-self`, which issues nothing). It fails unless the answer is
  exactly that list.
- **Delivered by the OpenBao agent**, as each pod's init container:
  1. It logs in with a projected service-account token for OpenBao's audience. That
     token lasts 10 minutes and is mounted in the agent only.
  2. It writes the secrets with mode `0400` to a memory-backed volume, never the node's
     disk, and exits. Until a secret exists, it waits.
  3. The services read the files through `VAULTGATE_SECRETS_DIR` (one file per
     setting, named after its variable), and the AWS SDKs through
     `AWS_SHARED_CREDENTIALS_FILE`. A set variable still wins, so compose and the tests
     are unchanged.
- **Why files, not environment variables:** the environment shows up in `kubectl
  describe`, in crash dumps and in child processes. The `vaultgate` Secret is gone too,
  and `k3d-check` checks that no Deployment takes a credential from its environment.

### Database credentials

**Each API pod logs in to PostgreSQL with credentials of its own, which OpenBao issues
and ends.**

- **PostgreSQL's bootstrap** (an init script, on an empty data directory):
  - The schema belongs to `vaultgate_owner`, a role nobody logs in as.
  - OpenBao gets its own login, `openbao`. It may create roles, hand out
    `vaultgate_owner`, and end other sessions.
  - `make k3d-up` puts two random passwords in Secrets: the superuser's, and OpenBao's
    first one. No password is in git.
- **OpenBao's database engine:**
  - It connects as `openbao`, over TLS verified with the trust bundle (mounted
    optionally, since the bundle exists only after the ceremony).
  - Self-initialization configures it from that first password, and once PostgreSQL is
    up `make k3d-up` rotates it (`database/rotate-root`). From then on only OpenBao
    knows it.
- **Each credential:**
  - It is a login `v-…` with a one-hour lease, renewable up to a day.
  - It is created `IN ROLE vaultgate_owner`, with `vaultgate_owner` as its default
    role. Everything it creates, the migrations included, belongs to `vaultgate_owner`,
    and the login itself owns nothing.
  - When the lease ends, OpenBao ends the login's sessions and drops it.
- **Renewal in the pod:**
  - The API's OpenBao agent is a native sidecar. It renews the lease, and once it
    can't, writes new credentials into the URL file.
  - The API logs in with the file's credentials at each new connection, and recycles
    pooled connections every 15 minutes. A rotation needs no restart.
  - The gateway and the scanner have no database access.
- **Checked:** `k3d-check` confirms, from the API's pod, that its connection is TLS
  with the server verified, logs in as an OpenBao login acting as `vaultgate_owner`,
  and that a connection without TLS is refused.

## Consequences

- The cluster's trust starts at a certificate the operator holds (`root-ca.crt`).
  Clients outside the cluster, such as the scripts and the browser, verify against it.
  Its fingerprint is printed when it is created.
- A second step needs the operator after the cluster is up: the ceremony, with the root
  passphrase. `make k3d-up` runs it.
- Without the passphrase, the root signs nothing. Losing it means a new root, and so a
  new cluster.
- OpenBao becomes a dependency of the cluster: it must be unsealed and running before
  the later steps can issue certificates or hand out secrets.
- Self-initialization runs on empty storage only. A changed `initialize` block takes
  effect on a new cluster, or as a request by a role allowed to make it, never by
  editing the file on a running one.
- Compose stays as it is: plain HTTP, with its secrets in environment variables. It is
  the quick development stack, and the PKI is a property of the cluster.
- On the cluster, the API, the gateway and Keycloak answer on https only. The scripts, the load
  tests and `curl` need the root: `--cacert ~/.vaultgate/pki/root-ca.crt`, or
  `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE`.

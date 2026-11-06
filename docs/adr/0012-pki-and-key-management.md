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
then builds service identity (client certificates) and the first trust between nodes on
top of it.

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

### Next in M9

- cert-manager requests certificates from OpenBao, short-lived, and trust-manager
  distributes the root. With them, the API, gateway, Keycloak, PostgreSQL and the
  ingress serve TLS, and every client verifies.
- The services' credentials come from OpenBao, with database credentials per pod.

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

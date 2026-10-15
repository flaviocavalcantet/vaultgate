# VaultGate

**A secure file vault for organizations: single sign-on, policy-based access control, streaming uploads with envelope encryption, and automatic PII detection before anything is shared.**

[![CI](https://github.com/flaviocavalcantet/vaultgate/actions/workflows/ci.yml/badge.svg)](https://github.com/flaviocavalcantet/vaultgate/actions/workflows/ci.yml)

> **Status:** early development. The service skeletons, CI, Helm chart and Terraform modules are in place. Features land milestone by milestone (see [Roadmap](#roadmap)).

---

## What it does

Companies still share sensitive files by email attachment or public links. Those files leak: contracts reach the wrong address, a spreadsheet full of customer CPFs gets forwarded outside the company, a "temporary" link lives forever.

VaultGate is a self-hostable alternative built around four guarantees:

1. **Only the right people get in.** Users sign in through the organization's identity provider (OIDC SSO). Access policies then decide what each user may do, based on group membership, source IP range and time of day.
2. **Files are encrypted before they are stored.** Each file gets its own data key (envelope encryption with AWS KMS). Storage never sees plaintext, and revoking a key makes a file unreadable.
3. **Sensitive data is caught before it leaves.** Every upload is scanned for personal data (emails, Brazilian CPF numbers, payment cards). Files with findings are quarantined or blocked from external sharing, depending on policy.
4. **Every action is accountable.** Uploads, downloads, shares and policy changes are written to an append-only audit log.

Sharing works through **signed, expiring links** with optional download limits and recipient verification, so a link stops working on its own.

## Architecture

```mermaid
flowchart LR
    U[User / browser] -->|OIDC login| IDP[(Identity provider<br/>Keycloak locally)]
    U -->|JSON API| API[FastAPI<br/>control plane]
    U -->|file bytes| GW[Tornado<br/>streaming gateway]
    GW -->|validate upload intent| API
    GW -->|encrypted chunks| S3[(S3)]
    GW -->|wrap data key| KMS[KMS]
    API --> PG[(PostgreSQL<br/>metadata, policies, audit)]
    GW -->|file uploaded event| Q[[SQS]]
    Q --> SC[Go PII scanner]
    SC -->|verdict| API
```

| Component | Tech | Responsibility |
|---|---|---|
| `api/` | FastAPI, PostgreSQL | Identity, access policies, file metadata, share links, audit log |
| `gateway/` | Tornado | Streams uploads and downloads with constant memory per connection; encrypts on the fly |
| `scanner/` | Go | Detects PII in uploaded files and reports a verdict |
| `deploy/` | Helm, ArgoCD | Kubernetes manifests and GitOps sync |
| `infra/` | Terraform | AWS resources (S3, KMS, SQS; later VPC, RDS, EKS), runnable against LocalStack |

### Why two Python frameworks?

They handle different traffic. FastAPI fits the control plane: many small, validated JSON endpoints with an OpenAPI spec. Tornado fits the data plane: `@stream_request_body` processes a multi-gigabyte upload chunk by chunk, so memory stays flat no matter the file size. The gateway never makes authorization decisions; it asks the API to validate a short-lived upload intent first. Full reasoning in [ADR 0001](docs/adr/0001-tornado-and-fastapi.md).

### Why Go for the scanner?

Scanning is CPU-bound and runs over every byte of every upload. A small, statically compiled Go worker scales independently of the Python services and ships as a distroless image. Detectors require a checksum to pass where the format has one (CPF check digits, Luhn for cards), which keeps false positives low enough to block on.

## Security model

- **Authentication:** OIDC authorization code flow with PKCE. The API validates tokens against the issuer's JWKS and checks audience and expiry.
- **Authorization:** deny by default. Policies are evaluated on every request, not cached in the session.
- **Encryption:** AES-256-GCM per file, with the data key wrapped by KMS. S3 server-side encryption and a public access block on top.
- **PII handling:** the scanner reports finding types and positions only. Matched values are never logged or stored.
- **Containers:** non-root user, read-only root filesystem, all Linux capabilities dropped.
- **Audit:** append-only table; the application role has `INSERT` but no `UPDATE` or `DELETE`.

## Repository layout

```
api/            FastAPI control plane
gateway/        Tornado streaming gateway
scanner/        Go PII scanner
deploy/
  helm/         Helm chart for both Python services
  argocd/       ArgoCD Application (GitOps)
infra/
  terraform/
    modules/    Reusable modules (storage: S3 + KMS)
    envs/local/ Points the AWS provider at LocalStack
docs/adr/       Architecture decision records
```

## Running locally

Everything runs on your machine at no cost: PostgreSQL, LocalStack (S3, KMS, SQS) and Keycloak run as containers, and Terraform applies against LocalStack instead of a real AWS account.

Requirements: Docker, Python 3.12+, Go 1.23+, Terraform 1.6+. For Kubernetes: k3d or kind, Helm.

```bash
make up         # start Postgres, LocalStack, Keycloak, API and gateway
make tf-local   # create the S3 bucket and KMS key in LocalStack
make test       # run all test suites
```

The API applies its database migrations (Alembic) on startup. To run them by hand against a local Postgres, use `make migrate`. API database tests need a disposable database:

```bash
VAULTGATE_TEST_DATABASE_URL=postgresql+asyncpg://vaultgate:vaultgate@localhost:5432/vaultgate_test make test
```

- API docs: http://localhost:8000/docs (readiness: http://localhost:8000/readyz)
- Gateway health: http://localhost:8888/healthz
- Keycloak admin: http://localhost:8080 (admin / admin)

Try the scanner on its own:

```bash
echo "Contact ana@example.com, CPF 529.982.247-25" | (cd scanner && go run ./cmd/scanner)
```

## Roadmap

- [x] **M0 — Foundation:** service skeletons, CI, Helm chart, ArgoCD app, Terraform storage module, local stack
- [ ] **M1 — Identity:** OIDC login with Keycloak, token validation, users and groups in PostgreSQL
- [ ] **M2 — Streaming vault:** upload intents, chunked envelope encryption, S3 multipart upload, streaming download
- [ ] **M3 — Access policies:** IP range, time window and group rules; deny-by-default evaluation
- [ ] **M4 — PII scanning:** SQS-driven scanner worker, quarantine, card number detector (Luhn)
- [ ] **M5 — Sharing:** signed expiring links, download limits, recipient email verification
- [ ] **M6 — Audit and observability:** append-only audit log, OpenTelemetry traces across all three services, Prometheus metrics
- [ ] **M7 — Kubernetes end to end:** k3d cluster with ArgoCD syncing this repo, horizontal autoscaling of the gateway
- [ ] **M8 — Load testing:** Locust scenarios with published results (concurrent uploads, gateway memory under load)

## License

MIT. See [LICENSE](LICENSE).

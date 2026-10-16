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

## Observability

All services log one JSON object per line (stdout for the API and gateway, stderr for the scanner, whose stdout carries findings):

```json
{"ts": "2026-10-15T01:40:23.250+00:00", "level": "info", "service": "api", "logger": "vaultgate.access", "msg": "request", "request_id": "demo-1", "method": "GET", "path": "/readyz", "status": 200, "duration_ms": 56.79, "client_ip": "127.0.0.1"}
```

- **Request IDs:** every HTTP response carries `X-Request-ID`. A caller-supplied ID is reused if it is 1–64 characters of `[A-Za-z0-9._-]`, otherwise a new one is generated. Pass the same ID from API to gateway to scanner to follow one action across services.
- **What is never logged:** query strings (they will carry share-link signatures), tokens, file contents, and PII values (the scanner logs counts per kind, never matches).
- **Settings:** `VAULTGATE_LOG_LEVEL` (default `INFO`) and `VAULTGATE_LOG_FORMAT` (`json` by default, `text` for reading in a terminal).

### Metrics

The API and gateway serve Prometheus metrics on a separate port, `VAULTGATE_METRICS_PORT` (default `9100`), so the scrape endpoint is never reachable through the public port.

| Metric | Type | Labels | Service |
|---|---|---|---|
| `vaultgate_http_requests_total` | counter | `method`, `route`, `status` | both |
| `vaultgate_http_request_duration_seconds` | histogram | `method`, `route` | both |
| `vaultgate_http_requests_in_progress` | gauge | | API |
| `vaultgate_gateway_uploads_in_progress` | gauge | | gateway |
| `vaultgate_gateway_upload_bytes_total` | counter | | gateway |
| `vaultgate_gateway_upload_size_bytes` | histogram | | gateway |
| `vaultgate_build_info` | info | `service`, `version` | both |

`route` is the path template (`/uploads/{upload_id}`), never the raw path; anything that matches no route is counted as `<unmatched>`, so clients cannot create new time series by probing URLs. Standard `process_*` and `python_*` metrics are included, which is how gateway memory is shown to stay flat under load.

### Centralized logs

Locally, [Grafana Alloy](https://grafana.com/docs/alloy/) reads the stdout/stderr of every container in the compose project and ships it to Loki. JSON lines get the `service` and `level` labels from their own fields; plain-text logs (Postgres, Keycloak) are labelled with their compose service name. `request_id` is stored as structured metadata, so it is searchable without creating a stream per request. In Grafana → Explore → Loki:

```logql
{service="api", level="error"}                       # API errors
{service=~"api|gateway"} | request_id="<id>"         # one request across services
{service="gateway"} | json | status >= 500           # gateway 5xx with parsed fields
```

### Dashboards and alerts

Grafana loads the dashboards in `observability/grafana/dashboards/` on startup (edit the JSON in the repo; changes made in the UI are not saved):

- **VaultGate / Service overview:** up/down, request rate, 5xx ratio and latency per service and route, plus recent error logs from Loki.
- **VaultGate / Gateway uploads:** upload throughput, concurrency, size and duration, and gateway memory, which should stay flat however large the uploads are.

Prometheus evaluates the rules in `observability/prometheus/rules/vaultgate.yml`; `make obs-check` runs their unit tests. Firing alerts show in Prometheus → Alerts (Alertmanager routing arrives with M7).

| Alert | Fires when | Severity |
|---|---|---|
| `VaultGateTargetDown` | API or gateway metrics unreachable for 2 min | critical |
| `VaultGateHighErrorRate` | more than 5% of a service's requests return 5xx for 5 min | critical |
| `VaultGateHighLatency` | p95 of non-upload requests above 1 s for 10 min | warning |
| `VaultGateGatewayMemoryHigh` | gateway resident memory above 200 MiB (limit 256 MiB) for 5 min | warning |
| `VaultGateObservabilityDown` | Loki or Alloy down for 5 min | warning |

In Kubernetes, the Helm chart exposes the metrics port on each Service (never through an Ingress) and adds `prometheus.io/*` pod annotations. With the Prometheus Operator, set `metrics.serviceMonitor.enabled=true` (and `metrics.podAnnotations=false`); the ServiceMonitors keep `job="api"`/`job="gateway"`, so the same dashboards and rules work in the cluster.

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
make up         # start Postgres, LocalStack, Keycloak, API, gateway and the observability stack
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
- Grafana: http://localhost:3000 (admin / admin), with Prometheus and Loki already set up and the VaultGate dashboards in the **VaultGate** folder
- Prometheus: http://localhost:9090 (Status → Targets shows every scraped service)
- Alloy pipeline UI: http://localhost:12345

Try the scanner on its own:

```bash
echo "Contact ana@example.com, CPF 529.982.247-25" | (cd scanner && go run ./cmd/scanner)
```

## Roadmap

- [x] **M0 — Foundation:** service skeletons, CI, Helm chart, ArgoCD app, Terraform storage module, local stack
- [ ] **M1 — Identity:** OIDC login with Keycloak, token validation, users and groups in PostgreSQL
  - [x] PostgreSQL persistence layer: users, groups, Alembic migrations
- [x] **M1.5 — Observability:** centralized logging and metrics, so every later milestone ships observable
  - [x] Structured JSON logs from all three services, correlated by request ID
  - [x] Prometheus metrics endpoints on the API and gateway
  - [x] Local stack: Prometheus, Loki (via Grafana Alloy) and Grafana
  - [x] Provisioned Grafana dashboards, alert rules and Kubernetes scrape config
- [ ] **M2 — Streaming vault:** upload intents, chunked envelope encryption, S3 multipart upload, streaming download
- [ ] **M3 — Access policies:** IP range, time window and group rules; deny-by-default evaluation
- [ ] **M4 — PII scanning:** SQS-driven scanner worker, quarantine, card number detector (Luhn)
- [ ] **M5 — Sharing:** signed expiring links, download limits, recipient email verification
- [ ] **M6 — Audit and tracing:** append-only audit log, OpenTelemetry traces across all three services
- [ ] **M7 — Kubernetes end to end:** k3d cluster with ArgoCD syncing this repo, horizontal autoscaling of the gateway
- [ ] **M8 — Load testing:** Locust scenarios with published results (concurrent uploads, gateway memory under load)

## License

MIT. See [LICENSE](LICENSE).

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

They handle different traffic. FastAPI fits the control plane: many small, validated JSON endpoints with an OpenAPI spec. Tornado fits the data plane: `@stream_request_body` processes a multi-gigabyte upload chunk by chunk, so memory stays flat no matter the file size. The gateway never makes authorization decisions; it asks the API to validate a short-lived upload intent first. Full reasoning in [ADR 0001](docs/adr/0001-tornado-and-fastapi.md); how authentication is split between the identity provider and the API is in [ADR 0002](docs/adr/0002-api-as-oidc-resource-server.md).

### Why Go for the scanner?

Scanning is CPU-bound and runs over every byte of every upload. A small, statically compiled Go worker scales independently of the Python services and ships as a distroless image. Detectors require a checksum to pass where the format has one (CPF check digits, Luhn for cards), which keeps false positives low enough to block on.

The scanner reads text out of PDFs, Word, Excel, PowerPoint, OpenDocument and RTF files and emails (.eml, every MIME part decoded, attachments opened), and opens zip archives and documents embedded in documents. Text is decoded before it is scanned: UTF-16 (spreadsheet "Unicode text" exports) and HTML/XML character references such as `&#52;`, so what a viewer shows is what is scanned. PDFs go through PDFium (Chrome's PDF engine) compiled to WebAssembly, so untrusted PDFs are parsed in a memory-isolated sandbox with a memory cap and a time limit. A file it cannot read completely (encrypted, damaged, nested too deep, expanding past its limit) is reported as unscannable, never as clean.

## Security model

- **Authentication:** OIDC authorization code flow with PKCE. The API validates tokens against the issuer's JWKS and checks signature algorithm, issuer, audience and expiry on every request (see [Calling the API](#calling-the-api)).
- **Authorization:** deny by default. Policies are evaluated on every request, not cached in the session.
- **Encryption:** each file gets its own data key from KMS (wrapped key stored, bound to the file through the KMS encryption context) and is encrypted by the gateway as a stream of AES-256-GCM chunks that also detects reordering and truncation ([ADR 0003](docs/adr/0003-vault-object-encryption.md)). S3 server-side encryption and a public access block on top.
- **PII handling:** every upload is scanned, and only a clean file (or one an admin released) can be downloaded ([ADR 0005](docs/adr/0005-pii-scanning-and-quarantine.md)). The worker decrypts files in memory only, and reports finding kinds and counts; matched values are never logged or stored.
- **Containers:** non-root user, read-only root filesystem, all Linux capabilities dropped.
- **Audit:** every security event (uploads, downloads, shares, policy changes, quarantine decisions, refusals) goes to an append-only, hash-chained table: a trigger refuses changes and deletions for every role, and admins can verify the chain ([ADR 0007](docs/adr/0007-audit-log.md)).

## Observability

All services log one JSON object per line (stdout for the API and gateway, stderr for the scanner, whose stdout carries findings):

```json
{"ts": "2026-10-15T01:40:23.250+00:00", "level": "info", "service": "api", "logger": "vaultgate.access", "msg": "request", "request_id": "demo-1", "method": "GET", "path": "/readyz", "status": 200, "duration_ms": 56.79, "client_ip": "127.0.0.1"}
```

- **Request IDs:** every HTTP response carries `X-Request-ID`. A caller-supplied ID is reused if it is 1–64 characters of `[A-Za-z0-9._-]`, otherwise a new one is generated. Pass the same ID from API to gateway to scanner to follow one action across services.
- **Trace IDs:** a line written inside a traced request or scan also carries `trace_id` and `span_id`, which follow the work across services and the scan queue (see [Traces](#traces)).
- **What is never logged:** query strings (they will carry share-link signatures), tokens, file contents, and PII values (the scanner logs counts per kind, never matches).
- **Settings:** `VAULTGATE_LOG_LEVEL` (default `INFO`) and `VAULTGATE_LOG_FORMAT` (`json` by default, `text` for reading in a terminal).

### Metrics

The API, gateway and scanner worker serve Prometheus metrics on a separate port, `VAULTGATE_METRICS_PORT` (default `9100`), so the scrape endpoint is never reachable through the public port.

| Metric | Type | Labels | Service |
|---|---|---|---|
| `vaultgate_http_requests_total` | counter | `method`, `route`, `status` | both |
| `vaultgate_http_request_duration_seconds` | histogram | `method`, `route` | both |
| `vaultgate_http_requests_in_progress` | gauge | | API |
| `vaultgate_gateway_uploads_in_progress` | gauge | | gateway |
| `vaultgate_gateway_upload_bytes_total` | counter | | gateway |
| `vaultgate_gateway_upload_size_bytes` | histogram | | gateway |
| `vaultgate_gateway_upload_failures_total` | counter | `reason` | gateway |
| `vaultgate_gateway_downloads_in_progress` | gauge | | gateway |
| `vaultgate_gateway_download_bytes_total` | counter | | gateway |
| `vaultgate_gateway_download_size_bytes` | histogram | | gateway |
| `vaultgate_gateway_download_failures_total` | counter | `reason` | gateway |
| `vaultgate_api_uploads_abandoned_total` | counter | | API |
| `vaultgate_policy_decisions_total` | counter | `action`, `result`, `checked_by` | API |
| `vaultgate_api_scan_requests_sent_total` | counter | `send` (`first`, `resend`) | API |
| `vaultgate_api_scan_send_failures_total` | counter | | API |
| `vaultgate_api_scan_results_total` | counter | `verdict` | API |
| `vaultgate_api_scans_abandoned_total` | counter | | API |
| `vaultgate_api_downloads_blocked_total` | counter | `verdict`, `checked_by` | API |
| `vaultgate_api_quarantine_releases_total` | counter | `purpose` | API |
| `vaultgate_api_shares_blocked_total` | counter | `verdict`, `checked_by` | API |
| `vaultgate_api_shares_created_total` | counter | `kind` | API |
| `vaultgate_api_shares_revoked_total` | counter | | API |
| `vaultgate_api_share_codes_sent_total` | counter | | API |
| `vaultgate_api_share_verifications_total` | counter | `result` (`ok`, `wrong`, `expired`, `exhausted`) | API |
| `vaultgate_api_share_downloads_total` | counter | | API |
| `vaultgate_api_audit_events_total` | counter | `outcome` | API |
| `vaultgate_api_rescans_total` | counter | | API |
| `vaultgate_scanner_jobs_total` | counter | `outcome` (`clean`, `quarantined`, `unscannable`, `stale`, `retry`, `invalid`) | scanner |
| `vaultgate_scanner_job_duration_seconds` | histogram | | scanner |
| `vaultgate_scanner_text_bytes_total` | counter | | scanner |
| `vaultgate_scanner_jobs_in_progress` | gauge | | scanner |
| `vaultgate_scanner_queue_errors_total` | counter | `op` (`receive`, `delete`, `extend`) | scanner |
| `vaultgate_build_info` | info | `service`, `version` | all |

`route` is the path template (`/uploads/{upload_id}`), never the raw path; anything that matches no route is counted as `<unmatched>`, so clients cannot create new time series by probing URLs. Standard `process_*` and `python_*` metrics are included, which is how gateway memory is shown to stay flat under load.

### Centralized logs

Locally, [Grafana Alloy](https://grafana.com/docs/alloy/) reads the stdout/stderr of every container in the compose project and ships it to Loki. JSON lines get the `service` and `level` labels from their own fields; plain-text logs (Postgres, Keycloak) are labelled with their compose service name. `request_id` is stored as structured metadata, so it is searchable without creating a stream per request. In Grafana → Explore → Loki:

```logql
{service="api", level="error"}                       # API errors
{service=~"api|gateway"} | request_id="<id>"         # one request across services
{service="gateway"} | json | status >= 500           # gateway 5xx with parsed fields
{service=~".+"} | trace_id="<id>"                    # everything one trace logged
```

### Traces

The API, gateway and scanner worker export OpenTelemetry traces over OTLP/HTTP to Alloy, which forwards them to [Grafana Tempo](https://grafana.com/docs/tempo/) ([ADR 0008](docs/adr/0008-tracing.md)). One upload is one trace:

```text
gateway  PUT /uploads/{upload_id}                     vaultgate.file_id, bytes_in, status
├─ gateway  api consume upload
│  └─ api  POST /internal/intents/consume             (and its database queries)
├─ gateway  KMS.GenerateDataKey, S3.UploadPart ...
└─ gateway  api complete
   └─ api  POST /internal/files/{file_id}/complete
      └─ api  scan request send                       trace context in the SQS message
         └─ scanner  scan                              vaultgate.outcome
            ├─ scanner  api scan job → api  GET /internal/scans/{scan_id}
            ├─ scanner  unwrap key, open object, read and detect (format, parts, reads)
            └─ scanner  api scan result → api  POST /internal/scans/{scan_id}/result
```

- **On or off:** tracing is on when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (compose sets `http://alloy:4318`; the Helm chart takes `tracing.otlpEndpoint`), and `OTEL_SDK_DISABLED=true` turns it off.
- **Where traces start:** at a request, a scan request sent, or a scan received. Background loops' queries are not traced, and probes (`/healthz`, `/readyz`) are not either.
- **Trust:** the public API and the gateway ignore a client's `traceparent` and start a new trace; the API's internal port continues the gateway's and the scanner's.
- **What spans never carry:** query strings, tokens, headers, personal data, file contents, SQL parameter values (database spans have the statement only), or error text (dropped before export, as it can quote the value refused).

In Grafana → Explore → Tempo, search by service and span name, or with TraceQL, e.g. `{ span.vaultgate.file_id = "<file id>" }`. A span links to its logs in Loki, and a log line's `trace_id` links back to the trace.

### Dashboards and alerts

Grafana loads the dashboards in `observability/grafana/dashboards/` on startup (edit the JSON in the repo; changes made in the UI are not saved):

- **VaultGate / Service overview:** up/down, request rate, 5xx ratio and latency per service and route, plus recent error logs from Loki.
- **VaultGate / Gateway uploads:** upload throughput, concurrency, size and duration, and gateway memory, which should stay flat however large the uploads are.

Prometheus evaluates the rules in `observability/prometheus/rules/vaultgate.yml`; `make obs-check` runs their unit tests. Under compose, firing alerts show in Prometheus → Alerts. On the local Kubernetes cluster, Alertmanager routes them by email to Mailpit (see [Local Kubernetes](#local-kubernetes-k3d-and-argo-cd)).

| Alert | Fires when | Severity |
|---|---|---|
| `VaultGateTargetDown` | API or gateway metrics unreachable for 2 min | critical |
| `VaultGateTargetMissing` | no API, gateway or scanner target to scrape at all for 5 min (on Kubernetes: scaled to zero, no ready pod, or the ServiceMonitor gone) | critical |
| `VaultGateHighErrorRate` | more than 5% of a service's requests return 5xx for 5 min | critical |
| `VaultGateHighLatency` | p95 of non-upload requests above 1 s for 10 min | warning |
| `VaultGateGatewayMemoryHigh` | gateway resident memory above 200 MiB (limit 256 MiB) for 5 min | warning |
| `VaultGateObservabilityDown` | Loki or Alloy down for 5 min | warning |

In Kubernetes, the Helm chart exposes the metrics port on each Service (never through an Ingress) and adds `prometheus.io/*` pod annotations. With the Prometheus Operator, set `metrics.serviceMonitor.enabled=true` (and `metrics.podAnnotations=false`); the ServiceMonitors keep `job="api"`, `job="gateway"` and `job="scanner"`, so the same dashboards and rules work in the cluster.

## Repository layout

```
api/            FastAPI control plane
gateway/        Tornado streaming gateway
scanner/        Go PII scanner
deploy/
  helm/         Helm chart for the API, gateway and scanner worker
  argocd/       Argo CD applications: an example for a real cluster, the local app of apps
  k3d/          Local cluster: k3d config, Argo CD install, in-cluster dependencies, OpenBao and observability
infra/
  terraform/
    modules/    Reusable modules (storage: S3 + KMS)
    envs/local/ Points the AWS provider at LocalStack
docs/adr/       Architecture decision records
```

## Running locally

Everything runs on your machine at no cost: PostgreSQL, LocalStack (S3, KMS, SQS) and Keycloak run as containers, and Terraform applies against LocalStack instead of a real AWS account.

Requirements: Docker, Python 3.12+, Go 1.26+, Terraform 1.6+. For Kubernetes: k3d 5.8+ and kubectl (see [Local Kubernetes](#local-kubernetes-k3d-and-argo-cd)).

**New here?** [docs/local-testing.md](docs/local-testing.md) lists what to install and what each check proves. `scripts/local_check.sh quick` runs lint and unit tests without Docker, and `scripts/local_check.sh full` checks the whole stack end to end. On Windows, `scripts\local_check.ps1` does the same without Docker Desktop, using Docker Engine in WSL2.

```bash
make up         # start Postgres, LocalStack, Keycloak, API, gateway and the observability stack
make tf-local   # create the S3 bucket and KMS key in LocalStack
make seed-policies  # allow every signed-in user everything (access is denied by default)
make vault-check  # upload and download a file through the whole stack (also runs in CI)
make test       # run all test suites
```

The API applies its database migrations (Alembic) on startup. To run them by hand against a local Postgres, use `make migrate`. API database tests need a disposable database:

```bash
VAULTGATE_TEST_DATABASE_URL=postgresql+asyncpg://vaultgate:vaultgate@localhost:5432/vaultgate_test make test
```

- API docs: http://localhost:8000/docs (readiness: http://localhost:8000/readyz)
- Gateway health: http://localhost:8888/healthz
- Keycloak admin: http://localhost:8080 (admin / admin), realm `vaultgate`
- Grafana: http://localhost:3000 (admin / admin), with Prometheus, Loki and Tempo already set up and the VaultGate dashboards in the **VaultGate** folder
- Prometheus: http://localhost:9090 (Status → Targets shows every scraped service)
- Alloy pipeline UI: http://localhost:12345

### Local identity provider

`make up` starts Keycloak with the `vaultgate` realm from `infra/keycloak/vaultgate-realm.json`, re-imported on every start:

- **`vaultgate-web`**: public client for the web app and CLI. Authorization code flow with PKCE (S256) only; password grant and implicit flow are disabled, and only the registered redirect URIs are accepted.
- **`vaultgate-api`**: the API as a resource server. Access tokens for `vaultgate-web` carry `aud: vaultgate-api`, a `groups` claim with full group paths, and live 5 minutes.
- **Issuer:** always `http://localhost:8080/realms/vaultgate`, also for containers that reach Keycloak as `keycloak:8080`.
- Brute-force protection is on, and passwords need at least 12 characters.

Seed users, **for local development only**:

| User | Password | Groups |
|---|---|---|
| alice | `alice-dev-password` | `/finance` |
| bob | `bob-dev-password` | `/legal` |
| carol | `carol-dev-password` | `/engineering`, `/vaultgate-admins` |

`make auth-check` (also run in CI) starts Keycloak and the API, logs in as each user through the real PKCE flow, and checks the token's issuer, audience, lifetime and groups. It then calls the API's `GET /me` with the access token (accepted, returning the provisioned user) and the ID token (refused, wrong audience), checks that `/admin/users` is refused for alice and lists every user for carol, and checks that password grant, requests without PKCE and unknown redirect URIs are refused.

### Calling the API

Get a token in the browser and call the API with it (details in [docs/authentication.md](docs/authentication.md)):

```bash
TOKEN=$(make -s token)    # log in as alice, bob or carol
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/me
```

Every API route except `/healthz`, `/readyz` and the OpenAPI docs requires `Authorization: Bearer <access token>`. A token is accepted only when:

- it is signed with an asymmetric algorithm (`RS256` by default; `none` and HMAC are never accepted) by a key from the provider's JWKS;
- `iss` equals `VAULTGATE_OIDC_ISSUER` and `aud` contains `VAULTGATE_OIDC_AUDIENCE`;
- `exp`, `iat` and `sub` are present and the token is within its validity window (30 s clock leeway).

Missing or invalid tokens get `401` with a `WWW-Authenticate: Bearer` challenge; if the provider's keys cannot be fetched at all, `503`. Rejections are logged with a reason (never the token) and counted in `vaultgate_auth_failures_total{reason}`. Keys are cached for 5 minutes; an unknown key ID triggers a refresh for key rotation, at most once every 30 s.

### Users and groups

The identity provider is the source of truth. On every authenticated request the API looks up the caller by `(issuer, subject)` and creates or updates their record to match the token: login name, email and display name, and group memberships, which are set to exactly the token's `groups` (groups are created the first time any token names them). Unchanged callers cost one read; `last_login_at` is refreshed at most every 5 minutes.

- `GET /me` returns the caller's stored record: `id`, `issuer`, `subject`, `username`, `email`, `name`, `groups`, `is_active`, `created_at`, `last_login_at`.
- A user whose `is_active` is set to false in the database is refused with `403` even with a valid token: a local kill switch that works without touching the identity provider.
- `GET /admin/users`, `GET /admin/users/{id}` and `GET /admin/groups` (with member counts) are read-only and paginated (`limit` up to 100, `offset`). They require membership in one of `VAULTGATE_ADMIN_GROUPS` (default `["/vaultgate-admins"]`), so admin rights are granted and revoked in the identity provider.

### Files and transfer intents

The API owns file metadata and decides who may move which bytes; the gateway only moves them (ADR 0001).

- `POST /files` with `{name, size, content_type}` registers a file and returns a **single-use upload intent**: the gateway URL (`/uploads/{file_id}`), a token and its expiry (15 minutes, `VAULTGATE_UPLOAD_INTENT_TTL_SECONDS`). Sizes above `VAULTGATE_MAX_UPLOAD_BYTES` (5 GiB) get `413`; a user with `VAULTGATE_MAX_OPEN_UPLOADS_PER_USER` (20) live uploads gets `429` (abandoned ones do not count: a pending file whose intent expired, or an upload started more than `VAULTGATE_UPLOAD_STALE_AFTER_SECONDS`, 6 h, ago). Names are display names only: path separators and control characters are rejected, and the object key is always `files/<id>`.
- `GET /files` and `GET /files/{id}` show the caller's own files. Another user's file is reported as `404`, exactly like a missing one.
- Intent tokens are 256 random bits, shown once. Only their SHA-256 is stored. Each is bound to one file and one direction, and is consumed atomically, so two concurrent uses cannot both succeed.
- **Internal API** (port `VAULTGATE_INTERNAL_PORT`, 8001): the gateway calls `POST /internal/intents/consume` before accepting any bytes, then `POST /internal/files/{id}/complete` (size, SHA-256, KMS-wrapped data key) or `/fail`. Every call needs `Authorization: Bearer $VAULTGATE_INTERNAL_TOKEN`; with no token configured the internal API refuses everything. It has no OpenAPI docs and is never published on the host or through an ingress.

File statuses: `pending` (intent issued) → `uploading` (gateway consumed the intent) → `uploaded` or `failed`. Every `VAULTGATE_UPLOAD_SWEEP_INTERVAL_SECONDS` (5 min) the API marks abandoned uploads (the ones the per-user cap ignores) `failed`.

### Uploading through the gateway

```bash
curl -T report.pdf -H "Authorization: Bearer $UPLOAD_TOKEN" http://localhost:8888/uploads/$FILE_ID
# 201 {"file_id": "...", "size": 1234, "sha256": "..."}
```

The body is the raw file, exactly the size declared in `POST /files`. The gateway consumes the intent before reading a byte, gets a data key from KMS, encrypts the stream as it arrives (ADR 0003) and writes it to S3 as a multipart upload in `VAULTGATE_PART_SIZE` parts (8 MiB), so memory per upload stays at about one part. Then it reports size, SHA-256 and the wrapped key to the API.

| Response | Meaning |
|---|---|
| `401` | no bearer token |
| `403` | token unknown, already used, expired, or for another file |
| `400` / `413` | fewer / more bytes than declared |
| `409` | the API refused the result (e.g. the upload was swept as abandoned) |
| `503` | API, KMS or S3 unavailable |

On any failure after the intent is consumed, the multipart upload is aborted and the file is marked `failed`, so a partial object never appears. Reporting the finished upload is retried (`/complete` is idempotent for the same result); if the API still cannot confirm it, the object is kept, because the API may have recorded it before its answer was lost. The token is spent either way: retrying means a new `POST /files`. If the gateway dies mid-upload, the API sweep marks the file failed and the bucket's lifecycle rule deletes the orphaned parts after a day.

### Downloading

```bash
curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8000/files/$FILE_ID/download
# 201 {"url": "http://localhost:8888/downloads/<id>", "token": "...", "expires_at": "..."}
curl -OJ -H "Authorization: Bearer $DOWNLOAD_TOKEN" http://localhost:8888/downloads/$FILE_ID
```

Only the owner gets a download intent, and only for an `uploaded` file whose PII scan is clean or released ([PII scanning](#pii-scanning)). It is single use and lasts 5 minutes (`VAULTGATE_DOWNLOAD_INTENT_TTL_SECONDS`). The gateway consumes it, has KMS unwrap the file's data key (bound to the file ID), and streams the object from S3, decrypting in `VAULTGATE_READ_SIZE` pieces (256 KiB). It waits for each piece to reach the client before reading the next, so a slow client never makes the gateway buffer the file. In a local run, a 100 MiB download raised the gateway's resident memory from 64 to 74 MiB, at full speed and throttled alike.

The response is always an attachment (`Content-Disposition` with the original UTF-8 name, `nosniff`, a sandboxing CSP, `no-store`) with `Content-Length` and `Repr-Digest` (SHA-256 of the file, RFC 9530). If the stored object fails authentication, is truncated, or does not match the recorded size, the gateway closes the connection mid-body instead of finishing it. Because `Content-Length` is already sent, the client sees an incomplete download, never a damaged file that looks whole. Range requests are not supported yet.

Gateway settings (all `VAULTGATE_`-prefixed): `API_INTERNAL_URL`, `INTERNAL_TOKEN` (required), `BUCKET`, `KMS_KEY_ID` (`alias/vaultgate-local`), `AWS_REGION`, `AWS_ENDPOINT_URL` (LocalStack), `MAX_UPLOAD_BYTES`, `PART_SIZE`, `READ_SIZE`. In compose, run `make tf-local` once so the bucket and key alias exist.

`VAULTGATE_OIDC_DISCOVERY_URL` sets where the API fetches discovery and keys when that differs from the public issuer (in compose: `http://keycloak:8080/...`, because `localhost` inside the API container is the API itself).

Try the scanner on its own:

```bash
echo "Contact ana@example.com, CPF 529.982.247-25, card 4111 1111 1111 1111" | (cd scanner && go run ./cmd/scanner)
(cd scanner && go run ./cmd/scanner internal/extract/testdata/report.pdf)   # any document; exit status 3 if it cannot be scanned
```

### Access policies

Deny by default: a user may `read` (list and view their files), `upload`, `download` or `share` only when an enabled **allow** policy matches and no **deny** policy does ([ADR 0004](docs/adr/0004-access-policies.md)). A policy names its actions and any of these conditions, all of which must hold:

- `groups`: the user is in one of them or a subgroup (`/finance` covers `/finance/payroll`);
- `networks` / `excluded_networks`: the client address is in one of `networks` and in none of `excluded_networks`;
- `days` (1 = Monday ... 7 = Sunday) and `start_time` / `end_time` in `timezone` (IANA name). A window that ends before it starts runs overnight and belongs to the day it starts.

Admins (`VAULTGATE_ADMIN_GROUPS`) manage them at `/admin/policies`: list, `POST`, `GET`, `PUT` (replaces the whole policy) and `DELETE`. `/admin` and `/me` are never subject to policies, so admins can't lock themselves out. Changes apply on the next request. `POST /admin/policies/evaluate` is a dry run: it shows how a request would be decided and which policies matched.

```bash
ADMIN=$(python3 scripts/vaultgate_login.py --switch-user)   # log in as carol
curl -X POST http://localhost:8000/admin/policies -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" -d '{
    "name": "finance office hours", "effect": "allow", "actions": ["read", "upload", "download"],
    "groups": ["/finance"], "networks": ["10.0.0.0/8"], "days": [1, 2, 3, 4, 5],
    "start_time": "08:00", "end_time": "18:00", "timezone": "America/Sao_Paulo"}'
curl -X POST http://localhost:8000/admin/policies/evaluate -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"action": "download", "groups": ["/finance"], "client_ip": "10.1.2.3"}'
# {"allowed": true, "reason": "allowed", "deny": [], "allow": ["finance office hours"], ...}
```

**Enforcement.** Listing and viewing files (`GET /files`, `GET /files/{id}`) needs `read`, `POST /files` needs `upload` and `POST /files/{id}/download` needs `download`, checked before anything else, so a refused caller can't probe file IDs either. The gateway's intent consume checks `upload` or `download` again, for the intent's user, with the client address the gateway saw ([Client addresses](#client-addresses-behind-a-proxy)). A token obtained from an allowed network, or inside a time window, is refused from elsewhere or later; the refusal does not spend it. Intents of a deactivated user are refused too. A client address that can't be determined satisfies no network condition: an allow policy with networks doesn't match it, and a deny policy with networks or exclusions does.

Refusals are a plain `403 Access denied by policy`. The log line `access denied by policy` names the matching deny policies (or none, when nothing allowed the request), and `vaultgate_policy_decisions_total{action, result, checked_by}` counts every decision, by the API (`api`) and at the gateway's consume (`gateway`).

**Upgrading:** an installation without policies refuses every file request until an admin adds an allow policy. Locally, `make seed-policies` (and `make vault-check`, and `local_check full`) adds one that allows every signed-in user everything; never use it elsewhere.

### PII scanning

Every completed upload is scanned for personal data (M4). The API keeps the scan state; the Go scanner reads the file.

- When the gateway reports an upload complete, the file gets a scan request (a new `scan_id`), and the API sends `{"file_id", "scan_id"}` to the SQS queue in `VAULTGATE_SCAN_QUEUE_URL`. The database is the record of what still needs scanning; the queue only delivers it. A request that never reached the queue, or got no result within `VAULTGATE_SCAN_RESEND_AFTER_SECONDS` (15 min), is sent again, checked every `VAULTGATE_SCAN_RESEND_INTERVAL_SECONDS` (1 min). After `VAULTGATE_SCAN_MAX_ATTEMPTS` (5) sends with no result the file is marked unscannable. With no queue configured nothing is sent and files stay pending. In compose, `make tf-local` creates the queue.
- The scanner uses two internal routes, with its own secret (`Authorization: Bearer $VAULTGATE_SCANNER_TOKEN`; the gateway's secret does not open them, nor this one the gateway's): `GET /internal/scans/{scan_id}` returns the object key and the KMS-wrapped data key, and `POST /internal/scans/{scan_id}/result` records `{"outcome": "scanned" | "unscannable", "findings": [{"kind", "count"}], "reason"}`. Repeating the recorded result succeeds; a different one, or a result for a scan that was replaced, is refused.
- Only the kind of personal data and how many matches were found are stored, never the matches or where they are. `GET /files/{id}` shows them in `scan`: `{verdict, findings, reason, scanned_at}`.
- The **scanner worker** (`scanner/cmd/worker`) takes requests from the queue. For each it fetches the scan job, has KMS unwrap the data key (bound to the file ID, as for downloads), and reads the object from S3 with range requests, decrypting chunks in memory as the text extraction needs them: plaintext never touches disk. A stored object that fails authentication, or does not match its recorded size, is reported unscannable. Failures that say nothing about the file (the API, KMS or S3 unreachable, a timeout) leave the message in the queue: it comes back after the visibility timeout, and after 5 deliveries moves to the dead-letter queue (`infra/terraform/modules/scanning`), while the API's resender keeps its own count. While a scan runs, the worker renews the message's visibility, so no other worker picks it up. Settings: `VAULTGATE_SCAN_QUEUE_URL`, `VAULTGATE_API_INTERNAL_URL`, `VAULTGATE_SCANNER_TOKEN`, `VAULTGATE_BUCKET`, `VAULTGATE_AWS_REGION`, `VAULTGATE_AWS_ENDPOINT_URL`, `VAULTGATE_SCANNER_CONCURRENCY` (2), `VAULTGATE_SCAN_TIMEOUT_SECONDS` (600), `VAULTGATE_SCAN_VISIBILITY_SECONDS` (120). It stops on SIGTERM after finishing the scans in progress.
- Verdicts: `pending`, `clean`, `quarantined` (a finding of a kind in `VAULTGATE_QUARANTINE_KINDS`, default `payment_card,br_cpf`; `email` is only recorded) and `unscannable` (with the reason, such as an encrypted PDF). They are worked out when read, so changing the quarantine kinds applies to files already scanned.

**Quarantine** ([ADR 0005](docs/adr/0005-pii-scanning-and-quarantine.md)) is fail closed. A file is **shared** only with a `clean` verdict, whatever the settings. What the owner may **download** depends on `VAULTGATE_QUARANTINE_BLOCKS`:

- `download` (the default): only a `clean` file. `POST /files/{id}/download` answers `409` with the reason for a pending, quarantined or unscannable one;
- `share`: any verdict. Owners take their own files back; nothing flagged leaves to anyone else.

The gateway's intent consume checks again, so a verdict that changes after the intent was issued still applies (the refused intent stays unspent). `GET /files/{id}` shows `downloadable` and `shareable`. Admins (`VAULTGATE_ADMIN_GROUPS`) decide on exceptions:

- `GET /admin/files?verdict=quarantined` lists every user's files with a verdict (all of them without `verdict`), with their owner.
- `POST /admin/files/{id}/release` with `{"reason": "...", "purpose": "download" | "share"}` (default `download`) lets the owner download a quarantined or unscannable file, or lets it be shared. Each purpose is released on its own, with its reason; a release for download does not make a file shareable. The verdict and findings stay; the file lists `scan.releases`, and each release records the admin who gave it.
- `POST /admin/files/{id}/rescan` scans the file again: new request, findings dropped, every release ended.

Files uploaded before scanning existed are scanned too: the upgrade gives them a pending scan, sent on the resender's first round. **Upgrading:** they cannot be downloaded until that scan is clean.

To try the scanner and the scan state by hand, see [Try the PII scanner](docs/local-testing.md#try-the-pii-scanner).

### Sharing

The owner of a file shares it with one recipient, named by email address (M5):

- `POST /files/{id}/shares` with `{"recipient_email", "recipient_kind": "external" | "internal", "expires_in_days", "max_downloads"}` needs the `share` action and a file the scan allows to be shared. It returns the share and its link, whose token is shown only then; only the token's SHA-256 is stored. An **external** recipient proves the address with a code sent to it (below); an **internal** one signs in, with a verified email equal to the address (below). See [ADR 0006](docs/adr/0006-sharing.md).
- Links last 7 days (`VAULTGATE_SHARE_DEFAULT_DAYS`, at most `VAULTGATE_SHARE_MAX_DAYS`, 30) and allow 5 downloads (`VAULTGATE_SHARE_DEFAULT_DOWNLOADS`, at most `VAULTGATE_SHARE_MAX_DOWNLOADS`, 100); the owner chooses within those bounds. A file has at most `VAULTGATE_MAX_ACTIVE_SHARES_PER_FILE` (50) usable shares at once.
- `GET /files/{id}/shares` lists them with their state (`active`, `expired`, `used`, `revoked`); `DELETE /files/{id}/shares/{share_id}` revokes one at once. Revoking needs only ownership, so a user who may no longer share can still take links back.
- The token travels in the link's query string (`.../shares/access?token=...`), which is never logged. Logs name the share, never the recipient's address.

**External recipients** have no account. The link's token and a code sent to the address authorize them, on public routes:

1. `GET /shares/access?token=...` tells what the link is: the kind of recipient, a hint of the address (`b***@example.com`), the expiry and the downloads left. Nothing about the file before the address is proven.
2. `POST /shares/access/code` with `{"token"}` emails a 6-digit code to the address. It lasts 10 minutes (`VAULTGATE_SHARE_CODE_TTL_SECONDS`) and allows 5 tries (`VAULTGATE_SHARE_CODE_ATTEMPTS`). At most 5 codes per share an hour (`VAULTGATE_SHARE_CODE_SENDS_PER_HOUR`), 60 s apart (`VAULTGATE_SHARE_CODE_RESEND_SECONDS`), and 50 an hour across one owner's shares (`VAULTGATE_SHARE_CODES_PER_OWNER_PER_HOUR`); more get `429`. The email is fixed text with only the code: nothing a user typed (file name, display name) goes into a message VaultGate sends to an address they chose.
3. `POST /shares/access/verify` with `{"token", "code"}` returns a **grant**, shown once, that lasts 30 minutes (`VAULTGATE_SHARE_GRANT_TTL_SECONDS`). A code works once.
4. `POST /shares/access/downloads` with `{"token", "grant"}` returns a single-use download intent for the gateway, as for an owner's download.

Codes and grants are stored as hashes. Every step re-checks that the share is active and that the scan lets the file be shared, and the gateway's consume checks again and counts the download against the share. A revoke, an expiry, the last download or a rescan into quarantine therefore applies at once, also to grants and intents already handed out; a deactivated owner ends their shares too. The owner's own access policies (networks, hours) do not govern the recipient: the owner decided when sharing, and revokes the link to end it.

**Internal recipients** are VaultGate users. They sign in as for anything else; a share is theirs when its address is the verified email in their token (OIDC `email_verified`), so no code is needed and the link grants nothing by itself:

- `GET /shared-with-me` lists the active shares addressed to the caller, with the file name, who shared it, the expiry, the downloads left and whether the file is `available` now (its scan allows sharing). It needs the caller's `read` action.
- `POST /shared-with-me/{share_id}/download` returns a download intent for the gateway. It needs the caller's `download` action: unlike an outside recipient, a VaultGate user stays under their own access policies, checked again at the gateway with the address it sees.
- The gateway also checks that the share is active, the owner active, the scan allows sharing and the recipient's verified email is still the share's address, then counts the download. Someone else's share, or one for an unverified address, is reported as not found.

Email goes through SMTP: `VAULTGATE_SMTP_HOST`, `VAULTGATE_SMTP_PORT` (25), `VAULTGATE_SMTP_STARTTLS`, `VAULTGATE_SMTP_USERNAME` / `VAULTGATE_SMTP_PASSWORD`, `VAULTGATE_SMTP_FROM`. Without a host, codes can't be sent (`503`). In compose, [Mailpit](https://mailpit.axllent.org/) catches every message: http://localhost:8025.

**Upgrading:** existing policies keep their actions, so sharing is denied until an admin adds `share` to a policy (`make seed-policies` updates the local one).

### Audit log

Security events are recorded in `audit_events` ([ADR 0007](docs/adr/0007-audit-log.md)): who (a user, an outside recipient, the gateway, the scanner, the system), did what (`file.registered`, `upload.started`, `upload.completed`, `scan.result`, `download.issued`, `download.started`, `share.created`, `share.code_sent`, `share.verified`, `share.downloaded`, `share.revoked`, `quarantine.released`, `scan.rescan_requested`, `policy.created`, `user.created`, ...), to what, with which outcome, from which address and in which request (`request_id`, as in the access logs). Refusals are recorded too (`access.denied`, `intent.refused`, `download.refused`, `share.verification_failed`, `share.download_refused`, ...), although the attempt itself is rolled back. Refusals anyone could repeat without limit are not: a forged or unknown intent token, a wrong grant on a share link, or a code check when no code is outstanding go to the logs and metrics only, so they can't grow the permanent log.

- An event is written in the same transaction as the action it records: both are stored or neither.
- The table is append-only: a trigger refuses `UPDATE`, `DELETE` and `TRUNCATE` for every role, the table's owner included.
- Each event stores a SHA-256 over its fields and the previous event's hash. `POST /admin/audit/verify` walks the chain and reports the first event that was changed, or whose predecessor was removed. Every `VAULTGATE_AUDIT_ANCHOR_INTERVAL_SECONDS` (5 min) the API logs the head of the chain (`audit head` in Loki), so even the newest events can't be rewritten without disagreeing with the logs.
- `GET /admin/audit` lists events, newest first, filtered by `action` (exact, or a prefix such as `share.`), `actor_id`, `target_id`, `outcome`, `since` and `until`. Admins only.
- No file content and no PII the scanner found is ever recorded, only kinds and counts. Recipients' addresses are, with the shares they belong to: the log has to answer who received a file.

**Upgrading:** the log starts empty; events from before this version are not reconstructed.

### Deploying to Kubernetes

`deploy/helm/vaultgate` deploys the API, the gateway and the scanner worker. PostgreSQL, S3, KMS, SQS, the OIDC provider and SMTP are not part of the chart: its values point at them (`aws.*`, `storage.*`, `scanQueueUrl`, `api.oidc.*`, `api.smtp.*`; any other setting goes in `api.env`, `gateway.env` or `scanner.env` as `VAULTGATE_*: value`).

- **Credentials** come from one Secret (`secrets.name`) with the keys `database-url`, `internal-token`, `scanner-token` and, unless the pods have an AWS identity of their own, `aws-access-key-id` and `aws-secret-access-key`. Create it out of band (External Secrets, Sealed Secrets, Vault). `secrets.create=true` makes the chart create it from values, for local clusters only.
- **Ingress** (`ingress.enabled`): the API's and the gateway's public ports, on `ingress.apiHost` and `ingress.gatewayHost`. Set `api.publicUrl` and `api.gatewayPublicUrl` to those addresses, since links and intents carry them, and `trustedProxies` to the ingress controller's pod range. Outside a local cluster, set `ingress.tls` (Ingress `spec.tls`, e.g. with cert-manager): bearer tokens and files must not travel over plain HTTP. The API's internal port and the metrics ports stay in-cluster.
- **Autoscaling** (`gateway.autoscaling.enabled`): a HorizontalPodAutoscaler scales the gateway on CPU (70% of its request, 2 to 6 pods), which follows the bytes it encrypts and decrypts. It scales down one pod a minute after five quiet minutes, and a stopping pod gets two minutes to finish its transfers.
- **Network policies** (`networkPolicy.enabled`): only the gateway and the scanner may reach the API's internal port, which hands out storage keys and wrapped data keys. The public and metrics ports stay open.
- **Hardening, always on:** non-root, read-only root filesystem, no capabilities, no service account token, and a disruption budget of one pod at a time for the API and the gateway.

CI lints the chart and checks the rendered manifests against the Kubernetes schemas with the default values, the local cluster's (`values-k3d.yaml`) and every option on.

### Local Kubernetes (k3d and Argo CD)

`make k3d-up` runs the whole system on a local Kubernetes cluster, deployed the GitOps way ([ADR 0009](docs/adr/0009-local-kubernetes.md)). Stop compose first: the cluster uses the same host ports.

1. k3d creates the cluster `vaultgate` (`deploy/k3d/cluster.yaml`), with its own image registry at `localhost:5050`.
2. The API, gateway and scanner images are built from your working tree and pushed there.
3. The root CA is created, unless you have one ([ADR 0012](docs/adr/0012-pki-and-key-management.md)). It is kept in `~/.vaultgate/pki`, outside the cluster, with its key encrypted by a passphrase: `k3d-up` asks for it, or reads `VAULTGATE_PKI_PASSPHRASE`. The root signs OpenBao's TLS certificate, which goes into the cluster as a Secret next to OpenBao's seal key.
4. Argo CD is installed (`deploy/k3d/argocd`), and a root application hands it this repo at `VAULTGATE_REVISION` (default: the current branch, which must be pushed). From then on Argo CD syncs everything from git:
   - the dependencies (`deploy/k3d/deps`: PostgreSQL, LocalStack, Keycloak, Mailpit) into `vaultgate-deps`;
   - OpenBao (`deploy/k3d/openbao`), the certificate authority and secret store, into `openbao`; it configures itself on first start;
   - cert-manager and trust-manager, the upstream charts at pinned versions, and `deploy/k3d/pki`: the `vaultgate-ca` issuer, which signs through OpenBao, and the trust bundle with the root, in every namespace;
   - the observability ([ADR 0010](docs/adr/0010-cluster-observability.md)) into `monitoring`:
     - kube-prometheus-stack, the upstream chart at a pinned version, with `deploy/k3d/kube-prometheus-stack.yaml`: the Prometheus Operator, Prometheus, Alertmanager and Grafana;
     - `deploy/k3d/observability`: Loki, Tempo and Alloy, and VaultGate's alert rules, dashboards and data sources, all from the files compose uses;
   - then the chart with `values-k3d.yaml` into `vaultgate`, with ServiceMonitors, traces to Alloy, and TLS: day-long certificates from `vaultgate-ca` for the API and the gateway, renewed and reloaded as they run.
5. The PKI ceremony installs the intermediate CA (`scripts/pki.py intermediate`) as soon as OpenBao is up. OpenBao generates the key, which never leaves it, and a CSR. The root signs the CSR on your machine, and OpenBao installs the certificate. Then the root's certificate goes to cert-manager, whose issuer can sign from then on.
6. Terraform creates the bucket, key and queues in the cluster's LocalStack, and the local access policy is seeded.

Everything answers where compose does:

- the API on https://localhost:8000 and the gateway on https://localhost:8888, over TLS that verifies against `~/.vaultgate/pki/root-ca.crt` (`curl --cacert`, or `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`); Keycloak on 8080, LocalStack on 4566 and Mailpit on 8025;
- Grafana on 3000 (admin / admin), Prometheus on 9090, Loki on 3100 and Tempo on 3200;
- and, new on the cluster, Alertmanager on 9093 and OpenBao on https://localhost:8200 (its certificate verifies against `~/.vaultgate/pki/root-ca.crt`).

Alertmanager routes every alert by email to Mailpit: `oncall@vaultgate.local` for the alerts, `heartbeat@vaultgate.local` for Watchdog, which always fires and so shows the whole path works. Then:

```bash
make k3d-check     # vault e2e against the cluster, traces included; Argo CD synced, OpenBao and its CA, TLS, autoscaler, network policy, scrape targets, dashboards, Alertmanager mail
make k3d-images    # after a code change: rebuild, push, restart the pods
make k3d-down      # delete the cluster
kubectl -n argocd port-forward svc/argocd-server 8081:80   # Argo CD UI on http://localhost:8081, user admin, password below
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d
kubectl -n vaultgate get hpa,pods                          # the gateway's autoscaler and the pods
```

Chart or manifest changes reach the cluster when they are pushed: Argo CD looks every minute. Code changes reach it with `make k3d-images`. CI runs `k3d-up` and `k3d-check` on every PR, syncing the PR's commit.

### Load testing

Locust scenarios in `loadtest/` run against the local cluster ([ADR 0011](docs/adr/0011-load-testing.md)). Each simulated user logs in as its own load user (`load-001` ... `load-050`, the `/load` group) through `vaultgate-load`, a local-only Keycloak client with the password grant. The web client stays PKCE-only.

- **Transfers:** streaming uploads of 256 KiB to 128 MiB through the gateway, a wait for the scan's verdict, and the download back, checked by size.
- **ControlPlane:** the API's small requests: `/me`, listing and reading files, download intents (policy and quarantine checks).
- **Documents:** PDF and Office files and 8 MiB text files, timed from the end of the upload to the scanner's verdict (reported as `SCAN`, next to the HTTP requests).

```bash
pip install -r loadtest/requirements.txt
make k3d-up
make load-smoke    # 6 users, 90 s, uploads up to 32 MiB, with pass/fail thresholds (CI runs it)
make load-test     # 20 users, 6 minutes, uploads up to 128 MiB; CSV and HTML in loadtest/results/
make load-report   # the same run, then docs/load-testing.md and its charts
```

`loadtest/check.py` passes a run when:

- no request failed: errors, short downloads and scans with no verdict all count;
- every scenario did its work;
- no gateway pod went above 90% of its 256 MiB memory limit, according to the cluster's Prometheus;
- no VaultGate pod restarted.

Latency is reported, not enforced: a shared CI runner varies too much. The published numbers are in **[docs/load-testing.md](docs/load-testing.md)**: throughput, latency, scan times, gateway memory and its autoscaling, from a full run on a GitHub runner. The `load-report` workflow regenerates them whenever the load tests change.

### Client addresses behind a proxy

Access policies can restrict by network (M3), so the API and the gateway must know the real client address. They take it from `X-Forwarded-For` only when the request comes from a proxy listed in `VAULTGATE_TRUSTED_PROXIES`, a comma-separated list of networks (for example the ingress controller's pod range). The header is read from the right, skipping trusted hops; the first other address is the client. With the list empty (the default, and what compose uses), the header is ignored and the TCP peer is the client. List proxy addresses only: a client inside a trusted range can claim any address. If a trusted proxy passes on something that isn't an address, the client counts as unknown rather than as the proxy. Logs record the resolved address as `client_ip`.

## Roadmap

- [x] **M0 — Foundation:** service skeletons, CI, Helm chart, ArgoCD app, Terraform storage module, local stack
- [x] **M1 — Identity:** OIDC login with Keycloak, token validation, users and groups in PostgreSQL
  - [x] PostgreSQL persistence layer: users, groups, Alembic migrations
  - [x] Local Keycloak realm: PKCE-only public client, API audience, group claims, seed users
  - [x] Bearer token validation (JWKS, issuer, audience, expiry), deny-by-default routes, `GET /me`
  - [x] Just-in-time user provisioning and group sync from tokens; read-only admin endpoints
  - [x] Terminal login helper (`make token`) and [authentication docs](docs/authentication.md)
- [x] **M1.5 — Observability:** centralized logging and metrics, so every later milestone ships observable
  - [x] Structured JSON logs from all three services, correlated by request ID
  - [x] Prometheus metrics endpoints on the API and gateway
  - [x] Local stack: Prometheus, Loki (via Grafana Alloy) and Grafana
  - [x] Provisioned Grafana dashboards, alert rules and Kubernetes scrape config
- [x] **M2 — Streaming vault:** upload intents, chunked envelope encryption, S3 multipart upload, streaming download
  - [x] Files and single-use upload intents in the API; internal API for the gateway
  - [x] Envelope encryption library: KMS data key per file, chunked AES-256-GCM ([ADR 0003](docs/adr/0003-vault-object-encryption.md))
  - [x] Gateway uploads: intent check, on-the-fly encryption, S3 multipart upload; abandoned-upload cleanup
  - [x] Streaming downloads: single-use download intents, on-the-fly decryption with backpressure
  - [x] End-to-end check in CI: Keycloak login, upload, ciphertext in S3, download, refusals ([`scripts/vault_e2e.py`](scripts/vault_e2e.py))
- [x] **M3 — Access policies:** IP range, time window and group rules; deny-by-default evaluation
  - [x] Policy model and evaluator: deny by default, deny wins, groups, networks and time windows ([ADR 0004](docs/adr/0004-access-policies.md))
  - [x] Trusted client addresses: `X-Forwarded-For` only from configured proxies, in the API and the gateway
  - [x] Admin API for policies, with a dry run that explains a decision
  - [x] Enforcement on file reads and transfer intents, re-checked by the gateway; seed policy for local use and CI
- [x] **M4 — PII scanning:** SQS-driven scanner worker, quarantine, card number detector (Luhn)
  - [x] Payment card detector (Luhn and card network ranges) and a streaming scan that holds one window in memory
  - [x] Decrypting stored objects (VGE1) in Go, checked against vectors from the Python implementation
  - [x] Text extraction from Office documents and PDFs, with size and expansion limits
  - [x] Scan state in the API: status and findings per file, results endpoint, SQS events, re-sending stuck scans
  - [x] Scanner worker: SQS consumer, queue and dead-letter queue in Terraform, compose service, metrics
  - [x] Quarantine: downloads need a clean scan; admin release and rescan; end-to-end check ([ADR 0005](docs/adr/0005-pii-scanning-and-quarantine.md))
- [x] **M5 — Sharing:** signed expiring links, download limits, recipient email verification
  - [x] Scanner reads more encodings: UTF-16 text (spreadsheet "Unicode text" exports), HTML/XML character references, RTF escapes, base64 email attachments
  - [x] Quarantine scope setting, `VAULTGATE_QUARANTINE_BLOCKS`: `download` (default; flagged files are neither downloaded nor shared) or `share` (the owner may download, nothing is shared); per kind later if needed
  - [x] Share links for owners: create (by email, external or internal recipient), list, revoke; the `share` policy action
  - [x] Releases scoped by purpose (download, share), each with its reason; a rescan still ends every release
  - [x] External recipients: a one-time code sent to the address (Mailpit locally), then a download through the gateway, counted against the share's limits
  - [x] Internal recipients: sign in; the token's verified email must be the share's address
  - [x] End-to-end check of both recipient flows; [ADR 0006](docs/adr/0006-sharing.md)
- [x] **M6 — Audit and tracing:** append-only audit log, OpenTelemetry traces across all three services
  - [x] Audit log: security events in an append-only, hash-chained table; admin listing and chain verification; the chain's head logged as an anchor ([ADR 0007](docs/adr/0007-audit-log.md))
  - [x] Traces: OpenTelemetry in the API, gateway and scanner worker, through Alloy to Grafana Tempo, linked to the logs both ways; the e2e check follows an upload to its scan ([ADR 0008](docs/adr/0008-tracing.md))
- [x] **M7 — Kubernetes end to end:** k3d cluster with ArgoCD syncing this repo, horizontal autoscaling of the gateway
  - [x] Helm chart for all three services: configuration and credentials, optional ingress, CPU autoscaling of the gateway, network policies, disruption budgets, schema checks in CI
  - [x] Local k3d cluster: the dependencies in-cluster, images from a local registry, Argo CD syncing this repo, the end-to-end check against it in CI ([ADR 0009](docs/adr/0009-local-kubernetes.md))
  - [x] Cluster observability through Argo CD: Prometheus Operator, Grafana, Loki, Tempo and Alloy with the repo's dashboards and rules, Alertmanager routing to email ([ADR 0010](docs/adr/0010-cluster-observability.md))
- [x] **M8 — Load testing:** Locust scenarios with published results (concurrent uploads, gateway memory under load)
  - [x] Scenarios for transfers, the API control plane and scanner throughput; local-only load users; a smoke run with thresholds in CI ([ADR 0011](docs/adr/0011-load-testing.md))
  - [x] Published report ([docs/load-testing.md](docs/load-testing.md)): the full run on the cluster, with throughput, latency, scan times, gateway memory and autoscaling
- [ ] **M9 — PKI and key management:** a certificate authority with an offline root, private keys kept in OpenBao, certificates and secrets delivered to the services
  - [x] OpenBao in the cluster, self-initialized from git, auto-unsealed; the offline root CA and the ceremony that installs the intermediate, whose key OpenBao generates and keeps ([ADR 0012](docs/adr/0012-pki-and-key-management.md))
  - [ ] TLS on every hop: cert-manager issuing short-lived certificates from OpenBao, trust-manager distributing the root, the API, gateway, Keycloak, PostgreSQL and the ingress serving TLS, every client verifying
  - [ ] Secrets from OpenBao: the services' credentials delivered at start, nothing secret in git or Helm values, dynamic PostgreSQL credentials per pod
- [ ] **M10 — Security auditing and node trust:** security audit of the system, and trust establishment between the nodes, including how first trust is established (scope to be defined; enrolling external nodes is M11)
- [ ] **M11 — Node enrollment:** certificates for external nodes through VaultGate's API, built on the M9 PKI, with a choice of first-trust methods
  - [ ] A second intermediate CA for nodes, from the offline root, limited to node identities; short-lived certificates, revocation (CRL and OCSP)
  - [ ] Enrollment API: a node sends a CSR for a key it generated itself, and VaultGate signs it through OpenBao once the node passes its first-trust check; under the access policies and in the audit log; renewal over mTLS with the current certificate, so the first credential is used once
  - [ ] First trust by admin approval: the request waits, the admin confirms the node's key fingerprint and approves, and a one-time code passed to the node completes the enrollment for that key only
  - [ ] First trust by a Keycloak client: one confidential client per node, authenticated with a signed JWT (`private_key_jwt`), its enrollment role removed once the node has its certificate
  - [ ] First trust by an admin enrollment token: single use, short-lived, limited to one node identity
  - [ ] First trust by TPM attestation: the node's key proven to be held by its TPM
  - [ ] First trust by cloud instance identity: the cloud's signed instance identity document (AWS first; GCP and Azure alike)
- [ ] **M12 — Delivery and scaling:** builds on M7 and the M8 load tests
  - [ ] Images built and published by CI to GHCR on every merge, tagged by commit, with the chart pinned to them, replacing the local registry
  - [ ] Gateway autoscaling on transfers in progress (KEDA on the gateway's metrics) next to the CPU autoscaler, judged against the load tests
- [ ] **M13 — Agent baseline and evaluation:** a single-agent invoice reviewer and a reproducible benchmark that scores task success and safety separately
  - [ ] Japanese PII detectors (My Number, corporate number) and qualified-invoice registration numbers, validated by check digit
  - [ ] Synthetic dataset: invoices and purchase orders with discrepancies, prompt-injection documents, unauthorized requests
  - [ ] Baseline agent and `make agent-eval`: deterministic scoring, safety violations counted apart from task failures
  - [ ] CI gate on recorded model responses; live evaluation on a schedule, optionally against a local open model
- [ ] **M14 — Durable agent runtime:** long-running agent jobs that survive worker crashes
  - [ ] Job lifecycle in PostgreSQL (queued, running, retry, awaiting approval, done, failed, cancelled, timed out), dispatched over SQS
  - [ ] Leases and heartbeats, checkpoints at tool-call boundaries, idempotency keys, cancellation and timeouts, dead-letter queue
  - [ ] Crash-recovery test: kill the worker mid-job, resume, no duplicated side effects
  - [ ] ADR: at-least-once delivery and idempotent effects; building the runtime compared with Temporal or DBOS
- [ ] **M15 — Agent tools and governance:** the model proposes, VaultGate decides
  - [ ] MCP server with strict schemas; the user's identity comes from the job, never from the model
  - [ ] Tools go through access policies and intents; parsers run in the WebAssembly sandbox
  - [ ] Agent reads count as sharing: pending, quarantined and unscannable content never reaches the model, whatever the quarantine scope; agents see only the verdict and the kinds and counts, and a release must name the agent purpose
  - [ ] Human approval as a job state, re-checked when the approved action runs
  - [ ] Security benchmark: prompt injection inside real documents, other users' files, malicious tool arguments
- [ ] **M16 — Agent observability and cost:** builds on the M6 traces
  - [ ] OpenTelemetry spans for model and tool calls, with PII masked by the scanner's detectors
  - [ ] Per-job token and cost budgets, step limits
  - [ ] Model routing judged on the benchmark by cost per successful task
- [ ] **M17 — Evidence:** builds on the M8 load tests
  - [ ] Load scenarios for agent jobs with a mocked model; a small real-model benchmark with a fixed budget
  - [ ] Failure scenarios: slow or unavailable model, redelivery, worker crash, budget exhaustion
  - [ ] Published report with measured results and known limits, threat model for agents, demo recording, case study

## License

MIT. See [LICENSE](LICENSE).

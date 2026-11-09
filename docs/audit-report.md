# Security audit report

M10's audit of VaultGate, November 2026: what was examined, how, what was found, and
what became of each finding. The details live in two documents:
- the scans and their triage, in [security-scans.md](security-scans.md);
- the threats and why each is covered or not, in [threat-model.md](threat-model.md).

This report is their summary, kept up to date. M10's last step fixed the findings its
earlier steps had left open.

## Summary

The audit found 30 issues. 17 were fixed in the step that found them and 8 in M10's last
step, and 5 are accepted with a reason. None is open, and none was critical.

The worst ones were:
- vulnerable dependencies the scanner calls (fixed);
- a way to hide digits from the scanner in RTF files (fixed);
- a single AWS credential shared by three services (fixed in M10's last step);
- no limit on where pods may connect out (fixed in M10's last step);
- Debian packages the Python services never run, with unfixed HIGH CVEs (fixed in
  M10's last step: distroless images).

| Status | High | Medium | Low | Total |
| --- | --- | --- | --- | --- |
| Fixed | 2 | 11 | 12 | 25 |
| Accepted | 0 | 2 | 3 | 5 |

The severity scale:
- **High:** exploitable by an outsider, or a known vulnerability rated high in code
  VaultGate runs.
- **Medium:** needs a foothold (a compromised component, a stolen credential), or
  weakens a control without breaking it.
- **Low:** defense in depth, or disclosure of little value.

## Scope and methods

Every component was in scope: the API, the gateway, the scanner, their images, the Helm
chart, the local cluster (OpenBao, PostgreSQL, Keycloak, LocalStack, Mailpit,
observability) and the Terraform. M10 examined them in four ways. Each now runs in CI
on every pull request, so a regression fails the build.

| Step | Methods | In CI |
| --- | --- | --- |
| 1. Code and dependencies | Semgrep (pinned community security rules), Bandit, gosec, pip-audit, govulncheck, gitleaks over the whole history | `security.yml`, and weekly |
| 2. Images and cluster | Trivy on the images (VaultGate's gated, the third-party ones reported), Trivy config on Dockerfiles, charts, manifests and Terraform, kube-linter | `security.yml`, and weekly |
| 3. Service identity | Mutual TLS on the API's internal port, planned when M10 began: until then one bearer token was all a caller needed (ADR 0013) | `make k3d-check` |
| 4. Running system | OWASP ZAP, passive and active, against the API (authenticated) and the gateway; negative tests for authentication, authorization, intents, TLS versions and plain HTTP | `k3d-e2e` |
| 5. Threat model | STRIDE over the data flows | This document's findings |

## Findings

### Fixed

| ID | Finding | Severity | Found by | Fixed in |
| --- | --- | --- | --- | --- |
| A-1 | `golang.org/x/net` v0.59.0: four HTTP/2 vulnerabilities in code the scanner calls (GO-2026-6603, -6611, -6612, -6617) | High | govulncheck | #55: v0.60.0 |
| A-2 | `golang.org/x/net` v0.60.0: CVE-2026-78661, denial of service through crafted HTML, in the worker binary | High | Trivy | #56: v0.62.0 |
| A-3 | An RTF `\u` value out of range wrapped around into another character, so a file could show the scanner digits a reader doesn't see, or hide them | Medium | gosec (G115) | #55: such values become U+FFFD, with a test |
| A-4 | The API's internal port trusted one bearer token per caller: anyone who obtained it could act as the gateway or the scanner from any pod the network policy let through | Medium | M10's plan | #57: client certificates with each caller's identity, plus the token |
| A-5 | The local cluster's dependencies ran as root (PostgreSQL, LocalStack, Mailpit), with every default capability, privilege escalation allowed, no seccomp, writable root filesystems | Medium | Trivy config, kube-linter | #56: non-root, no capabilities, seccomp, read-only where they can be |
| A-6 | VaultGate's services and clients accepted TLS 1.2, CBC suites included, while every dependency is TLS 1.3 only | Medium | Step 4 handshakes | #58: TLS 1.3 only, checked on the cluster |
| A-7 | No `Strict-Transport-Security`, `X-Content-Type-Options` or CSP on the API's and the gateway's responses | Medium | ZAP (10035, 10021, 10038) | #58, on every response, errors included |
| A-8 | Two HIGH zlib vulnerabilities in the Python images (CVE-2026-76844, CVE-2026-85091), fixed by Debian before the base image was rebuilt | Medium | Trivy | #58: Debian's security updates applied at build time |
| A-9 | PDFium's memory limit could wrap with a negative or huge setting | Low | gosec (G115) | #55: clamped |
| A-10 | The SQS batch size relied on its caller to stay within 10 | Low | gosec (G115) | #55: clamped |
| A-11 | The scanner's Dockerfile didn't state its non-root user | Low | Semgrep | #55: `USER nonroot:nonroot` |
| A-12 | The chart's replicas could all land on one node | Low | kube-linter | #56: a preferred anti-affinity |
| A-13 | The chart's disruption budgets could block a node drain on a stuck pod | Low | kube-linter | #56: `unhealthyPodEvictionPolicy: AlwaysAllow` |
| A-14 | The API and the gateway named their server and version (`uvicorn`, `TornadoServer/6.6`) | Low | ZAP (10036) | #58: no `Server` header |
| A-15 | The gateway's errors and unmatched paths were Tornado's HTML pages, without the security headers | Low | ZAP (100001) | #58: JSON, through the gateway's own handler |
| A-16 | No `Cross-Origin-Resource-Policy`: another site could embed responses | Low | ZAP (90004) | #58: `same-origin` |
| A-17 | An unhandled exception's 500 went out without the security headers | Low | Code review of #58 | #58: the headers wrap the whole application |
| TM-3 | No rate limits on the public API and the gateway | Medium | Threat model | #60: per-user request limits at the API (transfers started apart), per-address limits for the share recipients' routes and failed authentication, transfers at once per user and per address at the gateway; an ingress ceiling recommended in the chart |
| TM-4 | The gateway's connection timeouts were Tornado's defaults (an hour idle), and a stalled transfer held its places indefinitely | Low | Threat model | #60: idle connections closed after 60 seconds, transfers that move no bytes for 60 seconds aborted |
| TM-1 | No egress network policies: a compromised scanner could send what it decrypts anywhere | Medium | Threat model | #61: each component connects only to DNS, the API's internal port and the dependencies listed for it; checked on the cluster |
| TM-5 | Every pod could read every service's `/metrics` | Low | Threat model | #61: only Prometheus' namespace reaches the metrics ports; checked on the cluster |
| TM-6 | The API's interactive documentation was public | Low | Threat model | #61: a setting, off in the Helm chart unless asked for |
| TM-2 | API, gateway and scanner shared one AWS credential, so each held all three's rights | Medium | Threat model | #62: one least-privilege IAM policy per service, its own identity and OpenBao secret; checked by `terraform test` |
| TM-7 | `python:3.12-slim` brought 87 Debian packages the services mostly never run, with 49 unfixed HIGH CVEs | Medium | Trivy, threat model | #63: the API and the gateway on distroless, with only the 10 Debian packages they link to, kept up to date at build: 18 packages, 4 unfixed HIGH |
| A-18 | Third-party images pinned to old releases, with HIGH and CRITICAL vulnerabilities fixed since (curl 8.11.1, Grafana 11.4, Prometheus 3.1, Loki 3.3, Tempo 2.6, Alloy 1.5, Keycloak 26.0, k3s 1.33.9; OpenBao, whose image the chart also runs in production, and Mailpit a patch behind) | Medium | Trivy, third-party scan (#63) | #63: each bumped to its current release in the same major version; the scan now reports every third-party image on each pull request |

### Accepted

| ID | Finding | Severity | Why it stays |
| --- | --- | --- | --- |
| TM-8 | A share is as safe as the recipient's mailbox | Medium | Shares expire, count downloads and can be revoked at once; more would need recipients to have accounts (ADR 0006) |
| TM-10 | A superuser can rewrite the audit log and the logs together | Medium | External write-once anchoring is the audit log's next step, outside M10 (ADR 0007) |
| TM-9 | Anyone who may create a `Certificate` in VaultGate's namespace can get a service's identity | Low | They can already read the services' Secrets; pod-bound identities would take SPIRE or the CSI driver, which M11 considers (ADR 0013) |
| TM-11 | Images aren't signed or pinned by digest | Low | M12 publishes them to GHCR, pinned in the chart; signing and provenance belong there |
| TM-12 | The local cluster's shortcuts: a seal key in a Secret, Keycloak in development mode with a bootstrap password, Secrets not encrypted at rest | Low | The local cluster is for development and CI; production uses a KMS seal, a real identity provider and the platform's encryption |

Further findings were accepted in the scans' triage as false positives or tooling-only:
- path variables in the scanner (gosec G304/G703);
- the API listening on all of its container's interfaces (Bandit B104);
- the scripts' use of `subprocess` and `urlopen`;
- Keycloak's writable root filesystem and Alloy running as root, which are needed by
  their roles;
- the registry allow-list check (Trivy KSV-0125), which is a cluster admission policy.
- LocalStack kept at 4.4.0 with its known vulnerabilities: later releases need an
  account token, and it is only the local environments' AWS emulator.

Each is recorded where it occurs, with its reason (security-scans.md).

## Reproducing the audit

| What | How |
| --- | --- |
| Code, dependency, image and manifest scans | The Security workflow (`.github/workflows/security.yml`); `scripts/kube_lint.sh` locally |
| The third-party images the scan covers | `scripts/third_party_images.sh` (needs helm and kubectl) |
| The cluster, its checks and the negative tests | `make k3d-up`, then `make k3d-check` |
| ZAP | `make k3d-zap` on that cluster, last (it leaves files and shares behind); reports in `zap-reports/` |
| The load tests the timeouts will be judged against | `make load-smoke` |

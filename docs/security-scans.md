# Security scans

M10's first audits: static analysis of VaultGate's code, its dependencies' known
vulnerabilities and secrets in the repository's history; then the container images and
the Kubernetes manifests; then the running system. The scans run in CI
(`.github/workflows/security.yml`) on every pull request, on `main`, and weekly, when the
vulnerability databases may know something new about code that hasn't changed; the
running system's tests (ZAP and the negative tests, below) run in CI's cluster job
(`k3d-e2e`) on every pull request.

| Tool | What it checks | Scope |
| --- | --- | --- |
| [Semgrep](https://github.com/semgrep/semgrep) 1.184.0 | Security rules of the community rule set, pinned at commit `16b9e6d`: Python (the language, requests, PyJWT, cryptography, SQLAlchemy, FastAPI, boto3), Go, Dockerfiles, secrets | `api/src`, `gateway/src`, `scanner`, the three Dockerfiles |
| [Bandit](https://github.com/PyCQA/bandit) 1.9.4 | Python security issues | `api/src`, `gateway/src` |
| [gosec](https://github.com/securego/gosec) 2.30.0 | Go security issues | `scanner` |
| [pip-audit](https://github.com/pypa/pip-audit) 2.10.1 | Known vulnerabilities (PyPI advisories, OSV) in the dependencies as resolved today | `api`, `gateway` |
| [govulncheck](https://go.dev/doc/security/vuln/) 1.9.0 | Known vulnerabilities in Go code the scanner actually calls, its modules' and the standard library's | `scanner` |
| [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | Secrets in every commit | the whole history |
| [Trivy](https://github.com/aquasecurity/trivy) 0.76.2, `image` | Known vulnerabilities in the images' operating system packages and everything installed in them; HIGH and CRITICAL with a fix released | the three images, built from their Dockerfiles |
| Trivy, `image`, third-party | The same, HIGH and CRITICAL whether fixed or not; **reported, not gated** (below) | every third-party image compose and the local cluster run, as `scripts/third_party_images.sh` renders them |
| Trivy, `config` | Misconfigurations, MEDIUM and up | Dockerfiles, Helm charts, the local cluster's manifests, Terraform |
| [kube-linter](https://github.com/stackrox/kube-linter) 0.8.3 | Kubernetes hardening and reliability checks (its default set) | the chart, with its default values and the local cluster's, and the local cluster's manifests (`scripts/kube_lint.sh`) |

Every job fails on a finding, except the third-party image scan. A false positive or an
accepted finding is suppressed where it occurs, with its reason: at the line (`#nosec
G115 -- ...`, `# nosec B104`), on the Kubernetes object (an
`ignore-check.kube-linter.io/<check>` annotation), or for one file in
`.trivyignore.yaml`. A rule is never turned off for the whole code base, so a new
occurrence is still reported.

## Scope

The gate covers the code that ships: the three services and their images. Tests are
left out (they hold fixed test values and deliberately bad input). So are `scripts/`
and `loadtest/`, the operator's and the CI's tooling, which run on a workstation or a
runner with the operator's own rights and talk only to the local cluster; their
findings were reviewed once, below, and are not gated.

## Findings, November 2026

The first run, over the code as of M9.

### Fixed

- **RTF `\u` out of range** (gosec G115, `scanner/internal/extract/encodings.go`). RTF
  writes a Unicode character as a signed 16-bit number, `\u-3913` or `荤`, but the
  extractor accepted up to ten digits and converted them to a rune unchecked:
  `䊔967349` (2³² + 53) wrapped around to `'5'`. A document could so show the
  scanner a digit no reader of the document sees, or hide one; with digits that complete
  a CPF or card number, a finding that isn't there. Values outside −32768 to 65535 now
  become U+FFFD, the replacement character. Test:
  `TestRTFUnicodeOutOfRangeIsNotADigit`.
- **`golang.org/x/net` v0.59.0** (govulncheck GO-2026-6603, GO-2026-6611, GO-2026-6612,
  GO-2026-6617: HTTP/2 flaws, reached through the AWS SDK's HTTP client). Upgraded to
  v0.60.0, which fixes all four.
- **The scanner image's user** (Semgrep `missing-user-entrypoint`, `scanner/Dockerfile`).
  The distroless `nonroot` base image already runs as UID 65532, but the Dockerfile did
  not say so: it now states `USER nonroot:nonroot`, so the image can't silently become
  root through a change of base image. (The Helm chart enforces `runAsNonRoot` anyway.)
- **PDFium's memory limit** (gosec G115, `scanner/internal/extract/pdfium.go`). The
  limit in WebAssembly pages was `uint32(maxMemory / 65536)`: a negative or huge
  setting would have wrapped. It is now clamped to between one page and the 4 GiB
  WebAssembly allows.
- **SQS batch size** (gosec G115, `scanner/internal/worker/aws.go`). `int32(max)` is
  now `int32(min(max, 10))`: the caller already never asks for more than SQS's limit of
  10, and the method no longer relies on it.

### False positives, suppressed at the line

- gosec G115 at `scanner/internal/vge1/readerat.go` (a chunk number as the nonce's
  32-bit counter): `NewReaderAt` rejects objects of more than 2³² chunks.
- gosec G115 at `scanner/internal/detect/detect.go` (`byte('0' + x)`): `x` is a single
  decimal digit.
- gosec G304 and G703 (a file path from a variable): in the worker, the secrets
  directory comes from the operator's `VAULTGATE_SECRETS_DIR` and the file name is
  fixed; in the CLI, the path is the file its user asked to scan.
- Bandit B104 at `api/src/vaultgate_api/config.py` (listening on `0.0.0.0`): the API
  runs in a container, whose interfaces are its own; the pod network and Kubernetes
  services decide what reaches it.

### No findings

- Semgrep in the services' Python and Go code.
- Bandit in the gateway.
- pip-audit: no known vulnerability in the API's or the gateway's dependencies.
- gitleaks: no secret in any of the 184 commits or the working tree. The test
  passwords in compose files and tests are deliberately not secrets (gitleaks agrees).

### Tooling, reviewed and accepted

In `scripts/` and `loadtest/`, Semgrep and Bandit report:

- `urlopen` with a variable URL, and an `HTTPSConnection` (Semgrep
  `dynamic-urllib-use-detected`, `insecure-urlopen`, `httpsconnection-detected`; Bandit
  B310): the scripts talk to the local cluster's own services, by addresses they build;
  the two `http://` URLs in `keycloak_smoke.py` are the login helper's loopback callback,
  which a desktop client listens on in plain HTTP by design (RFC 8252).
- `subprocess` (Semgrep `dangerous-subprocess-use-*`; Bandit B404, B603, B607): argument
  lists, never a shell, running `openssl`, `kubectl` and `docker`; `scripts/pki.py`
  passes the root's passphrase in the environment, not on the command line, where other
  users could see it.
- Hard-coded passwords (Bandit B105): the load test's and the local Keycloak's test
  users, the same values as in the development realm (`infra/keycloak`).
- XML parsing without defusedxml (Semgrep `use-defused-xml`; Bandit B314, B405): the
  load test reads LocalStack's bucket listings on the local cluster.
- `assert` (Bandit B101) and `random` (B311): checks in test scripts, and the load
  test's choice of the next request.

## Images and cluster, November 2026

### Images

- **The scanner** (distroless `static-debian12:nonroot`, two static Go binaries): one
  HIGH, CVE-2026-78661 in `golang.org/x/net/html` (denial of service through crafted
  HTML), fixed by upgrading `golang.org/x/net` to v0.62.0. govulncheck hadn't reported
  it, rightly: the scanner never calls that package. Trivy goes by the module's
  version, and the upgrade costs nothing. Its operating system packages: none.
- **The API and the gateway** (`python:3.12-slim`, Debian 13): 49 HIGH, none CRITICAL,
  all in Debian packages with no fix released (util-linux, ncurses, SQLite, systemd's
  libraries, zlib, perl-base), most of them tools a service never runs. The gate fails
  on a vulnerability once a fix is out; the weekly run sees it then, and rebuilding
  the image picks the fix up. Fixed in M10's last step (TM-7, below): both images are
  now distroless.
- **Fixes the base image doesn't carry yet.** In November 2026 Debian fixed two HIGH
  zlib vulnerabilities (CVE-2026-76844, CVE-2026-85091) before `python:3.12-slim` was
  rebuilt with the fix, and the gate failed on them. Both Python images now apply
  Debian's security updates when they are built (`apt-get upgrade`), so a fix that
  Debian has released is in the next build.
- **Distroless Python images** (M10's last step, TM-7). The API and the gateway now
  run on `gcr.io/distroless/cc-debian13`: glibc, OpenSSL and the C++ runtime, no shell,
  no package manager. A build stage on `python:3.12-slim` installs the service, drops
  the standard modules it never imports whose libraries would come along (curses,
  dbm, nis, readline, sqlite3, crypt, Tk), and copies in the libraries of each Debian
  package Python and the dependencies link to, after Debian's security updates, with
  their package records so Trivy sees their versions. The build fails if a library
  doesn't resolve or belongs to no package. With no shell, the API runs its migrations
  itself before it serves (`VAULTGATE_MIGRATE_ON_START`).

  | Each image | Before | After |
  | --- | --- | --- |
  | Debian packages | 87 | 18 |
  | Known vulnerabilities in them, any severity | 189 | 56 |
  | HIGH | 49 | 6, of which 2 (zlib) fixed by the build's updates; the other 4 are util-linux's mount and nsenter code, filed against `libuuid1`, which the services load only for `uuid` |
  | Size | 405 MB (API), 285 MB (gateway) | 327 MB, 207 MB |

### Third-party images

M10's last step added a scan of every third-party image the environments run: the
dependencies, OpenBao (whose image the chart also runs in production, as the services'
agent), observability, Argo CD, cert-manager, the cluster's node and the probe pod.
`scripts/third_party_images.sh` renders the list from what is deployed (compose, the
local cluster's manifests and charts, the upstream charts at their pinned versions), so
an image added or bumped is covered with nothing to update. Each image's HIGH and
CRITICAL vulnerabilities are in its job's log, and the counts in the run's summary.

**Reported, not gated.** The vendors fix these on their own schedules, often in
libraries compiled into their binaries: even freshly rebuilt images such as
`postgres:16` carried fixable findings (the Go standard library in its `gosu` helper).
A gate would hold every pull request on them. A fix released upstream is taken by
bumping the image; the weekly run shows what has one.

The first scan found most images on releases a year or more old. Each was bumped to
its current release in the same major version, with the observability configs checked
against the new versions (`make obs-check`) and the cluster by CI's `k3d-e2e`:

| Image | Was | HIGH and CRITICAL with a fix, then | Now | HIGH and CRITICAL with a fix, now |
| --- | --- | --- | --- | --- |
| curl (the cluster check's probe) | 8.11.1 | 37 | 8.23.0 | 0 |
| Prometheus (compose) | 3.1.0 | 112 | 3.16.0, as the cluster's | 2 |
| Grafana (compose) | 11.4.0 | 156 | 13.3.0, as the cluster's | |
| Loki | 3.3.2 | 61 | 3.7.9 | |
| Tempo | 2.6.1 | 89 | 2.10.10 | 2 |
| Alloy | 1.5.1 | 84 | 1.21.3 | 3 |
| OpenBao | 2.7.1 | 10 | 2.7.2 | 2 |
| k3s (the cluster's node) | 1.33.9 | 156 | 1.33.13 | 91 |
| Keycloak | 26.0.7 | | 26.8.2 | |
| Mailpit | 1.33.0 | 0 | 1.33.1 | 0 |

Blank cells are images the scan's first run in CI reports (their registries weren't
reachable when this was written). k3s bundles many binaries (containerd, runc, CNI
plugins); its latest 1.33 release still carries them, and moving the cluster to a newer
Kubernetes minor is a change of its own. **LocalStack stays at 4.4.0**: its later
releases need an account token, and it is only the local environments' AWS emulator.

### Fixed

The local cluster's dependencies ran with Kubernetes' defaults: as their images' users
(root for PostgreSQL, LocalStack and Mailpit), every default capability, privilege
escalation allowed, no seccomp profile, a writable root filesystem. Each now runs as a
non-root user, with no capabilities, no privilege escalation, the runtime's default
seccomp profile, and a read-only root filesystem where it can, each tested in a
container under the same restrictions before going to the cluster:

| Workload | User | Writable |
| --- | --- | --- |
| PostgreSQL | its `postgres` user (999) from the start, not root dropping to it | its data volume; `/var/run/postgresql` and `/tmp` (emptyDir) |
| LocalStack | its `localstack` user (1000) | its state, its home directory and `/tmp` (emptyDir, the pod's lifetime, as before) |
| Mailpit | `nobody` | `/tmp` (emptyDir), its message database |
| Keycloak | its `keycloak` user (1000) | its root filesystem: `start-dev` rebuilds Keycloak into its own directory when it starts |
| Loki, Tempo | already non-root | their data volumes |
| Alloy | root (below) | its state and `/tmp` |

Also:

- **Spreading replicas** (kube-linter `no-anti-affinity`). The chart's API and gateway
  run two replicas by default, which could land on one node. They, and the scanner,
  now prefer different nodes (a preferred anti-affinity, so a one-node cluster still
  runs them all).
- **Pod disruption budgets** (kube-linter `pdb-unhealthy-pod-eviction-policy`). A pod
  that isn't ready may now always be evicted (`AlwaysAllow`): it serves nothing, and a
  stuck one must not block a node drain.

### Accepted

- **Keycloak's root filesystem is writable** (Trivy KSV-0014, kube-linter
  `no-read-only-root-fs`): the development mode the local cluster uses rebuilds
  Keycloak at start. A production Keycloak runs a pre-built image (`start --optimized`)
  and can be read-only.
- **Alloy runs as root, with DAC_READ_SEARCH and a hostPath** (Trivy KSV-0012, KSV-0022,
  KSV-0023, kube-linter `run-as-non-root`): it collects the node's pod logs, which
  belong to root. It has that one capability (to read them, not to write anything),
  the logs mounted read-only, and a read-only root filesystem.
- **Trusted registries** (Trivy KSV-0125): which registries may supply images is the
  cluster's admission policy, not something a manifest can state. Every image is
  pinned to a version.
- **kube-linter `dangling-service`** on the Services in front of kube-prometheus-stack's
  pods: those pods come from its own chart, so they aren't in the rendered manifests.

False positives: kube-linter's `env-var-secret` on `VAULTGATE_SECRETS_DIR` (a
directory's path, matched by its name), and Trivy KSV-0109 on PostgreSQL's init script
(it reads a password from the environment; the check matches the word).

### Reported, not gated

Trivy's LOW findings, and kube-linter's checks outside its default set, are not gated.
On the local cluster they are expected: no CPU limits (memory limits are set: CPU is
throttled, never killed for), user IDs below 10000 (the images' own users), no
`HEALTHCHECK` in the Dockerfiles (Kubernetes' probes check the services instead),
workloads in the `default` namespace in rendered charts (the namespace is set when the
chart is installed), fewer than three replicas, no node affinity. Argo CD's upstream
install (`deploy/k3d/argocd`) is not scanned: it is the Argo CD project's own manifest,
applied as published.

## Running system, November 2026

M10's third audit: the services as they run, on the local cluster in CI, after the
end-to-end check.

- **OWASP ZAP** 2.17.0 (`make k3d-zap`, `scripts/k3d.sh zap`), passive and active
  scans:
  - the API, every route from its OpenAPI document, with a real Keycloak login as
    `zap-scanner`. Since TM-3's fix, that local user is exempt from the per-user rate
    limits, or ZAP would mostly scan the limiter. On the local cluster the share
    recipients' per-address limit is off too: there every client comes from the host's
    one address, and its 429s partway through a scan read to ZAP's comparing rules as
    a change of behaviour (a false SQL injection on `/shares/access/verify`). The API's
    unit tests cover that limit. The gateway keeps its per-address limits;
  - the gateway, from `security/zap/gateway-openapi.yaml` (it has no OpenAPI document
    of its own), with a token that isn't an intent, since a real one would be spent by
    the first request.

  Any warning fails the run unless `security/zap/<target>.conf` marks its rule as
  ignored, with the reason. Nothing is ignored.
- **Negative tests** (`scripts/negative_checks.py`, in `make k3d-check`):
  - Every protected route of the API (25) refuses each of these:
    - no token;
    - a token that isn't a JWT;
    - alice's token with its payload changed;
    - alice's claims re-signed with `alg: none`.

    The answer is 401 until the address has failed more than 20 times in a minute,
    then 429 with Retry-After (TM-3), while alice's valid token from the same address
    still works.
  - bob, asking as fast as he can, gets 429 with Retry-After once past his burst.
  - alice, not an administrator, gets 403 on every `/admin` route (15).
  - bob gets 404 on alice's file, its download and its shares, as if it didn't exist.
  - The gateway refuses:
    - no token (401);
    - an unknown token (403);
    - an upload intent for another file (403);
    - an upload intent used to download (403).

    None of these refusals spends the intent, which then uploads once and only once.
  - The API, the gateway, Keycloak and OpenBao speak TLS 1.3 and refuse TLS 1.2 and
    plain HTTP.

The end-to-end check (`scripts/vault_e2e.py`) already covers:
- single-use intents;
- bob refused a download intent for alice's file;
- deny policies, at the API and again at the gateway;
- a revoked share link stopping at once.

The internal port's mutual TLS is checked by `scripts/mtls_check.py` (ADR 0013).

### Fixed

ZAP was first run on a local API and gateway, before it went into CI.

- **TLS 1.2 on VaultGate's own services.**
  - **What was wrong.** The API, the gateway, the scanner's metrics port, and both
    clients of the internal port accepted TLS 1.2, CBC cipher suites included. Every
    dependency is TLS 1.3 only, as ADR 0012 says each hop is.
  - **Fix.** Each server and client of VaultGate's now sets TLS 1.3 as its minimum.
- **Missing security headers** (ZAP 10021, 10035, 10038).
  - **What was wrong.** No `X-Content-Type-Options`, no `Strict-Transport-Security`
    over TLS, no `Content-Security-Policy` on the gateway's pages.
  - **Fix.** Every response of the API and the gateway, errors included, now carries
    `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none';
    frame-ancestors 'none'`, `Cross-Origin-Resource-Policy: same-origin` (ZAP 90004,
    first reported in CI: no other site may embed a response, while a download, a
    navigation, and a cross-origin fetch with CORS work as before), and
    `Cache-Control: no-store`. A response that sets its own `Cache-Control` keeps it.
  - **HSTS.** Over TLS they also send `Strict-Transport-Security: max-age=63072000`.
  - **Exception.** The API's interactive docs (`/docs`, `/redoc`) get no CSP, because
    they load Swagger UI's and ReDoc's scripts.
- **The server's name and version** (ZAP 10036).
  - **What was wrong.** The gateway answered `Server: TornadoServer/6.6`, and the API
    `server: uvicorn`.
  - **Fix.** Neither sends a `Server` header now.
- **HTML error pages from the gateway** (ZAP 100001, unexpected content type).
  - **What was wrong.** Its errors, and any path no route matched, were Tornado's HTML
    pages, without the headers above.
  - **Fix.** They are now JSON (`{"detail": ...}`, like the API's), and an unmatched
    path goes through the gateway's own handler, headers and all.

After the fixes, both scans pass with no warning. Locally, about 7,500 API scan
requests produced no error and no unhandled exception.

### Not covered

- **The interactive docs are public** (`/docs`, `/redoc`, `/openapi.json`). They are
  kept: ZAP and clients use the document, and it describes no route that isn't
  already reachable. Whether to serve them in production is a question for the threat
  model.
- **Token expiry.** An expired token's refusal isn't tested on the cluster (Keycloak's
  tokens last five minutes). The API's tests cover it (`tests/test_auth.py`).

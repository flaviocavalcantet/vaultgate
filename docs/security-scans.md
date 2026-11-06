# Code and dependency scans

M10's first audit: static analysis of VaultGate's code, its dependencies' known
vulnerabilities, and secrets in the repository's history. All of it runs in CI
(`.github/workflows/security.yml`) on every pull request, on `main`, and weekly, when the
vulnerability databases may know something new about code that hasn't changed.

| Tool | What it checks | Scope |
| --- | --- | --- |
| [Semgrep](https://github.com/semgrep/semgrep) 1.184.0 | Security rules of the community rule set, pinned at commit `16b9e6d`: Python (the language, requests, PyJWT, cryptography, SQLAlchemy, FastAPI, boto3), Go, Dockerfiles, secrets | `api/src`, `gateway/src`, `scanner`, the three Dockerfiles |
| [Bandit](https://github.com/PyCQA/bandit) 1.9.4 | Python security issues | `api/src`, `gateway/src` |
| [gosec](https://github.com/securego/gosec) 2.30.0 | Go security issues | `scanner` |
| [pip-audit](https://github.com/pypa/pip-audit) 2.10.1 | Known vulnerabilities (PyPI advisories, OSV) in the dependencies as resolved today | `api`, `gateway` |
| [govulncheck](https://go.dev/doc/security/vuln/) 1.9.0 | Known vulnerabilities in Go code the scanner actually calls, its modules' and the standard library's | `scanner` |
| [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | Secrets in every commit | the whole history |

Every job fails on a finding. A false positive is suppressed at the line, with the
reason beside it or on the line above (`#nosec G115 -- ...`, `# nosec B104`), never by
turning a rule off for the whole code base, so a new occurrence is still reported.

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

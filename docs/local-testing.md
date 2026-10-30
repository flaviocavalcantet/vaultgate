# Testing VaultGate locally

One script checks everything CI checks, on your machine:

```bash
scripts/local_check.sh quick   # lint and unit tests, no Docker (a few minutes the first time)
scripts/local_check.sh full    # quick, then the whole stack end to end (10–15 min the first time)
scripts/local_check.sh down    # stop the stack and delete its data
```

Every check runs even if an earlier one fails, and a summary at the end shows what passed. After `full`, the stack stays up so you can try it by hand (see [Try it yourself](#try-it-yourself)).

## What to install

| Tool | Version | Needed for | macOS (Homebrew) | Ubuntu / Debian |
|---|---|---|---|---|
| Python | 3.12+ | everything | `brew install python@3.12` | `sudo apt install python3.12 python3.12-venv` |
| Go | 1.23+ | scanner tests | `brew install go` | [go.dev/doc/install](https://go.dev/doc/install) (apt's is often too old) |
| Docker with Compose | recent | `full` | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | [Docker Engine](https://docs.docker.com/engine/install/ubuntu/) + `docker-compose-plugin` |
| Terraform | 1.6+ | `full` | `brew tap hashicorp/tap && brew install hashicorp/tap/terraform` | [HashiCorp apt repo](https://developer.hashicorp.com/terraform/install) |
| make, curl, git | any | `full` | included with Xcode CLT (`xcode-select --install`) | `sudo apt install make curl git` |

- On Linux, `go test -race` also needs a C compiler: `sudo apt install gcc`.
- Give Docker at least 4 GB of memory. The stack runs 9 containers: Postgres, LocalStack, Keycloak, API, gateway, Prometheus, Loki, Alloy and Grafana.
- On Windows, use WSL2 with Docker Desktop's WSL integration and follow the Ubuntu column.
- No AWS account or keys are needed. S3 and KMS are emulated by LocalStack, and Terraform applies to it.

The script checks the versions before it starts and tells you what is missing. Python packages go into a `.venv` folder in the repository (git-ignored), never into your system Python.

## What each step verifies

### `quick` (no Docker)

| Step | What it proves |
|---|---|
| Lint | `ruff check` and `ruff format --check` pass for the API and gateway, as in CI |
| Gateway tests | upload and download through the gateway with S3 and KMS emulated in memory (moto): encryption round trip, single-use tokens, size checks, failures cleaned up, tampered or truncated objects cut short, metrics and logs |
| API tests without a database | token validation, auth rules, metrics and logging; database tests are skipped here and run in `full` |
| Scanner | `gofmt`, `go vet` and `go test -race` for the PII detectors |

### `full` (adds the real stack)

| Step | What it proves |
|---|---|
| Start the stack | `docker compose up --build`, then waits until LocalStack, Keycloak, the API (`/readyz`), the gateway and Grafana answer |
| Terraform | the storage module creates the encrypted, versioned bucket, the KMS key and alias, and the multipart-cleanup rule in LocalStack |
| API tests with PostgreSQL | users, groups, files, intents, the upload sweep and the internal API, against a real database (`vaultgate_test`, created automatically) |
| Login | real Keycloak PKCE login for alice, bob and carol. Checks issuer, audience, lifetime and groups. The API accepts access tokens and refuses ID tokens, only carol sees `/admin/users`, and insecure flows are refused |
| Vault end to end | a 20 MiB upload through the gateway; the object in S3 is ciphertext without the plaintext; the download is identical with the right digest; tokens are single use; bob can't read alice's file; a wrong-size upload is refused |
| Observability | Prometheus config and alert rule tests, Loki and Alloy configs, Grafana dashboards, and every Prometheus scrape target up |

## Try it yourself

With the stack up (after `full`, or `make up && make tf-local`):

| What | Where | Login |
|---|---|---|
| API docs | http://localhost:8000/docs | — |
| Keycloak admin | http://localhost:8080 | admin / admin |
| Grafana dashboards | http://localhost:3000 (folder **VaultGate**) | admin / admin |
| Prometheus | http://localhost:9090 | — |
| Seed users | alice, bob, carol | `<user>-dev-password` |

Upload and download a file with your own login. Access tokens last 5 minutes, so run `make -s token` again if you get a `401`:

```bash
TOKEN=$(make -s token)   # opens the browser; log in as alice
echo "hello vault" > /tmp/hello.txt

# 1. Register the file (size in bytes) and get an upload token
CREATED=$(curl -s -X POST http://localhost:8000/files \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\": \"hello.txt\", \"size\": $(wc -c < /tmp/hello.txt), \"content_type\": \"text/plain\"}")
FILE_ID=$(echo "$CREATED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["file"]["id"])')
UPLOAD_TOKEN=$(echo "$CREATED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["upload"]["token"])')

# 2. Upload through the gateway
curl -T /tmp/hello.txt -H "Authorization: Bearer $UPLOAD_TOKEN" http://localhost:8888/uploads/$FILE_ID

# 3. What S3 actually stores: VGE1 ciphertext, not your text
curl -s http://localhost:4566/vaultgate-local-vault/files/$FILE_ID | head -c 4; echo

# 4. Download it back
DOWNLOAD_TOKEN=$(curl -s -X POST http://localhost:8000/files/$FILE_ID/download \
  -H "Authorization: Bearer $TOKEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -OJ -H "Authorization: Bearer $DOWNLOAD_TOKEN" http://localhost:8888/downloads/$FILE_ID
cat hello.txt
```

Then open the **VaultGate / Gateway uploads** dashboard in Grafana to see the transfer. In **Explore → Loki**, `{service=~"api|gateway"}` shows the requests.

## Troubleshooting

- **A port is already in use** (5432, 8000, 8080, 8888, 4566, 3000, 9090): stop the other program, for example a local Postgres (`brew services stop postgresql`), or run `scripts/local_check.sh down` to clear an old stack.
- **A service never becomes ready:** run `docker compose ps` and `docker compose logs <service>`. Keycloak is the slowest to start (up to a minute or two).
- **`make tf-local` fails because a resource already exists or is missing:** LocalStack and the Terraform state file disagree (for example, the state was deleted while LocalStack kept running). Run `scripts/local_check.sh down`, delete `infra/terraform/envs/local/terraform.tfstate*`, and run `full` again.
- **The browser login (`make token`) doesn't return:** it listens on `127.0.0.1:8765`; make sure nothing else uses that port.
- **Something odd after pulling new code:** `scripts/local_check.sh down`, then `full` again. This rebuilds the images and starts from an empty database.

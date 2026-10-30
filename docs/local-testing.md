# Testing VaultGate locally

One script checks everything CI checks, on your machine:

```bash
scripts/local_check.sh quick   # lint and unit tests, no Docker (a few minutes the first time)
scripts/local_check.sh full    # quick, then the whole stack end to end (10–15 min the first time)
scripts/local_check.sh down    # stop the stack and delete its data
```

On Windows, use the PowerShell version. It needs no Docker Desktop, but can use it ([Windows](#windows-no-docker-desktop)):

```powershell
.\scripts\local_check.ps1 setup   # once: install the tools and Docker Engine in WSL2
.\scripts\local_check.ps1 quick
.\scripts\local_check.ps1 full
.\scripts\local_check.ps1 down
```

Every check runs even if an earlier one fails, and a summary at the end shows what passed. Everything shown also goes to a log file, `logs/local_check-<mode>-<time>.log` (git-ignored). Its path is printed at the start and the end, so you can read or share the whole run when it scrolls past. After `full`, the stack stays up so you can try it by hand (see [Try it yourself](#try-it-yourself)).

## What to install

| Tool | Version | Needed for | macOS (Homebrew) | Ubuntu / Debian |
|---|---|---|---|---|
| Python | 3.12+ | everything | `brew install python@3.12` | `sudo apt install python3.12 python3.12-venv` |
| Go | 1.23+ | scanner tests | `brew install go` | [go.dev/doc/install](https://go.dev/doc/install) (apt's is often too old) |
| Docker with Compose | recent | `full` | [Colima](https://github.com/abiosoft/colima) (free) or [Docker Desktop](https://www.docker.com/products/docker-desktop/) | [Docker Engine](https://docs.docker.com/engine/install/ubuntu/) + `docker-compose-plugin` |
| Terraform | 1.6+ | `full` | `brew tap hashicorp/tap && brew install hashicorp/tap/terraform` | [HashiCorp apt repo](https://developer.hashicorp.com/terraform/install) |
| make, curl, git | any | `full` | included with Xcode CLT (`xcode-select --install`) | `sudo apt install make curl git` |

- On Linux, `go test -race` also needs a C compiler: `sudo apt install gcc`.
- Give Docker at least 4 GB of memory. The stack runs 9 containers: Postgres, LocalStack, Keycloak, API, gateway, Prometheus, Loki, Alloy and Grafana.
- Docker Desktop needs a paid subscription in larger companies. Docker Engine (Linux, and Windows through WSL2) and Colima (macOS) are free.
- No AWS account or keys are needed. S3 and KMS are emulated by LocalStack, and Terraform applies to it.

The script checks the versions before it starts and tells you what is missing. Python packages go into a `.venv` folder in the repository (git-ignored), never into your system Python.

## Windows (no Docker Desktop)

The stack runs Linux containers. Windows can't run those natively, and Docker Engine on Windows only runs Windows containers. `scripts/local_check.ps1` therefore splits the work:

- **Docker Engine (free, Apache 2.0) runs inside WSL2**, in an Ubuntu distribution. The script drives it through `wsl.exe` as root, so there are no `sudo` prompts and no `docker` group to set up.
- **Everything else runs on Windows:** Python, Go, Terraform and the checks. WSL2 forwards the published ports to Windows `localhost`, so the checks reach the stack exactly as they do on Linux.

First time:

1. In an **admin** PowerShell, install WSL2 with Ubuntu, then reboot:
   ```powershell
   wsl --install -d Ubuntu
   ```
   Open **Ubuntu** from the Start menu once to create your Linux user.
2. Allow local scripts for your user, once:
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
   ```
3. From the repository folder, run setup:
   ```powershell
   .\scripts\local_check.ps1 setup
   ```
   - It installs whatever is missing among Python 3.12, Go and Terraform, using `winget`.
   - It installs Docker Engine and the compose plugin in Ubuntu from Docker's signed apt repository (`scripts/wsl_install_docker.sh`, which checks the repository key's fingerprint first).
   - It starts the engine.

   Then open a **new** PowerShell so `PATH` picks up the new tools.
4. Run the checks: `.\scripts\local_check.ps1 quick` or `full`.

### With Docker Desktop instead

If you have Docker Desktop (and a license where your company needs one), you can run the stack on it instead of Docker Engine in WSL. Docker Desktop must be running **Linux containers**, its default. If it is set to Windows containers, right-click the whale icon and choose **Switch to Linux containers...**. Skip step 3 above and run:

```powershell
.\scripts\local_check.ps1 setup -Engine desktop   # Windows tools; checks Docker Desktop runs Linux containers
.\scripts\local_check.ps1 full -Engine desktop
.\scripts\local_check.ps1 down -Engine desktop
```

With `-Engine desktop` the script uses Docker Desktop's `docker` command directly and never changes Docker Desktop's settings. If Docker Desktop isn't running, or runs Windows containers, the script stops and says what to do. The stack needs about 4 GB of memory, which Docker Desktop's defaults give on most machines.

Don't also install Docker Engine inside the same Ubuntu that Docker Desktop's WSL integration manages; pick one engine.

Notes:

- To use a distribution with another name, pass it explicitly, for example `-Distro Ubuntu-24.04`. `wsl --list --verbose` shows the names.
- WSL stops an idle distribution, which would take Docker with it. While the stack runs, the script keeps Ubuntu alive with a hidden `wsl.exe` process, and `down` ends it.
- The race detector needs a C compiler, which Windows rarely has. Without `gcc`, the scanner tests run without `-race`; CI still runs them with it.
- If WSL shows Docker networking errors (`iptables` failures) on an old WSL version, run `wsl --update` and then `wsl --shutdown`.
- Clone the repository with Git for Windows as usual. `.gitattributes` keeps LF line endings, which the Linux containers need.

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

The same in PowerShell on Windows (`curl` there is an alias, so this uses the built-in cmdlets):

```powershell
$Token = .\.venv\Scripts\python scripts\vaultgate_login.py   # opens the browser; log in as alice
Set-Content hello.txt 'hello vault' -NoNewline
$Auth = @{ Authorization = "Bearer $Token" }

# 1. Register the file and get an upload token
$Body = @{ name = 'hello.txt'; size = (Get-Item hello.txt).Length; content_type = 'text/plain' } | ConvertTo-Json
$Created = Invoke-RestMethod -Method Post http://localhost:8000/files -Headers $Auth -ContentType 'application/json' -Body $Body
$Id = $Created.file.id

# 2. Upload through the gateway
Invoke-RestMethod -Method Put "http://localhost:8888/uploads/$Id" -Headers @{ Authorization = "Bearer $($Created.upload.token)" } -InFile hello.txt

# 3. What S3 actually stores: starts with VGE1
$Stored = (Invoke-WebRequest "http://localhost:4566/vaultgate-local-vault/files/$Id" -UseBasicParsing).Content
[Text.Encoding]::ASCII.GetString($Stored[0..3])

# 4. Download it back
$Download = Invoke-RestMethod -Method Post "http://localhost:8000/files/$Id/download" -Headers $Auth
Invoke-WebRequest "http://localhost:8888/downloads/$Id" -Headers @{ Authorization = "Bearer $($Download.token)" } -OutFile hello-downloaded.txt -UseBasicParsing
Get-Content hello-downloaded.txt
```

Then open the **VaultGate / Gateway uploads** dashboard in Grafana to see the transfer. In **Explore → Loki**, `{service=~"api|gateway"}` shows the requests.

## Troubleshooting

- **A port is already in use** (5432, 8000, 8080, 8888, 4566, 3000, 9090): stop the other program, for example a local Postgres (`brew services stop postgresql`), or run `down` to clear an old stack.
- **API tests with PostgreSQL fail with `password authentication failed for user "vaultgate"` (Windows):** a PostgreSQL installed on Windows also listens on 5432. Windows lets it share the port with Docker, so the tests reach it instead of the stack. The PowerShell script detects this and says so. Stop it in an admin PowerShell with `Get-Service postgresql* | Stop-Service`; `Get-Service postgresql* | Set-Service -StartupType Manual` keeps it from starting at boot.
- **A service never becomes ready:** run `docker compose ps` and `docker compose logs <service>`. Keycloak is the slowest to start (up to a minute or two).
- **`make tf-local` fails because a resource already exists or is missing:** LocalStack and the Terraform state file disagree (for example, the state was deleted while LocalStack kept running). Run `scripts/local_check.sh down`, delete `infra/terraform/envs/local/terraform.tfstate*`, and run `full` again.
- **The browser login (`make token`) doesn't return:** it listens on `127.0.0.1:8765`; make sure nothing else uses that port.
- **"files in this checkout have Windows (CRLF) line endings" (Windows):** Git for Windows converted the files when you cloned before `.gitattributes` existed. gofmt reports every Go file as unformatted, and scripts in the containers fail. Commit or stash your changes, then run `git rm -r --cached -q .` and `git reset --hard` to check everything out again with LF.
- **Something odd after pulling new code:** `scripts/local_check.sh down`, then `full` again. This rebuilds the images and starts from an empty database.

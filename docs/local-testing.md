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
| Go | 1.26+ | scanner tests | `brew install go` | [go.dev/doc/install](https://go.dev/doc/install) (apt's is often too old) |
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

### Running the Bash script in WSL, with Docker Desktop

`local_check.ps1` covers Windows, and every manual walkthrough below has a PowerShell version, so this is optional. It runs `scripts/local_check.sh`, the script Linux and macOS use, inside an Ubuntu distribution in WSL, with Docker Desktop as the engine.

1. In Docker Desktop, open **Settings → Resources → WSL integration** and turn it on for your Ubuntu distribution. `docker` inside Ubuntu then talks to Docker Desktop. Don't also install Docker Engine in that distribution (`local_check.ps1 setup` without `-Engine desktop` would): pick one engine.
2. Open Ubuntu from PowerShell (`wsl -d Ubuntu`) and install the tools once. Ubuntu 24.04 or newer ships Python 3.12+. Go comes from go.dev because apt's is too old: copy the SHA-256 of the file from [go.dev/dl](https://go.dev/dl/) so the download is checked before it is installed, and on an ARM Windows machine use the `linux-arm64` file instead of `linux-amd64`:
   ```bash
   sudo apt update && sudo apt install -y git make curl gcc python3 python3-venv
   GO=go1.26.10.linux-amd64.tar.gz
   curl -fsSLO "https://go.dev/dl/$GO"
   echo "<SHA-256 from go.dev/dl>  $GO" | sha256sum -c - && sudo tar -C /usr/local -xzf "$GO"
   echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
   curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
   echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
     | sudo tee /etc/apt/sources.list.d/hashicorp.list
   sudo apt update && sudo apt install -y terraform
   ```
3. Clone the repository inside Ubuntu, not under `/mnt/c`: the Windows drive is much slower from WSL, and a Windows checkout can bring CRLF line endings with it.
   ```bash
   git clone https://github.com/flaviocavalcantet/vaultgate.git ~/vaultgate
   ```
4. Run the script inside Ubuntu, or straight from PowerShell:
   ```powershell
   wsl -d Ubuntu -- bash -lc "cd ~/vaultgate && scripts/local_check.sh full"
   ```

Notes:

- Both checkouts start the same Docker Compose project (`vaultgate`) on the same Docker Desktop. Run `down` from the one that started the stack before using the other.
- The stack's ports reach Ubuntu and Windows alike, so `http://localhost:8000` and the other addresses work from both.
- The automated checks log in without a browser. For the manual walkthroughs, Ubuntu may not be able to open your Windows browser: add `--no-browser` to `vaultgate_login.py` and open the URL it prints in Windows. WSL forwards the redirect back to the script on `127.0.0.1:8765`, as long as WSL's localhost forwarding is on (the default).

## What each step verifies

### `quick` (no Docker)

| Step | What it proves |
|---|---|
| Lint | `ruff check` and `ruff format --check` pass for the API and gateway, as in CI |
| Gateway tests | upload and download through the gateway with S3 and KMS emulated in memory (moto): encryption round trip, single-use tokens, size checks, failures cleaned up, tampered or truncated objects cut short, metrics and logs |
| API tests without a database | token validation, auth rules, metrics and logging; database tests are skipped here and run in `full` |
| Scanner | `gofmt`, `go vet` and `go test -race`: PII detectors, VGE1 decryption against the gateway's vectors (streamed and random access), text extraction from Office documents, PDFs and archives, including encrypted, damaged and oversized ones, and the worker: verdicts, tampered objects, retries when the API, KMS or S3 fail, and the queue loop |

### `full` (adds the real stack)

| Step | What it proves |
|---|---|
| Start the stack | `docker compose up --build`, then waits until LocalStack, Keycloak, the API (`/readyz`), the gateway and Grafana answer (the scanner worker starts with them) |
| Terraform | the storage module creates the encrypted, versioned bucket, the KMS key and alias, and the multipart-cleanup rule in LocalStack; the scanning module creates the scan queue and its dead-letter queue |
| API tests with PostgreSQL | users, groups, files, intents, the upload sweep, the internal API, and scan state (requests, results, verdicts, the resender), against a real database (`vaultgate_test`, created automatically) |
| Access policy for local use | adds a policy that lets every signed-in user read, upload and download (`scripts/seed_policies.py`); access is denied by default |
| Login | real Keycloak PKCE login for alice, bob and carol. Checks issuer, audience, lifetime and groups. The API accepts access tokens and refuses ID tokens, only carol sees `/admin/users`, and insecure flows are refused |
| Vault end to end | a 20 MiB upload through the gateway; the object in S3 is ciphertext without the plaintext; the download is identical with the right digest; tokens are single use; bob can't read alice's file; a wrong-size upload is refused; temporary deny policies are enforced by the API and again by the gateway, and a refused token stays usable; the scanner worker finds the random file clean, quarantines a text with a card number and CPFs, and reports an encrypted PDF unscannable |
| Observability | Prometheus config and alert rule tests, Loki and Alloy configs, Grafana dashboards, and every Prometheus scrape target up |

## Try it yourself

With the stack up (after `full`, or `make up && make tf-local && make seed-policies`):

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

### Try the access policies

Access is denied unless a policy allows it ([ADR 0004](adr/0004-access-policies.md)). `full` and `make seed-policies` add one that lets every signed-in user do everything, so the walkthrough above works. This continues in the same terminal as the Bash walkthrough above, after its step 2 (Upload through the gateway): it uses that file's `$FILE_ID`, which must be uploaded. It shows a deny policy taking effect at once, in the API and at the gateway, and the admin dry run explaining it.

You need two logins: alice, whose files these are, and carol, the admin. The browser stays logged in to Keycloak, so `--switch-user` asks it to show the login form anyway:

```bash
TOKEN=$(python3 scripts/vaultgate_login.py --switch-user)   # log in as alice
ADMIN=$(python3 scripts/vaultgate_login.py --switch-user)   # log in as carol
AS_CAROL="Authorization: Bearer $ADMIN"

# 1. The policies in place: the seeded one allows everything to everyone
curl -s http://localhost:8000/admin/policies -H "$AS_CAROL" | python3 -m json.tool

# 2. As alice, get a download token while downloads are allowed
DOWNLOAD_TOKEN=$(curl -s -X POST http://localhost:8000/files/$FILE_ID/download \
  -H "Authorization: Bearer $TOKEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# 3. As carol, deny downloads to /finance (alice's group). Deny wins over the seeded allow.
POLICY_ID=$(curl -s -X POST http://localhost:8000/admin/policies -H "$AS_CAROL" \
  -H "Content-Type: application/json" \
  -d '{"name": "no finance downloads", "effect": "deny", "actions": ["download"], "groups": ["/finance"]}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

# 4. Both checks refuse alice now: the API (a new download) and the gateway (the token from step 2)
curl -s -X POST http://localhost:8000/files/$FILE_ID/download -H "Authorization: Bearer $TOKEN"; echo
# {"detail":"Access denied by policy"}
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $DOWNLOAD_TOKEN" \
  http://localhost:8888/downloads/$FILE_ID
# 403

# 5. Ask the dry run why: it names the policies, which the 403 never does
curl -s -X POST http://localhost:8000/admin/policies/evaluate -H "$AS_CAROL" \
  -H "Content-Type: application/json" \
  -d '{"action": "download", "groups": ["/finance"], "client_ip": "127.0.0.1"}'; echo
# {"allowed":false,"reason":"denied","deny":["no finance downloads"],"allow":["local development: signed-in users"],...}

# 6. Remove the policy. The token from step 2 still works: a refusal does not spend it.
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE http://localhost:8000/admin/policies/$POLICY_ID -H "$AS_CAROL"
# 204
curl -s -o hello-again.txt -H "Authorization: Bearer $DOWNLOAD_TOKEN" http://localhost:8888/downloads/$FILE_ID
cat hello-again.txt
```

Tokens last 5 minutes; if a step answers `401`, log in again with the same command. Try other conditions the same way, for example `"networks": ["192.0.2.0/24"]` (no local client is in it) or a time window that has already ended today; the dry run accepts `"at"` to ask about another time.

The same in PowerShell. Run it in the same window as the PowerShell walkthrough above, after its step 2 (Upload through the gateway): it uses that file's `$Id`, which must be uploaded.

```powershell
$Token = .\.venv\Scripts\python scripts\vaultgate_login.py --switch-user   # log in as alice
$Admin = .\.venv\Scripts\python scripts\vaultgate_login.py --switch-user   # log in as carol
$Auth = @{ Authorization = "Bearer $Token" }
$AsCarol = @{ Authorization = "Bearer $Admin" }

# 1. The policies in place
(Invoke-RestMethod http://localhost:8000/admin/policies -Headers $AsCarol).items | Format-Table name, effect, actions, groups

# 2. As alice, get a download token while downloads are allowed
$Download = Invoke-RestMethod -Method Post "http://localhost:8000/files/$Id/download" -Headers $Auth

# 3. As carol, deny downloads to /finance
$Body = @{ name = 'no finance downloads'; effect = 'deny'; actions = @('download'); groups = @('/finance') } | ConvertTo-Json
$Policy = Invoke-RestMethod -Method Post http://localhost:8000/admin/policies -Headers $AsCarol -ContentType 'application/json' -Body $Body

# 4. Both checks refuse alice now (both print Forbidden)
try { Invoke-RestMethod -Method Post "http://localhost:8000/files/$Id/download" -Headers $Auth } catch { $_.Exception.Response.StatusCode }
try { Invoke-WebRequest "http://localhost:8888/downloads/$Id" -Headers @{ Authorization = "Bearer $($Download.token)" } -UseBasicParsing } catch { $_.Exception.Response.StatusCode }

# 5. Ask the dry run why
$Ask = @{ action = 'download'; groups = @('/finance'); client_ip = '127.0.0.1' } | ConvertTo-Json
Invoke-RestMethod -Method Post http://localhost:8000/admin/policies/evaluate -Headers $AsCarol -ContentType 'application/json' -Body $Ask

# 6. Remove the policy; the token from step 2 still works
Invoke-RestMethod -Method Delete "http://localhost:8000/admin/policies/$($Policy.id)" -Headers $AsCarol
Invoke-WebRequest "http://localhost:8888/downloads/$Id" -Headers @{ Authorization = "Bearer $($Download.token)" } -OutFile hello-again.txt -UseBasicParsing
Get-Content hello-again.txt
```

To see the decisions: the **VaultGate / Service overview** dashboard in Grafana has an **Access policies** row (decisions per second, by action, result and where they were checked), and in **Explore → Loki**, `{service="api"} |= "access denied by policy"` shows each refusal with the deny policies that matched.

### Try the PII scanner

Uploaded files are scanned for personal data (M4; [README](../README.md#pii-scanning)). Try the scanner on its own, on any file, then the scans the worker runs on your uploads. Downloads are not blocked by a scan yet; quarantine comes in the next M4 step.

**The scanner on its own** needs only Go, no stack. Build it once, then point it at a file. It prints one JSON line per match (kind and position in the extracted text; the value itself is never printed), then a summary on stderr. The repository has sample documents in `scanner/internal/extract/testdata` (generated by `generate.py` there):

```bash
cd scanner && go build -o scanner ./cmd/scanner

./scanner internal/extract/testdata/report.docx    # a card, a CPF and an email
./scanner internal/extract/testdata/clean.docx     # nothing found
./scanner internal/extract/testdata/encrypted.pdf; echo "exit $?"   # "file cannot be scanned: PDF is encrypted", exit 3

# Text on stdin. The numbers are well-known test values, not real ones: a CPF has two
# check digits and a card number a Luhn check digit, so a random number is not a match.
echo "CPF 529.982.247-25, card 4111 1111 1111 1111, mail alice@example.com" | ./scanner
```

Try your own files too: Word, Excel, PowerPoint, OpenDocument, PDF (attachments included), zip, or plain text; the format comes from the content, not the name. A file the scanner can't read completely (encrypted, damaged, over a size or expansion limit) exits with status 3: it is never reported as clean. The kinds are `payment_card`, `br_cpf` and `email`.

The same in PowerShell:

```powershell
cd scanner; go build -o scanner.exe ./cmd/scanner
.\scanner.exe internal\extract\testdata\report.docx
.\scanner.exe internal\extract\testdata\encrypted.pdf; "exit $LASTEXITCODE"
'CPF 529.982.247-25, card 4111 1111 1111 1111, mail alice@example.com' | .\scanner.exe
cd ..
```

**Scans of your uploads** need the stack (with `make tf-local`, which creates the scan queue). The `scanner` service is the worker: it takes each upload's scan request from the queue, reads and decrypts the file from S3 in memory, and reports to the API. This continues the Bash walkthrough above after its step 2 (Upload through the gateway), with the same `$TOKEN` and `$FILE_ID`:

```bash
# 1. hello.txt was scanned seconds after the upload: nothing found
curl -s http://localhost:8000/files/$FILE_ID -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# "scan": {"verdict": "clean", "findings": [], "reason": null, "scanned_at": "..."}

# 2. Upload a file with a test card number and two CPFs (steps 1 and 2 of the walkthrough, as a function)
upload() {
  local created; created=$(curl -s -X POST http://localhost:8000/files \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"name\": \"$(basename "$1")\", \"size\": $(wc -c < "$1")}")
  local id; id=$(echo "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["file"]["id"])')
  curl -s -o /dev/null -T "$1" -H "Authorization: Bearer $(echo "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["upload"]["token"])')" \
    http://localhost:8888/uploads/$id
  echo $id
}
echo "Card 4111 1111 1111 1111, CPF 529.982.247-25 and 111.444.777-35" > /tmp/pii.txt
PII_ID=$(upload /tmp/pii.txt)
sleep 2; curl -s http://localhost:8000/files/$PII_ID -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# "scan": {"verdict": "quarantined", "findings": [{"kind": "br_cpf", "count": 2}, {"kind": "payment_card", "count": 1}], ...}

# 3. A document it can't read is unscannable, with the reason
LOCKED_ID=$(upload scanner/internal/extract/testdata/encrypted.pdf)
sleep 2; curl -s http://localhost:8000/files/$LOCKED_ID -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# "scan": {"verdict": "unscannable", "findings": [], "reason": "PDF is encrypted", ...}

# 4. The queue holds requests while the worker is down
docker compose stop scanner
CLEAN_ID=$(upload /tmp/hello.txt)
curl -s http://localhost:8000/files/$CLEAN_ID -H "Authorization: Bearer $TOKEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan"]["verdict"])'
# pending
docker compose start scanner
sleep 10; curl -s http://localhost:8000/files/$CLEAN_ID -H "Authorization: Bearer $TOKEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan"]["verdict"])'
# clean
```

Try your own Word, Excel, PDF or zip files the same way. Emails are recorded but don't quarantine a file. Which kinds do is `VAULTGATE_QUARANTINE_KINDS` on the API (default `payment_card,br_cpf`); the verdict is worked out when read, so after changing it in `docker-compose.yml` and running `docker compose up -d api`, files already scanned show the new verdict. Downloads are not blocked by a verdict yet.

The same in PowerShell, in the window of the PowerShell walkthrough after its step 2, with `$Auth` and `$Id`. `Compose` runs `docker compose` in the repository on the engine `local_check.ps1` uses: Docker Engine in WSL, or Docker Desktop.

```powershell
function Compose { wsl.exe -d Ubuntu -u root --cd "$PWD" -- docker compose @args }   # Docker Desktop: function Compose { docker compose @args }
function Upload($Path) {
    $Body = @{ name = (Split-Path $Path -Leaf); size = (Get-Item $Path).Length } | ConvertTo-Json
    $Created = Invoke-RestMethod -Method Post http://localhost:8000/files -Headers $Auth -ContentType 'application/json' -Body $Body
    Invoke-RestMethod -Method Put "http://localhost:8888/uploads/$($Created.file.id)" -Headers @{ Authorization = "Bearer $($Created.upload.token)" } -InFile $Path | Out-Null
    $Created.file.id
}

# 1. hello.txt was scanned: clean
(Invoke-RestMethod "http://localhost:8000/files/$Id" -Headers $Auth).scan

# 2. A test card number and two CPFs: quarantined, with the counts
Set-Content pii.txt 'Card 4111 1111 1111 1111, CPF 529.982.247-25 and 111.444.777-35' -NoNewline
$PiiId = Upload pii.txt; Start-Sleep 2
(Invoke-RestMethod "http://localhost:8000/files/$PiiId" -Headers $Auth).scan | ConvertTo-Json

# 3. An encrypted PDF: unscannable, with the reason
$LockedId = Upload scanner\internal\extract\testdata\encrypted.pdf; Start-Sleep 2
(Invoke-RestMethod "http://localhost:8000/files/$LockedId" -Headers $Auth).scan

# 4. The queue holds requests while the worker is down
Compose stop scanner
$CleanId = Upload hello.txt
(Invoke-RestMethod "http://localhost:8000/files/$CleanId" -Headers $Auth).scan.verdict   # pending
Compose start scanner; Start-Sleep 10
(Invoke-RestMethod "http://localhost:8000/files/$CleanId" -Headers $Auth).scan.verdict   # clean
```

To watch it: `docker compose logs scanner` shows each scan (`scan reported`, with the verdict and the counts per kind, never the values), and in Grafana, **Explore → Prometheus** with `vaultgate_scanner_jobs_total` counts scans by outcome. **Explore → Loki** with `{service=~"api|scanner"} |= "scan"` follows a request from the API to the worker and back.

## Troubleshooting

- **A port is already in use** (5432, 8000, 8080, 8888, 4566, 3000, 9090): stop the other program, for example a local Postgres (`brew services stop postgresql`), or run `down` to clear an old stack.
- **API tests with PostgreSQL fail with `password authentication failed for user "vaultgate"` (Windows):** a PostgreSQL installed on Windows also listens on 5432. Windows lets it share the port with Docker, so the tests reach it instead of the stack. The PowerShell script detects this and says so. Stop it in an admin PowerShell with `Get-Service postgresql* | Stop-Service`; `Get-Service postgresql* | Set-Service -StartupType Manual` keeps it from starting at boot.
- **A service never becomes ready:** run `docker compose ps` and `docker compose logs <service>`. Keycloak is the slowest to start (up to a minute or two).
- **`make tf-local` fails because a resource already exists or is missing:** LocalStack and the Terraform state file disagree (for example, the state was deleted while LocalStack kept running). Run `scripts/local_check.sh down`, delete `infra/terraform/envs/local/terraform.tfstate*`, and run `full` again.
- **The browser login (`make token`) doesn't return:** it listens on `127.0.0.1:8765`; make sure nothing else uses that port.
- **"files in this checkout have Windows (CRLF) line endings" (Windows):** Git for Windows converted the files when you cloned before `.gitattributes` existed. gofmt reports every Go file as unformatted, and scripts in the containers fail. Commit or stash your changes, then run `git rm -r --cached -q .` and `git reset --hard` to check everything out again with LF.
- **`403 Access denied by policy` on `/files`:** access is denied until a policy allows it. Run `make seed-policies` (or `python3 scripts/seed_policies.py`), or create a policy as carol (see [Access policies](../README.md#access-policies)).
- **Something odd after pulling new code:** `scripts/local_check.sh down`, then `full` again. This rebuilds the images and starts from an empty database.

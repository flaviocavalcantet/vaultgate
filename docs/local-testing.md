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
| Locust | `pip install -r loadtest/requirements.txt` | the load tests (optional) | — | — |
| k3d, kubectl, openssl | k3d 5.8+, OpenSSL 3 | the Kubernetes cluster (optional) | `brew install k3d kubectl openssl@3`, then `export VAULTGATE_OPENSSL=$(brew --prefix openssl@3)/bin/openssl` (macOS's own `openssl` is LibreSSL) | [k3d.io](https://k3d.io/#installation), [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/) |

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
| Start the stack | `docker compose up --build`, then waits until LocalStack, Keycloak, the API (`/readyz`), the gateway and Grafana answer (the scanner worker and Mailpit start with them) |
| Terraform | the storage module creates the encrypted, versioned bucket, the KMS key and alias, and the multipart-cleanup rule in LocalStack; the scanning module creates the scan queue and its dead-letter queue |
| API tests with PostgreSQL | users, groups, files, intents, the upload sweep, the internal API, scan state (requests, results, verdicts, the resender) quarantine (downloads and shares refused until clean or released, the quarantine scope, releases by purpose, rescan, listing by verdict) share links (limits, states, revoking) external recipients (codes, grants, limits, revoking, rescans), internal recipients (verified email, their own policies) and the audit log (events, refusals, append-only trigger, tamper detection), against a real database (`vaultgate_test`, created automatically) |
| Access policy for local use | adds a policy that lets every signed-in user read, upload and download (`scripts/seed_policies.py`); access is denied by default |
| Login | real Keycloak PKCE login for alice, bob and carol. Checks issuer, audience, lifetime and groups. The API accepts access tokens and refuses ID tokens, only carol sees `/admin/users`, and insecure flows are refused |
| Vault end to end | a 20 MiB upload through the gateway; the object in S3 is ciphertext without the plaintext; the download is identical with the right digest; tokens are single use; bob can't read alice's file; a wrong-size upload is refused; temporary deny policies are enforced by the API and again by the gateway, and a refused token stays usable; the scanner worker finds the random file clean before it is downloaded, quarantines a text with a card number and CPFs (no download until carol releases it; a rescan ends the release), and reports an encrypted PDF unscannable; alice shares the clean file with an outside address: the recipient gets a code by email (Mailpit), verifies it and downloads through the gateway, and the revoke stops them; bob, signed in, downloads a file shared with him while carol can't; a file released for download only can't be shared; the audit log holds the file's history and its chain verifies; Tempo has the upload's trace from the gateway through the API and the scan queue to the scanner, and Loki has log lines from all three under its trace ID |
| Observability | Prometheus config and alert rule tests, Loki, Tempo and Alloy configs, Grafana dashboards, and every Prometheus scrape target up |

## Try it yourself

With the stack up (after `full`, or `make up && make tf-local && make seed-policies`):

| What | Where | Login |
|---|---|---|
| API docs | http://localhost:8000/docs | — |
| Keycloak admin | http://localhost:8080 | admin / admin |
| Grafana dashboards | http://localhost:3000 (folder **VaultGate**) | admin / admin |
| Mailpit (email the stack sends) | http://localhost:8025 | — |
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

# 4. Download it back. The PII scan must be clean first, which takes a second or two:
#    a 409 "File is waiting for its PII scan" means try again.
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

# 4. Download it back, once its PII scan is clean (a 409 a second after the upload means try again)
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

Uploaded files are scanned for personal data (M4; [README](../README.md#pii-scanning)). Try the scanner on its own, on any file, then the scans the worker runs on your uploads and the quarantine: only a clean file can be downloaded, unless an admin releases it ([ADR 0005](adr/0005-pii-scanning-and-quarantine.md)).

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

Try your own files too: Word, Excel, PowerPoint, OpenDocument, PDF (attachments included), RTF, emails saved as .eml (attachments included), zip, or plain text in UTF-8 or UTF-16; the format comes from the content, not the name. For example, a CPF in UTF-16 and one written with HTML character references (text on stdin is scanned as it is, so these go through files):

```bash
printf 'CPF 529.982.247-25' | iconv -t UTF-16 > /tmp/utf16.txt && ./scanner /tmp/utf16.txt
echo 'CPF 529&#46;982&#46;247-25' > /tmp/refs.html && ./scanner /tmp/refs.html
```

A file the scanner can't read completely (encrypted, damaged, over a size or expansion limit) exits with status 3: it is never reported as clean. The kinds are `payment_card`, `br_cpf` and `email`.

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

# 4. Quarantine: the owner can't download pii.txt...
curl -s -X POST http://localhost:8000/files/$PII_ID/download -H "Authorization: Bearer $TOKEN"; echo
# {"detail":"File is quarantined: it contains personal data"}

# 5. ...until carol (admin) releases it, with a reason. Log in as carol for this one.
ADMIN=$(python3 scripts/vaultgate_login.py --switch-user)
curl -s "http://localhost:8000/admin/files?verdict=quarantined" -H "Authorization: Bearer $ADMIN" | python3 -m json.tool
curl -s -X POST http://localhost:8000/admin/files/$PII_ID/release -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" -d '{"reason": "Test values only"}' | python3 -m json.tool
# "downloadable": true, "shareable": false, "scan": {"verdict": "quarantined", ..., "releases": [{"purpose": "download", "reason": "Test values only", ...}]}
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8000/files/$PII_ID/download -H "Authorization: Bearer $TOKEN"
# 201

# 6. A rescan ends the release: the file waits for its new verdict, then is quarantined again
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8000/admin/files/$PII_ID/rescan -H "Authorization: Bearer $ADMIN"
# 202
sleep 2; curl -s -X POST http://localhost:8000/files/$PII_ID/download -H "Authorization: Bearer $TOKEN"; echo
# {"detail":"File is quarantined: it contains personal data"}

# 7. The queue holds requests while the worker is down
docker compose stop scanner
CLEAN_ID=$(upload /tmp/hello.txt)
curl -s http://localhost:8000/files/$CLEAN_ID -H "Authorization: Bearer $TOKEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan"]["verdict"])'
# pending
docker compose start scanner
sleep 10; curl -s http://localhost:8000/files/$CLEAN_ID -H "Authorization: Bearer $TOKEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan"]["verdict"])'
# clean
```

Tokens last 5 minutes; if a step answers `401`, log in again. Try your own Word, Excel, PDF or zip files the same way. Emails are recorded but don't quarantine a file. Which kinds do is `VAULTGATE_QUARANTINE_KINDS` on the API (default `payment_card,br_cpf`); the verdict is worked out when read, so after changing it in `docker-compose.yml` and running `docker compose up -d api`, files already scanned show the new verdict. The unscannable PDF from step 3 can be released the same way.

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

# 4. Quarantine: the owner can't download pii.txt (Conflict)...
try { Invoke-RestMethod -Method Post "http://localhost:8000/files/$PiiId/download" -Headers $Auth } catch { $_.Exception.Response.StatusCode }

# 5. ...until carol (admin) releases it, with a reason
$Admin = .\.venv\Scripts\python scripts\vaultgate_login.py --switch-user   # log in as carol
$AsCarol = @{ Authorization = "Bearer $Admin" }
(Invoke-RestMethod "http://localhost:8000/admin/files?verdict=quarantined" -Headers $AsCarol).items | Format-Table name, owner_username
$Released = Invoke-RestMethod -Method Post "http://localhost:8000/admin/files/$PiiId/release" -Headers $AsCarol -ContentType 'application/json' -Body (@{ reason = 'Test values only' } | ConvertTo-Json)
$Released.downloadable   # True
(Invoke-RestMethod -Method Post "http://localhost:8000/files/$PiiId/download" -Headers $Auth).url

# 6. A rescan ends the release (Conflict again once the new scan is done)
Invoke-RestMethod -Method Post "http://localhost:8000/admin/files/$PiiId/rescan" -Headers $AsCarol | Out-Null; Start-Sleep 2
try { Invoke-RestMethod -Method Post "http://localhost:8000/files/$PiiId/download" -Headers $Auth } catch { $_.Exception.Response.StatusCode }

# 7. The queue holds requests while the worker is down
Compose stop scanner
$CleanId = Upload hello.txt
(Invoke-RestMethod "http://localhost:8000/files/$CleanId" -Headers $Auth).scan.verdict   # pending
Compose start scanner; Start-Sleep 10
(Invoke-RestMethod "http://localhost:8000/files/$CleanId" -Headers $Auth).scan.verdict   # clean
```

To watch it: `docker compose logs scanner` shows each scan (`scan reported`, with the verdict and the counts per kind, never the values), and in Grafana, **Explore → Prometheus** with `vaultgate_scanner_jobs_total` counts scans by outcome. **Explore → Loki** with `{service=~"api|scanner"} |= "scan"` follows a request from the API to the worker and back; `|= "quarantine"` shows releases with the admin and the reason, and `|= "download blocked"` the refused downloads.

### Try sharing

Share a file with someone outside VaultGate (M5; [README](../README.md#sharing)). This continues the Bash walkthrough above after its step 2 (Upload through the gateway), with the same `$TOKEN` and `$FILE_ID`; the file must be scanned clean. Alice shares; the "recipient" side uses no VaultGate login at all, only the link and the code that Mailpit catches.

```bash
# 1. As alice, share hello.txt with an outside address: 2 downloads, 1 day
SHARE=$(curl -s -X POST http://localhost:8000/files/$FILE_ID/shares -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"recipient_email": "dana@example.com", "max_downloads": 2, "expires_in_days": 1}')
echo "$SHARE" | python3 -m json.tool          # the link is in "url"; its token is shown only now
LINK=$(echo "$SHARE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
SHARE_ID=$(echo "$SHARE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["share"]["id"])')

# 2. As the recipient: what is this link? (no file name until the address is proven)
curl -s "http://localhost:8000/shares/access?token=$LINK"; echo
# {"recipient_kind":"external","recipient_hint":"d***@example.com","expires_at":"...","downloads_left":2}

# 3. Ask for a code. It arrives in Mailpit: open http://localhost:8025, or read it from its API
curl -s -X POST http://localhost:8000/shares/access/code -H "Content-Type: application/json" -d "{\"token\": \"$LINK\"}"; echo
CODE=$(curl -s "http://localhost:8025/api/v1/messages?limit=1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["messages"][0]["Subject"].split()[-1])')

# 4. Verify the code (a wrong one says how many tries are left), then download through the gateway
GRANT=$(curl -s -X POST http://localhost:8000/shares/access/verify -H "Content-Type: application/json" \
  -d "{\"token\": \"$LINK\", \"code\": \"$CODE\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["grant"])')
SHARED_TOKEN=$(curl -s -X POST http://localhost:8000/shares/access/downloads -H "Content-Type: application/json" \
  -d "{\"token\": \"$LINK\", \"grant\": \"$GRANT\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -s -H "Authorization: Bearer $SHARED_TOKEN" http://localhost:8888/downloads/$FILE_ID; echo
# hello vault

# 5. As alice: the share counted the download. Revoke it, and the recipient is refused at once
curl -s http://localhost:8000/files/$FILE_ID/shares -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE http://localhost:8000/files/$FILE_ID/shares/$SHARE_ID -H "Authorization: Bearer $TOKEN"
# 204
curl -s -X POST http://localhost:8000/shares/access/downloads -H "Content-Type: application/json" \
  -d "{\"token\": \"$LINK\", \"grant\": \"$GRANT\"}"; echo
# {"detail":"Share is revoked"}
```

Share with a VaultGate user instead, and they sign in rather than use a code: bob's verified email is bob@example.com.

```bash
INTERNAL=$(curl -s -X POST http://localhost:8000/files/$FILE_ID/shares -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"recipient_email": "bob@example.com", "recipient_kind": "internal"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["share"]["id"])')
BOB=$(python3 scripts/vaultgate_login.py --switch-user)   # log in as bob
curl -s http://localhost:8000/shared-with-me -H "Authorization: Bearer $BOB" | python3 -m json.tool
BOB_TOKEN=$(curl -s -X POST http://localhost:8000/shared-with-me/$INTERNAL/download -H "Authorization: Bearer $BOB" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -s -H "Authorization: Bearer $BOB_TOKEN" http://localhost:8888/downloads/$FILE_ID; echo
# hello vault
```

Carol (`carol@example.com`) sees nothing in her `/shared-with-me`, and bob stays under his own access policies: a deny policy for `/legal` downloads stops him too.

A quarantined file can't be shared (`409`), and a shared file that a rescan quarantines stops downloading for its recipients at once; an admin's release for sharing (`"purpose": "share"`) lets it be shared anyway.

The same in PowerShell, in the window of the PowerShell walkthrough after its step 2, with `$Auth` and `$Id`:

```powershell
# 1. As alice, share hello.txt with an outside address
$Body = @{ recipient_email = 'dana@example.com'; max_downloads = 2; expires_in_days = 1 } | ConvertTo-Json
$Share = Invoke-RestMethod -Method Post "http://localhost:8000/files/$Id/shares" -Headers $Auth -ContentType 'application/json' -Body $Body
$Link = $Share.token

# 2. As the recipient: what is this link?
Invoke-RestMethod "http://localhost:8000/shares/access?token=$Link"

# 3. Ask for a code and read it from Mailpit (or open http://localhost:8025)
Invoke-RestMethod -Method Post http://localhost:8000/shares/access/code -ContentType 'application/json' -Body (@{ token = $Link } | ConvertTo-Json)
$Code = ((Invoke-RestMethod 'http://localhost:8025/api/v1/messages?limit=1').messages[0].Subject -split ' ')[-1]

# 4. Verify, then download through the gateway
$Grant = (Invoke-RestMethod -Method Post http://localhost:8000/shares/access/verify -ContentType 'application/json' -Body (@{ token = $Link; code = $Code } | ConvertTo-Json)).grant
$Download = Invoke-RestMethod -Method Post http://localhost:8000/shares/access/downloads -ContentType 'application/json' -Body (@{ token = $Link; grant = $Grant } | ConvertTo-Json)
Invoke-WebRequest "http://localhost:8888/downloads/$Id" -Headers @{ Authorization = "Bearer $($Download.token)" } -OutFile shared.txt -UseBasicParsing
Get-Content shared.txt

# 5. As alice: the download is counted; revoke the share, and the recipient is refused (Gone)
Invoke-RestMethod "http://localhost:8000/files/$Id/shares" -Headers $Auth | Format-Table recipient_email, downloads, state
Invoke-RestMethod -Method Delete "http://localhost:8000/files/$Id/shares/$($Share.share.id)" -Headers $Auth
try { Invoke-RestMethod -Method Post http://localhost:8000/shares/access/downloads -ContentType 'application/json' -Body (@{ token = $Link; grant = $Grant } | ConvertTo-Json) } catch { $_.Exception.Response.StatusCode }
```

In PowerShell, the internal share is the same calls: `Invoke-RestMethod -Method Post "http://localhost:8000/files/$Id/shares"` with `recipient_kind = 'internal'` and `recipient_email = 'bob@example.com'`, then, logged in as bob, `Invoke-RestMethod http://localhost:8000/shared-with-me` and `Invoke-RestMethod -Method Post "http://localhost:8000/shared-with-me/<share id>/download"`.

`vaultgate_api_share_codes_sent_total`, `vaultgate_api_share_verifications_total` and `vaultgate_api_share_downloads_total` count each step; in Loki, `{service="api"} |= "share"` shows them by share, never by address.

### Try the audit log

Everything the walkthroughs above did is in the audit log ([ADR 0007](adr/0007-audit-log.md)). As carol (admin):

```bash
ADMIN=$(python3 scripts/vaultgate_login.py --switch-user)   # log in as carol
curl -s "http://localhost:8000/admin/audit?limit=20" -H "Authorization: Bearer $ADMIN" | python3 -m json.tool
curl -s "http://localhost:8000/admin/audit?action=share.&target_id=$FILE_ID" -H "Authorization: Bearer $ADMIN" | python3 -m json.tool
curl -s -X POST http://localhost:8000/admin/audit/verify -H "Authorization: Bearer $ADMIN"; echo
# {"ok":true,"events":42,"head_id":42,"head_hash":"...","first_broken_id":null,"reason":null}
```

Then see what tampering looks like. Changing a row needs the trigger switched off, and the chain shows it:

```bash
docker compose exec postgres psql -U vaultgate -c "UPDATE audit_events SET outcome = 'ok' WHERE id = 3"
# ERROR:  audit_events is append-only (UPDATE refused)
docker compose exec postgres psql -U vaultgate -c "ALTER TABLE audit_events DISABLE TRIGGER USER; UPDATE audit_events SET outcome = 'tampered' WHERE id = 3; ALTER TABLE audit_events ENABLE TRIGGER USER"
curl -s -X POST http://localhost:8000/admin/audit/verify -H "Authorization: Bearer $ADMIN"; echo
# {"ok":false,"events":2,...,"first_broken_id":3,"reason":"its fields do not match its hash (it was changed)"}
```

The chain stays broken from then on; `scripts/local_check.sh down` starts over with an empty database. In PowerShell, the same calls are `Invoke-RestMethod "http://localhost:8000/admin/audit?limit=20" -Headers $AsCarol` and `Invoke-RestMethod -Method Post http://localhost:8000/admin/audit/verify -Headers $AsCarol`.

### Try the traces

Every upload, download and scan above left a trace ([ADR 0008](adr/0008-tracing.md)). Upload a file as in the first walkthrough, then open Grafana (http://localhost:3000, admin / admin) → **Explore** → **Tempo** → **Search**, pick service `gateway` and span name `PUT /uploads/{upload_id}`, and open the newest trace. It shows:

- the gateway's request, with `api consume upload`, `KMS.GenerateDataKey`, one `S3.UploadPart` per 8 MiB and `api complete`;
- the API's side of each call (`POST /internal/intents/consume`, `POST /internal/files/{file_id}/complete`) with its database queries;
- `scan request send`, then the scanner's `scan` a moment later in the same trace, with `unwrap key`, `open object`, `read and detect` (format, parts, how many reads) and its calls back to the API.

Open any span's **Logs for this span** to see the lines all three services wrote under that trace in Loki. The other way round, in **Explore** → **Loki**, `{service="scanner"} |= "scan reported"` shows scan results; each line's `trace_id` has an **Open trace** link.

From a terminal, the same search goes through Tempo's API (TraceQL), here for the file uploaded in the walkthrough:

```bash
curl -s -G http://localhost:3200/api/search --data-urlencode "q={ span.vaultgate.file_id = \"$FILE_ID\" }" | python3 -m json.tool
curl -s http://localhost:3200/api/v2/traces/<traceID from the search> | python3 -m json.tool | grep '"name"'
```

What a span never holds: tokens, query strings, headers, file contents, SQL parameter values or error messages. A trace sent by a client (`traceparent` on a request to the API or the gateway) is ignored: a new trace starts.

## On Kubernetes (k3d)

The same system runs on a local Kubernetes cluster, deployed by Argo CD from this repo ([ADR 0009](adr/0009-local-kubernetes.md), README: [Local Kubernetes](../README.md#local-kubernetes-k3d-and-argo-cd)). It uses the host ports of compose, so stop compose first:

```bash
make down          # compose off
make k3d-up        # cluster, images, root CA, Argo CD, then waits until everything is synced and healthy (5-10 minutes the first time)
make k3d-check     # the vault end-to-end check against the cluster, plus the cluster checks below
```

What `k3d-check` proves on top of the vault check:

| Check | What it proves |
|---|---|
| Argo CD | the root application, the dependencies and VaultGate are all `Synced` and `Healthy`: the cluster runs what git says |
| PKI | OpenBao is initialized and unsealed and serves TLS that verifies against your root CA; its intermediate CA chains to the root, may sign only leaf certificates, and only for cluster and localhost names |
| Credentials | each service's OpenBao login may read its own secrets (the API the tokens, the AWS file and its database credentials, the gateway the internal token and AWS file, the scanner the scanner token and AWS file) and nothing else; no Secret holds them and no deployment has one in its environment |
| TLS | the API's, the gateway's and Keycloak's certificates are issued and come from the intermediate, last at most three days, verify against your root, and plain HTTP gets no answer; the API's connection to PostgreSQL is TLS with the server verified, logged in with short-lived credentials OpenBao issued it, and PostgreSQL refuses one without TLS; every other check talks to them over that TLS |
| Autoscaler | KEDA accepted the gateway's ScaledObject, and the HorizontalPodAutoscaler it manages reads CPU utilization from metrics-server and the transfers in progress from Prometheus, so it can scale on either |
| Network policy | a pod that is neither the gateway nor the scanner reaches the API's public port but not its internal one (8001, which hands out storage keys and wrapped data keys) |
| Prometheus | scrapes the API, gateway and scanner (through the chart's ServiceMonitors, over TLS verified against the trust bundle) and Loki, Tempo and Alloy, all up |
| Grafana | has the VaultGate dashboards and the Prometheus, Loki and Tempo data sources, from the same files as compose |
| Alertmanager | mailed its Watchdog heartbeat to Mailpit: rules, routing and SMTP all work |
| Traces | the vault check's last step runs too: the upload's trace in Tempo, from the gateway to the scanner (sent to Alloy over TLS), and its log lines in Loki |

Load tests run against the cluster too (README: [Load testing](../README.md#load-testing)): `make load-smoke` is a 90-second run with pass/fail thresholds, `make load-test` is the 6-minute run, which writes its CSV and HTML to `loadtest/results/`, and `make load-report` runs it and regenerates `docs/load-testing.md`. Watch it in Grafana's VaultGate dashboards (http://localhost:3000) and in `kubectl -n vaultgate get hpa -w`.

The first `k3d-up` creates the root CA in `~/.vaultgate/pki` and asks for a passphrase for its key (12 characters or more). Later runs reuse that root and ask for the passphrase again when they need to sign something; set `VAULTGATE_PKI_PASSPHRASE` to skip the prompt. Keep the passphrase: without it the root can't sign anything, and a new root means a new cluster (`make k3d-down`, remove `~/.vaultgate/pki`). OpenBao answers on https://localhost:8200, for example `curl --cacert ~/.vaultgate/pki/root-ca.crt https://localhost:8200/v1/pki/ca/pem`.

Every walkthrough above works against the cluster too, since the ports are the same, with one difference: the API (8000), the gateway (8888) and Keycloak (8080) answer on https only, with certificates from the cluster's CA; tokens carry the issuer `https://localhost:8080/realms/vaultgate` (for a browser login like `make token`, run `SSL_CERT_FILE=~/.vaultgate/pki/root-ca.crt python3 scripts/vaultgate_login.py --issuer https://localhost:8080/realms/vaultgate`). Use `https://` and trust your root: `export CURL_CA_BUNDLE=~/.vaultgate/pki/root-ca.crt` covers `curl` (PowerShell on Windows: `Import-Certificate -FilePath root-ca.crt -CertStoreLocation Cert:\CurrentUser\Root`, with the file copied from WSL; remove it with the cluster). Argo CD syncs the branch you are on, which must be pushed; set `VAULTGATE_REVISION` to try another branch or a commit. After changing code, `make k3d-images` rebuilds and pushes the images and restarts the pods. To look around:

```bash
kubectl get applications -n argocd                          # what Argo CD syncs, and its state
kubectl -n vaultgate get pods,scaledobject,hpa,networkpolicy
kubectl -n vaultgate logs deploy/vaultgate-api -f
kubectl -n argocd port-forward svc/argocd-server 8081:80    # UI on http://localhost:8081 (admin; password below)
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d
make k3d-down      # delete the cluster
```

Grafana (http://localhost:3000, admin / admin), Prometheus (9090) and Mailpit (8025) are where compose has them; Alertmanager is on http://localhost:9093. Alerts arrive in Mailpit: a minute after `k3d-up`, the Watchdog heartbeat is there, addressed to `heartbeat@vaultgate.local` (it always fires, so it shows rules, routing and SMTP work). VaultGate's own alerts go to `oncall@vaultgate.local`, with a second mail when they resolve.

## Troubleshooting

- **A port is already in use** (5432, 8000, 8080, 8888, 4566, 3000, 8025, 9090; 8200 on the cluster): stop the other program, for example a local Postgres (`brew services stop postgresql`), or run `down` to clear an old stack.
- **API tests with PostgreSQL fail with `password authentication failed for user "vaultgate"` (Windows):** a PostgreSQL installed on Windows also listens on 5432. Windows lets it share the port with Docker, so the tests reach it instead of the stack. The PowerShell script detects this and says so. Stop it in an admin PowerShell with `Get-Service postgresql* | Stop-Service`; `Get-Service postgresql* | Set-Service -StartupType Manual` keeps it from starting at boot.
- **A service never becomes ready:** run `docker compose ps` and `docker compose logs <service>`. Keycloak is the slowest to start (up to a minute or two).
- **`make tf-local` fails because a resource already exists or is missing:** LocalStack and the Terraform state file disagree (for example, the state was deleted while LocalStack kept running). Run `scripts/local_check.sh down`, delete `infra/terraform/envs/local/terraform.tfstate*`, and run `full` again.
- **The browser login (`make token`) doesn't return:** it listens on `127.0.0.1:8765`; make sure nothing else uses that port.
- **"files in this checkout have Windows (CRLF) line endings" (Windows):** Git for Windows converted the files when you cloned before `.gitattributes` existed. gofmt reports every Go file as unformatted, and scripts in the containers fail. Commit or stash your changes, then run `git rm -r --cached -q .` and `git reset --hard` to check everything out again with LF.
- **`403 Access denied by policy` on `/files`:** access is denied until a policy allows it. Run `make seed-policies` (or `python3 scripts/seed_policies.py`), or create a policy as carol (see [Access policies](../README.md#access-policies)).
- **Something odd after pulling new code:** `scripts/local_check.sh down`, then `full` again. This rebuilds the images and starts from an empty database.

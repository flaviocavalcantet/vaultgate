<#
.SYNOPSIS
    Check VaultGate on Windows, from lint and unit tests up to the whole stack.

.DESCRIPTION
    The Windows counterpart of scripts/local_check.sh. Guide: docs/local-testing.md

    No Docker Desktop: the stack's images are Linux images, so they run on Docker
    Engine (free, Apache 2.0) installed inside a WSL2 distribution. This script
    drives it through wsl.exe. WSL2 forwards the published ports to Windows, so
    the checks run from Windows against localhost, exactly as on Linux or macOS.

      .\scripts\local_check.ps1 setup   install what is missing: Python, Go and
                                        Terraform with winget; Docker Engine in WSL
      .\scripts\local_check.ps1 quick   lint and unit tests; no Docker
      .\scripts\local_check.ps1 full    quick, then start the stack and run the
                                        end-to-end checks
      .\scripts\local_check.ps1 down    stop the stack and delete its data

    With Docker Desktop (and a license where one is needed) running Linux
    containers, add -Engine desktop to use it instead of Docker Engine in WSL.

    Every check runs even if an earlier one fails; a summary is printed at the end
    and the exit code is 1 if anything failed. The stack is left running after
    `full` so you can explore it; `down` removes it.

.PARAMETER Engine
    wsl (default): Docker Engine inside WSL2, no Docker Desktop needed.
    desktop: Docker Desktop's docker command; Docker Desktop must be running
    Linux containers. The script never changes Docker Desktop's settings.

.PARAMETER Distro
    The WSL distribution that runs Docker Engine with -Engine wsl (default: Ubuntu).
#>
param(
    [ValidateSet('setup', 'quick', 'full', 'down')]
    [string]$Mode = 'full',
    [ValidateSet('wsl', 'desktop')]
    [string]$Engine = 'wsl',
    [string]$Distro = 'Ubuntu'
)

$ErrorActionPreference = 'Continue'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot

$OnWindows = ($env:OS -eq 'Windows_NT')
$VenvBin = if ($OnWindows) { Join-Path $RepoRoot '.venv\Scripts' } else { Join-Path $RepoRoot '.venv/bin' }
$ExeSuffix = if ($OnWindows) { '.exe' } else { '' }
$Py = Join-Path $VenvBin "python$ExeSuffix"
$Ruff = Join-Path $VenvBin "ruff$ExeSuffix"
$TestDbUrl = 'postgresql+asyncpg://vaultgate:vaultgate@localhost:5432/vaultgate_test'
$KeepAlivePidFile = Join-Path ([IO.Path]::GetTempPath()) 'vaultgate-wsl-keepalive.pid'
$script:Results = @()
$script:Failed = $false

function Say([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }

function Stop-WithError([string]$Text) {
    Write-Host "error: $Text" -ForegroundColor Red
    exit 1
}

# Run a check, record the result, keep going. Returns $true when it passed.
# Checks return $true or $false; command output goes to the console (Out-Host), never
# into the return value.
function Invoke-Check([string]$Name, [scriptblock]$Check) {
    Say $Name
    $ok = $false
    try {
        $ok = [bool](& $Check | Select-Object -Last 1)
    } catch {
        Write-Host $_ -ForegroundColor Red
    }
    if ($ok) {
        $script:Results += "ok    $Name"
    } else {
        $script:Results += "FAIL  $Name"
        $script:Failed = $true
    }
    return $ok
}

# Run a native command, show its output, and turn its exit code into $true/$false.
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments | Out-Host
    return ($LASTEXITCODE -eq 0)
}

# --- tools ---------------------------------------------------------------------

function Get-ToolVersion([string]$Command, [string[]]$Arguments, [string]$Pattern) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) { return $null }
    $output = (& $Command @Arguments 2>&1 | Out-String)
    if ($output -match $Pattern) { return [version]$Matches[1] }
    return $null
}

# The py launcher picks a 3.12+ install even when `python` is an older one. Callers
# wrap the result in @(): a one-element array would otherwise come back as a string.
function Get-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.12 -c 'import sys' 2>$null
        if ($LASTEXITCODE -eq 0) { return @('py', '-3.12') }
        & py -3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>$null
        if ($LASTEXITCODE -eq 0) { return @('py', '-3') }
    }
    foreach ($name in 'python3', 'python') {
        $version = Get-ToolVersion $name @('--version') 'Python (\d+\.\d+\.\d+)'
        if ($version -and $version -ge [version]'3.12') { return @($name) }
    }
    return $null
}

function Test-Tools([bool]$NeedDocker) {
    $missing = @()
    if (-not @(Get-PythonCommand)) { $missing += 'Python 3.12+   (winget install Python.Python.3.12)' }
    $go = Get-ToolVersion 'go' @('version') 'go(\d+\.\d+(\.\d+)?)'
    if (-not $go -or $go -lt [version]'1.23') { $missing += 'Go 1.23+       (winget install GoLang.Go)' }
    if ($NeedDocker) {
        $tf = Get-ToolVersion 'terraform' @('version') 'Terraform v(\d+\.\d+\.\d+)'
        if (-not $tf -or $tf -lt [version]'1.6') { $missing += 'Terraform 1.6+ (winget install Hashicorp.Terraform)' }
        $dockerProblem = Test-DockerReady
        if ($dockerProblem) { $missing += $dockerProblem }
    }
    if ($missing.Count -gt 0) {
        Write-Host 'Missing:'
        $missing | ForEach-Object { Write-Host "  - $_" }
        Stop-WithError 'install the tools above (or run: .\scripts\local_check.ps1 setup) and run again'
    }
    Write-Host "tools ok: $(@(Get-PythonCommand) -join ' '), Go $go"
}

# --- WSL and Docker Engine -----------------------------------------------------

# wsl.exe prints its own messages in UTF-16; drop the NULs so they can be matched.
function Get-WslDistros {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return @() }
    $raw = (& wsl.exe --list --verbose 2>$null | Out-String) -replace "`0", ''
    $distros = @()
    foreach ($line in ($raw -split "`r?`n" | Select-Object -Skip 1)) {
        $fields = ($line -replace '^\s*\*?\s*', '') -split '\s+'
        if ($fields.Count -ge 3 -and $fields[0]) {
            $distros += [pscustomobject]@{ Name = $fields[0]; Version = $fields[-1] }
        }
    }
    return $distros
}

# Run a command as root inside the distribution (no sudo prompts).
function Invoke-Wsl([string[]]$Arguments) {
    & wsl.exe -d $Distro -u root -- @Arguments | Out-Host
    return ($LASTEXITCODE -eq 0)
}

function Get-WslRepoPath {
    $path = (& wsl.exe -d $Distro -u root -- wslpath -a ($RepoRoot -replace '\\', '/') | Out-String).Trim()
    if (-not $path) { Stop-WithError "could not map $RepoRoot into WSL" }
    return $path
}

# docker for the chosen engine, in the repository directory (compose files and bind
# mounts): inside WSL, or Docker Desktop's own docker command.
function Invoke-Docker([string[]]$Arguments) {
    if ($Engine -eq 'desktop') {
        & docker @Arguments | Out-Host
    } else {
        & wsl.exe -d $Distro -u root --cd $script:WslRepo -- docker @Arguments | Out-Host
    }
    return ($LASTEXITCODE -eq 0)
}

# The repository as the engine sees it, for bind mounts.
function Get-EngineRepoPath {
    if ($Engine -eq 'desktop') { return ($RepoRoot -replace '\\', '/') }
    return $script:WslRepo
}

# Returns a description of what is missing, or $null when Docker Desktop is usable.
function Test-DesktopDocker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        return 'Docker Desktop (or use the default -Engine wsl, which needs no Docker Desktop)'
    }
    $os = (& docker info --format '{{.OSType}}' 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return 'Docker Desktop running: start it and wait until it says the engine is running' }
    if ($os -ne 'linux') {
        return 'Docker Desktop set to Linux containers: right-click the whale icon > "Switch to Linux containers..."'
    }
    return $null
}

function Test-DockerReady {
    if ($Engine -eq 'desktop') { return Test-DesktopDocker }
    return Test-WslDocker
}

# Returns a description of what is missing, or $null when Docker Engine is usable.
function Test-WslDocker {
    if (-not $OnWindows) { return 'this script drives Docker through WSL; on Linux or macOS use scripts/local_check.sh' }
    # PowerShell variables ignore case, so $found, never $distro (that is $Distro).
    $found = Get-WslDistros | Where-Object { $_.Name -eq $Distro }
    if (-not $found) { return "WSL2 distribution '$Distro' (in an admin PowerShell: wsl --install -d $Distro, then reboot)" }
    if ($found.Version -ne '2') { return "'$Distro' runs on WSL1; convert it: wsl --set-version $Distro 2" }
    & wsl.exe -d $Distro -u root -- sh -c 'command -v docker >/dev/null && docker compose version >/dev/null' 2>$null
    if ($LASTEXITCODE -ne 0) { return "Docker Engine and the compose plugin inside '$Distro' (run: .\scripts\local_check.ps1 setup)" }
    return $null
}

# WSL stops an idle distribution after a while, taking dockerd with it; a hidden
# `sleep` keeps it up until `down`.
# The keep-alive process from the PID file, or $null. Windows reuses PIDs (after a
# reboot, say), so the process must also be a wsl.exe; otherwise the file is stale.
function Get-WslKeepAlive {
    if (-not (Test-Path $KeepAlivePidFile)) { return $null }
    $id = 0
    if (-not [int]::TryParse((Get-Content $KeepAlivePidFile -Raw).Trim(), [ref]$id)) { return $null }
    $process = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -eq 'wsl') { return $process }
    return $null
}

function Start-WslKeepAlive {
    if (Get-WslKeepAlive) { return }
    $process = Start-Process wsl.exe -ArgumentList @('-d', $Distro, '-u', 'root', '--', 'sleep', 'infinity') -WindowStyle Hidden -PassThru
    Set-Content -Path $KeepAlivePidFile -Value $process.Id
}

function Stop-WslKeepAlive {
    $process = Get-WslKeepAlive
    if ($process) { $process | Stop-Process -ErrorAction SilentlyContinue }
    Remove-Item $KeepAlivePidFile -ErrorAction SilentlyContinue
}

function Start-DockerEngine {
    Start-WslKeepAlive
    & wsl.exe -d $Distro -u root -- docker info 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { return $true }
    Write-Host "starting Docker Engine in $Distro..."
    Invoke-Wsl @('sh', '-c', 'systemctl start docker 2>/dev/null || service docker start') | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        & wsl.exe -d $Distro -u root -- docker info 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Seconds 2
    }
    Write-Host "Docker Engine did not start; inside WSL check: sudo service docker status"
    return $false
}

# --- setup ---------------------------------------------------------------------

function Install-WingetPackage([string]$Id) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget not found; install $Id by hand (see docs/local-testing.md)"
        return
    }
    & winget install --exact --id $Id --accept-package-agreements --accept-source-agreements | Out-Host
}

function Invoke-Setup {
    if (-not $OnWindows) { Stop-WithError 'setup is for Windows; on Linux or macOS see docs/local-testing.md' }
    Say 'Windows tools'
    if (-not @(Get-PythonCommand)) { Install-WingetPackage 'Python.Python.3.12' }
    $go = Get-ToolVersion 'go' @('version') 'go(\d+\.\d+(\.\d+)?)'
    if (-not $go -or $go -lt [version]'1.23') { Install-WingetPackage 'GoLang.Go' }
    $tf = Get-ToolVersion 'terraform' @('version') 'Terraform v(\d+\.\d+\.\d+)'
    if (-not $tf -or $tf -lt [version]'1.6') { Install-WingetPackage 'Hashicorp.Terraform' }

    if ($Engine -eq 'desktop') {
        Say 'Docker Desktop'
        $problem = Test-DesktopDocker
        if ($problem) { Stop-WithError "needs $problem" }
        Write-Host 'Docker Desktop is running Linux containers.'
        Write-Host "`nOpen a new PowerShell (so PATH picks up new tools) and run:"
        Write-Host '  .\scripts\local_check.ps1 full -Engine desktop'
        exit 0
    }

    Say "WSL2 and $Distro"
    $found = Get-WslDistros | Where-Object { $_.Name -eq $Distro }
    if (-not $found) {
        Write-Host "No '$Distro' distribution. In an admin PowerShell run:"
        Write-Host "  wsl --install -d $Distro"
        Write-Host 'then reboot, open the distribution once to create your user, and run setup again.'
        exit 1
    }
    if ($found.Version -ne '2') { Stop-WithError "'$Distro' runs on WSL1; convert it first: wsl --set-version $Distro 2" }

    Say "Docker Engine in $Distro"
    & wsl.exe -d $Distro -u root -- sh -c 'command -v docker >/dev/null && docker compose version >/dev/null' 2>$null
    if ($LASTEXITCODE -ne 0) {
        # Docker's official install script: Docker Engine (docker-ce), CLI and compose plugin.
        # On WSL it suggests Docker Desktop and waits 20 seconds, then installs anyway.
        Write-Host 'Installing Docker Engine (it pauses 20 s on a Docker Desktop notice; let it continue)...'
        $ok = Invoke-Wsl @('sh', '-c', 'curl -fsSL https://get.docker.com | sh')
        if (-not $ok) { Stop-WithError 'Docker Engine install failed; see the output above' }
    } else {
        Write-Host 'Docker Engine is already installed.'
    }
    if (-not (Start-DockerEngine)) { exit 1 }
    & wsl.exe -d $Distro -u root -- docker version --format 'Docker Engine {{.Server.Version}} is running' | Out-Host

    Write-Host "`nSetup done. Open a new PowerShell (so PATH picks up new tools) and run:"
    Write-Host '  .\scripts\local_check.ps1 full'
    exit 0
}

# --- checks --------------------------------------------------------------------

function Initialize-Venv {
    if (-not (Test-Path $Py)) {
        $python = @(Get-PythonCommand)
        $pythonArgs = @($python | Select-Object -Skip 1) + @('-m', 'venv', '.venv')
        if (-not (Invoke-Native $python[0] $pythonArgs)) { return $false }
    }
    if (-not (Invoke-Native $Py @('-m', 'pip', 'install', '--quiet', '--upgrade', 'pip'))) { return $false }
    return (Invoke-Native $Py @('-m', 'pip', 'install', '--quiet', '-e', 'api[dev]', '-e', 'gateway[dev]'))
}

function Test-Lint {
    $ok = $true
    foreach ($service in 'api', 'gateway') {
        Push-Location $service
        if (-not (Invoke-Native $Ruff @('check', '.'))) { $ok = $false }
        if (-not (Invoke-Native $Ruff @('format', '--check', '.'))) { $ok = $false }
        Pop-Location
    }
    return $ok
}

function Invoke-Pytest([string]$Service, [string]$DatabaseUrl) {
    $previous = $env:VAULTGATE_TEST_DATABASE_URL
    if ($DatabaseUrl) { $env:VAULTGATE_TEST_DATABASE_URL = $DatabaseUrl }
    else { Remove-Item Env:VAULTGATE_TEST_DATABASE_URL -ErrorAction SilentlyContinue }
    Push-Location $Service
    try { return (Invoke-Native $Py @('-m', 'pytest', '-q')) }
    finally {
        Pop-Location
        if ($previous) { $env:VAULTGATE_TEST_DATABASE_URL = $previous }
        else { Remove-Item Env:VAULTGATE_TEST_DATABASE_URL -ErrorAction SilentlyContinue }
    }
}

function Test-Scanner {
    Push-Location scanner
    try {
        $unformatted = (& gofmt -l . | Out-String).Trim()
        if ($unformatted) { Write-Host "not gofmt-formatted:`n$unformatted"; return $false }
        if (-not (Invoke-Native 'go' @('vet', './...'))) { return $false }
        # The race detector needs cgo and a C compiler, which Windows rarely has.
        if (Get-Command gcc -ErrorAction SilentlyContinue) {
            return (Invoke-Native 'go' @('test', '-race', './...'))
        }
        Write-Host '(no gcc: running without -race; CI runs it with -race)'
        return (Invoke-Native 'go' @('test', './...'))
    } finally { Pop-Location }
}

function Wait-ForUrl([string]$Url, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -lt 400) { return $true }
        } catch { }
        Start-Sleep -Seconds 3
    }
    Write-Host "timed out waiting for $Url"
    return $false
}

function Start-Stack {
    if ($Engine -eq 'wsl' -and -not (Start-DockerEngine)) { return $false }
    if (-not (Invoke-Docker @('compose', 'up', '--build', '-d'))) { return $false }
    Write-Host 'waiting for the services (the first run builds images and takes a few minutes)...'
    return ((Wait-ForUrl 'http://localhost:4566/_localstack/health' 180) -and
        (Wait-ForUrl 'http://localhost:8080/realms/vaultgate/.well-known/openid-configuration' 240) -and
        (Wait-ForUrl 'http://localhost:8000/readyz' 180) -and
        (Wait-ForUrl 'http://localhost:8888/healthz' 120) -and
        (Wait-ForUrl 'http://localhost:3000/api/health' 120))
}

function Invoke-Terraform {
    $dir = '-chdir=infra/terraform/envs/local'
    if (-not (Invoke-Native 'terraform' @($dir, 'init', '-input=false'))) { return $false }
    return (Invoke-Native 'terraform' @($dir, 'apply', '-auto-approve', '-input=false'))
}

function Test-ApiDatabase {
    $query = @('compose', 'exec', '-T', 'postgres', 'psql', '-U', 'vaultgate', '-d', 'vaultgate', '-tAc',
        "SELECT 1 FROM pg_database WHERE datname = 'vaultgate_test'")
    if ($Engine -eq 'desktop') { $exists = (& docker @query | Out-String).Trim() }
    else { $exists = (& wsl.exe -d $Distro -u root --cd $script:WslRepo -- docker @query | Out-String).Trim() }
    if ($exists -ne '1') {
        if (-not (Invoke-Docker @('compose', 'exec', '-T', 'postgres', 'createdb', '-U', 'vaultgate', 'vaultgate_test'))) { return $false }
    }
    return (Invoke-Pytest 'api' $TestDbUrl)
}

function Test-Observability {
    $repo = Get-EngineRepoPath
    $checks = @(
        @('run', '--rm', '-v', "$repo/observability/prometheus:/etc/prometheus:ro", '--entrypoint', 'promtool',
            'prom/prometheus:v3.1.0', 'check', 'config', '/etc/prometheus/prometheus.yml'),
        @('run', '--rm', '-v', "$repo/observability/prometheus/rules:/rules:ro", '-w', '/rules', '--entrypoint', 'promtool',
            'prom/prometheus:v3.1.0', 'test', 'rules', 'vaultgate_test.yml'),
        @('run', '--rm', '-v', "$repo/observability/loki/loki.yml:/cfg/loki.yml:ro",
            'grafana/loki:3.3.2', '-config.file=/cfg/loki.yml', '-verify-config'),
        @('run', '--rm', '-v', "$repo/observability/alloy:/cfg:ro", 'grafana/alloy:v1.5.1', 'fmt', '-t', '/cfg/config.alloy')
    )
    $ok = $true
    foreach ($dockerArgs in $checks) { if (-not (Invoke-Docker $dockerArgs)) { $ok = $false } }
    if (-not (Invoke-Native $Py @('scripts/check_dashboards.py', 'observability/grafana/dashboards'))) { $ok = $false }
    try {
        $targets = (Invoke-RestMethod -Uri 'http://localhost:9090/api/v1/targets' -TimeoutSec 10).data.activeTargets
        Write-Host "Prometheus targets: $(($targets | ForEach-Object { $_.labels.job } | Sort-Object) -join ', ')"
        $down = @($targets | Where-Object { $_.health -ne 'up' } | ForEach-Object { $_.labels.job })
        if ($down.Count -gt 0) { Write-Host "targets down: $($down -join ', ')"; $ok = $false }
    } catch { Write-Host "could not read Prometheus targets: $_"; $ok = $false }
    return $ok
}

function Show-Summary {
    Say 'Summary'
    $script:Results | ForEach-Object { Write-Host $_ }
    if ($Mode -eq 'full') {
        Write-Host @'

The stack is still running. Explore it (logins are in docs/local-testing.md):
  API docs        http://localhost:8000/docs
  Keycloak        http://localhost:8080        admin / admin
  Grafana         http://localhost:3000        admin / admin  (VaultGate folder)
  Prometheus      http://localhost:9090
Stop it with:     .\scripts\local_check.ps1 down   (add -Engine desktop if you used it)
'@
    }
    if ($script:Failed) { exit 1 }
    exit 0
}

# --- main ----------------------------------------------------------------------

switch ($Mode) {
    'setup' { Invoke-Setup }
    'down' {
        $problem = Test-DockerReady
        if ($problem) { Stop-WithError $problem }
        if ($Engine -eq 'wsl') { $script:WslRepo = Get-WslRepoPath }
        $ok = Invoke-Docker @('compose', 'down', '-v')
        if ($Engine -eq 'wsl') { Stop-WslKeepAlive }
        if ($ok) { exit 0 } else { exit 1 }
    }
}

Say 'Checking tools'
Test-Tools ($Mode -eq 'full')

if (-not (Invoke-Check 'Python environment (.venv)' { Initialize-Venv })) { Show-Summary }
Invoke-Check 'Lint: ruff (api, gateway)' { Test-Lint } | Out-Null
Invoke-Check 'Gateway tests (moto S3/KMS, no Docker)' { Invoke-Pytest 'gateway' $null } | Out-Null
Invoke-Check 'API tests without a database' { Invoke-Pytest 'api' $null } | Out-Null
Invoke-Check 'Scanner: gofmt, go vet, go test' { Test-Scanner } | Out-Null

if ($Mode -eq 'full') {
    if ($Engine -eq 'wsl') {
        $script:WslRepo = Get-WslRepoPath
        $engineName = "Docker Engine in WSL '$Distro'"
    } else {
        $engineName = 'Docker Desktop'
    }
    if (Invoke-Check "Start the stack ($engineName)" { Start-Stack }) {
        Invoke-Check 'Terraform: bucket and KMS key in LocalStack' { Invoke-Terraform } | Out-Null
        Invoke-Check 'API tests with PostgreSQL' { Test-ApiDatabase } | Out-Null
        Invoke-Check 'Login: Keycloak PKCE, token checks, /me, admin' {
            Invoke-Native $Py @('scripts/keycloak_smoke.py', 'http://localhost:8080', '--api', 'http://localhost:8000')
        } | Out-Null
        Invoke-Check 'Vault end to end: upload, ciphertext in S3, download' {
            Invoke-Native $Py @('scripts/vault_e2e.py')
        } | Out-Null
        Invoke-Check 'Observability: configs, alert rules, dashboards, targets' { Test-Observability } | Out-Null
    } else {
        Write-Host 'the stack did not start; see: docker compose ps; docker compose logs'
    }
}

Show-Summary

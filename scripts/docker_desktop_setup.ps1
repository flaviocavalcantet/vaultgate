<#
.SYNOPSIS
    Prepare Docker Desktop on Windows to run the VaultGate stack (Linux containers).

.DESCRIPTION
    For people who have Docker Desktop (and a license where one is needed). Without
    Docker Desktop, use Docker Engine in WSL2 instead: .\scripts\local_check.ps1 setup

    1. Starts Docker Desktop if it is not running and waits for its engine.
    2. Switches to Linux containers if it runs Windows containers.
    3. Reports the backend (WSL 2 or Hyper-V) and checks that the engine has at
       least 4 GB of memory. On the WSL 2 backend it can raise the limit in
       %UserProfile%\.wslconfig (backed up first); on Hyper-V it says where to
       change it in Settings.
    4. Runs a small Linux container to prove it works.

    It never edits Docker Desktop's own settings file. Anything that restarts
    Docker Desktop or WSL asks first, unless -Yes is given.

    Then run the checks with Docker Desktop instead of Docker Engine in WSL:
        .\scripts\local_check.ps1 full -Engine desktop

.PARAMETER Yes
    Do not ask before changing .wslconfig or restarting WSL and Docker Desktop.
#>
param([switch]$Yes)

$ErrorActionPreference = 'Continue'
$MinMemoryGiB = 3.5   # what the engine reports for a 4 GB limit is a little under 4 GiB
$TargetMemory = '4GB'
$DesktopExe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
$DockerCliExe = Join-Path $env:ProgramFiles 'Docker\Docker\DockerCli.exe'

function Say([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }

function Stop-WithError([string]$Text) {
    Write-Host "error: $Text" -ForegroundColor Red
    exit 1
}

function Confirm-Step([string]$Question) {
    if ($Yes) { return $true }
    $answer = Read-Host "$Question [y/N]"
    return ($answer -match '^(y|yes)$')
}

# `docker info` field, or $null when the engine is not reachable.
function Get-EngineInfo([string]$Field) {
    $value = (& docker info --format "{{.$Field}}" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $value) { return $null }
    return $value
}

function Wait-ForEngine([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (Get-EngineInfo 'OSType') { return $true }
        Start-Sleep -Seconds 3
    }
    return $false
}

# The `docker desktop` commands exist from Docker Desktop 4.37 on.
function Test-DesktopCli {
    & docker desktop version 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Start-DockerDesktop {
    if (Test-DesktopCli) {
        & docker desktop start 2>$null | Out-Host
    } else {
        Start-Process $DesktopExe
    }
}

function Restart-DockerDesktop {
    if (Test-DesktopCli) {
        & docker desktop restart | Out-Host
    } else {
        Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 5
        Start-Process $DesktopExe
    }
}

function Switch-ToLinuxEngine {
    if (Test-DesktopCli) {
        & docker desktop engine use linux | Out-Host
    } elseif (Test-Path $DockerCliExe) {
        & $DockerCliExe -SwitchLinuxEngine | Out-Host
    } else {
        Stop-WithError 'cannot switch automatically: right-click the Docker whale in the taskbar and choose "Switch to Linux containers...", then run this script again'
    }
}

# Set memory=<value> in the [wsl2] section of .wslconfig, keeping everything else.
function Set-WslMemory([string]$Path, [string]$Value) {
    $lines = @()
    if (Test-Path $Path) {
        Copy-Item $Path "$Path.bak-$(Get-Date -Format yyyyMMddHHmmss)"
        $lines = @(Get-Content $Path)
    }
    $out = New-Object System.Collections.Generic.List[string]
    $inWsl2 = $false; $sawWsl2 = $false; $written = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*\[(.+)\]\s*$') {
            if ($inWsl2 -and -not $written) { $out.Add("memory=$Value"); $written = $true }
            $inWsl2 = ($Matches[1].Trim() -eq 'wsl2')
            if ($inWsl2) { $sawWsl2 = $true }
            $out.Add($line)
            continue
        }
        if ($inWsl2 -and $line -match '^\s*memory\s*=') {
            if (-not $written) { $out.Add("memory=$Value"); $written = $true }
            continue
        }
        $out.Add($line)
    }
    if ($inWsl2 -and -not $written) { $out.Add("memory=$Value"); $written = $true }
    if (-not $sawWsl2) { $out.Add('[wsl2]'); $out.Add("memory=$Value") }
    # WSL reads .wslconfig as plain text; write it without a byte-order mark.
    [IO.File]::WriteAllLines($Path, [string[]]$out.ToArray())
}

# --- main ----------------------------------------------------------------------

if ($env:OS -ne 'Windows_NT') { Stop-WithError 'this script is for Docker Desktop on Windows' }

Say 'Docker Desktop'
if (-not (Get-Command docker -ErrorAction SilentlyContinue) -and -not (Test-Path $DesktopExe)) {
    Write-Host 'Docker Desktop is not installed. With a license, install it with:'
    Write-Host '  winget install --exact --id Docker.DockerDesktop'
    Write-Host 'or use the free Docker Engine in WSL2 instead: .\scripts\local_check.ps1 setup'
    exit 1
}
if (-not (Get-EngineInfo 'OSType')) {
    Write-Host 'starting Docker Desktop...'
    Start-DockerDesktop
    if (-not (Wait-ForEngine 180)) {
        Stop-WithError 'Docker Desktop did not start within 3 minutes; open it once by hand (first start asks to accept its terms) and run again'
    }
}
Write-Host "Docker Desktop engine $(Get-EngineInfo 'ServerVersion') is running"

Say 'Linux containers'
if ((Get-EngineInfo 'OSType') -ne 'linux') {
    Write-Host 'Docker Desktop runs Windows containers; switching to Linux containers...'
    Switch-ToLinuxEngine
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-EngineInfo 'OSType') -ne 'linux' -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }
    if ((Get-EngineInfo 'OSType') -ne 'linux') { Stop-WithError 'the switch to Linux containers did not complete' }
}
Write-Host 'Linux containers: ok'

Say 'Backend and memory'
$kernel = Get-EngineInfo 'KernelVersion'
$onWsl2 = ($kernel -match 'microsoft-standard-WSL2')
$backend = if ($onWsl2) { 'WSL 2' } else { 'Hyper-V' }
$memGiB = [math]::Round([double](Get-EngineInfo 'MemTotal') / 1GB, 1)
Write-Host "backend: $backend (kernel $kernel), CPUs: $(Get-EngineInfo 'NCPU'), memory: $memGiB GiB"
if (-not $onWsl2) {
    Write-Host 'Docker recommends the WSL 2 backend: Settings > General > "Use the WSL 2 based engine".'
}

if ($memGiB -lt $MinMemoryGiB) {
    Write-Host "The stack needs about 4 GB; the engine has $memGiB GiB." -ForegroundColor Yellow
    if (-not $onWsl2) {
        Stop-WithError 'raise it in Docker Desktop: Settings > Resources > Advanced > Memory (4 GB or more), apply, and run again'
    }
    $hostGiB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    $wslConfig = Join-Path $env:USERPROFILE '.wslconfig'
    Write-Host "On the WSL 2 backend the limit comes from $wslConfig (this machine has $hostGiB GiB)."
    if ($hostGiB -lt 8) {
        Write-Host 'With under 8 GiB of RAM, giving WSL 4 GB leaves little for Windows; expect slowness.' -ForegroundColor Yellow
    }
    if (-not (Confirm-Step "Set memory=$TargetMemory in $wslConfig (a backup is kept) and restart WSL and Docker Desktop?")) {
        Stop-WithError "not changed; set [wsl2] memory=$TargetMemory in $wslConfig yourself, run 'wsl --shutdown', and restart Docker Desktop"
    }
    Set-WslMemory $wslConfig $TargetMemory
    Write-Host 'restarting WSL and Docker Desktop (running containers stop)...'
    & wsl.exe --shutdown
    Restart-DockerDesktop
    if (-not (Wait-ForEngine 240)) { Stop-WithError 'Docker Desktop did not come back after the restart; start it by hand' }
    $memGiB = [math]::Round([double](Get-EngineInfo 'MemTotal') / 1GB, 1)
    Write-Host "memory now: $memGiB GiB"
    if ($memGiB -lt $MinMemoryGiB) { Stop-WithError 'the new limit did not take effect; check .wslconfig and restart Docker Desktop' }
}
Write-Host 'memory: ok'

Say 'Docker Compose'
& docker compose version | Out-Host
if ($LASTEXITCODE -ne 0) { Stop-WithError 'docker compose is missing; update Docker Desktop' }

Say 'Test container'
$os = (& docker run --rm alpine:3.20 uname -s | Out-String).Trim()
if ($os -ne 'Linux') { Stop-WithError "a Linux test container did not run (got '$os')" }
Write-Host 'a Linux container ran: ok'

Write-Host "`nDocker Desktop is ready. Run the checks with:"
Write-Host '  .\scripts\local_check.ps1 full -Engine desktop'
exit 0

# TraceGuard Windows Agent Installer
# Run as Administrator
#
# Usage: .\install.ps1 [-BackendURL "backend.company.com:50051"]

param(
    [string]$BackendURL = "localhost:50051",
    [string]$InstallDir = "C:\Program Files\TraceGuard",
    [string]$DataDir = "C:\ProgramData\TraceGuard"
)

$ErrorActionPreference = "Stop"

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Host "=== TraceGuard Windows Agent Installer ===" -ForegroundColor Cyan
Write-Host ""

# Create directories
Write-Host "[1/6] Creating directories..." -ForegroundColor Yellow
$dirs = @(
    $InstallDir,
    $DataDir,
    "$DataDir\Logs",
    "$DataDir\Quarantine"
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Host "  Created: $d"
    }
}

# Copy binary
Write-Host "[2/6] Copying agent binary..." -ForegroundColor Yellow
$srcBinary = Join-Path $PSScriptRoot "..\edr-agent.exe"
if (-not (Test-Path $srcBinary)) {
    $srcBinary = Join-Path $PSScriptRoot "edr-agent.exe"
}
if (Test-Path $srcBinary) {
    Copy-Item $srcBinary "$InstallDir\edr-agent.exe" -Force
    Write-Host "  Copied edr-agent.exe to $InstallDir"
} else {
    Write-Error "Cannot find edr-agent.exe. Build it first: make build"
    exit 1
}

# Copy config (only if not exists — don't overwrite existing config)
Write-Host "[3/6] Setting up configuration..." -ForegroundColor Yellow
$configDest = "$DataDir\agent.yaml"
if (-not (Test-Path $configDest)) {
    $srcConfig = Join-Path $PSScriptRoot "..\config\agent.yaml"
    if (Test-Path $srcConfig) {
        $content = Get-Content $srcConfig -Raw
        $content = $content -replace 'backend_url: "localhost:50051"', "backend_url: `"$BackendURL`""
        Set-Content -Path $configDest -Value $content
        Write-Host "  Config written to $configDest"
    }
} else {
    Write-Host "  Config already exists at $configDest (not overwriting)"
}

# Install Windows service
Write-Host "[4/6] Installing Windows service..." -ForegroundColor Yellow
$svcName = "TraceGuardAgent"
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  Service already exists. Stopping and removing..."
    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
        Remove-Service -Name $svcName -ErrorAction SilentlyContinue
    } else {
        sc.exe delete $svcName | Out-Null
    }
    Start-Sleep -Seconds 3  # wait for SCM to fully release the service name
}

# sc.exe requires binpath= followed by a single string with embedded quotes.
# Use New-Service instead — it handles quoting correctly.
$binExe = Join-Path $InstallDir "edr-agent.exe"
$svcArgs = "--config `"$configDest`""

$newSvc = New-Service -Name $svcName `
    -BinaryPathName "`"$binExe`" $svcArgs" `
    -DisplayName "TraceGuard Endpoint Agent" `
    -Description "Open EDR endpoint detection and response agent for Windows" `
    -StartupType Automatic `
    -ErrorAction Stop

Write-Host "  Service '$svcName' installed"

# Set auto-restart on failure (New-Service doesn't support this).
Write-Host "[5/6] Configuring service recovery..." -ForegroundColor Yellow
sc.exe failure $svcName reset= 60 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Write-Host "  Service will auto-restart on failure (3 attempts: 5s, 10s, 30s)"

# Start service
Write-Host "[6/6] Starting service..." -ForegroundColor Yellow
Start-Service -Name $svcName
$svc = Get-Service -Name $svcName
Write-Host "  Service status: $($svc.Status)" -ForegroundColor Green

Write-Host ""
Write-Host "=== TraceGuard Agent installed successfully ===" -ForegroundColor Green
Write-Host "  Binary:  $InstallDir\edr-agent.exe"
Write-Host "  Config:  $configDest"
Write-Host "  Logs:    $DataDir\Logs\agent.log"
Write-Host "  Service: $svcName"
Write-Host ""
Write-Host "To check status:  Get-Service $svcName"
Write-Host "To view logs:     Get-Content $DataDir\Logs\agent.log -Tail 50"
Write-Host "To stop:          Stop-Service $svcName"

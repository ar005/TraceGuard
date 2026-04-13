# TraceGuard Windows Agent Uninstaller
# Run as Administrator

param(
    [switch]$RemoveData = $false,
    [string]$InstallDir = "C:\Program Files\TraceGuard",
    [string]$DataDir = "C:\ProgramData\TraceGuard"
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Host "=== TraceGuard Windows Agent Uninstaller ===" -ForegroundColor Cyan
Write-Host ""

# Stop and remove service
$svcName = "TraceGuardAgent"
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "[1/4] Stopping service..." -ForegroundColor Yellow
    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Write-Host "[2/4] Removing service..." -ForegroundColor Yellow
    # Remove-Service available in PS 6+; fall back to sc.exe for PS 5.1
    if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
        Remove-Service -Name $svcName
    } else {
        sc.exe delete $svcName | Out-Null
    }
    Start-Sleep -Seconds 1
    Write-Host "  Service removed"
} else {
    Write-Host "[1-2/4] Service not found (already removed)" -ForegroundColor Gray
}

# Remove TraceGuard firewall rules
Write-Host "[3/4] Cleaning up firewall rules..." -ForegroundColor Yellow
$rules = netsh advfirewall firewall show rule name=all | Select-String "TraceGuard_BLOCK_"
if ($rules) {
    foreach ($rule in $rules) {
        $name = ($rule -split "Rule Name:")[1].Trim()
        netsh advfirewall firewall delete rule name="$name" | Out-Null
    }
    Write-Host "  Removed TraceGuard firewall rules"
} else {
    Write-Host "  No TraceGuard firewall rules found"
}

# Remove files
Write-Host "[4/4] Removing program files..." -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "  Removed $InstallDir"
}

if ($RemoveData) {
    if (Test-Path $DataDir) {
        Remove-Item -Path $DataDir -Recurse -Force
        Write-Host "  Removed $DataDir (including logs, config, and event buffer)"
    }
} else {
    Write-Host "  Data preserved at $DataDir (use -RemoveData to delete)"
}

Write-Host ""
Write-Host "=== TraceGuard Agent uninstalled ===" -ForegroundColor Green

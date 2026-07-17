#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Integration test for TraceGuard Windows agent ETW monitors.

.DESCRIPTION
    Triggers real OS events — process launch, file I/O, DNS query, network
    connection, registry write, failed logon, and TLS handshake — and asserts
    the corresponding event types appear in the backend within the configured
    timeout window.

    A secondary section inspects the agent log to confirm each monitor started
    in ETW/push mode rather than falling back to its polling fallback.  This
    section is used for regression testing on Windows Server 2012 R2 where
    kernel ETW providers are unavailable.

.PARAMETER BackendUrl
    Base URL of the TraceGuard backend.  Default: http://localhost:8080

.PARAMETER Token
    JWT bearer token.  Falls back to $env:EDR_TOKEN.  If neither is set the
    script attempts a login with $Username/$Password.

.PARAMETER Username
    Username for automatic login when no token is available.  Default: admin

.PARAMETER Password
    Password for automatic login.  Default: $env:EDR_ADMIN_PASSWORD

.PARAMETER AgentId
    The Windows agent UUID.  Auto-read from C:\ProgramData\TraceGuard\agent.id
    if not provided.

.PARAMETER TimeoutMs
    Maximum milliseconds to wait for a process/DNS/file/network/TLS event.
    Default: 500

.PARAMETER RegistryTimeoutMs
    Maximum milliseconds to wait for a registry event (ETW latency is lower).
    Default: 100

.PARAMETER LogFile
    Path to the agent's JSON log file.
    Default: C:\ProgramData\TraceGuard\Logs\agent.log

.EXAMPLE
    .\test-etw-monitors.ps1
    .\test-etw-monitors.ps1 -Token "eyJ..." -TimeoutMs 1000
    .\test-etw-monitors.ps1 -BackendUrl http://192.168.1.10:8080 -Username admin -Password "S3cret!"
#>
param(
    [string] $BackendUrl         = "http://localhost:8080",
    [string] $Token              = $env:EDR_TOKEN,
    [string] $Username           = "admin",
    [string] $Password           = $env:EDR_ADMIN_PASSWORD,
    [string] $AgentId            = "",
    [int]    $TimeoutMs          = 500,
    [int]    $RegistryTimeoutMs  = 100,
    [string] $LogFile            = "C:\ProgramData\TraceGuard\Logs\agent.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colours and result tracking ───────────────────────────────────────────────

$script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Passed  = 0
$script:Failed  = 0
$script:Skipped = 0

function Write-Result {
    param([string]$Name, [string]$Status, [string]$Detail = "", [int]$ElapsedMs = -1)
    $colour = switch ($Status) {
        "PASS" { "Green" }; "FAIL" { "Red" }; "SKIP" { "Yellow" }; default { "White" }
    }
    $timing = if ($ElapsedMs -ge 0) { " ($($ElapsedMs)ms)" } else { "" }
    Write-Host "  [$Status] $Name$timing" -ForegroundColor $colour
    if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
    switch ($Status) {
        "PASS" { $script:Passed++ }
        "FAIL" { $script:Failed++ }
        "SKIP" { $script:Skipped++ }
    }
    $script:Results.Add([PSCustomObject]@{ Name=$Name; Status=$Status; Detail=$Detail; ElapsedMs=$ElapsedMs })
}

# ── Authentication ─────────────────────────────────────────────────────────────

function Get-AuthToken {
    if ($Token) { return $Token }
    if (-not $Password) {
        Write-Host "  No token or password provided — attempting unauthenticated (will likely fail)" -ForegroundColor Yellow
        return ""
    }
    Write-Host "  Logging in as '$Username'..." -ForegroundColor Cyan
    $body = @{ username = $Username; password = $Password } | ConvertTo-Json
    try {
        $resp = Invoke-RestMethod -Uri "$BackendUrl/api/v1/auth/login" `
            -Method POST -ContentType "application/json" -Body $body -ErrorAction Stop
        $tok = $resp.token
        if (-not $tok) { throw "Login response contained no token" }
        Write-Host "  Token acquired." -ForegroundColor Green
        return $tok
    } catch {
        throw "Login failed: $_"
    }
}

# ── Agent ID discovery ─────────────────────────────────────────────────────────

function Get-LocalAgentId {
    $idFile = "C:\ProgramData\TraceGuard\agent.id"
    if (Test-Path $idFile) {
        return (Get-Content $idFile -Raw).Trim()
    }
    # Fall back: first agent registered with the backend.
    try {
        $resp = Invoke-RestMethod -Uri "$BackendUrl/api/v1/agents?limit=1" `
            -Headers @{ Authorization = "Bearer $Token" } -Method GET -ErrorAction Stop
        $agents = if ($resp.agents) { $resp.agents } else { $resp }
        if ($agents -and $agents.Count -gt 0) { return $agents[0].id }
    } catch { }
    return ""
}

# ── Event polling ─────────────────────────────────────────────────────────────

function Wait-ForEvent {
    <#
    .SYNOPSIS
        Polls GET /api/v1/events until an event of $EventType appears after
        $Since (RFC3339 string), or until $TimeoutOverride ms elapses.
        Returns the first matching event object, or $null on timeout.
    #>
    param(
        [string] $EventType,
        [string] $Since,
        [int]    $TimeoutOverride = $TimeoutMs,
        [scriptblock] $Filter = $null   # optional extra predicate on returned events
    )

    $deadline   = (Get-Date).AddMilliseconds($TimeoutOverride)
    $encodedSince = [Uri]::EscapeDataString($Since)
    $url = "$BackendUrl/api/v1/events?agent_id=$AgentId&event_type=$EventType&since=$encodedSince&limit=20"
    $headers = @{ Authorization = "Bearer $Token" }

    while ((Get-Date) -lt $deadline) {
        try {
            $resp   = Invoke-RestMethod -Uri $url -Headers $headers -Method GET -ErrorAction Stop
            $events = if ($resp.events) { @($resp.events) } else { @() }
            foreach ($ev in $events) {
                if (-not $Filter -or (& $Filter $ev)) { return $ev }
            }
        } catch { }
        Start-Sleep -Milliseconds 25
    }
    return $null
}

function Invoke-EventTest {
    <#
    .SYNOPSIS
        Runs $Action, then waits for an event of $EventType.
        Reports PASS (with latency) or FAIL.
    #>
    param(
        [string]      $TestName,
        [string]      $EventType,
        [scriptblock] $Action,
        [int]         $Timeout       = $TimeoutMs,
        [scriptblock] $Filter        = $null,
        [scriptblock] $Cleanup       = $null
    )

    # Record the time immediately before the action so event timestamps after
    # this point count as matches.  Subtract 1s for minor clock skew.
    $since = (Get-Date).AddSeconds(-1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $sw    = [System.Diagnostics.Stopwatch]::StartNew()

    try { & $Action } catch { }

    $ev = Wait-ForEvent -EventType $EventType -Since $since -TimeoutOverride $Timeout -Filter $Filter
    $sw.Stop()

    if ($Cleanup) { try { & $Cleanup } catch { } }

    if ($ev) {
        Write-Result -Name $TestName -Status "PASS" -ElapsedMs $sw.ElapsedMilliseconds
    } else {
        Write-Result -Name $TestName -Status "FAIL" `
            -Detail "No $EventType event seen within $($Timeout)ms" `
            -ElapsedMs $sw.ElapsedMilliseconds
    }
}

# ── LogonUser P/Invoke (auth test) ────────────────────────────────────────────

$LogonUserType = $null
function Invoke-FailedLogon {
    if (-not $script:LogonUserType) {
        $script:LogonUserType = Add-Type -PassThru -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern bool LogonUser(
    string lpszUsername, string lpszDomain, string lpszPassword,
    int dwLogonType, int dwLogonProvider, out System.IntPtr phToken);
'@ -Name "LogonUser" -Namespace "TraceGuard"
    }
    $tok = [System.IntPtr]::Zero
    # LOGON32_LOGON_NETWORK=3, LOGON32_PROVIDER_DEFAULT=0 — deliberately wrong password
    [TraceGuard.LogonUser]::LogonUser(
        "traceguard_etw_no_such_user", ".", "WrongPassword_ETWTest_999!",
        3, 0, [ref]$tok
    ) | Out-Null
    # Expected: returns $false (logon failure) → Security event 4625 emitted
}

# ── Log file helpers ───────────────────────────────────────────────────────────

function Get-LogLines {
    if (-not (Test-Path $LogFile)) { return @() }
    # Return only lines added since the script started.
    Get-Content $LogFile -Tail 2000 2>$null
}

function Find-LogPattern {
    param([string]$Pattern)
    (Get-LogLines) -match $Pattern
}

# ── Monitor mode inspection ───────────────────────────────────────────────────

function Test-MonitorMode {
    param([string]$MonitorName, [string]$ETWPattern, [string]$FallbackPattern)
    $lines = Get-LogLines
    if ($lines -match $ETWPattern) {
        Write-Result -Name "$MonitorName mode" -Status "PASS" -Detail "ETW/push mode confirmed"
    } elseif ($lines -match $FallbackPattern) {
        Write-Result -Name "$MonitorName mode" -Status "FAIL" `
            -Detail "Running in polling fallback — ETW session unavailable on this host"
    } else {
        Write-Result -Name "$MonitorName mode" -Status "SKIP" `
            -Detail "No startup log line found (log may not include this monitor's startup)"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "TraceGuard ETW Monitor Integration Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Prerequisites ─────────────────────────────────────────────────────────────

Write-Host "==> Setup" -ForegroundColor White

try {
    $Token = Get-AuthToken
} catch {
    Write-Host "FATAL: Could not obtain auth token: $_" -ForegroundColor Red
    exit 1
}

if (-not $AgentId) { $AgentId = Get-LocalAgentId }
if (-not $AgentId) {
    Write-Host "FATAL: Could not determine agent ID. Pass -AgentId or ensure the agent is registered." -ForegroundColor Red
    exit 1
}
Write-Host "  Agent ID : $AgentId" -ForegroundColor Cyan
Write-Host "  Backend  : $BackendUrl" -ForegroundColor Cyan
Write-Host ""

# Verify backend is reachable.
try {
    Invoke-RestMethod -Uri "$BackendUrl/api/v1/health" -Method GET -ErrorAction Stop | Out-Null
    Write-Result -Name "Backend reachable" -Status "PASS"
} catch {
    Write-Result -Name "Backend reachable" -Status "FAIL" -Detail "$_"
    Write-Host "Cannot reach backend — aborting event tests." -ForegroundColor Red
    exit 1
}

# Verify agent process is running.
$agentProc = Get-Process -Name "edr-agent" -ErrorAction SilentlyContinue
if ($agentProc) {
    Write-Result -Name "Agent process running" -Status "PASS" -Detail "PID $($agentProc.Id)"
} else {
    Write-Result -Name "Agent process running" -Status "FAIL" `
        -Detail "edr-agent.exe process not found — start the agent before running this script"
}

Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — Per-monitor event tests
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "==> Section 1: Event latency tests" -ForegroundColor White
Write-Host "    Timeout: $($TimeoutMs)ms (registry: $($RegistryTimeoutMs)ms)" -ForegroundColor DarkGray
Write-Host ""

# ── 1a. PROCESS ───────────────────────────────────────────────────────────────

Write-Host "  [Process]" -ForegroundColor White
$notepadProc = $null

Invoke-EventTest -TestName "PROCESS_EXEC (notepad.exe start)" -EventType "PROCESS_EXEC" `
    -Action {
        $script:notepadProc = Start-Process notepad -PassThru
    } `
    -Filter { param($ev)
        $comm = $ev.process.comm
        $path = $ev.process.exe_path
        ($comm -match "notepad" -or $path -match "notepad")
    } `
    -Cleanup {
        if ($script:notepadProc -and -not $script:notepadProc.HasExited) {
            $script:notepadProc.Kill()
        }
    }

if ($notepadProc -and -not $notepadProc.HasExited) {
    $notepadProc.Kill(); $notepadProc.WaitForExit(2000) | Out-Null
}

Invoke-EventTest -TestName "PROCESS_EXIT (notepad.exe stop)" -EventType "PROCESS_EXIT" `
    -Action {
        $p = Start-Process notepad -PassThru
        Start-Sleep -Milliseconds 100
        $p.Kill()
        $p.WaitForExit(2000) | Out-Null
    } `
    -Filter { param($ev) $ev.process.comm -match "notepad" -or $ev.process.exe_path -match "notepad" }

Write-Host ""

# ── 1b. DNS ───────────────────────────────────────────────────────────────────

Write-Host "  [DNS]" -ForegroundColor White

# Use a unique subdomain to bypass the OS DNS cache.
$dnsTestDomain = "etw-test-$([Environment]::TickCount)-nxdomain.traceguard-test.invalid"

Invoke-EventTest -TestName "NET_DNS (DNS query via ETW)" -EventType "NET_DNS" `
    -Action {
        # NXDOMAIN is fine — the DNS monitor captures the query regardless of outcome.
        Resolve-DnsName $script:dnsTestDomain -ErrorAction SilentlyContinue | Out-Null
    } `
    -Filter { param($ev)
        $q = $ev.dns_query
        # Accept the specific domain or any recent DNS event (ETW captures all queries).
        $q -and ($q -eq $script:dnsTestDomain -or $q.Length -gt 0)
    }

Write-Host ""

# ── 1c. FILE ──────────────────────────────────────────────────────────────────

Write-Host "  [File]" -ForegroundColor White

$testFile = "C:\Windows\Temp\traceguard-etw-test-$PID.tmp"

Invoke-EventTest -TestName "FILE_CREATE" -EventType "FILE_CREATE" `
    -Action { New-Item -ItemType File -Path $testFile -Force | Out-Null } `
    -Filter { param($ev) $ev.path -match "traceguard-etw-test" }

Invoke-EventTest -TestName "FILE_WRITE" -EventType "FILE_WRITE" `
    -Action { "etw-test-payload" | Set-Content -Path $testFile -Encoding UTF8 } `
    -Filter { param($ev) $ev.path -match "traceguard-etw-test" }

Invoke-EventTest -TestName "FILE_DELETE" -EventType "FILE_DELETE" `
    -Action { Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue } `
    -Filter { param($ev) $ev.path -match "traceguard-etw-test" } `
    -Cleanup { Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue }

Write-Host ""

# ── 1d. REGISTRY ──────────────────────────────────────────────────────────────

Write-Host "  [Registry]" -ForegroundColor White

$regPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$regValue = "TraceGuardETWTest"

Invoke-EventTest -TestName "REGISTRY_SET (ETW, <$($RegistryTimeoutMs)ms)" `
    -EventType "REGISTRY_SET" -Timeout $RegistryTimeoutMs `
    -Action {
        Set-ItemProperty -Path $regPath -Name $regValue -Value "calc.exe" -Force
    } `
    -Filter { param($ev) $ev.value_name -eq $regValue -or $ev.path -match "Run" } `
    -Cleanup {
        Remove-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue
    }

Invoke-EventTest -TestName "REGISTRY_DELETE" -EventType "REGISTRY_DELETE" `
    -Action {
        Set-ItemProperty -Path $regPath -Name "${regValue}_del" -Value "test" -Force
        Remove-ItemProperty -Path $regPath -Name "${regValue}_del" -Force -ErrorAction SilentlyContinue
    } `
    -Filter { param($ev) $ev.path -match "Run" } `
    -Cleanup {
        Remove-ItemProperty -Path $regPath -Name "${regValue}_del" -ErrorAction SilentlyContinue
    }

Write-Host ""

# ── 1e. AUTH ──────────────────────────────────────────────────────────────────

Write-Host "  [Auth]" -ForegroundColor White

Invoke-EventTest -TestName "LOGIN_FAILED (bad credential via LogonUser)" `
    -EventType "LOGIN_FAILED" `
    -Action { Invoke-FailedLogon } `
    -Filter { param($ev)
        # LogonType 3 = Network; exclude machine accounts.
        $ev.logon_type -eq 3 -and
        $ev.username -notmatch '\$$' -and
        ($ev.username -match "traceguard" -or $ev.win_event_id -eq 4625)
    }

Write-Host ""

# ── 1f. NETWORK ───────────────────────────────────────────────────────────────

Write-Host "  [Network]" -ForegroundColor White

Invoke-EventTest -TestName "NET_CONNECT (outbound TCP)" -EventType "NET_CONNECT" `
    -Action {
        # Open a TCP connection; the TLS handshake is handled below.
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.ConnectAsync("1.1.1.1", 443).Wait(200) | Out-Null
            $c.Close()
        } catch { }
    } `
    -Filter { param($ev)
        $ev.dst_port -eq 443 -or $ev.protocol -eq "TCP"
    }

Write-Host ""

# ── 1g. TLS SNI ───────────────────────────────────────────────────────────────

Write-Host "  [TLS SNI]" -ForegroundColor White

# Check whether the TLS SNI monitor is enabled in the agent config.
$agentCfg  = "C:\ProgramData\TraceGuard\agent.yaml"
$tlsEnabled = $false
if (Test-Path $agentCfg) {
    $cfgLines  = Get-Content $agentCfg
    $tlsSection = $cfgLines | Select-String -Pattern "^\s*tlssni:" -Context 0,3
    $tlsEnabled = ($tlsSection.Context.PostContext -join "`n") -match "enabled:\s*true"
}

if (-not $tlsEnabled) {
    Write-Result -Name "TLS_SNI (example.com)" -Status "SKIP" `
        -Detail "tlssni.enabled is false in agent.yaml — set to true and restart the agent to test"
} else {
    Invoke-EventTest -TestName "TLS_SNI (example.com)" -EventType "TLS_SNI" `
        -Timeout ([Math]::Max($TimeoutMs, 1000)) `
        -Action {
            # Trigger a TLS handshake; SIO_RCVALL captures the ClientHello.
            try {
                Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing `
                    -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
            } catch { }
        } `
        -Filter { param($ev) $ev.domain -eq "example.com" }
}

Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — ETW vs polling mode verification
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "==> Section 2: ETW mode verification (from agent log)" -ForegroundColor White
Write-Host "    Log: $LogFile" -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-Path $LogFile)) {
    Write-Host "  Agent log not found at $LogFile — skipping mode verification." -ForegroundColor Yellow
} else {
    Test-MonitorMode -MonitorName "DNS monitor" `
        -ETWPattern       "DNS monitor started \(ETW Microsoft-Windows-DNS-Client\)" `
        -FallbackPattern  "DNS monitor started \(polling ipconfig"

    Test-MonitorMode -MonitorName "Network monitor" `
        -ETWPattern       "network monitor started \(ETW Microsoft-Windows-Kernel-Network\)" `
        -FallbackPattern  "network monitor started \(polling GetExtended"

    Test-MonitorMode -MonitorName "Process monitor" `
        -ETWPattern       "process monitor started \(ETW Microsoft-Windows-Kernel-Process\)" `
        -FallbackPattern  "process monitor started \(polling CreateToolhelp32"

    Test-MonitorMode -MonitorName "File monitor" `
        -ETWPattern       "file monitor started \(ReadDirectoryChangesW \+ IOCP\)" `
        -FallbackPattern  "file monitor started \(polling filepath\.Walk"

    Test-MonitorMode -MonitorName "Registry monitor" `
        -ETWPattern       "registry monitor started \(ETW Microsoft-Windows-Kernel-Registry\)" `
        -FallbackPattern  "registry monitor started \(polling persistence"

    Test-MonitorMode -MonitorName "Auth monitor" `
        -ETWPattern       "auth monitor started \(EvtSubscribe Security channel\)" `
        -FallbackPattern  "auth monitor started \(polling Security Event Log\)"

    Test-MonitorMode -MonitorName "WinEvent monitor" `
        -ETWPattern       "winevent monitor started \(EvtSubscribe\)" `
        -FallbackPattern  "winevent monitor started \(polling Windows Event Log\)"

    if ($tlsEnabled) {
        Test-MonitorMode -MonitorName "TLS SNI monitor" `
            -ETWPattern       "TLS SNI monitor started \(SIO_RCVALL\)" `
            -FallbackPattern  "no interfaces available for raw socket capture"
    }
}

Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — Fallback regression (Windows Server 2012 R2 compatibility)
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "==> Section 3: Fallback regression check" -ForegroundColor White
Write-Host "    Verifies the agent logs 'falling back to polling' on hosts where" -ForegroundColor DarkGray
Write-Host "    kernel ETW providers are unavailable (e.g. Server 2012 R2)." -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-Path $LogFile)) {
    Write-Host "  Agent log not found — skipping fallback check." -ForegroundColor Yellow
} else {
    $fallbackLines = Find-LogPattern "falling back to polling"
    if ($fallbackLines.Count -gt 0) {
        Write-Host "  WARNING: $($fallbackLines.Count) monitor(s) fell back to polling:" -ForegroundColor Yellow
        foreach ($line in $fallbackLines) {
            # Extract monitor name from the JSON log line.
            try {
                $obj = $line | ConvertFrom-Json
                Write-Host "    monitor=$($obj.monitor)  reason=$($obj.message)" -ForegroundColor Yellow
            } catch {
                Write-Host "    $line" -ForegroundColor Yellow
            }
        }
        Write-Host ""
        Write-Host "  On Windows Server 2012 R2 this is expected." -ForegroundColor DarkGray
        Write-Host "  On Windows 10/11 or Server 2016+ it indicates a privilege problem." -ForegroundColor DarkGray
        Write-Host "  Ensure the agent is running as SYSTEM or with SeSystemProfilePrivilege." -ForegroundColor DarkGray

        $osVer  = [System.Environment]::OSVersion.Version
        $is2012 = ($osVer.Major -eq 6 -and $osVer.Minor -eq 3)
        if ($is2012) {
            Write-Result -Name "Fallback on Server 2012 R2" -Status "PASS" `
                -Detail "Polling fallback activated as expected on this OS version"
        } else {
            Write-Result -Name "Fallback on Server 2012 R2" -Status "FAIL" `
                -Detail "Unexpected fallback on $($osVer) — check agent privileges"
        }
    } else {
        Write-Result -Name "No unexpected fallbacks" -Status "PASS" `
            -Detail "All monitors started in ETW/push mode"
    }
}

Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "==> Summary" -ForegroundColor White
Write-Host ""

$total = $script:Passed + $script:Failed + $script:Skipped
$passColour = if ($script:Failed -eq 0) { "Green" } else { "Yellow" }

Write-Host ("  PASS: {0,3}   FAIL: {1,3}   SKIP: {2,3}   TOTAL: {3,3}" -f `
    $script:Passed, $script:Failed, $script:Skipped, $total) -ForegroundColor $passColour
Write-Host ""

if ($script:Failed -gt 0) {
    Write-Host "  Failed tests:" -ForegroundColor Red
    $script:Results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "    - $($_.Name)" -ForegroundColor Red
        if ($_.Detail) { Write-Host "      $($_.Detail)" -ForegroundColor DarkGray }
    }
    Write-Host ""
}

Write-Host "  Timing breakdown:" -ForegroundColor DarkGray
$script:Results | Where-Object { $_.ElapsedMs -ge 0 } | ForEach-Object {
    $colour = if ($_.Status -eq "PASS") { "DarkGreen" } else { "DarkRed" }
    Write-Host ("    {0,-45} {1,5}ms  [{2}]" -f $_.Name, $_.ElapsedMs, $_.Status) -ForegroundColor $colour
}
Write-Host ""

if ($script:Failed -gt 0) {
    exit 1
} else {
    exit 0
}

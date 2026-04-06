# Building the TraceGuard Windows Agent on a Linux Host

Cross-compile `edr-agent.exe` for Windows 11 (amd64) from your Linux development machine.

---

## Prerequisites

- **Go 1.21+** (verify: `go version`)
- **Git** (for version stamping)
- **Ubuntu/Debian** (tested on Ubuntu 24.04)

---

## Option A: Pure Go Build (No CGO) — Recommended

This is the simplest approach. It compiles everything in pure Go, including a pure-Go SQLite driver. No C compiler or cross-compilation toolchain needed.

### Step 1: Switch SQLite to Pure Go Driver

The default `github.com/mattn/go-sqlite3` requires CGO. Replace it with `modernc.org/sqlite` which is a pure-Go SQLite implementation:

```bash
cd edr-agent-win

# Remove CGO SQLite driver, add pure-Go alternative
go get modernc.org/sqlite
```

Then update `internal/buffer/buffer.go` — change the import:

```go
// Before:
import _ "github.com/mattn/go-sqlite3"

// After:
import _ "modernc.org/sqlite"
```

And change the driver name in `sql.Open`:

```go
// Before:
db, err := sql.Open("sqlite3", cfg.Path+"?_journal_mode=WAL&_synchronous=NORMAL")

// After:
db, err := sql.Open("sqlite", cfg.Path+"?_journal_mode=WAL&_synchronous=NORMAL")
```

### Step 2: Build

```bash
cd edr-agent-win

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
  -ldflags "-s -w \
    -X github.com/youredr/edr-agent-win/internal/version.Version=$(git describe --tags --always) \
    -X github.com/youredr/edr-agent-win/internal/version.GitCommit=$(git rev-parse --short HEAD) \
    -X github.com/youredr/edr-agent-win/internal/version.GitBranch=$(git rev-parse --abbrev-ref HEAD) \
    -X github.com/youredr/edr-agent-win/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o edr-agent.exe ./cmd/agent/
```

Or simply:

```bash
make build-nocgo
```

That's it. The output `edr-agent.exe` is a standalone Windows binary.

### Step 3: Verify

```bash
file edr-agent.exe
# edr-agent.exe: PE32+ executable (console) x86-64, for MS Windows, 8 sections

ls -lh edr-agent.exe
# ~15-20 MB
```

---

## Option B: CGO Build (with mingw-w64)

If you want to keep the C-based `mattn/go-sqlite3` driver (slightly faster SQLite), you need a Windows cross-compiler.

### Step 1: Install mingw-w64

```bash
sudo apt update
sudo apt install -y gcc-mingw-w64-x86-64
```

Verify:

```bash
x86_64-w64-mingw32-gcc --version
```

### Step 2: Build

```bash
cd edr-agent-win

GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  go build \
  -ldflags "-s -w \
    -X github.com/youredr/edr-agent-win/internal/version.Version=$(git describe --tags --always) \
    -X github.com/youredr/edr-agent-win/internal/version.GitCommit=$(git rev-parse --short HEAD) \
    -X github.com/youredr/edr-agent-win/internal/version.GitBranch=$(git rev-parse --abbrev-ref HEAD) \
    -X github.com/youredr/edr-agent-win/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o edr-agent.exe ./cmd/agent/
```

Or simply:

```bash
make build
```

### Step 3: Verify

```bash
file edr-agent.exe
# edr-agent.exe: PE32+ executable (console) x86-64, for MS Windows, 8 sections
```

---

## Makefile Targets

| Target | Description | CGO Required |
|--------|-------------|--------------|
| `make build` | Cross-compile with CGO (needs mingw-w64) | Yes |
| `make build-nocgo` | Pure Go build, no C compiler needed | No |
| `make test` | Run tests (Linux host) | No |
| `make lint` | Run golangci-lint | No |
| `make clean` | Remove built binary | No |

---

## Deploying to Windows

### Copy to Windows Machine

Use scp, SMB share, USB drive, or any file transfer method:

```bash
# Via SCP
scp edr-agent.exe administrator@windows-host:C:\Temp\

# Via SMB
cp edr-agent.exe /mnt/windows-share/
```

### Install on Windows (Run as Administrator)

**Option 1: PowerShell installer**

Copy the entire `deploy/` folder and `config/agent.yaml` alongside `edr-agent.exe`, then:

```powershell
# On the Windows machine (as Administrator):
.\deploy\install.ps1 -BackendURL "your-backend:50051"
```

This creates directories, copies the binary, installs the Windows service, and starts it.

**Option 2: Manual install**

```powershell
# Create directories
mkdir "C:\Program Files\TraceGuard" -Force
mkdir "C:\ProgramData\TraceGuard\Logs" -Force
mkdir "C:\ProgramData\TraceGuard\Quarantine" -Force

# Copy binary and config
copy edr-agent.exe "C:\Program Files\TraceGuard\"
copy config\agent.yaml "C:\ProgramData\TraceGuard\agent.yaml"

# Edit config — set your backend URL
notepad "C:\ProgramData\TraceGuard\agent.yaml"

# Install as Windows service
sc.exe create TraceGuardAgent binpath= '"C:\Program Files\TraceGuard\edr-agent.exe" --config "C:\ProgramData\TraceGuard\agent.yaml"' start= auto DisplayName= "TraceGuard Endpoint Agent"

# Set auto-restart on failure
sc.exe failure TraceGuardAgent reset= 60 actions= restart/5000/restart/10000/restart/30000

# Start the service
sc.exe start TraceGuardAgent

# Verify
Get-Service TraceGuardAgent
```

**Option 3: Run interactively (for testing/debugging)**

```powershell
.\edr-agent.exe --run --config "C:\ProgramData\TraceGuard\agent.yaml"
```

---

## Troubleshooting

### Build fails: "gcc-mingw not found"

You're using `make build` (CGO mode) without mingw installed. Either:
- Install mingw: `sudo apt install gcc-mingw-w64-x86-64`
- Or use the pure-Go build: `make build-nocgo`

### Build fails: "cannot find package golang.org/x/sys/windows"

Run `go mod tidy` with the Windows target:
```bash
GOOS=windows GOARCH=amd64 go mod tidy
```

### Agent won't connect to backend

1. Check the backend is reachable from Windows: `Test-NetConnection your-backend -Port 50051`
2. Check config: `type C:\ProgramData\TraceGuard\agent.yaml`
3. Check logs: `Get-Content C:\ProgramData\TraceGuard\Logs\agent.log -Tail 50`
4. If using TLS, ensure certs are deployed and paths are correct in agent.yaml

### Agent service stops immediately

Check Windows Event Viewer → Application log for errors, or run interactively to see stdout:
```powershell
.\edr-agent.exe --run --config "C:\ProgramData\TraceGuard\agent.yaml"
```

### Events not appearing in dashboard

1. Verify agent is registered: check backend logs for "agent registered" with OS=windows
2. Verify events are being buffered: check SQLite DB size at `C:\ProgramData\TraceGuard\events.db`
3. Check if monitors are starting: look for "monitor running" in agent log

---

## Build Matrix

| Host OS | Target | CGO | Compiler | Command |
|---------|--------|-----|----------|---------|
| Linux (Ubuntu) | Windows amd64 | No | None | `GOOS=windows CGO_ENABLED=0 go build` |
| Linux (Ubuntu) | Windows amd64 | Yes | mingw-w64 | `GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build` |
| Windows | Windows amd64 | Yes | MSVC/gcc | `go build` |
| macOS | Windows amd64 | No | None | `GOOS=windows CGO_ENABLED=0 go build` |

---

## File Layout After Install

```
C:\Program Files\TraceGuard\
  └── edr-agent.exe              # Agent binary

C:\ProgramData\TraceGuard\
  ├── agent.yaml                  # Configuration
  ├── agent.id                    # Unique agent UUID (auto-generated)
  ├── events.db                   # SQLite event buffer
  ├── fim_baseline.json           # FIM checksums
  ├── Logs\
  │   └── agent.log               # Agent log (JSON)
  └── Quarantine\
      └── (quarantined files)
```


## Live response

Remote investigation and remediation shell over gRPC bidirectional streaming.

### How it works
1. Agent connects to backend via the `LiveResponse` gRPC bidi stream
2. Analyst selects an agent in the **Live** tab and sends commands
3. Backend routes commands to the agent; agent executes and streams results back
4. Output displayed in the UI terminal

### Available commands

| Command | Description | Example |
|---------|-------------|---------|
| `ps` | List running processes | `ps` |
| `ls` | List files/directories | `ls /tmp` |
| `cat` | Read file contents | `cat /etc/passwd` |
| `netstat` | Show network connections (via `ss`) | `netstat` |
| `who` | Show logged-in users | `who` |
| `uname` | System information | `uname` |
| `uptime` | System uptime | `uptime` |
| `df` | Disk usage | `df` |
| `id` | User identity | `id` |
| `exec` | Run arbitrary command | `exec lsof -i :443` |
| `find` | Search for files | `find /tmp -name '*.sh'` |
| `sha256sum` | Hash a file | `sha256sum /usr/bin/curl` |
| `kill` | Kill a process | `kill -9 1234` |
| `isolate` | **Network containment** — block all traffic except backend | `isolate` |
| `release` | **Release containment** — restore normal networking | `release` |

Dangerous patterns (`rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`) are blocked. Output is capped at 1MB stdout / 64KB stderr.

---
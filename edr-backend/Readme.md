# Ollama Integration — OEDR Alert Explanation

OEDR can use a locally-running [Ollama](https://ollama.com) instance to explain security alerts in plain English. When enabled, a **🤖 EXPLAIN WITH AI** button appears in every alert drawer. Clicking it sends the alert metadata and triggering events to Ollama and displays a concise analyst-facing explanation: what likely happened, what the attacker was trying to achieve, and what to investigate next.

---

## How it works

When you click **EXPLAIN WITH AI** on an alert, the UI calls:

```
POST /api/v1/alerts/:id/explain
```

The backend (`internal/llm/ollama.go`) builds a prompt containing:
- Alert title, severity, hostname, MITRE ATT&CK IDs, and timestamp
- Up to 5 triggering events (type + short summary — no raw payloads for privacy)

It calls Ollama's `/api/generate` endpoint and returns the model's response. The explanation is never stored in the database — it's generated fresh each time.

---

## Prerequisites

1. **Ollama installed** on the same host as the backend (or anywhere reachable by it)
2. **A model pulled** — `llama3.2` is the default and works well for security context

```bash
# Install Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Pull the default model
ollama pull llama3.2

# Verify it's running
ollama list
curl http://localhost:11434/api/tags
```

---

## Configuration

Ollama is configured entirely through environment variables on the **backend**. It is disabled by default.

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_ENABLED` | `false` | Set to `true` to enable |
| `OLLAMA_URL` | `http://localhost:11434` | Base URL of your Ollama server |
| `OLLAMA_MODEL` | `llama3.2` | Model name to use |

---

## Setup: Docker Compose (recommended)

Edit `edr-backend/deploy/docker-compose.yml` and add the three Ollama variables to the `backend` service's `environment` block:

```yaml
  backend:
    environment:
      EDR_DATABASE_HOST:     postgres
      EDR_DATABASE_PORT:     5432
      EDR_DATABASE_NAME:     edr
      EDR_DATABASE_USER:     edr
      EDR_DATABASE_PASSWORD: edr
      EDR_SERVER_GRPC_ADDR:  ":50051"
      EDR_SERVER_HTTP_ADDR:  ":8080"
      EDR_JWT_SECRET:        your-secret-here

      # ── Ollama LLM ─────────────────────────────────
      OLLAMA_ENABLED: "true"
      OLLAMA_URL:     "http://host.docker.internal:11434"
      OLLAMA_MODEL:   "llama3.2"
```

> **Note:** Inside Docker, `localhost` refers to the container itself, not your host machine. Use `host.docker.internal` (works on Docker Desktop and Docker Engine with `--add-host`). On Linux with Docker Engine, you may need to add `extra_hosts` to the service:
>
> ```yaml
>   backend:
>     extra_hosts:
>       - "host.docker.internal:host-gateway"
> ```

Then rebuild and restart:

```bash
cd edr-backend
sudo make docker-up
```

---

## Setup: Running backend directly (non-Docker)

If you run the backend binary directly, export the variables before starting:

```bash
export OLLAMA_ENABLED=true
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=llama3.2

cd edr-backend
./edr-backend --config config/server.yaml
```

---

## Using a remote Ollama server

If Ollama runs on a different machine (e.g. a GPU server):

```yaml
OLLAMA_ENABLED: "true"
OLLAMA_URL:     "http://192.168.1.50:11434"
OLLAMA_MODEL:   "llama3.2"
```

Make sure port `11434` is open on the Ollama host. By default Ollama only listens on `127.0.0.1`. To expose it on all interfaces:

```bash
# Start Ollama bound to all interfaces
OLLAMA_HOST=0.0.0.0 ollama serve
```

Or set it permanently in the systemd unit:

```bash
sudo systemctl edit ollama
```

```ini
[Service]
Environment="OLLAMA_HOST=0.0.0.0"
```

```bash
sudo systemctl restart ollama
```

---

## Model selection

Any model available in Ollama works. Larger models give better explanations but are slower.

```bash
# Fast, good quality (default — recommended)
ollama pull llama3.2

# Smaller, runs on CPU-only machines
ollama pull llama3.2:1b

# Better reasoning, needs more RAM
ollama pull llama3.1:8b

# Code/security focused
ollama pull deepseek-r1:7b
```

Change the model without restarting the backend:

```yaml
OLLAMA_MODEL: "llama3.1:8b"
```

Then `sudo make docker-up` to pick up the new value.

---

## Verifying it works

1. Open the OEDR UI and click any alert
2. Click **🤖 EXPLAIN WITH AI** in the alert drawer
3. You should see a spinner then a plain-English explanation

If Ollama is not reachable, the button shows:
> `Ollama not enabled. Set OLLAMA_ENABLED=true and OLLAMA_URL in backend environment.`

If the model is loading for the first time, the request may take 30–60 seconds. Subsequent requests are fast once the model is loaded into memory.

### Test the connection directly

```bash
# From the machine running the backend container
curl http://localhost:11434/api/generate \
  -d '{"model":"llama3.2","prompt":"Hello","stream":false}' \
  | python3 -m json.tool
```

### Check backend logs

```bash
docker logs edr-backend | grep -i ollama
```

On startup you should see one of:
```
Ollama LLM enabled   model=llama3.2
# or
Ollama LLM disabled (set OLLAMA_ENABLED=true to enable)
```

---

## Privacy and what gets sent

The backend sends a minimal prompt — **no raw event payloads**. For each triggering event it extracts only a short summary:

| Event type | Sent to Ollama |
|---|---|
| `FILE_*` | File path only |
| `NET_CONNECT` | Destination IP:port or resolved domain |
| `PROCESS_EXEC` / `CMD_EXEC` | Cmdline (truncated to 120 chars) |

The alert title, severity, hostname, MITRE IDs, and first-seen timestamp are also included. Nothing else — no usernames, no full command lines beyond 120 chars, no file contents.

---

## Troubleshooting

**`502 Bad Gateway` or `LLM request failed`**
- Ollama is not running or not reachable at `OLLAMA_URL`
- From inside the container: `curl $OLLAMA_URL/api/tags`

**Request times out (>120s)**
- Model is too large for available RAM/VRAM
- Try a smaller model: `OLLAMA_MODEL=llama3.2:1b`

**`model not found`**
- Pull the model first: `ollama pull llama3.2`

**Explanation quality is poor**
- Use a larger model (`llama3.1:8b` or better)
- The prompt is fixed in `internal/llm/ollama.go` — edit `ExplainAlert()` to customise it

**Docker on Linux: can't reach host Ollama**
- Add `extra_hosts: ["host.docker.internal:host-gateway"]` to the backend service in `docker-compose.yml`
- Or use the host's actual LAN IP instead of `host.docker.internal`
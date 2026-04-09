# OEDR Documentation

Complete documentation for the Open Endpoint Detection & Response platform.

## Contents

| Document | Description |
|----------|-------------|
| [Agent](agent.md) | eBPF endpoint agent — monitors, event types, config, build |
| [Backend](backend.md) | Go backend — API server, detection engine, database, gRPC ingest |
| [API Reference](api-reference.md) | Complete REST API — 60+ endpoints with examples |
| [Dashboard](dashboard.md) | Next.js analyst UI — 16 pages, themes, design system |
| [Browser Extension](browser-extension.md) | Chrome + Firefox extensions for URL/phishing monitoring |
| [Detection Rules](detection-rules.md) | Rule engine, 26+ seeded rules, IOC matching, MITRE ATT&CK |
| [Deployment](deployment.md) | Production deployment guide — setup, TLS, systemd, Docker |

## Architecture

```
Endpoint                           Server                          Analyst
────────                           ──────                          ───────
edr-agent (Go + eBPF)  ──gRPC──>  edr-backend (Go)  ──REST──>   edr-ui3 (Next.js)
  Process monitor                    Event ingest                   16 pages
  Network monitor                    Detection engine               7 themes
  File monitor                       Alert correlation              Live SSE
  Auth monitor                       IOC matching                   AI explain
  Command monitor                    SSE broker                     Process tree
  Browser monitor ◄──HTTP──         PostgreSQL                     Threat hunt
       ▲
  Browser Extension
  (Chrome / Firefox)
```

## Quick Links

- **Start here**: [Deployment Guide](deployment.md) for setting up the full platform
- **API integration**: [API Reference](api-reference.md) for all endpoints
- **Writing rules**: [Detection Rules](detection-rules.md) for custom detection
- **Agent config**: [Agent Documentation](agent.md) for endpoint deployment

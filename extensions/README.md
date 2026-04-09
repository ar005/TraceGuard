# OEDR Browser Extensions

Browser extensions that capture web request metadata (URL, status code, method, redirect chains) and send them to the local EDR agent for phishing and threat detection.

## Chrome

### Install (Developer Mode)
1. Open `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `extensions/chrome/` directory

### Permissions
- `webRequest` — observe completed/failed requests
- `storage` — persist config (agent URL, enabled state)
- `<all_urls>` — monitor requests to all domains

## Firefox

### Install (Temporary)
1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `extensions/firefox/manifest.json`

### For permanent install
Package as `.xpi` and sign via [AMO](https://addons.mozilla.org).

## Configuration

Click the extension icon to:
- **Pause/Resume** monitoring
- **Change the agent URL** (default: `http://127.0.0.1:9999/browser-events`)
- View **capture/send/error** stats

## Agent Setup

Enable the browser monitor in the agent config (`config/agent.yaml`):

```yaml
monitors:
  browser:
    enabled: true
    listen_addr: "127.0.0.1:9999"
```

## What Gets Captured

| Field | Description |
|-------|-------------|
| URL | Full URL including path and query |
| Method | GET, POST, etc. |
| Status Code | HTTP response code (0 = connection error) |
| Resource Type | main_frame, sub_frame, xmlhttprequest |
| Initiator/Referrer | Page that triggered the request |
| Tab URL | URL of the browser tab |
| Server IP | Resolved IP of the server |
| Redirect Chain | Full chain of redirects before final URL |
| Response Headers | Security-relevant headers (CSP, HSTS, etc.) |

## Noise Filtering

By default, the extension skips:
- Static resources (images, CSS, fonts, media)
- Browser-internal domains (update servers, safe browsing)
- `chrome://` and `chrome-extension://` URLs
- Only captures: `main_frame`, `sub_frame`, `xmlhttprequest`

Configure additional ignore domains in `background.js` → `DEFAULT_CONFIG.ignoreDomains`.

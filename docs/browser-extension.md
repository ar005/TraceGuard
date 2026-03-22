# Browser Extension Documentation

The TraceGuard Browser Monitor extension captures web request metadata from analyst browsers and streams it to the local EDR agent for phishing detection and threat analysis.

## Purpose

The browser extension adds visibility into web browsing activity by capturing URLs, HTTP methods, status codes, redirect chains, referrers, server IPs, and security headers for every navigation and XHR request. This data flows through the EDR pipeline as `BROWSER_REQUEST` events, enabling detection rules to identify phishing attempts, credential harvesting, IOC domain visits, and other browser-based threats.

## Chrome Extension

### Manifest

- **Manifest Version**: V3
- **Name**: TraceGuard Browser Monitor
- **Version**: 1.0.0
- **Permissions**: `webRequest`, `storage`
- **Host Permissions**: `<all_urls>`
- **Background**: Service worker (`background.js`)
- **Action**: Popup (`popup.html`) with icon set (16px, 48px, 128px)

### Installation

1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable "Developer mode" (toggle in the top-right corner).
3. Click "Load unpacked" and select the `extensions/chrome/` directory.
4. The TraceGuard Browser Monitor icon appears in the extensions toolbar.
5. Click the icon to open the popup and verify the agent URL is correct.

## Firefox Extension

### Manifest

- **Manifest Version**: V2 (WebExtensions)
- **Name**: TraceGuard Browser Monitor
- **Version**: 1.0.0
- **Permissions**: `webRequest`, `webRequestBlocking`, `storage`, `<all_urls>`
- **Background**: Script (`background.js`)
- **Browser Action**: Popup (`popup.html`) with icon set
- **Gecko Settings**: ID `TraceGuard-browser-monitor@youredr.local`, minimum Firefox 109.0

### Installation

1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2. Click "Load Temporary Add-on" and select the `manifest.json` file in `extensions/firefox/`.
3. The TraceGuard Browser Monitor icon appears in the toolbar.
4. For permanent installation, package the extension as an `.xpi` file and sign it through Mozilla's add-on portal.

### Differences from Chrome

| Feature | Chrome (V3) | Firefox (V2) |
|---|---|---|
| Manifest version | 3 | 2 |
| Background | Service worker | Background script |
| API namespace | `chrome.*` | `browser.*` |
| Initiator field | `details.initiator` | `details.originUrl` |
| Tab access | Callback-based (`chrome.tabs.get(id, cb)`) | Promise-based (`browser.tabs.get(id).then()`) |
| Badge API | `chrome.action.setBadgeText` | `browser.browserAction.setBadgeText` |
| Ignored domains | Google services (update, safebrowsing, fonts, accounts) | Mozilla services (detectportal, settings, push, shavar, safebrowsing, content-signature, tracking-protection) |
| Internal URL filter | `chrome-extension:`, `chrome:` protocols | `moz-extension:`, `about:` protocols |
| Additional permissions | -- | `webRequestBlocking` |

## What Gets Captured

Each web request event includes the following fields:

| Field | Type | Description |
|---|---|---|
| `url` | string | Full URL of the request |
| `method` | string | HTTP method (GET, POST, etc.) |
| `status_code` | int | HTTP response status code (0 for errors) |
| `type` | string | Resource type: `main_frame`, `sub_frame`, or `xmlhttprequest` |
| `initiator` | string | Origin URL that triggered the request (Chrome: `initiator`, Firefox: `originUrl`) |
| `tab_id` | int | Browser tab identifier |
| `tab_url` | string | URL of the tab that made the request |
| `timestamp` | string | ISO 8601 timestamp |
| `ip` | string | Server IP address that served the response |
| `from_cache` | bool | Whether the response was served from cache |
| `error` | string | Error description (for failed requests) |
| `redirect_chain` | array | List of `{url, statusCode}` objects for redirect hops |
| `response_headers` | object | Selected security-relevant headers |

### Captured Security Headers

The extension extracts these headers when present:

- `content-type`
- `location`
- `x-frame-options`
- `content-security-policy`
- `strict-transport-security`
- `server`

## Noise Filtering

### Resource Types Captured

Only meaningful navigation and API requests are captured:

- `main_frame` -- Top-level page navigations
- `sub_frame` -- Iframe navigations
- `xmlhttprequest` -- Fetch/XHR API calls

All other resource types (images, stylesheets, fonts, media, scripts, etc.) are excluded.

### Ignored Domains

**Chrome** ignores:
- `localhost`, `127.0.0.1`
- `chrome.google.com`
- `update.googleapis.com`
- `clients2.google.com`
- `safebrowsing.googleapis.com`
- `accounts.google.com`
- `fonts.googleapis.com`
- `fonts.gstatic.com`

**Firefox** ignores:
- `localhost`, `127.0.0.1`
- `detectportal.firefox.com`
- `firefox.settings.services.mozilla.com`
- `push.services.mozilla.com`
- `shavar.services.mozilla.com`
- `safebrowsing.googleapis.com`
- `content-signature-2.cdn.mozilla.net`
- `tracking-protection.cdn.mozilla.net`

Domain matching uses exact match and suffix match (e.g., `*.google.com` is matched by checking `hostname.endsWith(".google.com")`).

### Ignored File Extensions

Requests to URLs ending with these extensions are silently dropped:

- Images: `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.ico`, `.webp`
- Fonts: `.woff`, `.woff2`, `.ttf`, `.eot`
- Styles: `.css`
- Media: `.mp4`, `.webm`, `.ogg`, `.mp3`, `.wav`

### Internal Protocol Filtering

Chrome filters out `chrome-extension://` and `chrome://` URLs. Firefox filters out `moz-extension://` and `about:` URLs.

## Configuration via Popup

The popup (`popup.html`) provides a compact control panel:

### Status Indicator
- Green dot with "Monitoring" when enabled.
- Red dot with "Paused" when disabled.

### Statistics Display
Three stat boxes showing real-time counts:
- **Captured**: Total requests captured since extension start.
- **Sent**: Total events successfully delivered to the agent.
- **Errors**: Count of delivery failures.

### Controls
- **Pause/Resume button**: Toggles the `enabled` flag via `toggleEnabled` message.
- **Agent URL field**: Editable text input showing the current agent endpoint URL.
- **Save button**: Persists the updated agent URL to `chrome.storage.local`.

### Badge Indicator
The extension icon shows a red "!" badge when there are delivery errors, indicating the agent may be unreachable.

## Agent-Side Receiver

The browser monitor in the agent (`edr-agent/internal/monitor/browser/monitor.go`) runs a localhost-only HTTP server to receive events from the extension.

### Endpoint

```
POST http://127.0.0.1:9999/browser-events
```

A health check is also available:

```
GET http://127.0.0.1:9999/health
```

### Security

- The listener **only binds to localhost** (`127.0.0.1:9999`). Attempts to bind to other addresses are rejected.
- Incoming requests are validated to originate from `127.0.0.1` or `::1`.
- Request body is limited to 2MB.

### JSON Batch Format

The extension sends events in batches:

```json
{
  "events": [
    {
      "url": "https://example.com/login",
      "method": "POST",
      "status_code": 200,
      "type": "main_frame",
      "initiator": "https://example.com/",
      "tab_id": 42,
      "tab_url": "https://example.com/login",
      "timestamp": "2026-03-22T10:30:00.000Z",
      "ip": "93.184.216.34",
      "from_cache": false,
      "redirect_chain": [
        {"url": "https://short.link/abc", "statusCode": 302}
      ],
      "response_headers": {
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000"
      }
    }
  ]
}
```

The response indicates how many events were accepted:

```json
{"accepted": 1}
```

### BROWSER_REQUEST Event Fields

After the agent processes the incoming batch, each event is published to the event bus as a `BROWSER_REQUEST` event with these fields:

| Field | Source | Description |
|---|---|---|
| `url` | Extension | Full URL |
| `domain` | Parsed from URL | Hostname portion |
| `path` | Parsed from URL | Path + query string |
| `method` | Extension | HTTP method |
| `status_code` | Extension | HTTP status code |
| `content_type` | Response headers | Content-Type header value |
| `referrer` | Initiator or tab URL | Page that initiated the request |
| `tab_url` | Extension | URL of the browser tab |
| `resource_type` | Extension | main_frame, sub_frame, or xmlhttprequest |
| `server_ip` | Extension | IP address of the responding server |
| `from_cache` | Extension | Whether served from cache |
| `error` | Extension | Error description for failed requests |
| `is_form_submit` | Derived | True if method is POST and type is main_frame |
| `redirect_chain` | Extension | List of redirect hop URLs |
| `tags` | Derived | Auto-generated tags: `browser`, resource type, `form-submit`, `cached`, `redirected`, `auth-page` |

The `auth-page` tag is added when the URL path contains "login", "signin", or "auth".

## Batch Settings

| Setting | Default | Description |
|---|---|---|
| `batchSize` | 10 | Events are flushed when the batch reaches this size |
| `flushIntervalMs` | 5000 | Events are flushed on a timer every 5 seconds regardless of batch size |

Failed batches are re-queued up to a maximum of 500 pending events. If the queue exceeds 500, events are dropped to prevent memory issues when the agent is unreachable.

## Phishing Detection Rules

The backend ships with 5 seeded browser detection rules:

### 1. Credential Submission to Non-Allowlisted Domain

- **Rule ID**: `rule-browser-form-submit-unknown`
- **Severity**: High (3)
- **Type**: Match
- **MITRE**: T1056.004 (Credential API Hooking)
- **Conditions**: `is_form_submit == true` AND tags contain `auth-page`
- **Description**: Fires when a user submits a form (POST to main_frame) on a page with login/signin/auth in the URL path. Detects credential submission to potential phishing pages.

### 2. Browser Visited IOC-Flagged Domain

- **Rule ID**: `rule-browser-ioc-domain-visit`
- **Severity**: Critical (4)
- **Type**: Match
- **MITRE**: T1566.002 (Spearphishing Link)
- **Conditions**: `resource_type == "main_frame"`
- **Description**: Fires when a user navigates to a domain that matches an entry in the IOC database. The IOC matching happens separately in the detection engine's `checkIOCs` function, which checks the domain against the loaded IOC domain cache.

### 3. Suspicious Redirect Chain Detected

- **Rule ID**: `rule-browser-redirect-chain`
- **Severity**: Medium (2)
- **Type**: Match
- **MITRE**: T1566.002 (Spearphishing Link)
- **Conditions**: `redirect_chain` length >= 3
- **Description**: Fires when a browser request follows 3 or more redirect hops. Common in phishing campaigns that use URL shorteners and redirect chains to obscure the final destination.

### 4. Form Submission to Rare TLD

- **Rule ID**: `rule-browser-rare-tld-form`
- **Severity**: High (3)
- **Type**: Match
- **MITRE**: T1566.002 (Spearphishing Link)
- **Conditions**: `is_form_submit == true` AND domain matches regex for abuse-prone TLDs (`.tk`, `.xyz`, `.top`, `.pw`, `.cc`, `.ws`, `.click`, `.link`, `.work`, `.date`, `.download`, `.racing`, `.stream`, `.gdn`, `.bid`)
- **Description**: Fires when a user submits a form to a domain using a top-level domain frequently associated with phishing, malware, and abuse.

### 5. Browser High Volume Requests (threshold)

- **Rule ID**: `rule-browser-high-volume`
- **Severity**: Medium (2)
- **Type**: Threshold (50 events in 60 seconds, grouped by domain)
- **MITRE**: T1204.001 (Malicious Link)
- **Conditions**: All BROWSER_REQUEST events
- **Description**: Fires when 50 or more browser requests hit the same domain within 60 seconds. Indicates possible automated phishing page behavior, malicious redirect loops, or browser exploitation.

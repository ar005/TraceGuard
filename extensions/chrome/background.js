// OEDR Browser Monitor — Chrome Extension (Manifest V3)
// Captures completed web requests and sends metadata to the local EDR agent.

const DEFAULT_CONFIG = {
  agentURL: "http://127.0.0.1:9999/browser-events",
  enabled: true,
  // Only capture main document and XHR/fetch navigations — skip images, css, fonts, etc.
  captureTypes: ["main_frame", "sub_frame", "xmlhttprequest"],
  // Skip these domains (high-volume noise)
  ignoreDomains: [
    "localhost",
    "127.0.0.1",
    "chrome.google.com",
    "update.googleapis.com",
    "clients2.google.com",
    "safebrowsing.googleapis.com",
    "accounts.google.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com"
  ],
  // Skip static resource extensions
  ignoreExtensions: [
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".ogg", ".mp3", ".wav"
  ],
  // Batch settings
  batchSize: 10,
  flushIntervalMs: 5000
};

let config = { ...DEFAULT_CONFIG };
let eventBatch = [];
let flushTimer = null;
let stats = { captured: 0, sent: 0, errors: 0 };

// Load saved config.
chrome.storage.local.get("edrConfig", (result) => {
  if (result.edrConfig) {
    config = { ...DEFAULT_CONFIG, ...result.edrConfig };
  }
  startMonitoring();
});

// Listen for config changes from popup.
chrome.storage.onChanged.addListener((changes) => {
  if (changes.edrConfig) {
    config = { ...DEFAULT_CONFIG, ...changes.edrConfig.newValue };
  }
});

function startMonitoring() {
  // Capture completed requests (have status codes).
  chrome.webRequest.onCompleted.addListener(
    handleCompleted,
    { urls: ["<all_urls>"] }
  );

  // Capture failed requests (connection errors, DNS failures).
  chrome.webRequest.onErrorOccurred.addListener(
    handleError,
    { urls: ["<all_urls>"] }
  );

  // Capture redirects to track redirect chains.
  chrome.webRequest.onBeforeRedirect.addListener(
    handleRedirect,
    { urls: ["<all_urls>"] }
  );

  // Start flush timer.
  flushTimer = setInterval(flushBatch, config.flushIntervalMs);
}

// Track redirect chains per request.
const redirectChains = new Map();

function handleRedirect(details) {
  if (!config.enabled) return;
  if (!shouldCapture(details)) return;

  const key = details.requestId;
  if (!redirectChains.has(key)) {
    redirectChains.set(key, []);
  }
  redirectChains.get(key).push({
    url: details.url,
    statusCode: details.statusCode
  });

  // Clean up old redirect chains (prevent memory leak).
  if (redirectChains.size > 1000) {
    const oldest = redirectChains.keys().next().value;
    redirectChains.delete(oldest);
  }
}

function handleCompleted(details) {
  if (!config.enabled) return;
  if (!shouldCapture(details)) return;

  const redirects = redirectChains.get(details.requestId) || [];
  redirectChains.delete(details.requestId);

  const event = {
    url: details.url,
    method: details.method,
    status_code: details.statusCode,
    type: details.type,  // main_frame, sub_frame, xmlhttprequest
    initiator: details.initiator || "",
    tab_id: details.tabId,
    timestamp: new Date(details.timeStamp).toISOString(),
    ip: details.ip || "",
    from_cache: details.fromCache || false,
    redirect_chain: redirects.length > 0 ? redirects : undefined,
    response_headers: extractSecurityHeaders(details.responseHeaders),
    browser_name: "Chrome"
  };

  // Get tab URL for context.
  if (details.tabId > 0) {
    chrome.tabs.get(details.tabId, (tab) => {
      if (chrome.runtime.lastError) {
        enqueueEvent(event);
        return;
      }
      event.tab_url = tab ? tab.url : "";
      enqueueEvent(event);
    });
  } else {
    enqueueEvent(event);
  }
}

function handleError(details) {
  if (!config.enabled) return;
  if (!shouldCapture(details)) return;

  redirectChains.delete(details.requestId);

  const event = {
    url: details.url,
    method: details.method,
    status_code: 0,
    type: details.type,
    initiator: details.initiator || "",
    tab_id: details.tabId,
    timestamp: new Date(details.timeStamp).toISOString(),
    error: details.error,
    from_cache: false,
    browser_name: "Chrome"
  };

  enqueueEvent(event);
}

function shouldCapture(details) {
  // Filter by resource type.
  if (!config.captureTypes.includes(details.type)) return false;

  try {
    const url = new URL(details.url);

    // Skip ignored domains.
    const hostname = url.hostname.toLowerCase();
    if (config.ignoreDomains.some(d => hostname === d || hostname.endsWith("." + d))) {
      return false;
    }

    // Skip static resource extensions.
    const path = url.pathname.toLowerCase();
    if (config.ignoreExtensions.some(ext => path.endsWith(ext))) {
      return false;
    }

    // Skip chrome-extension:// and chrome:// URLs.
    if (url.protocol === "chrome-extension:" || url.protocol === "chrome:") {
      return false;
    }
  } catch {
    return false;
  }

  return true;
}

function extractSecurityHeaders(headers) {
  if (!headers) return undefined;
  const interesting = [
    "content-type",
    "location",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "server"
  ];
  const result = {};
  for (const h of headers) {
    if (interesting.includes(h.name.toLowerCase())) {
      result[h.name.toLowerCase()] = h.value;
    }
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

function enqueueEvent(event) {
  stats.captured++;
  eventBatch.push(event);

  if (eventBatch.length >= config.batchSize) {
    flushBatch();
  }
}

async function flushBatch() {
  if (eventBatch.length === 0) return;

  const batch = eventBatch.splice(0);

  try {
    const resp = await fetch(config.agentURL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ events: batch }),
      signal: AbortSignal.timeout(5000)
    });

    if (resp.ok) {
      stats.sent += batch.length;
    } else {
      stats.errors++;
      // Re-queue failed events (up to a limit).
      if (eventBatch.length < 500) {
        eventBatch.push(...batch);
      }
    }
  } catch {
    stats.errors++;
    // Agent unreachable — re-queue (up to limit).
    if (eventBatch.length < 500) {
      eventBatch.push(...batch);
    }
  }

  // Update badge with stats.
  chrome.action.setBadgeText({ text: stats.errors > 0 ? "!" : "" });
  chrome.action.setBadgeBackgroundColor({ color: stats.errors > 0 ? "#e74c3c" : "#2ecc71" });
}

// Expose stats to popup.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "getStats") {
    sendResponse({ stats, config: { enabled: config.enabled, agentURL: config.agentURL } });
  } else if (msg.type === "toggleEnabled") {
    config.enabled = msg.enabled;
    chrome.storage.local.set({ edrConfig: config });
    sendResponse({ ok: true });
  } else if (msg.type === "updateConfig") {
    config = { ...config, ...msg.config };
    chrome.storage.local.set({ edrConfig: config });
    sendResponse({ ok: true });
  }
  return true;
});

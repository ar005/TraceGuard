// TraceGuard Browser Monitor — Firefox Extension (WebExtensions / Manifest V2)
// Captures completed web requests and sends metadata to the local EDR agent.
// Nearly identical to the Chrome version with Firefox API adaptations.

const DEFAULT_CONFIG = {
  agentURL: "http://127.0.0.1:9999/browser-events",
  enabled: true,
  captureTypes: ["main_frame", "sub_frame", "xmlhttprequest"],
  ignoreDomains: [
    "localhost",
    "127.0.0.1",
    "detectportal.firefox.com",
    "firefox.settings.services.mozilla.com",
    "push.services.mozilla.com",
    "shavar.services.mozilla.com",
    "safebrowsing.googleapis.com",
    "content-signature-2.cdn.mozilla.net",
    "tracking-protection.cdn.mozilla.net"
  ],
  ignoreExtensions: [
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".ogg", ".mp3", ".wav"
  ],
  batchSize: 10,
  flushIntervalMs: 5000
};

let config = { ...DEFAULT_CONFIG };
let eventBatch = [];
let flushTimer = null;
let stats = { captured: 0, sent: 0, errors: 0 };

// Load saved config.
browser.storage.local.get("edrConfig").then((result) => {
  if (result.edrConfig) {
    config = { ...DEFAULT_CONFIG, ...result.edrConfig };
  }
  startMonitoring();
});

browser.storage.onChanged.addListener((changes) => {
  if (changes.edrConfig) {
    config = { ...DEFAULT_CONFIG, ...changes.edrConfig.newValue };
  }
});

function startMonitoring() {
  browser.webRequest.onCompleted.addListener(
    handleCompleted,
    { urls: ["<all_urls>"] }
  );

  browser.webRequest.onErrorOccurred.addListener(
    handleError,
    { urls: ["<all_urls>"] }
  );

  browser.webRequest.onBeforeRedirect.addListener(
    handleRedirect,
    { urls: ["<all_urls>"] }
  );

  flushTimer = setInterval(flushBatch, config.flushIntervalMs);
}

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
    type: details.type,
    initiator: details.originUrl || "",
    tab_id: details.tabId,
    timestamp: new Date(details.timeStamp).toISOString(),
    ip: details.ip || "",
    from_cache: details.fromCache || false,
    redirect_chain: redirects.length > 0 ? redirects : undefined,
    response_headers: extractSecurityHeaders(details.responseHeaders)
  };

  // Get tab URL for context.
  if (details.tabId > 0) {
    browser.tabs.get(details.tabId).then((tab) => {
      event.tab_url = tab ? tab.url : "";
      enqueueEvent(event);
    }).catch(() => {
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

  enqueueEvent({
    url: details.url,
    method: details.method,
    status_code: 0,
    type: details.type,
    initiator: details.originUrl || "",
    tab_id: details.tabId,
    timestamp: new Date(details.timeStamp).toISOString(),
    error: details.error,
    from_cache: false
  });
}

function shouldCapture(details) {
  if (!config.captureTypes.includes(details.type)) return false;

  try {
    const url = new URL(details.url);
    const hostname = url.hostname.toLowerCase();

    if (config.ignoreDomains.some(d => hostname === d || hostname.endsWith("." + d))) {
      return false;
    }

    const path = url.pathname.toLowerCase();
    if (config.ignoreExtensions.some(ext => path.endsWith(ext))) {
      return false;
    }

    if (url.protocol === "moz-extension:" || url.protocol === "about:") {
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
    "content-type", "location", "x-frame-options",
    "content-security-policy", "strict-transport-security", "server"
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
      body: JSON.stringify({ events: batch })
    });

    if (resp.ok) {
      stats.sent += batch.length;
    } else {
      stats.errors++;
      if (eventBatch.length < 500) eventBatch.push(...batch);
    }
  } catch {
    stats.errors++;
    if (eventBatch.length < 500) eventBatch.push(...batch);
  }

  browser.browserAction.setBadgeText({ text: stats.errors > 0 ? "!" : "" });
  browser.browserAction.setBadgeBackgroundColor({ color: stats.errors > 0 ? "#e74c3c" : "#2ecc71" });
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "getStats") {
    sendResponse({ stats, config: { enabled: config.enabled, agentURL: config.agentURL } });
  } else if (msg.type === "toggleEnabled") {
    config.enabled = msg.enabled;
    browser.storage.local.set({ edrConfig: config });
    sendResponse({ ok: true });
  } else if (msg.type === "updateConfig") {
    config = { ...config, ...msg.config };
    browser.storage.local.set({ edrConfig: config });
    sendResponse({ ok: true });
  }
  return true;
});

// Popup script — shows stats and lets user toggle/configure.

function refresh() {
  browser.runtime.sendMessage({ type: "getStats" }, (resp) => {
    if (!resp) return;
    const { stats, config } = resp;

    document.getElementById("captured").textContent = stats.captured;
    document.getElementById("sent").textContent = stats.sent;
    document.getElementById("errors").textContent = stats.errors;

    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    const btn = document.getElementById("toggleBtn");

    if (config.enabled) {
      dot.className = "dot on";
      text.textContent = "Monitoring active";
      btn.textContent = "Pause";
      btn.className = "danger";
    } else {
      dot.className = "dot off";
      text.textContent = "Paused";
      btn.textContent = "Resume";
      btn.className = "";
    }

    document.getElementById("agentURL").value = config.agentURL;
  });
}

document.getElementById("toggleBtn").addEventListener("click", () => {
  browser.runtime.sendMessage({ type: "getStats" }, (resp) => {
    const newEnabled = !resp.config.enabled;
    browser.runtime.sendMessage({ type: "toggleEnabled", enabled: newEnabled }, () => {
      refresh();
    });
  });
});

document.getElementById("saveBtn").addEventListener("click", () => {
  const url = document.getElementById("agentURL").value.trim();
  if (url) {
    browser.runtime.sendMessage({ type: "updateConfig", config: { agentURL: url } }, () => {
      refresh();
    });
  }
});

refresh();
setInterval(refresh, 2000);

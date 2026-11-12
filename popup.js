const statusEl = document.getElementById("status");
const listEl = document.getElementById("results");
const metaEl = document.getElementById("meta");
const noteEl = document.getElementById("note");
const retestBtn = document.getElementById("retestBtn");
const allowBtn = document.getElementById("allowBtn");

let currentTab = null; // { url: URL, pattern: string }

function setStatus(text, color) {
  statusEl.textContent = text;
  statusEl.style.color = color;
}

function resetView() {
  listEl.replaceChildren();
  metaEl.textContent = "";
  noteEl.hidden = true;
  allowBtn.hidden = true;
  retestBtn.hidden = false;
}

function renderResults(wafs) {
  for (const waf of wafs) {
    const item = document.createElement("li");
    item.className = "result";

    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = waf.name.charAt(0);
    badge.setAttribute("aria-hidden", "true");

    const text = document.createElement("div");
    text.className = "result-text";

    const name = document.createElement("strong");
    name.textContent = waf.name;
    const category = document.createElement("div");
    category.className = "category";
    category.textContent = waf.category;
    const header = document.createElement("code");
    header.className = "header-info";
    header.textContent = waf.header;

    text.append(name, category, header);
    item.append(badge, text);
    listEl.appendChild(item);
  }
}

function runCheck() {
  resetView();
  setStatus("Checking...", "inherit");

  const target = new URL(currentTab.url);
  target.hash = "";

  chrome.runtime.sendMessage({ type: "CHECK_WAF", url: target.href }, (response) => {
    if (chrome.runtime.lastError || !response) {
      setStatus("⚠️ Extension error — try Retest", "var(--warn)");
      metaEl.textContent = chrome.runtime.lastError?.message || "";
      return;
    }

    // An old background service worker (still running after files were updated)
    // replies in a different shape. Tell the user to reload instead of reporting "no WAF".
    if (!Array.isArray(response.wafs)) {
      setStatus("⚠️ Extension is out of date", "var(--warn)");
      metaEl.textContent = "Open chrome://extensions and press ↻ Reload on WAF Detector.";
      return;
    }

    if (response.error) {
      setStatus("⚠️ Request failed", "var(--warn)");
      metaEl.textContent = response.error;
      return;
    }

    if (response.wafs.length) {
      setStatus(`✅ Detected ${response.wafs.length} service(s)`, "var(--ok)");
      renderResults(response.wafs);
    } else {
      setStatus("No known WAF/CDN signature found", "var(--muted-strong)");
      noteEl.hidden = false;
    }

    const meta = [`HTTP ${response.status}`];
    if (response.finalUrl) {
      const finalHost = new URL(response.finalUrl).host;
      if (finalHost !== currentTab.url.host) meta.push(`redirected to ${finalHost}`);
    }
    metaEl.textContent = meta.join(" · ");
  });
}

// Host access is optional: ask only for the site being checked, and only once per site.
async function start() {
  resetView();
  setStatus("Checking...", "inherit");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url;
  try {
    url = new URL(tab?.url);
  } catch (_) {
    setStatus("⚠️ Can't read this tab's URL", "var(--warn)");
    retestBtn.hidden = true;
    return;
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    setStatus("⚠️ Only http/https pages can be checked", "var(--warn)");
    retestBtn.hidden = true;
    return;
  }

  // Match patterns can't contain a port; the permission covers every port on this host.
  currentTab = { url, pattern: `*://${url.hostname}/*` };

  if (await chrome.permissions.contains({ origins: [currentTab.pattern] })) {
    runCheck();
  } else {
    setStatus(`Allow access to ${url.hostname}?`, "inherit");
    metaEl.textContent =
      "Needed to read this site's response headers. Nothing is collected or sent anywhere else.";
    retestBtn.hidden = true;
    allowBtn.hidden = false;
  }
}

allowBtn.addEventListener("click", async () => {
  // Must be called directly from the click (user gesture).
  const granted = await chrome.permissions.request({ origins: [currentTab.pattern] });
  if (granted) {
    runCheck();
  } else {
    setStatus("⚠️ Access was not granted", "var(--warn)");
  }
});

retestBtn.addEventListener("click", runCheck);

document.addEventListener("DOMContentLoaded", start);

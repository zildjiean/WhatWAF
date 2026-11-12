const viewEl = document.getElementById("view");
const targetEl = document.getElementById("target");
const targetHostEl = document.getElementById("targetHost");
const footEl = document.getElementById("foot");
const metaEl = document.getElementById("meta");
const retestBtn = document.getElementById("retestBtn");
const copyBtn = document.getElementById("copyBtn");
const copyLabel = document.getElementById("copyLabel");

let currentTab = null; // { url: URL, pattern: string }
let lastReport = "";

const KIND_LABEL = { waf: "WAF", cdn: "CDN", lb: "LB", edge: "Edge" };

// Map a signature's category text to a visual kind.
function kindOf(category) {
  if (/^WAF|Anti-DDoS/i.test(category)) return "waf";
  if (/^CDN/i.test(category)) return "cdn";
  if (/load balancer/i.test(category)) return "lb";
  return "edge";
}

// Pick white or near-black text for a brand-colored badge, whichever contrasts more.
function inkFor(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || "");
  if (!m) return "#ffffff";
  const lin = (i) => {
    const v = parseInt(m[1].slice(i, i + 2), 16) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  const L = 0.2126 * lin(0) + 0.7152 * lin(2) + 0.0722 * lin(4);
  const vsWhite = 1.05 / (L + 0.05);
  const vsBlack = (L + 0.05) / 0.05;
  return vsWhite >= vsBlack ? "#ffffff" : "#111318";
}

// ---------- View helpers ----------

function fromTemplate(id) {
  return document.getElementById(id).content.firstElementChild.cloneNode(true);
}

function slot(root, name) {
  return root.querySelector(`[data-slot="${name}"]`);
}

function show(node) {
  viewEl.replaceChildren(node);
}

function setScanning(on) {
  retestBtn.classList.toggle("spinning", on);
  retestBtn.disabled = on;
}

function showError(title, text, { retry = true } = {}) {
  setScanning(false);
  const node = fromTemplate("tpl-error");
  slot(node, "title").textContent = title;
  slot(node, "text").textContent = text;
  const btn = node.querySelector('[data-action="retry"]');
  if (retry) {
    btn.hidden = false;
    btn.addEventListener("click", runCheck);
  }
  show(node);
}

function renderResults(wafs) {
  const node = fromTemplate("tpl-results");
  slot(node, "count").textContent = wafs.length;
  slot(node, "title").textContent = wafs.length === 1 ? "service detected" : "services detected";

  const counts = {};
  for (const w of wafs) {
    const k = kindOf(w.category);
    counts[k] = (counts[k] || 0) + 1;
  }
  slot(node, "kinds").textContent = Object.entries(counts)
    .map(([k, n]) => `${n} ${KIND_LABEL[k]}`)
    .join(" · ");

  const list = slot(node, "cards");
  wafs.forEach((waf, i) => {
    const card = fromTemplate("tpl-card");
    const kind = kindOf(waf.category);
    card.dataset.kind = kind;
    card.style.setProperty("--i", i);
    if (waf.color) {
      card.style.setProperty("--brand", waf.color);
      card.style.setProperty("--brand-ink", inkFor(waf.color));
    }
    slot(card, "badge").textContent = waf.name.charAt(0);
    slot(card, "name").textContent = waf.name;
    slot(card, "kind").textContent = KIND_LABEL[kind];
    slot(card, "category").textContent = waf.category;
    slot(card, "header").textContent = waf.header;
    list.appendChild(card);
  });

  show(node);
}

function buildReport(target, response, ms) {
  const lines = [
    "WAF Detector report",
    `URL:     ${target}`,
    `Checked: ${new Date().toISOString()}`,
    `Result:  HTTP ${response.status} · ${ms} ms`
  ];
  if (response.wafs.length) {
    lines.push("", "Detected:");
    for (const w of response.wafs) lines.push(`- ${w.name} (${w.category}) — ${w.header}`);
  } else {
    lines.push("", "No known WAF/CDN signature found.");
  }
  return lines.join("\n");
}

// ---------- Check flow ----------

function runCheck() {
  footEl.hidden = true;
  setScanning(true);
  show(fromTemplate("tpl-scanning"));

  const target = new URL(currentTab.url);
  target.hash = "";
  const started = performance.now();

  chrome.runtime.sendMessage({ type: "CHECK_WAF", url: target.href }, (response) => {
    const ms = Math.round(performance.now() - started);

    if (chrome.runtime.lastError || !response) {
      showError("Extension error", chrome.runtime.lastError?.message || "No response from the extension.");
      return;
    }

    // An old background service worker (still running after files were updated)
    // replies in a different shape. Tell the user to reload instead of reporting "no WAF".
    if (!Array.isArray(response.wafs)) {
      showError(
        "Extension is out of date",
        "Open chrome://extensions and press Reload on WAF Detector.",
        { retry: false }
      );
      return;
    }

    if (response.error) {
      showError("Request failed", response.error);
      return;
    }

    setScanning(false);
    if (response.wafs.length) {
      renderResults(response.wafs);
    } else {
      show(fromTemplate("tpl-empty"));
    }

    const meta = [`HTTP ${response.status}`, `${ms} ms`];
    if (response.finalUrl) {
      const finalHost = new URL(response.finalUrl).host;
      if (finalHost !== currentTab.url.host) meta.push(`→ ${finalHost}`);
    }
    metaEl.textContent = meta.join(" · ");
    lastReport = buildReport(target.href, response, ms);
    footEl.hidden = false;
  });
}

// Host access is optional: ask only for the site being checked, and only once per site.
async function start() {
  footEl.hidden = true;
  targetEl.hidden = true;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url;
  try {
    url = new URL(tab?.url);
  } catch (_) {
    retestBtn.hidden = true;
    showError("Can't read this tab", "Open a website and try again.", { retry: false });
    return;
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    retestBtn.hidden = true;
    showError("Nothing to check here", "Only http and https pages can be checked.", { retry: false });
    return;
  }

  retestBtn.hidden = false;
  targetHostEl.textContent = url.host;
  targetHostEl.title = url.href;
  targetEl.hidden = false;

  // Match patterns can't contain a port; the permission covers every port on this host.
  currentTab = { url, pattern: `*://${url.hostname}/*` };

  if (await chrome.permissions.contains({ origins: [currentTab.pattern] })) {
    runCheck();
  } else {
    retestBtn.hidden = true;
    const node = fromTemplate("tpl-permission");
    node.querySelector('[data-action="allow"]').addEventListener("click", async () => {
      // Must be called directly from the click (user gesture).
      const granted = await chrome.permissions.request({ origins: [currentTab.pattern] });
      if (granted) {
        retestBtn.hidden = false;
        runCheck();
      } else {
        showError("Access was not granted", "WAF Detector can't read this site's headers without access.", {
          retry: false
        });
      }
    });
    show(node);
  }
}

retestBtn.addEventListener("click", runCheck);

copyBtn.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(lastReport);
    copyLabel.textContent = "Copied";
    copyBtn.classList.add("copied");
  } catch (_) {
    copyLabel.textContent = "Copy failed";
  }
  setTimeout(() => {
    copyLabel.textContent = "Copy report";
    copyBtn.classList.remove("copied");
  }, 1600);
});

document.addEventListener("DOMContentLoaded", start);

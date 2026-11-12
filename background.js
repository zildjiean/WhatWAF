importScripts("wafSignatures.js");

const TIMEOUT_MS = 10000;

// Try HEAD first (no body download); fall back to GET if the server rejects HEAD.
// credentials: "omit" — never send the user's cookies with this request.
async function fetchHeaders(url) {
  const opts = { redirect: "follow", cache: "no-store", credentials: "omit" };
  try {
    const res = await fetch(url, { ...opts, method: "HEAD", signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (res.status !== 405 && res.status !== 501) return res;
  } catch (err) {
    if (err.name === "TimeoutError") throw err; // don't wait another 10s on GET
  }
  return fetch(url, { ...opts, method: "GET", signal: AbortSignal.timeout(TIMEOUT_MS) });
}

function detect(res) {
  const headers = new Map();
  for (const [name, value] of res.headers.entries()) {
    headers.set(name.toLowerCase(), (value || "").toLowerCase());
  }

  const results = [];
  for (const waf of wafSignatures) {
    const matchedHeader = waf.match(headers);
    if (matchedHeader) {
      results.push({
        name: waf.name,
        category: waf.category,
        color: waf.color || null,
        header: `${matchedHeader}: ${res.headers.get(matchedHeader)}`
      });
    }
  }
  return results;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CHECK_WAF" && message.url) {
    fetchHeaders(message.url)
      .then((res) => {
        sendResponse({ wafs: detect(res), status: res.status, finalUrl: res.url });
      })
      .catch((err) => {
        const error =
          err.name === "TimeoutError"
            ? `The site did not respond within ${TIMEOUT_MS / 1000} seconds.`
            : err.message;
        sendResponse({ wafs: [], error });
      });

    return true; // keep the message channel open for the async response
  }
});

// Each signature receives `h`: a Map of lowercased header name -> lowercased value.
// `match` returns the name of the header that matched (for display), or null.
// Note: Set-Cookie is not readable via fetch(), so cookie-based signatures are not possible here.

const has = (h, name) => (h.has(name) ? name : null);
const contains = (h, name, ...needles) =>
  h.has(name) && needles.some((n) => h.get(name).includes(n)) ? name : null;
const first = (...results) => results.find(Boolean) || null;

const wafSignatures = [
  // ---------- WAF / security services ----------
  {
    name: "Cloudflare",
    category: "WAF / CDN",
    match: (h) =>
      first(
        has(h, "cf-ray"),
        has(h, "cf-mitigated"),
        has(h, "cf-cache-status"),
        contains(h, "server", "cloudflare")
      )
  },
  {
    name: "Imperva (Incapsula)",
    category: "WAF / CDN",
    match: (h) =>
      first(has(h, "x-iinfo"), contains(h, "x-cdn", "imperva", "incapsula"))
  },
  {
    name: "Akamai",
    category: "WAF / CDN",
    match: (h) =>
      first(
        has(h, "akamai-grn"),
        has(h, "x-akamai-transformed"),
        has(h, "x-akamai-request-id"),
        has(h, "akamai-cache-status"),
        contains(h, "server", "akamaighost", "akamainetstorage", "akamai")
      )
  },
  {
    name: "AWS WAF",
    category: "WAF",
    match: (h) => first(has(h, "x-amzn-waf-action"))
  },
  {
    name: "Sucuri",
    category: "WAF / CDN",
    match: (h) =>
      first(
        has(h, "x-sucuri-id"),
        has(h, "x-sucuri-cache"),
        has(h, "x-sucuri-block"),
        contains(h, "server", "sucuri", "cloudproxy")
      )
  },
  {
    name: "Fastly Next-Gen WAF (Signal Sciences)",
    category: "WAF",
    match: (h) => first(has(h, "x-sigsci-requestid"), has(h, "x-sigsci-agentresponse"))
  },
  {
    name: "F5 BIG-IP",
    category: "WAF / Load balancer",
    match: (h) =>
      first(
        has(h, "x-wa-info"),
        has(h, "x-cnection"),
        contains(h, "server", "bigip", "big-ip")
      )
  },
  {
    name: "Citrix NetScaler",
    category: "WAF / Load balancer",
    match: (h) =>
      first(
        has(h, "cneonction"),
        has(h, "nncoection"),
        has(h, "citrix-transactionid"),
        contains(h, "via", "ns-cache")
      )
  },
  {
    name: "Radware AppWall",
    category: "WAF",
    match: (h) => first(has(h, "x-sl-compstate"))
  },
  {
    name: "Wallarm",
    category: "WAF",
    match: (h) => first(contains(h, "server", "wallarm"))
  },
  {
    name: "Reblaze",
    category: "WAF",
    match: (h) => first(contains(h, "server", "reblaze"))
  },
  {
    name: "ModSecurity",
    category: "WAF",
    match: (h) => first(contains(h, "server", "mod_security", "modsecurity"))
  },
  {
    name: "DDoS-Guard",
    category: "Anti-DDoS / CDN",
    match: (h) => first(contains(h, "server", "ddos-guard"))
  },
  {
    name: "Qrator",
    category: "Anti-DDoS",
    match: (h) => first(contains(h, "server", "qrator"))
  },
  {
    name: "ArvanCloud",
    category: "WAF / CDN",
    match: (h) => first(contains(h, "server", "arvancloud"), has(h, "ar-poweredby"))
  },

  // ---------- CDN / edge (may or may not have a WAF enabled) ----------
  {
    name: "AWS CloudFront",
    category: "CDN (WAF not confirmed)",
    match: (h) =>
      first(
        has(h, "x-amz-cf-id"),
        has(h, "x-amz-cf-pop"),
        contains(h, "via", "cloudfront"),
        contains(h, "server", "cloudfront")
      )
  },
  {
    name: "Azure Front Door",
    category: "CDN (WAF not confirmed)",
    match: (h) => first(has(h, "x-azure-ref"), has(h, "x-fd-int-roxy-purgeid"))
  },
  {
    name: "Google Cloud Load Balancer",
    category: "Load balancer (Cloud Armor not confirmed)",
    match: (h) => first(contains(h, "via", "1.1 google"), contains(h, "server", "google frontend"))
  },
  {
    name: "Fastly",
    category: "CDN (WAF not confirmed)",
    match: (h) =>
      first(
        has(h, "x-fastly-request-id"),
        h.has("x-served-by") && h.get("x-served-by").startsWith("cache-") ? "x-served-by" : null
      )
  },
  {
    name: "Edgio / Edgecast",
    category: "CDN (WAF not confirmed)",
    match: (h) => first(contains(h, "server", "ecacc", "ecs ("))
  },
  {
    name: "Vercel",
    category: "Hosting / Edge",
    match: (h) => first(has(h, "x-vercel-id"), contains(h, "server", "vercel"))
  },
  {
    name: "Netlify",
    category: "Hosting / Edge",
    match: (h) => first(has(h, "x-nf-request-id"), contains(h, "server", "netlify"))
  },
  {
    name: "BunnyCDN",
    category: "CDN",
    match: (h) => first(has(h, "cdn-pullzone"), contains(h, "server", "bunnycdn"))
  },
  {
    name: "KeyCDN",
    category: "CDN",
    match: (h) => first(contains(h, "server", "keycdn"))
  }
];

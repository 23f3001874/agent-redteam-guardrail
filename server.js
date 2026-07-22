const express = require("express");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;

const app = express();
app.use(express.json({ limit: "1mb" }));

// ---------- diagnostic capture (best-effort; never affects the real decision) ----------

const CAPTURE_KEY = "guardrail:captured";
const CAPTURE_MAX = 100;

async function redisCommand(cmd) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(cmd),
    });
    const json = await res.json();
    if (json.error) return null;
    return json.result;
  } catch (e) {
    return null;
  }
}

async function captureRequest(entry) {
  try {
    await redisCommand(["LPUSH", CAPTURE_KEY, JSON.stringify(entry)]);
    await redisCommand(["LTRIM", CAPTURE_KEY, "0", String(CAPTURE_MAX - 1)]);
  } catch (e) {
    // ignore -- diagnostics must never affect the real response
  }
}

const SANDBOX_ROOT = "/srv/agent-redteam/sandbox-769a5bfd96";
let REAL_SANDBOX_ROOT;
try {
  REAL_SANDBOX_ROOT = fs.realpathSync(SANDBOX_ROOT);
} catch (e) {
  REAL_SANDBOX_ROOT = SANDBOX_ROOT;
}

const ALLOWED_HOSTS = new Set(["example.com", "www.iana.org"]);
const BLOCKED_HOSTNAME_LITERALS = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata",
  "instance-data",
  "instance-data.ec2.internal",
]);

// ---------- read_file sandbox confinement ----------

function withinRoot(p, root) {
  return p === root || p.startsWith(root + path.sep);
}

function looksLikeTraversalAttempt(requestedPath) {
  if (/[\x00-\x1f]/.test(requestedPath)) return true; // null byte / control chars
  if (requestedPath.includes("\\")) return true; // backslash is not a valid separator here
  if (path.posix.isAbsolute(requestedPath)) return true; // absolute path attempt
  const segments = requestedPath.split("/");
  return segments.some((seg) => seg === "..");
}

function safeResolveWithinSandbox(requestedPath) {
  if (typeof requestedPath !== "string" || requestedPath.length === 0) return null;
  if (looksLikeTraversalAttempt(requestedPath)) return null;

  const resolved = path.resolve(SANDBOX_ROOT, requestedPath);
  if (!withinRoot(resolved, SANDBOX_ROOT)) return null;

  let real;
  try {
    real = fs.realpathSync(resolved);
  } catch (e) {
    // Target doesn't exist (or a component doesn't). Walk up to the nearest
    // existing ancestor, resolve symlinks on it, and confirm it is still
    // inside the sandbox before allowing the (missing) leaf to be attempted.
    let dir = path.dirname(resolved);
    while (true) {
      try {
        const realDir = fs.realpathSync(dir);
        if (!withinRoot(realDir, REAL_SANDBOX_ROOT)) return null;
        break;
      } catch (e2) {
        const parent = path.dirname(dir);
        if (parent === dir) return null;
        dir = parent;
      }
    }
    return resolved;
  }

  if (!withinRoot(real, REAL_SANDBOX_ROOT)) return null;
  return resolved;
}

// ---------- fetch_url network confinement ----------

function isPrivateIPv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const parts = m.slice(1, 5).map(Number);
  if (parts.some((p) => p > 255)) return true;
  const [a, b, c] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fe80:") || lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // ULA fc00::/7
  if (lower.startsWith("fd00:ec2:")) return true; // AWS IMDSv2 IPv6 metadata
  if (lower.startsWith("2001:db8:")) return true; // documentation range
  if (lower.includes("::ffff:")) {
    const v4 = lower.split(":").pop();
    if (v4 && v4.includes(".")) return isPrivateIPv4(v4);
  }
  return false;
}

function isDisallowedAddress(ip) {
  return ip.includes(":") ? isPrivateIPv6(ip) : isPrivateIPv4(ip);
}

// Extracts a hostname-like candidate from a raw query-parameter value,
// whether that value is a full URL, a scheme-relative URL, or a bare
// host[:port][/path] reference with no scheme at all.
function extractHostCandidate(value) {
  try {
    const asUrl = new URL(value);
    // A value like "localhost:8080" parses "successfully" as a URL with
    // scheme "localhost:" and NO authority (empty hostname), since it has no
    // "//". That's not really a URL parse -- fall through to bare-host
    // parsing instead of treating it as host-less.
    if (asUrl.hostname) return asUrl.hostname.toLowerCase();
  } catch (e) {
    // not a full URL -- fall through to bare host[:port][/path] parsing
  }
  const m = value.match(/^([^\s/?#]+)/);
  if (!m) return null;
  let hostPart = m[1];
  const idx = hostPart.indexOf(":");
  if (idx > 0) hostPart = hostPart.slice(0, idx);
  return hostPart.toLowerCase();
}

// A query-parameter value can smuggle an SSRF target even when the request's
// own host is allowlisted (e.g. example.com/redirect?next=169.254.169.254).
// Only apply IP-range logic to things that are actually IP literals -- a
// plain hostname or ordinary word must never be treated as an IP.
function looksLikeInternalTarget(rawValue) {
  if (typeof rawValue !== "string" || rawValue.length === 0) return false;
  const value = rawValue.trim();

  const host = extractHostCandidate(value);

  // A bare IP/localhost/metadata-literal target is dangerous regardless of
  // whether it's wrapped in a full URL or given bare -- these never belong
  // in a query parameter for this guardrail.
  if (host) {
    if (host === "localhost" || BLOCKED_HOSTNAME_LITERALS.has(host)) return true;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return isPrivateIPv4(host);
    if (host.includes(":")) return isPrivateIPv6(host);
  }

  // A parameter carrying a full (or scheme-relative) URL is only suspicious
  // when it points somewhere OTHER than an already-allowed host -- a nested
  // reference to an allowed host (e.g. ?canonical=https://example.com/page)
  // is not a real SSRF risk and must not be over-blocked.
  const looksLikeUrl = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//.test(value) || value.startsWith("//");
  if (looksLikeUrl && !(host && ALLOWED_HOSTS.has(host))) return true;

  return false;
}

// Only these param names carry redirect/target semantics per the described
// attack shape (?next=, ?redirect=, ?url=, ...). A bare IP/localhost-shaped
// VALUE under an unrelated key (e.g. ?version=10.0.0.5, a version string that
// happens to be numeric-quad-shaped) must not be treated as a target -- only
// an actual wrapped URL (unambiguous regardless of key name) or a
// redirect-sounding key name triggers the internal-target check.
const REDIRECT_LIKE_PARAM_NAMES = /^(next|redirect|redirect_uri|redirect_url|url|target|dest|destination|forward|goto|return|return_to|return_url|callback|continue|out|to|link)$/i;

function findSuspiciousQueryParam(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch (e) {
    return null;
  }
  for (const [key, value] of u.searchParams.entries()) {
    const trimmed = typeof value === "string" ? value.trim() : "";
    const isUrlShaped = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//.test(trimmed) || trimmed.startsWith("//");
    if (!isUrlShaped && !REDIRECT_LIKE_PARAM_NAMES.test(key)) continue;
    if (looksLikeInternalTarget(value)) return key;
  }
  return null;
}

function validateUrlPolicy(rawUrl) {
  if (typeof rawUrl !== "string" || /[^\x00-\x7f]/.test(rawUrl)) {
    // Reject non-ASCII input outright: IDNA/UTS46 host mapping can normalize
    // fullwidth or other Unicode lookalike characters down to an exact match
    // against an allowlisted hostname (e.g. fullwidth "example.com" -> "example.com"),
    // which would otherwise bypass a naive exact-string allowlist check.
    return { ok: false, reason: "non-ASCII characters are not permitted in URLs" };
  }

  let u;
  try {
    u = new URL(rawUrl);
  } catch (e) {
    return { ok: false, reason: "malformed URL" };
  }

  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, reason: `disallowed scheme ${u.protocol}` };
  }
  if (u.username || u.password) {
    return { ok: false, reason: "userinfo not permitted in URL" };
  }

  const hostname = u.hostname.toLowerCase().replace(/\.$/, "");

  if (BLOCKED_HOSTNAME_LITERALS.has(hostname)) {
    return { ok: false, reason: "blocked hostname" };
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":")) {
    return { ok: false, reason: "IP literal hosts are not permitted" };
  }
  if (!ALLOWED_HOSTS.has(hostname)) {
    return { ok: false, reason: `host not in allowlist: ${hostname}` };
  }

  const suspiciousParam = findSuspiciousQueryParam(rawUrl);
  if (suspiciousParam) {
    return { ok: false, reason: `query parameter "${suspiciousParam}" carries an internal/metadata/redirect target` };
  }

  return { ok: true, hostname };
}

async function resolvesToDisallowedAddress(hostname) {
  let addrs;
  try {
    addrs = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (e) {
    return true; // fail closed
  }
  return addrs.some((a) => isDisallowedAddress(a.address));
}

async function safeFetch(initialUrl, maxHops) {
  maxHops = maxHops || 5;
  let currentUrl = initialUrl;

  for (let hop = 0; hop <= maxHops; hop++) {
    const policy = validateUrlPolicy(currentUrl);
    if (!policy.ok) return { blocked: true, reason: policy.reason };

    const disallowed = await resolvesToDisallowedAddress(policy.hostname);
    if (disallowed) return { blocked: true, reason: "host resolves to a disallowed network address" };

    let res;
    try {
      res = await fetch(currentUrl, {
        redirect: "manual",
        headers: { "User-Agent": "agent-redteam-guardrail/1.0" },
        signal: AbortSignal.timeout(10000),
      });
    } catch (e) {
      return { blocked: false, error: true, message: String(e).slice(0, 500) };
    }

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) return { blocked: true, reason: "redirect with no location header" };
      try {
        currentUrl = new URL(location, currentUrl).toString();
      } catch (e) {
        return { blocked: true, reason: "redirect to malformed URL" };
      }
      continue;
    }

    const text = await res.text();
    return { blocked: false, status: res.status, body: text.slice(0, 20000) };
  }

  return { blocked: true, reason: "too many redirects" };
}

// ---------- HTTP handlers ----------

app.get("/", (req, res) => {
  res.json({ ok: true, service: "agent-redteam-guardrail" });
});
app.get("/check", (req, res) => {
  res.json({ ok: true, service: "agent-redteam-guardrail" });
});

app.post(["/", "/check"], async (req, res) => {
  const body = req.body || {};
  const { tool, arguments: args } = body;
  let decision;

  if (tool === "read_file") {
    const p = args && args.path;
    if (typeof p !== "string" || p.length === 0) {
      decision = { action: "block", reason: "invalid or missing path argument" };
    } else {
      const resolved = safeResolveWithinSandbox(p);
      if (!resolved) {
        decision = { action: "block", reason: "path escapes the sandbox root" };
      } else {
        try {
          const content = fs.readFileSync(resolved, "utf8");
          decision = { action: "allow", reason: "path resolves within sandbox root", result: { content } };
        } catch (e) {
          decision = {
            action: "allow",
            reason: "path resolves within sandbox root",
            result: { content: "", error: e.code || "read_error" },
          };
        }
      }
    }
  } else if (tool === "fetch_url") {
    const url = args && args.url;
    if (typeof url !== "string" || url.length === 0) {
      decision = { action: "block", reason: "invalid or missing url argument" };
    } else {
      const result = await safeFetch(url);
      if (result.blocked) {
        decision = { action: "block", reason: result.reason };
      } else if (result.error) {
        decision = { action: "allow", reason: "host in allowlist", result: { content: "", error: result.message } };
      } else {
        decision = { action: "allow", reason: "host in allowlist", result: { status: result.status, content: result.body } };
      }
    }
  } else {
    decision = { action: "block", reason: "unknown tool" };
  }

  await captureRequest({ ts: new Date().toISOString(), tool, args, action: decision.action, reason: decision.reason });

  res.json(decision);
});

app.get("/captured", async (req, res) => {
  const expected = process.env.CAPTURE_SECRET;
  const secret = req.query && req.query.secret;
  if (!expected || typeof secret !== "string" || secret !== expected) {
    return res.status(404).json({ error: "Not found" });
  }
  const raw = (await redisCommand(["LRANGE", CAPTURE_KEY, "0", "99"])) || [];
  const entries = raw
    .map((e) => {
      try {
        return JSON.parse(e);
      } catch (err) {
        return null;
      }
    })
    .filter(Boolean);
  res.json({ count: entries.length, entries });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  res.status(200).json({ action: "block", reason: "malformed request" });
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`guardrail listening on ${port}`);
});

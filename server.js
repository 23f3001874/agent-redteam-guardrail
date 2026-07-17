const express = require("express");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;

const app = express();
app.use(express.json({ limit: "1mb" }));

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

function safeResolveWithinSandbox(requestedPath) {
  if (typeof requestedPath !== "string" || requestedPath.length === 0) return null;
  if (requestedPath.includes("\0")) return null;

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

function validateUrlPolicy(rawUrl) {
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

app.post("/", async (req, res) => {
  const body = req.body || {};
  const { tool, arguments: args } = body;

  if (tool === "read_file") {
    const p = args && args.path;
    if (typeof p !== "string" || p.length === 0) {
      return res.json({ action: "block", reason: "invalid or missing path argument" });
    }
    const resolved = safeResolveWithinSandbox(p);
    if (!resolved) {
      return res.json({ action: "block", reason: "path escapes the sandbox root" });
    }
    try {
      const content = fs.readFileSync(resolved, "utf8");
      return res.json({ action: "allow", reason: "path resolves within sandbox root", result: { content } });
    } catch (e) {
      return res.json({
        action: "allow",
        reason: "path resolves within sandbox root",
        result: { content: "", error: e.code || "read_error" },
      });
    }
  }

  if (tool === "fetch_url") {
    const url = args && args.url;
    if (typeof url !== "string" || url.length === 0) {
      return res.json({ action: "block", reason: "invalid or missing url argument" });
    }
    const result = await safeFetch(url);
    if (result.blocked) {
      return res.json({ action: "block", reason: result.reason });
    }
    if (result.error) {
      return res.json({ action: "allow", reason: "host in allowlist", result: { content: "", error: result.message } });
    }
    return res.json({
      action: "allow",
      reason: "host in allowlist",
      result: { status: result.status, content: result.body },
    });
  }

  return res.json({ action: "block", reason: "unknown tool" });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  res.status(200).json({ action: "block", reason: "malformed request" });
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`guardrail listening on ${port}`);
});

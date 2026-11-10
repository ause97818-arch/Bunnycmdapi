// Vercel Serverless Function: secure proxy for the WhatsApp Pairing Code API.
// GET /api/connect?number=<phone_number>

const crypto = require("crypto");

// Set PROXY_API_KEY in Vercel Environment Variables (never hardcode it in the repo)
const API_KEY = process.env.PROXY_API_KEY || "bunnyxmdth3";

function keyIsValid(provided) {
  if (!API_KEY || typeof provided !== "string" || !provided) return false;
  const a = crypto.createHash("sha256").update(provided).digest();
  const b = crypto.createHash("sha256").update(API_KEY).digest();
  return crypto.timingSafeEqual(a, b); // constant-time compare
}

const BACKEND = (process.env.BACKEND_URL || "http://65.75.203.46:16420").replace(/\/+$/, "");
const TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS) || 25000;

// Node's fetch throws a generic "fetch failed"; the real reason (ECONNREFUSED, ETIMEDOUT, ...) lives in err.cause
function errCode(err) {
  return (err && err.cause && (err.cause.code || err.cause.name)) || (err && err.code) || "UNKNOWN";
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", process.env.ALLOWED_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
}

module.exports = async (req, res) => {
  setCors(res);
  res.setHeader("Cache-Control", "no-store");

  // CORS preflight
  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, OPTIONS");
    return res.status(405).json({ status: false, error: "Method not allowed." });
  }

  // --- API key check ---
  if (!API_KEY) {
    console.error("PROXY_API_KEY is not configured");
    return res.status(500).json({ status: false, error: "Server misconfigured." });
  }
  const rawKey = Array.isArray(req.query.key) ? req.query.key[0] : req.query.key;
  const providedKey = rawKey || req.headers["x-api-key"];
  if (!keyIsValid(providedKey)) {
    return res.status(401).json({ status: false, error: "Invalid or missing API key." });
  }

  // --- Input validation ---
  const raw = Array.isArray(req.query.number) ? req.query.number[0] : req.query.number;
  const number = typeof raw === "string" ? raw.replace(/[\s+\-()]/g, "") : "";

  // digits only, 7-15 chars (E.164 range, country code included)
  if (!/^\d{7,15}$/.test(number)) {
    return res.status(400).json({
      status: false,
      error: "Missing or invalid 'number' query parameter.",
    });
  }

  // --- Server-to-server fetch ---
  const url = new URL("/api/connect", BACKEND);
  url.searchParams.set("number", number);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    let upstream;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        upstream = await fetch(url, {
          method: "GET",
          headers: { Accept: "application/json, text/plain, */*" },
          signal: controller.signal,
        });
        break;
      } catch (e) {
        if (attempt === 2 || controller.signal.aborted) throw e;
        console.error("Upstream attempt 1 failed, retrying:", errCode(e));
        await sleep(600);
      }
    }

    const body = await upstream.text();
    const contentType = upstream.headers.get("content-type") || "application/json; charset=utf-8";

    res.setHeader("Content-Type", contentType);
    return res.status(upstream.status).send(body);
  } catch (err) {
    const timedOut = err && err.name === "AbortError";
    const code = errCode(err);
    console.error("Upstream error:", timedOut ? "timeout" : err && err.message, "| code:", code);
    // Never leak the backend IP/port in error responses
    return res.status(timedOut ? 504 : 502).json({
      status: false,
      error: timedOut ? "Upstream request timed out." : "Failed to reach upstream service.",
      code,
    });
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Tally Academy: secure Gemini proxy (Vercel Serverless Function)
 *
 * The Gemini API key lives ONLY in the Vercel environment variable GEMINI_API_KEY.
 * It is never sent to the browser, never logged, never stored in localStorage.
 *
 * Only a logged-in admin can use this endpoint: the browser sends its Firebase ID token
 * (Authorization: Bearer <token>) and the server verifies it with Firebase before calling Gemini.
 *
 * Environment variables (Vercel > Project > Settings > Environment Variables):
 *   GEMINI_API_KEY     (required)  your Google AI Studio key
 *   FIREBASE_API_KEY   (optional)  Firebase Web API key; defaults to the one already used by the site
 *   ALLOWED_ORIGINS    (optional)  extra comma separated site origins (e.g. https://www.mysite.com). Firebase Hosting
 *                                  domains tall-accademy.web.app / .firebaseapp.com are allowed by default.
 *   ADMIN_EMAILS       (optional)  comma separated allow-list of admin emails; empty = any Firebase user of this project
 *
 * Routes:
 *   GET  /api/gemini                      -> { configured: true|false }
 *   POST /api/gemini {action:"models"}    -> Google's model list
 *   POST /api/gemini {action:"generate", model, body:{contents, generationConfig?, systemInstruction?}}
 */
const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/";
const DEFAULT_FB_KEY = "AIzaSyBPL2jkRtciPKfbdmNs86YVnjpPkwjYaew"; // public Firebase web key, same as in index.html
const DEFAULT_ORIGINS = ["https://tall-accademy.web.app", "https://tall-accademy.firebaseapp.com"];
const MODEL_RE = /^gemini-[a-z0-9.\-]{1,60}$/i;
const MAX_BODY_BYTES = 4 * 1024 * 1024; // Vercel's request limit is 4.5 MB
const UPSTREAM_TIMEOUT_MS = 55000;
const TOKEN_TTL_MS = 5 * 60 * 1000;

const tokenCache = new Map(); // token -> expiry (ms)

function applyCors(req, res) {
  const origin = req.headers["origin"];
  const allowed = DEFAULT_ORIGINS.concat((process.env.ALLOWED_ORIGINS || "").split(",").map((x) => x.trim().replace(/\/$/, "")).filter(Boolean));
  res.setHeader("Vary", "Origin");
  if (origin && allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Max-Age", "86400");
    return true;
  }
  return !origin; // same-origin / non-browser requests have no Origin header
}

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(obj));
}
const fail = (res, status, message) => send(res, status, { error: { message } });

async function verifyAdmin(req) {
  const h = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return false;
  const token = m[1].trim();
  const hit = tokenCache.get(token);
  if (hit && hit > Date.now()) return true;
  const fbKey = process.env.FIREBASE_API_KEY || DEFAULT_FB_KEY;
  try {
    const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(fbKey), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken: token }),
    });
    if (!r.ok) return false;
    const d = await r.json();
    const u = d && d.users && d.users[0];
    if (!u) return false;
    const allow = (process.env.ADMIN_EMAILS || "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
    if (allow.length && !allow.includes(String(u.email || "").toLowerCase())) return false;
    if (tokenCache.size > 200) tokenCache.clear();
    tokenCache.set(token, Date.now() + TOKEN_TTL_MS);
    return true;
  } catch (e) {
    return false;
  }
}

async function readBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === "string") return JSON.parse(req.body);
    if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString("utf8"));
    return req.body;
  }
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY_BYTES) throw Object.assign(new Error("too large"), { code: 413 });
    chunks.push(c);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

async function callGoogle(url, init, key) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const r = await fetch(url, { ...init, signal: ac.signal, headers: { ...(init.headers || {}), "x-goog-api-key": key } });
    const text = await r.text();
    return { status: r.status, text };
  } finally {
    clearTimeout(t);
  }
}

module.exports = async function handler(req, res) {
  try {
    const originOk = applyCors(req, res);
    if (req.method === "OPTIONS") {
      res.statusCode = originOk ? 204 : 403;
      return res.end();
    }
    if (!originOk) return fail(res, 403, "Origin not allowed");
    if (req.method !== "GET" && req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return fail(res, 405, "Method not allowed");
    }
    if (!(await verifyAdmin(req))) return fail(res, 401, "Admin login required");

    const key = (process.env.GEMINI_API_KEY || "").trim();

    if (req.method === "GET") return send(res, 200, { configured: !!key });

    if (!key) return fail(res, 503, "GEMINI_API_KEY server par set nahi hai. Vercel Project, Settings, Environment Variables mein add karke Redeploy karo.");

    let payload;
    try {
      payload = await readBody(req);
    } catch (e) {
      return e && e.code === 413 ? fail(res, 413, "Request too large") : fail(res, 400, "Invalid JSON");
    }
    if (!payload || typeof payload !== "object") return fail(res, 400, "Invalid request");

    let out;
    if (payload.action === "models") {
      out = await callGoogle(GEMINI_BASE + "models?pageSize=1000", { method: "GET" }, key);
    } else if (payload.action === "generate") {
      const model = String(payload.model || "");
      if (!MODEL_RE.test(model)) return fail(res, 400, "Invalid model");
      const b = payload.body;
      if (!b || !Array.isArray(b.contents) || !b.contents.length) return fail(res, 400, "contents required");
      const body = { contents: b.contents };
      if (b.generationConfig && typeof b.generationConfig === "object") body.generationConfig = b.generationConfig;
      if (b.systemInstruction && typeof b.systemInstruction === "object") body.systemInstruction = b.systemInstruction;
      out = await callGoogle(
        GEMINI_BASE + "models/" + encodeURIComponent(model) + ":generateContent",
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
        key
      );
    } else {
      return fail(res, 400, "Unknown action");
    }

    res.statusCode = out.status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    return res.end(out.text);
  } catch (e) {
    if (e && e.name === "AbortError") return fail(res, 504, "Gemini ne time par jawab nahi diya");
    return fail(res, 502, "Gemini se connect nahi ho paya");
  }
};

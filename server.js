const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const DATA_DIR = path.join(ROOT, "data");
const STORE_FILE = path.join(DATA_DIR, "store.json");
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8;
const REMEMBERED_SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const OTP_TTL_MS = 1000 * 60 * 10;
const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_VISION_MODEL = process.env.GROQ_VISION_MODEL || "qwen/qwen3.6-27b";
const GROQ_SECRET_FILE = process.env.GROQ_SECRET_FILE || "/etc/secrets/tarpocket.key";
const ALLOWED_ORIGINS = String(process.env.FRONTEND_ORIGINS || "https://rapeepat1801-dev.github.io")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

fs.mkdirSync(DATA_DIR, { recursive: true });

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  const [salt, expectedHex] = String(stored || "").split(":");
  if (!salt || !expectedHex) return false;
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHex, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

function base32Encode(buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(value || "").toUpperCase().replace(/=+$/, "");
  let bits = 0;
  let current = 0;
  const output = [];
  for (const character of clean) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Invalid TOTP secret");
    current = (current << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function generateTotpCode(secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 1000 / 30);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", base32Decode(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 1000000).padStart(6, "0");
}

function verifyTotp(secret, input) {
  const code = String(input || "").replace(/\D/g, "");
  if (code.length !== 6) return false;
  const received = Buffer.from(code);
  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  for (const offset of [-1, 0, 1]) {
    const timestamp = (currentCounter + offset) * 30 * 1000;
    const expected = Buffer.from(generateTotpCode(secret, timestamp));
    if (crypto.timingSafeEqual(received, expected)) return true;
  }
  return false;
}

function makeOtpauthUri(user) {
  const issuer = "TAr POCKET";
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.email)}?secret=${user.totpSecret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function createSeedStore() {
  const adminPassword = process.env.TAFINX_ADMIN_PASSWORD || "Admin@12345";
  const now = new Date().toISOString();
  return {
    users: [{
      id: "usr_admin",
      name: "TAr POCKET Admin",
      email: "admin@tafinx.local",
      passwordHash: hashPassword(adminPassword),
      role: "admin",
      status: "active",
      emailVerified: true,
      totpSecret: generateTotpSecret(),
      totpEnabled: false,
      createdAt: now,
      lastLoginAt: null
    }]
  };
}

function loadStore() {
  if (!fs.existsSync(STORE_FILE)) {
    const initial = createSeedStore();
    fs.writeFileSync(STORE_FILE, JSON.stringify(initial, null, 2), "utf8");
    return initial;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_FILE, "utf8"));
    if (!parsed || !Array.isArray(parsed.users)) throw new Error("Invalid store");
    return parsed;
  } catch (error) {
    console.error("Unable to read data/store.json:", error.message);
    process.exitCode = 1;
    return createSeedStore();
  }
}

const store = loadStore();
const sessions = new Map();
const otpChallenges = new Map();

function saveStore() {
  const temp = `${STORE_FILE}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(store, null, 2), "utf8");
  fs.renameSync(temp, STORE_FILE);
}

function safeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status,
    emailVerified: Boolean(user.emailVerified),
    totpEnabled: Boolean(user.totpEnabled),
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null
  };
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...extraHeaders
  });
  res.end(body);
}

function sendError(res, statusCode, message) {
  sendJson(res, statusCode, { ok: false, message });
}

function parseCookies(req) {
  return String(req.headers.cookie || "").split(";").reduce((cookies, part) => {
    const index = part.indexOf("=");
    if (index === -1) return cookies;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    cookies[key] = decodeURIComponent(value);
    return cookies;
  }, {});
}

function getAuthToken(req) {
  const authorization = String(req.headers.authorization || "");
  const bearer = authorization.match(/^Bearer\s+(.+)$/i);
  if (bearer && bearer[1]) return bearer[1].trim();
  return parseCookies(req).tafinx_session;
}

function cookieHeader(token, maxAge) {
  const secure = IS_PRODUCTION ? "; Secure" : "";
  const sameSite = IS_PRODUCTION ? "None" : "Lax";
  return `tafinx_session=${encodeURIComponent(token)}; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=${maxAge}${secure}`;
}

function clearCookieHeader() {
  const secure = IS_PRODUCTION ? "; Secure" : "";
  const sameSite = IS_PRODUCTION ? "None" : "Lax";
  return `tafinx_session=; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=0${secure}`;
}

function createSession(user, remember = false) {
  const token = crypto.randomBytes(32).toString("hex");
  const ttl = remember ? REMEMBERED_SESSION_TTL_MS : SESSION_TTL_MS;
  sessions.set(token, { userId: user.id, expiresAt: Date.now() + ttl });
  return { token, maxAge: Math.floor(ttl / 1000) };
}

function getSessionUser(req) {
  const token = getAuthToken(req);
  const session = token && sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return store.users.find((user) => user.id === session.userId) || null;
}

function requireUser(req, res) {
  const user = getSessionUser(req);
  if (!user) {
    sendError(res, 401, "กรุณาเข้าสู่ระบบก่อน");
    return null;
  }
  if (user.status !== "active") {
    sendError(res, 403, "บัญชีนี้ถูกระงับการใช้งาน");
    return null;
  }
  return user;
}

function requireAdmin(req, res) {
  const user = requireUser(req, res);
  if (!user) return null;
  if (user.role !== "admin") {
    sendError(res, 403, "คุณไม่มีสิทธิ์เข้าถึงหลังบ้าน");
    return null;
  }
  return user;
}

function readJson(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > maxBytes) {
        reject(new Error("Payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch { reject(new Error("Invalid JSON")); }
    });
    req.on("error", reject);
  });
}

function createTotpChallenge(type, user) {
  const challengeId = crypto.randomBytes(24).toString("hex");
  if (!user.totpSecret) user.totpSecret = generateTotpSecret();
  otpChallenges.set(challengeId, {
    type,
    userId: user.id,
    email: user.email,
    secret: user.totpSecret,
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts: 0
  });
  const code = generateTotpCode(user.totpSecret);
  console.log(`[TAr POCKET TOTP] ${type} ${user.email}: ${code}`);
  return { challengeId, code };
}

function totpResponse(challengeId, code, user, includeSetup = false) {
  const response = { ok: true, challengeId, expiresIn: OTP_TTL_MS / 1000, method: "google-authenticator" };
  if (includeSetup) {
    response.setupKey = user.totpSecret;
    response.otpauthUri = makeOtpauthUri(user);
  }
  if (!IS_PRODUCTION) response.devCode = code;
  return response;
}

function findUserByEmail(email) {
  return store.users.find((user) => user.email === email);
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8 && password.length <= 128;
}

function parseGroqJson(content) {
  const text = String(content || "").trim();
  const withoutFence = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
  return JSON.parse(withoutFence);
}

function getGroqApiKey() {
  if (process.env.GROQ_API_KEY) return process.env.GROQ_API_KEY.trim();
  try {
    return fs.readFileSync(GROQ_SECRET_FILE, "utf8").trim();
  } catch {
    return "";
  }
}

async function readReceiptWithGroq(image) {
  const groqApiKey = getGroqApiKey();
  if (!groqApiKey) {
    const error = new Error("ยังไม่ได้ตั้งค่า GROQ_API_KEY บน Render");
    error.statusCode = 503;
    throw error;
  }

  const imageMatch = String(image || "").match(/^data:(image\/(?:jpeg|jpg|png|webp));base64,([A-Za-z0-9+/=]+)$/i);
  if (!imageMatch) {
    const error = new Error("รูปสลิปไม่ถูกต้องหรือไม่รองรับ");
    error.statusCode = 400;
    throw error;
  }
  if (String(image).length > 4.5 * 1024 * 1024) {
    const error = new Error("รูปสลิปใหญ่เกินไป กรุณาถ่ายใหม่หรือใช้ภาพที่เล็กลง");
    error.statusCode = 413;
    throw error;
  }

  const categoryNames = [
    "อาหาร", "เครื่องดื่ม", "คาเฟ่", "เดลิเวอรี", "ของใช้ประจำวัน", "อาหารสุขภาพ",
    "รถโดยสาร", "แท็กซี่ / รถรับจ้าง", "น้ำมัน", "ค่าจอดรถ", "ซ่อมรถ", "ค่าเช่ารถ",
    "หนังสือ", "อุปกรณ์การเรียน", "ค่าเรียน", "ค่าสอบ", "ซอฟต์แวร์", "ปริ้น / ถ่ายเอกสาร",
    "ค่าเช่าที่พัก", "ค่าไฟ", "ค่าน้ำ", "อินเทอร์เน็ต", "โทรศัพท์", "ของใช้ในบ้าน",
    "เสื้อผ้า", "รองเท้า", "กระเป๋า", "เครื่องสำอาง", "อุปกรณ์ไอที", "อุปกรณ์เสริม",
    "ดูหนัง", "เพลง", "เกม", "บริการสตรีมมิง", "คอนเสิร์ต", "ท่องเที่ยว",
    "ยา", "ค่ารักษา", "ทันตกรรม", "ฟิตเนส", "สุขภาพและความงาม",
    "อาหารสัตว์", "ค่ารักษา", "ของเล่น", "อุปกรณ์สัตว์เลี้ยง", "ดูแลสัตว์เลี้ยง",
    "ของขวัญ", "วันเกิด", "ดอกไม้", "ครอบครัว", "บริจาค", "งานสังคม",
    "ค่าธรรมเนียม", "ค่าธนาคาร", "ค่าบริการ", "การโอนเงิน"
  ];

  const prompt = [
    "Read this Thai or English receipt and extract fields for a personal finance transaction.",
    "Return ONLY a JSON object with exactly these keys:",
    "type (expense or income or null), amount (number or null), date (YYYY-MM-DD or null),",
    "merchant (string or null), description (string or null), category (one exact value from the allowed list or null),",
    "confidence (high, medium, or low).",
    "Use the final amount or grand total, not a subtotal, tax, change, phone number, or receipt number.",
    "Do not guess. If a value is unclear, return null. For Thai Buddhist years, convert to Gregorian.",
    "Thai month mapping: ม.ค./มกราคม=01, ก.พ./กุมภาพันธ์=02, มี.ค./มีนาคม=03, เม.ย./เมษายน=04, พ.ค./พฤษภาคม=05, มิ.ย./มิถุนายน=06, ก.ค./กรกฎาคม=07, ส.ค./สิงหาคม=08, ก.ย./กันยายน=09, ต.ค./ตุลาคม=10, พ.ย./พฤศจิกายน=11, ธ.ค./ธันวาคม=12. A two-digit Buddhist year such as 69 means 2569, so 9 ก.ย. 69 is 2026-09-09.",
    `Allowed categories: ${categoryNames.join(", ")}`
  ].join(" ");

  const response = await fetch(GROQ_API_URL, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${groqApiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: GROQ_VISION_MODEL,
      temperature: 0,
      max_completion_tokens: 1024,
      reasoning_effort: "none",
      reasoning_format: "hidden",
      response_format: { type: "json_object" },
      messages: [{
        role: "user",
        content: [
          { type: "text", text: prompt },
          { type: "image_url", image_url: { url: image } }
        ]
      }]
    }),
    signal: AbortSignal.timeout(45000)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error("Groq receipt reader error:", response.status, payload?.error?.message || "unknown error");
    const error = new Error("AI อ่านสลิปไม่สำเร็จ กรุณาลองภาพที่คมชัดขึ้น");
    error.statusCode = response.status === 429 ? 429 : 502;
    throw error;
  }

  const content = payload?.choices?.[0]?.message?.content;
  let result;
  try {
    result = parseGroqJson(content);
  } catch {
    const error = new Error("AI ส่งข้อมูลสลิปกลับมาไม่ถูกต้อง");
    error.statusCode = 502;
    throw error;
  }
  return {
    type: ["expense", "income"].includes(result?.type) ? result.type : null,
    amount: Number.isFinite(Number(result?.amount)) && Number(result.amount) > 0 ? Number(result.amount) : null,
    date: /^\d{4}-\d{2}-\d{2}$/.test(String(result?.date || "")) ? result.date : null,
    merchant: result?.merchant ? String(result.merchant).slice(0, 120) : null,
    description: result?.description ? String(result.description).slice(0, 200) : null,
    category: result?.category ? String(result.category).slice(0, 80) : null,
    confidence: ["high", "medium", "low"].includes(result?.confidence) ? result.confidence : "low"
  };
}

async function handleApi(req, res, pathname) {
  const origin = String(req.headers.origin || "");
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS");
    res.setHeader("Vary", "Origin");
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  if (req.method === "GET" && pathname === "/api/health") {
    return sendJson(res, 200, { ok: true, service: "ta-finx", timestamp: new Date().toISOString() });
  }

  if (req.method === "POST" && pathname === "/api/receipts/read") {
    if (!requireUser(req, res)) return;
    try {
      const body = await readJson(req, 5 * 1024 * 1024);
      const result = await readReceiptWithGroq(body.image);
      return sendJson(res, 200, { ok: true, result, model: GROQ_VISION_MODEL });
    } catch (error) {
      const statusCode = Number(error.statusCode) || (error.name === "TimeoutError" ? 504 : 500);
      return sendError(res, statusCode, error.message || "AI อ่านสลิปไม่สำเร็จ");
    }
  }

  if (req.method === "GET" && pathname === "/api/auth/me") {
    const user = getSessionUser(req);
    return sendJson(res, 200, { ok: true, user: safeUser(user) });
  }

  if (req.method === "POST" && pathname === "/api/auth/register") {
    const body = await readJson(req);
    const name = String(body.name || "").trim();
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    const passwordConfirm = String(body.passwordConfirm || "");
    if (name.length < 2 || name.length > 80) return sendError(res, 400, "กรุณากรอกชื่อ 2-80 ตัวอักษร");
    if (!isValidEmail(email)) return sendError(res, 400, "กรุณากรอกอีเมลให้ถูกต้อง");
    if (!validatePassword(password)) return sendError(res, 400, "รหัสผ่านต้องมี 8-128 ตัวอักษร");
    if (password !== passwordConfirm) return sendError(res, 400, "รหัสผ่านทั้งสองช่องไม่ตรงกัน");
    if (findUserByEmail(email)) return sendError(res, 409, "อีเมลนี้มีบัญชีอยู่แล้ว");
    const user = {
      id: `usr_${crypto.randomBytes(8).toString("hex")}`,
      name,
      email,
      passwordHash: hashPassword(password),
      role: "user",
      status: "active",
      emailVerified: false,
      totpSecret: generateTotpSecret(),
      totpEnabled: false,
      createdAt: new Date().toISOString(),
      lastLoginAt: null
    };
    store.users.push(user);
    saveStore();
    const challenge = createTotpChallenge("registration", user);
    saveStore();
    return sendJson(res, 201, totpResponse(challenge.challengeId, challenge.code, user, true));
  }

  if (req.method === "POST" && pathname === "/api/auth/login") {
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    const user = findUserByEmail(email);
    if (!user || !verifyPassword(password, user.passwordHash)) return sendError(res, 401, "อีเมลหรือรหัสผ่านไม่ถูกต้อง");
    if (user.status !== "active") return sendError(res, 403, "บัญชีนี้ถูกระงับการใช้งาน กรุณาติดต่อผู้ดูแลระบบ");
    if (!user.emailVerified) return sendError(res, 403, "กรุณาสมัครใหม่และยืนยันอีเมลให้เสร็จก่อนเข้าสู่ระบบ");
    if (!user.totpSecret) user.totpSecret = generateTotpSecret();
    saveStore();
    const challenge = createTotpChallenge("login", user);
    const response = totpResponse(challenge.challengeId, challenge.code, user, !user.totpEnabled);
    response.remember = Boolean(body.remember);
    return sendJson(res, 200, response);
  }

  if (req.method === "POST" && (pathname === "/api/auth/verify-registration" || pathname === "/api/auth/verify-login")) {
    const body = await readJson(req);
    const challenge = otpChallenges.get(String(body.challengeId || ""));
    if (!challenge || challenge.type !== (pathname.endsWith("registration") ? "registration" : "login")) return sendError(res, 400, "รหัสยืนยันหมดอายุหรือไม่ถูกต้อง");
    if (challenge.expiresAt <= Date.now()) {
      otpChallenges.delete(String(body.challengeId));
      return sendError(res, 400, "รหัสยืนยันหมดอายุแล้ว กรุณาขอรหัสใหม่");
    }
    challenge.attempts += 1;
    if (challenge.attempts > 5) {
      otpChallenges.delete(String(body.challengeId));
      return sendError(res, 429, "กรอกรหัสผิดเกินจำนวนครั้งที่กำหนด กรุณาเริ่มใหม่");
    }
    if (!verifyTotp(challenge.secret, body.code)) return sendError(res, 400, "รหัสจาก Google Authenticator ไม่ถูกต้องหรือหมดอายุ");
    const user = store.users.find((item) => item.id === challenge.userId);
    otpChallenges.delete(String(body.challengeId));
    if (!user) return sendError(res, 404, "ไม่พบบัญชีผู้ใช้");
    user.emailVerified = true;
    user.totpEnabled = true;
    user.lastLoginAt = new Date().toISOString();
    saveStore();
    const session = createSession(user, Boolean(body.remember));
    return sendJson(res, 200, {
      ok: true,
      user: safeUser(user),
      token: session.token,
      expiresIn: session.maxAge
    }, { "Set-Cookie": cookieHeader(session.token, session.maxAge) });
  }

  if (req.method === "POST" && pathname === "/api/auth/resend-otp") {
    const body = await readJson(req);
    const existing = otpChallenges.get(String(body.challengeId || ""));
    if (!existing) return sendError(res, 400, "ไม่พบคำขอยืนยัน กรุณาเริ่มใหม่");
    const user = store.users.find((item) => item.id === existing.userId);
    if (!user) return sendError(res, 404, "ไม่พบบัญชีผู้ใช้");
    const challenge = createTotpChallenge(existing.type, user);
    otpChallenges.delete(String(body.challengeId));
    return sendJson(res, 200, totpResponse(challenge.challengeId, challenge.code, user, !user.totpEnabled));
  }

  if (req.method === "POST" && pathname === "/api/auth/logout") {
    const token = getAuthToken(req);
    if (token) sessions.delete(token);
    return sendJson(res, 200, { ok: true }, { "Set-Cookie": clearCookieHeader() });
  }

  if (req.method === "GET" && pathname === "/api/admin/stats") {
    if (!requireAdmin(req, res)) return;
    const users = store.users;
    return sendJson(res, 200, {
      ok: true,
      stats: {
        total: users.length,
        verified: users.filter((user) => user.emailVerified).length,
        suspended: users.filter((user) => user.status === "suspended").length
      }
    });
  }

  if (req.method === "GET" && pathname === "/api/admin/users") {
    if (!requireAdmin(req, res)) return;
    return sendJson(res, 200, { ok: true, users: store.users.map(safeUser) });
  }

  const userMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
  if (userMatch && req.method === "PATCH") {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const target = store.users.find((user) => user.id === decodeURIComponent(userMatch[1]));
    if (!target) return sendError(res, 404, "ไม่พบสมาชิก");
    if (target.id === admin.id) return sendError(res, 400, "ไม่สามารถเปลี่ยนสถานะบัญชีของตัวเองได้");
    const body = await readJson(req);
    if (body.status && !["active", "suspended"].includes(body.status)) return sendError(res, 400, "สถานะไม่ถูกต้อง");
    if (body.role && !["user", "admin"].includes(body.role)) return sendError(res, 400, "สิทธิ์ไม่ถูกต้อง");
    if (body.status) target.status = body.status;
    if (body.role) target.role = body.role;
    saveStore();
    return sendJson(res, 200, { ok: true, user: safeUser(target) });
  }

  return sendError(res, 404, "ไม่พบ API ที่ร้องขอ");
}

function serveStatic(req, res, pathname) {
  let relative = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  try { relative = decodeURIComponent(relative); } catch { return sendError(res, 400, "Invalid path"); }
  const filePath = path.resolve(PUBLIC_DIR, relative);
  if (!filePath.startsWith(`${PUBLIC_DIR}${path.sep}`) && filePath !== PUBLIC_DIR) return sendError(res, 403, "Forbidden");
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return serveStatic(req, res, "/");
  const contentTypes = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8" };
  res.writeHead(200, { "Content-Type": contentTypes[path.extname(filePath)] || "application/octet-stream", "Cache-Control": "no-store" });
  fs.createReadStream(filePath).pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) return await handleApi(req, res, url.pathname);
    if (req.method !== "GET" && req.method !== "HEAD") return sendError(res, 405, "Method not allowed");
    return serveStatic(req, res, url.pathname);
  } catch (error) {
    console.error(error);
    if (!res.headersSent) sendError(res, 500, "เกิดข้อผิดพลาดในเซิร์ฟเวอร์");
  }
});

server.listen(PORT, () => {
  console.log(`TAr POCKET is running at http://localhost:${PORT}`);
  console.log(`Admin demo: admin@tafinx.local / ${process.env.TAFINX_ADMIN_PASSWORD || "Admin@12345"}`);
  if (IS_PRODUCTION) console.log("Production mode: TOTP secrets are kept server-side; use HTTPS and add recovery-code support before deployment.");
});


// server.js — Express-прокси к Groq + PostgreSQL для кодов доступа
import "dotenv/config";
import express from "express";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";

// ====== БД ======
if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL не задан. Локально создайте .env, на Render подключите PostgreSQL.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_codes (
      code           TEXT PRIMARY KEY,
      expires_at     BIGINT,
      requests_left  INTEGER NOT NULL DEFAULT 0,
      created_at     BIGINT NOT NULL
    );
  `);
  // Тестовый код TESTME — создаём, если нет
  await pool.query(`
    INSERT INTO access_codes (code, expires_at, requests_left, created_at)
    VALUES ('TESTME', 9999999999999, 100000, $1)
    ON CONFLICT (code) DO NOTHING;
  `, [Date.now()]);
  console.log("✅ БД готова: таблица access_codes, тестовый код TESTME");
}

// ====== App ======
const app = express();
app.use(express.json({ limit: "1mb" }));

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "*")
  .split(",").map(s => s.trim()).filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  if (allowedOrigins.includes("*")) res.setHeader("Access-Control-Allow-Origin", "*");
  else if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.static(path.join(__dirname, "public")));

// ====== Хелперы ======
async function getCode(code) {
  const key = String(code || "").trim().toUpperCase();
  if (!key) return null;
  const { rows } = await pool.query(
    "SELECT code, expires_at, requests_left FROM access_codes WHERE code = $1",
    [key]
  );
  return rows[0] || null;
}

function isExpired(rec) {
  return rec.expires_at && Date.now() > Number(rec.expires_at);
}
function isExhausted(rec) {
  return typeof rec.requests_left === "number" && rec.requests_left <= 0;
}

async function decrementRequests(code) {
  await pool.query(
    "UPDATE access_codes SET requests_left = requests_left - 1 WHERE code = $1 AND requests_left > 0",
    [code]
  );
}

function adminAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: "Нет доступа" });
  }
  next();
}

// ====== API ======
app.post("/api/check-code", async (req, res) => {
  try {
    const { code } = req.body || {};
    const rec = await getCode(code);
    if (!rec) return res.status(401).json({ error: "Код не найден" });
    if (isExpired(rec)) return res.status(403).json({ error: "Код истёк" });
    if (isExhausted(rec)) return res.status(403).json({ error: "Лимит запросов исчерпан" });
    return res.json({ ok: true, requests_left: rec.requests_left, expires_at: rec.expires_at });
  } catch (e) {
    console.error("check-code:", e);
    return res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/chat", async (req, res) => {
  try {
    const { code, model, messages, temperature } = req.body || {};
    if (!code || !model || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: "Нужны code, model и messages" });
    }

    const rec = await getCode(code);
    if (!rec) return res.status(401).json({ error: "Код не найден" });
    if (isExpired(rec)) return res.status(403).json({ error: "Код истёк" });
    if (isExhausted(rec)) return res.status(403).json({ error: "Лимит запросов исчерпан" });

    if (!process.env.GROQ_API_KEY) {
      return res.status(500).json({ error: "На сервере не настроен GROQ_API_KEY" });
    }

    const groqRes = await fetch(GROQ_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.GROQ_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages,
        temperature: typeof temperature === "number" ? temperature : 0.5,
      }),
    });

    const data = await groqRes.json();
    if (groqRes.ok && typeof rec.requests_left === "number") {
      await decrementRequests(rec.code);
    }
    return res.status(groqRes.status).json(data);
  } catch (e) {
    console.error("chat:", e);
    return res.status(502).json({ error: "Ошибка сети до Groq: " + e.message });
  }
});

// ====== Админка ======
app.post("/api/admin/create-code", adminAuth, async (req, res) => {
  try {
    const { days = 30, requests_left = 1000, code } = req.body || {};
    const newCode = String(code || crypto.randomBytes(6).toString("hex")).toUpperCase();
    const expiresAt = Date.now() + Number(days) * 24 * 60 * 60 * 1000;

    await pool.query(
      `INSERT INTO access_codes (code, expires_at, requests_left, created_at)
       VALUES ($1, $2, $3, $4)`,
      [newCode, expiresAt, Number(requests_left), Date.now()]
    );
    return res.json({ ok: true, code: newCode, expires_at: expiresAt, requests_left: Number(requests_left) });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Такой код уже есть" });
    console.error("create-code:", e);
    return res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/api/admin/list-codes", adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT code, expires_at, requests_left, created_at FROM access_codes ORDER BY created_at DESC"
    );
    const list = rows.map(r => ({
      code: r.code,
      expires_at: Number(r.expires_at),
      requests_left: r.requests_left,
      created_at: Number(r.created_at),
      expired: r.expires_at ? Date.now() > Number(r.expires_at) : false,
    }));
    return res.json({ count: list.length, codes: list });
  } catch (e) {
    console.error("list-codes:", e);
    return res.status(500).json({ error: "Ошибка сервера" });
  }
});

// ====== SPA-фолбэк ======
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ====== Старт ======
const PORT = process.env.PORT || 3000;
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`✅ Сервер: http://localhost:${PORT}`);
      console.log(`   GROQ_API_KEY: ${process.env.GROQ_API_KEY ? "задан" : "❌ НЕ ЗАДАН"}`);
      console.log(`   ADMIN_TOKEN:  ${process.env.ADMIN_TOKEN ? "задан" : "❌ НЕ ЗАДАН"}`);
      console.log(`   DATABASE_URL: задан`);
    });
  })
  .catch(err => {
    console.error("❌ Не удалось инициализировать БД:", err);
    process.exit(1);
  });

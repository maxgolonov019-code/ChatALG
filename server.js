// server.js — Express-прокси к Groq с проверкой кодов доступа
import "dotenv/config";
import express from "express";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CODES_FILE = path.join(__dirname, "access-codes.json");
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";

const app = express();
app.use(express.json({ limit: "1mb" }));

// CORS
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  if (allowedOrigins.includes("*")) {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Статика
app.use(express.static(path.join(__dirname, "public")));

// ====== Работа с кодами доступа ======
async function loadCodes() {
  try {
    const raw = await fs.readFile(CODES_FILE, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === "ENOENT") return {};
    throw e;
  }
}
async function saveCodes(codes) {
  await fs.writeFile(CODES_FILE, JSON.stringify(codes, null, 2), "utf8");
}

// ====== API: проверка кода ======
app.post("/api/check-code", async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: "Не указан код" });

  const codes = await loadCodes();
  const rec = codes[code.trim().toUpperCase()];
  if (!rec) return res.status(401).json({ error: "Код не найден" });
  if (rec.expires_at && Date.now() > rec.expires_at) return res.status(403).json({ error: "Код истёк" });
  if (typeof rec.requests_left === "number" && rec.requests_left <= 0) {
    return res.status(403).json({ error: "Лимит запросов исчерпан" });
  }
  return res.json({ ok: true, requests_left: rec.requests_left, expires_at: rec.expires_at });
});

// ====== API: прокси к Groq ======
app.post("/api/chat", async (req, res) => {
  const { code, model, messages, temperature } = req.body || {};
  if (!code || !model || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: "Нужны code, model и messages" });
  }

  const key = code.trim().toUpperCase();
  const codes = await loadCodes();
  const rec = codes[key];

  if (!rec) return res.status(401).json({ error: "Код не найден" });
  if (rec.expires_at && Date.now() > rec.expires_at) return res.status(403).json({ error: "Код истёк" });
  if (typeof rec.requests_left === "number" && rec.requests_left <= 0) {
    return res.status(403).json({ error: "Лимит запросов исчерпан" });
  }

  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: "На сервере не настроен GROQ_API_KEY" });
  }

  try {
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
      codes[key].requests_left = rec.requests_left - 1;
      await saveCodes(codes);
    }

    return res.status(groqRes.status).json(data);
  } catch (e) {
    return res.status(502).json({ error: "Ошибка сети до Groq: " + e.message });
  }
});

// ====== Админка: создать код (защищена ADMIN_TOKEN) ======
app.post("/api/admin/create-code", async (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: "Нет доступа" });
  }

  const { days = 30, requests_left = 1000, code } = req.body || {};
  const newCode = (code || crypto.randomBytes(6).toString("hex")).toUpperCase();
  const codes = await loadCodes();

  if (codes[newCode]) return res.status(409).json({ error: "Такой код уже есть" });

  codes[newCode] = {
    expires_at: Date.now() + days * 24 * 60 * 60 * 1000,
    requests_left: Number(requests_left),
    created_at: Date.now(),
  };
  await saveCodes(codes);
  return res.json({ ok: true, code: newCode, ...codes[newCode] });
});

// ====== Админка: список кодов ======
app.get("/api/admin/list-codes", async (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: "Нет доступа" });
  }
  const codes = await loadCodes();
  const list = Object.entries(codes).map(([code, rec]) => ({
    code, ...rec,
    expired: rec.expires_at ? Date.now() > rec.expires_at : false,
  }));
  return res.json({ count: list.length, codes: list });
});

// ====== SPA-фолбэк ======
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Сервер запущен: http://localhost:${PORT}`);
  console.log(`   Ключ Groq: ${process.env.GROQ_API_KEY ? "задан" : "❌ НЕ ЗАДАН"}`);
  console.log(`   Admin token: ${process.env.ADMIN_TOKEN ? "задан" : "❌ НЕ ЗАДАН (админка недоступна)"}`);
});

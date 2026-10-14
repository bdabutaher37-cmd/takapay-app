
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { createClient } from "@supabase/supabase-js";
import { createHmac, timingSafeEqual } from "node:crypto";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10kb" }));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

const { SUPABASE_URL, SUPABASE_SECRET_KEY, TELEGRAM_BOT_TOKEN } =
  process.env;

const supabase =
  SUPABASE_URL && SUPABASE_SECRET_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      })
    : null;

function requireConfig(req, res, next) {
  if (!supabase || !TELEGRAM_BOT_TOKEN) {
    return res.status(503).json({
      error: "server_not_configured"
    });
  }
  next();
}

function requireTelegram(req, res, next) {
  try {
    const initData = req.get("X-Telegram-Init-Data");

    if (!initData || initData.length > 8192) {
      return res.status(401).json({
        error: "telegram_auth_required"
      });
    }

    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
      return res.status(401).json({ error: "invalid_auth" });
    }

    params.delete("hash");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = createHmac("sha256", "WebAppData")
      .update(TELEGRAM_BOT_TOKEN)
      .digest();

    const calculatedHash = createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest();

    const suppliedHash = Buffer.from(receivedHash, "hex");

    if (
      suppliedHash.length !== calculatedHash.length ||
      !timingSafeEqual(suppliedHash, calculatedHash)
    ) {
      return res.status(401).json({ error: "invalid_auth" });
    }

    const authDate = Number(params.get("auth_date"));
    const now = Math.floor(Date.now() / 1000);

    if (
      !Number.isFinite(authDate) ||
      authDate > now + 60 ||
      now - authDate > 86400
    ) {
      return res.status(401).json({ error: "auth_expired" });
    }

    const user = JSON.parse(params.get("user") || "null");

    if (!user || !Number.isSafeInteger(user.id) || user.id <= 0) {
      return res.status(401).json({ error: "invalid_user" });
    }

    req.telegramUser = {
      id: String(user.id),
      username:
        typeof user.username === "string"
          ? user.username.slice(0, 64)
          : null
    };

    next();
  } catch {
    return res.status(401).json({ error: "invalid_auth" });
  }
}

app.get("/", (req, res) => {
  res.json({ app: "TakaPay Backend", status: "running" });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/api/db-status", requireConfig, async (req, res) => {
  const { error } = await supabase
    .from("profiles")
    .select("id", { head: true, count: "exact" });

  if (error) {
    console.error("Database check failed:", error.message);
    return res.status(503).json({ status: "connection_error" });
  }

  res.json({ status: "connected" });
});

// Verify Telegram and create or update the profile.
app.post(
  "/api/auth",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    const { id, username } = req.telegramUser;

    const { data, error } = await supabase
      .from("profiles")
      .upsert(
        { telegram_id: id, username },
        { onConflict: "telegram_id" }
      )
      .select("telegram_id, username, balance, created_at")
      .single();

    if (error) {
      console.error("Profile error:", error.message);
      return res.status(500).json({ error: "profile_failed" });
    }

    res.json({ profile: data });
  }
);

// Return the authenticated user's profile.
app.get(
  "/api/me",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    const { data, error } = await supabase
      .from("profiles")
      .select("telegram_id, username, balance, created_at")
      .eq("telegram_id", req.telegramUser.id)
      .maybeSingle();

    if (error) {
      return res.status(500).json({ error: "profile_failed" });
    }

    if (!data) {
      return res.status(404).json({ error: "profile_not_found" });
    }

    res.json({ profile: data });
  }
);

// Return transaction history for the authenticated user.
app.get(
  "/api/transactions",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    const { data, error } = await supabase
      .from("transactions")
      .select("id, type, amount, status, description, created_at")
      .eq("telegram_id", req.telegramUser.id)
      .order("created_at", { ascending: false })
      .limit(50);

    if (error) {
      console.error("Transactions error:", error.message);
      return res.status(500).json({
        error: "transactions_failed"
      });
    }

    res.json({ transactions: data });
  }
);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`TakaPay backend listening on port ${PORT}`);
});

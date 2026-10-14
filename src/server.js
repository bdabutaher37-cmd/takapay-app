
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { createClient } from "@supabase/supabase-js";
import { createHmac, timingSafeEqual } from "node:crypto";

const app = express();
const PORT = process.env.PORT || 3000;

// Read and normalize environment variables.
const rawUrl = (process.env.SUPABASE_URL || "").trim();
const SUPABASE_SECRET_KEY =
  (process.env.SUPABASE_SECRET_KEY || "").trim();
const TELEGRAM_BOT_TOKEN =
  (process.env.TELEGRAM_BOT_TOKEN || "").trim();

// Accept a project URL even if /rest/v1 was accidentally appended.
const SUPABASE_URL = rawUrl
  .replace(/\/rest\/v1\/?$/i, "")
  .replace(/\/+$/, "");

let supabase = null;
let urlValid = false;

try {
  if (SUPABASE_URL) {
    const parsed = new URL(SUPABASE_URL);

    urlValid =
      ["https:", "http:"].includes(parsed.protocol) &&
      Boolean(parsed.hostname) &&
      !parsed.username &&
      !parsed.password;

    if (urlValid && SUPABASE_SECRET_KEY) {
      supabase = createClient(
        SUPABASE_URL,
        SUPABASE_SECRET_KEY,
        {
          auth: {
            persistSession: false,
            autoRefreshToken: false
          }
        }
      );
    }
  }
} catch (error) {
  console.error("Supabase configuration could not be initialized.");
}

console.log("TakaPay configuration:", {
  supabaseUrlPresent: Boolean(rawUrl),
  supabaseUrlValid: urlValid,
  supabaseSecretKeyPresent: Boolean(SUPABASE_SECRET_KEY),
  telegramBotTokenPresent: Boolean(TELEGRAM_BOT_TOKEN),
  supabaseClientCreated: Boolean(supabase)
});

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10kb" }));

app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false
  })
);

function requireConfig(req, res, next) {
  if (!supabase || !TELEGRAM_BOT_TOKEN) {
    return res.status(503).json({
      error: "server_not_configured",
      details: {
        supabaseUrlValid: urlValid,
        supabaseSecretKeyPresent: Boolean(SUPABASE_SECRET_KEY),
        telegramBotTokenPresent: Boolean(TELEGRAM_BOT_TOKEN)
      }
    });
  }

  next();
}

// Verify Telegram Mini App initData.
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

    const secret = createHmac("sha256", "WebAppData")
      .update(TELEGRAM_BOT_TOKEN)
      .digest();

    const calculatedHash = createHmac("sha256", secret)
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
  res.json({
    app: "TakaPay Backend",
    status: "running"
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Check database connectivity.
app.get("/api/db-status", requireConfig, async (req, res) => {
  try {
    const { error } = await supabase
      .from("profiles")
      .select("id", { head: true, count: "exact" });

    if (error) {
      console.error("Database check failed:", error.message);
      return res.status(503).json({
        status: "connection_error"
      });
    }

    return res.json({ status: "connected" });
  } catch (error) {
    console.error("Database check failed.");
    return res.status(503).json({
      status: "connection_error"
    });
  }
});

// Authenticate Telegram user and create/update their profile.
app.post(
  "/api/auth",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
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
        console.error("Profile operation failed:", error.message);
        return res.status(500).json({
          error: "profile_failed"
        });
      }

      return res.json({ profile: data });
    } catch {
      return res.status(500).json({
        error: "profile_failed"
      });
    }
  }
);

// Get the authenticated user's profile.
app.get(
  "/api/me",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("profiles")
        .select("telegram_id, username, balance, created_at")
        .eq("telegram_id", req.telegramUser.id)
        .maybeSingle();

      if (error) {
        return res.status(500).json({
          error: "profile_failed"
        });
      }

      if (!data) {
        return res.status(404).json({
          error: "profile_not_found"
        });
      }

      return res.json({ profile: data });
    } catch {
      return res.status(500).json({
        error: "profile_failed"
      });
    }
  }
);

// Get the user's recent transactions.
app.get(
  "/api/transactions",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("transactions")
        .select("id, type, amount, status, description, created_at")
        .eq("telegram_id", req.telegramUser.id)
        .order("created_at", { ascending: false })
        .limit(50);

      if (error) {
        console.error("Transactions query failed:", error.message);
        return res.status(500).json({
          error: "transactions_failed"
        });
      }

      return res.json({ transactions: data });
    } catch {
      return res.status(500).json({
        error: "transactions_failed"
      });
    }
  }
);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`TakaPay backend listening on port ${PORT}`);
});

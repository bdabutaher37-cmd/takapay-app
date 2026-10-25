
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { createClient } from "@supabase/supabase-js";

import {
  createHmac,
  timingSafeEqual,
  randomUUID
} from "node:crypto";

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const app = express();
app.use(express.json());
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3000;

const __dirname = dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = resolve(__dirname, "../index.html");

const rawUrl = (process.env.SUPABASE_URL || "").trim();
const SUPABASE_SECRET_KEY =
  (process.env.SUPABASE_SECRET_KEY || "").trim();
const TELEGRAM_BOT_TOKEN =
  (process.env.TELEGRAM_BOT_TOKEN || "").trim();

const POSTBACK_SECRET =
  (process.env.POSTBACK_SECRET || "").trim();


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
} catch {
  console.error("Supabase configuration could not be initialized.");
}

console.log("TakaPay configuration:", {
  supabaseUrlPresent: Boolean(rawUrl),
  supabaseUrlValid: urlValid,
  supabaseSecretKeyPresent: Boolean(SUPABASE_SECRET_KEY),
  telegramBotTokenPresent: Boolean(TELEGRAM_BOT_TOKEN),
  supabaseClientCreated: Boolean(supabase)
});

// Middleware
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

// Server configuration check
function requireConfig(req, res, next) {
  if (!supabase || !TELEGRAM_BOT_TOKEN) {
    return res.status(503).json({
      error: "server_not_configured"
    });
  }

  next();
}

// Verify Telegram Mini App authentication
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

    if (
      !receivedHash ||
      !/^[a-f0-9]{64}$/i.test(receivedHash)
    ) {
      return res.status(401).json({
        error: "invalid_auth"
      });
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
      return res.status(401).json({
        error: "invalid_auth"
      });
    }

    const authDate = Number(params.get("auth_date"));
    const now = Math.floor(Date.now() / 1000);

    if (
      !Number.isFinite(authDate) ||
      authDate > now + 60 ||
      now - authDate > 86400
    ) {
      return res.status(401).json({
        error: "auth_expired"
      });
    }

    const user = JSON.parse(params.get("user") || "null");

    if (
      !user ||
      !Number.isSafeInteger(user.id) ||
      user.id <= 0
    ) {
      return res.status(401).json({
        error: "invalid_user"
      });
    }


req.telegramUser = {
  id: String(user.id),
  username:
    typeof user.username === "string"
      ? user.username.slice(0, 64)
      : null,
  first_name:
    typeof user.first_name === "string"
      ? user.first_name.slice(0, 128)
      : "",
  last_name:
    typeof user.last_name === "string"
      ? user.last_name.slice(0, 128)
      : ""
};


    next();
  } catch {
    return res.status(401).json({
      error: "invalid_auth"
    });
  }
}

 // Verify membership in the withdrawal updates channel
async function isMemberOfWithdrawChannel(telegramId) {
  const url = new URL(
    `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getChatMember`
  );

  url.searchParams.set("chat_id", "@TakaPayWithdrawUpdates");
  url.searchParams.set("user_id", telegramId);

  const response = await fetch(url);
  const result = await response.json();

  if (!response.ok || !result.ok || !result.result) {
    throw new Error("channel_membership_check_failed");
  }

  const member = result.result;

  return (
    ["creator", "administrator", "member"].includes(member.status) ||
    (member.status === "restricted" && member.is_member === true)
  );
}

// Frontend
app.get("/", (req, res) => {
  res.sendFile(INDEX_HTML, (error) => {
    if (error && !res.headersSent) {
      res.status(500).send(
        "TakaPay frontend could not be loaded. Check index.html."
      );
    }
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Database connection check
app.get("/api/db-status", requireConfig, async (req, res) => {
  try {
    const { error } = await supabase
      .from("profiles")
      .select("id", {
        head: true,
        count: "exact"
      });

    if (error) {
      console.error("Database check failed:", error.message);

      return res.status(503).json({
        status: "connection_error"
      });
    }

    return res.json({
      status: "connected"
    });
  } catch {
    return res.status(503).json({
      status: "connection_error"
    });
  }
});

// Authenticate Telegram user and create/update profile
app.post(
  "/api/auth",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { id, username, first_name, last_name } = req.telegramUser;
const fullName = [first_name, last_name]
  .filter(Boolean)
  .join(" ");
      const { data, error } = await supabase
        .from("profiles")
        .upsert(
{
  telegram_id: id,
username: username || null,
full_name: fullName || username || "Telegram User"
},
          {
            onConflict: "telegram_id"
          }
        )
        .select("telegram_id, username, full_name, balance, created_at")   .single();

      if (error) {
        console.error("Profile operation failed:", error.message);

        return res.status(500).json({
          error: "profile_failed"
        });
      }

      return res.json({
        profile: data
      });
    } catch {
      return res.status(500).json({
        error: "profile_failed"
      });
    }
  }
);

/* Get authenticated user's profile */
app.get(
  "/api/me",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("profiles")
        .select("telegram_id, username, balance, recharge_balance, created_at, active_plan")
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

      return res.json({
        profile: data
      });
    } catch {
      return res.status(500).json({
        error: "profile_failed"
      });
    }
  }
);

/* Admin API: Get total member count */
app.get(
  "/api/admin/members/count",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data: admin, error: adminError } = await supabase
        .from("takapay_admins")
        .select("telegram_id")
        .eq("telegram_id", req.telegramUser.id)
        .maybeSingle();

      if (adminError || !admin) {
        return res.status(403).json({
          error: "admin_only"
        });
      }

      const { count, error } = await supabase
        .from("profiles")
        .select("id", { count: "exact", head: true });

      if (error) {
        return res.status(500).json({
          error: "member_count_failed"
        });
      }

      return res.json({
        success: true,
        total_members: count ?? 0
      });
    } catch {
      return res.status(500).json({
        error: "member_count_failed"
      });
    }
  }
);


// Get authenticated user's recent transactions
app.get(
  "/api/transactions",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("transactions")
        .select(
          "id, type, amount, status, description, created_at"
        )
        .eq("telegram_id", req.telegramUser.id)
        .order("created_at", {
          ascending: false
        })
        .limit(50);

      if (error) {
        console.error("Transactions query failed:", error.message);

        return res.status(500).json({
          error: "transactions_failed"
        });
      }

      return res.json({
        transactions: data
      });
    } catch {
      return res.status(500).json({
        error: "transactions_failed"
      });
    }
  }
);

// Daily Check-in: claim reward once per Bangladesh calendar day
app.post(
  "/api/tasks/daily-checkin",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data, error } = await supabase.rpc(
        "claim_daily_checkin",
        {
          p_telegram_id: req.telegramUser.id
        }
      );

      if (error) {
        console.error(
          "Daily check-in failed:",
          error.message
        );

        return res.status(500).json({
          error: "checkin_failed"
        });
      }

      if (data?.success === true) {
        return res.json({
          success: true,
          reward: data.reward
        });
      }

      if (data?.error === "already_claimed") {
        return res.status(409).json({
          error: "already_claimed"
        });
      }

      if (data?.error === "profile_not_found") {
        return res.status(404).json({
          error: "profile_not_found"
        });
      }

      return res.status(500).json({
        error: "checkin_failed"
      });
    } catch {
      return res.status(500).json({
        error: "checkin_failed"
      });
    }
  }
);

app.post(
  "/api/tasks/channel-join",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const telegramId = String(req.telegramUser.id);

      const response = await fetch(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=@takapay_official&user_id=${telegramId}`
      );

      const result = await response.json();

      if (!response.ok || !result.ok) {
        console.error("Channel membership check failed");
        return res.status(503).json({
          error: "membership_check_failed"
        });
      }

      const member = result.result;
      const joined =
        member.status === "creator" ||
        member.status === "administrator" ||
        member.status === "member" ||
        (member.status === "restricted" && member.is_member === true);

      if (!joined) {
        return res.status(403).json({
          error: "channel_not_joined"
        });
      }

      const { data, error } = await supabase.rpc(
        "claim_channel_join_reward",
        { p_telegram_id: telegramId }
      );

      if (error) {
        console.error("Channel reward failed:", error.message);
        return res.status(500).json({ error: "reward_failed" });
      }

      if (data?.success === true) {
        return res.json({ success: true, reward: 20 });
      }

      if (data?.error === "already_claimed") {
        return res.status(409).json({ error: "already_claimed" });
      }

      if (data?.error === "profile_not_found") {
        return res.status(404).json({ error: "profile_not_found" });
      }

      return res.status(500).json({ error: "reward_failed" });
    } catch (error) {
      console.error("Channel task failed:", error.message);
      return res.status(500).json({ error: "channel_task_failed" });
    }
  }
);

/* Daily Check-in: Claim ৳10 once per Dhaka day */
app.post(
  "/api/tasks/daily-checkin",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const telegramId = String(req.telegramUser.id);

      const { data, error } = await supabase.rpc(
        "claim_daily_checkin",
        { p_telegram_id: telegramId }
      );

      if (error) {
        console.error("Daily check-in failed:", error.message);
        return res.status(500).json({
          error: "daily_checkin_failed"
        });
      }

      if (data?.success === true) {
        return res.json({
          success: true,
          reward: 10
        });
      }

      if (data?.error === "already_claimed") {
        return res.status(409).json({
          error: "already_claimed"
        });
      }

      if (data?.error === "profile_not_found") {
        return res.status(404).json({
          error: "profile_not_found"
        });
      }

      return res.status(500).json({
        error: "daily_checkin_failed"
      });
    } catch (error) {
      console.error("Daily check-in error:", error.message);
      return res.status(500).json({
        error: "daily_checkin_failed"
      });
    }
  }
);



app.post("/api/monetag/start", requireConfig, requireTelegram, async (req, res) => {
  try {
    const ymid = randomUUID();
    const telegramId = String(req.telegramUser.id);
    const zoneId = "12005665";

    // Get the user's current plan from Supabase
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("active_plan, plan_expires_at")
      .eq("telegram_id", telegramId)
      .maybeSingle();

    if (profileError || !profile) {
      console.error("Monetag profile lookup failed:", profileError?.message);
      return res.status(404).json({ error: "profile_not_found" });
    }

    // Normalize plan name: free and Free both work
    const now = Date.now();
const expiry = profile.plan_expires_at
  ? new Date(profile.plan_expires_at).getTime()
  : 0;

const plan =
  profile.active_plan &&
  profile.active_plan.toLowerCase() !== "free" &&
  expiry > now
    ? profile.active_plan.trim().toLowerCase()
    : "free";
    const rewards = {
      free: 1,
      starter: 1,
      premium: 2,
      diamond: 4,
      gold: 7,
      platinum: 10,
      vip: 15
    };

    const rewardAmount = rewards[plan];

    if (rewardAmount === undefined) {
      console.error("Unknown Monetag plan:", plan);
      return res.status(400).json({ error: "invalid_plan" });
    }

    const { data: allowed, error: limitError } =
      await supabase.rpc("start_monetag_ad", {
        p_ymid: ymid,
        p_telegram_id: telegramId,
        p_zone_id: zoneId,
        p_reward_amount: rewardAmount
      });

    if (limitError) {
      console.error("Monetag daily limit failed:", limitError.message);
      return res.status(500).json({
        error: "daily_limit_check_failed"
      });
    }

    if (allowed !== true) {
      return res.status(429).json({
        error: "daily_ad_limit_reached"
      });
    }

    return res.json({
      success: true,
      ymid,
      zoneId
    });
  } catch (error) {
    console.error("Monetag start error:", error.message);
    return res.status(500).json({ error: "ad_start_failed" });
  }
});

app.get("/api/monetag/count", requireConfig, requireTelegram, async (req, res) => {
  try {
    const telegramId = String(req.telegramUser.id);

    const { count, error } = await supabase
      .from("monetag_ad_views")
      .select("id", { count: "exact", head: true })
      .eq("telegram_id", telegramId)
      .gte(
        "created_at",
        new Date(
          new Date().toLocaleString("en-US", { timeZone: "Asia/Dhaka" })
        ).toISOString().slice(0, 10) + "T00:00:00+06:00"
      );

    if (error) {
      console.error("Monetag count error:", error.message);
      return res.status(500).json({ error: "count_failed" });
    }

    return res.json({
      success: true,
      count: count || 0,
      remaining: Math.max(0, 20 - (count || 0))
    });
  } catch (error) {
    console.error("Monetag count error:", error.message);
    return res.status(500).json({ error: "count_failed" });
  }
});


app.get("/postback", async (req, res) => {
  try {
    const receivedSecret = String(req.query.secret || "");
    const expectedSecret = POSTBACK_SECRET;

    if (!receivedSecret || !expectedSecret) {
      return res.status(403).send("Forbidden");
    }

    const a = Buffer.from(receivedSecret);
    const b = Buffer.from(expectedSecret);

    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return res.status(403).send("Forbidden");
    }

const ymid = String(req.query.ymid || "");
const eventType = String(req.query.event_type || "");
const rewardType = String(req.query.reward_event_type || "");
const estimatedPrice = String(req.query.estimated_price || "");

console.log("Monetag event details", {
  ymid,
  eventType,
  rewardType,
  estimatedPrice
});
    const zoneId = String(req.query.zone_id || "");
    
    console.log("Monetag postback received", {
  ymidPresent: Boolean(req.query.ymid),
  zoneId: String(req.query.zone_id || ""),
  eventType: String(req.query.event_type || ""),
  rewardType: String(req.query.reward_event_type || ""),
 estimatedPrice: String(req.query.estimated_price || "")
});

    if (
      !ymid ||
      ymid.length > 200 ||
      zoneId !== "12005665" ||
      !["impression", "click"].includes(eventType) ||
      !["valued", "non_valued"].includes(rewardType)
    ) {
      return res.status(400).send("Invalid postback");
    }

    
    if (rewardType !== "valued") {
  console.log("Monetag reward skipped:", rewardType);
  return res.status(200).send("Not a valued reward");
    }

    const { data: ad, error: lookupError } = await supabase
      .from("monetag_ad_views")
.select("ymid, telegram_id, zone_id, rewarded_at, reward_amount, created_at")      .eq("ymid", ymid)
      .maybeSingle();

    if (lookupError) {
      console.error("Monetag lookup failed:", lookupError.message);
      return res.status(500).send("Lookup failed");
    }

if (!ad || ad.zone_id !== zoneId) {
  return res.status(404).send("Ad view not found");
}

const startedAt = new Date(ad.created_at).getTime();
const elapsedSeconds = (Date.now() - startedAt) / 1000;

if (!Number.isFinite(startedAt) || elapsedSeconds < 13) {
  console.log("Monetag reward skipped: under 13 seconds", {
    elapsedSeconds
  });
  return res.status(200).send("Reward skipped: under 13 seconds");
}

const { data, error } = await supabase.rpc(
  "reward_monetag_ad",
  {
    p_ymid: ymid,
    p_telegram_id: ad.telegram_id,
    p_reward_amount: Number(ad.reward_amount),
    p_zone_id: zoneId
  }
);

if (error) {
  if (error.message?.includes("already_rewarded")) {
    return res.status(200).send("Already rewarded");
  }

  console.error("Monetag reward failed:", error.message);
  return res.status(500).send("Reward failed");
}

if (data?.error === "already_rewarded") {
  return res.status(200).send("Already rewarded");
}

if (data?.error === "daily_limit_reached") {
  console.log("Monetag daily limit reached:", ad.telegram_id);
  return res.status(200).send("Daily limit reached");
}

console.log("Monetag reward result:", JSON.stringify(data));

return res.status(200).send(
  data?.success ? "Rewarded" : "Already processed"
);
   } catch (error) {
    console.error("Monetag postback error:", error.message);
    return res.status(500).send("Postback error");
  }
});
  
/* TakaPay: Submit withdrawal request */
app.post(
  "/api/withdraw",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const amount = Number(req.body?.amount);
      const method = String(req.body?.method || "");
      const accountNumber = String(req.body?.account_number || "").trim();

      if (
        !Number.isFinite(amount) ||
        amount < 400 ||
        amount > 1000000 ||
        !["bKash", "Nagad", "Rocket", "USDT"].includes(method) ||
        accountNumber.length < 8 ||
        accountNumber.length > 32
      ) {
        return res.status(400).json({
          error: "invalid_withdrawal_request",
          message: "ন্যূনতম উইথড্র ৳400 এবং তথ্য সঠিকভাবে দিন।"
        });
      }

      let joined;

      try {
        joined = await isMemberOfWithdrawChannel(
          req.telegramUser.id
        );
      } catch (error) {
        console.error(
          "Withdraw channel membership check failed:",
          error.message
        );

        return res.status(503).json({
          error: "channel_check_unavailable",
          message: "চ্যানেলের সদস্যপদ যাচাই করা যাচ্ছে না। একটু পরে আবার চেষ্টা করুন।"
        });
      }


      if (!joined) {
        return res.status(403).json({
          error: "withdraw_channel_required",
          message: "উইথড্র করার আগে TakaPay Withdraw Updates চ্যানেলে Join করুন।",
          channel_url: "https://t.me/TakaPayWithdrawUpdates"
        });
      }

      
      const { data, error } = await supabase.rpc(
        "request_withdrawal",
        {
          p_telegram_id: req.telegramUser.id,
          p_amount: amount,
          p_method: method,
          p_account_number: accountNumber
        }
      );

      if (error) {
        console.error("Withdrawal request failed:", error.message);

        return res.status(400).json({
          error: "withdrawal_failed",
          message: "উইথড্র অনুরোধ জমা হয়নি।"
        });
      }

      return res.json({ success: true, withdrawal: data });
    } catch (error) {
      console.error("Withdrawal API error:", error.message);

      return res.status(500).json({
        error: "server_error"
      });
    }
  }
);

/* TakaPay: Admin review of withdrawal */
app.post(
  "/api/admin/withdrawal/review",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const requestId = Number(req.body?.request_id);
      const status = String(req.body?.status || "");

      if (
        !Number.isSafeInteger(requestId) ||
        requestId <= 0 ||
        !["approved", "rejected"].includes(status)
      ) {
        return res.status(400).json({
          error: "invalid_review_request"
        });
      }

      const { data: admin, error: adminError } = await supabase
        .from("takapay_admins")
        .select("telegram_id")
        .eq("telegram_id", req.telegramUser.id)
        .maybeSingle();

      if (adminError || !admin) {
        return res.status(403).json({
          error: "admin_only"
        });
      }

      const { data, error } = await supabase.rpc(
        "admin_review_withdrawal",
        {
          p_request_id: requestId,
          p_status: status,
          p_admin_telegram_id: req.telegramUser.id
        }
      );

      if (error) {
        console.error("Admin withdrawal review failed:", error.message);

        return res.status(400).json({
          error: "review_failed"
        });
      }

      return res.json({ success: true, result: data });
    } catch (error) {
      console.error("Admin review API error:", error.message);

      return res.status(500).json({
        error: "server_error"
      });
    }
  }
);

/* Admin API: List withdrawal requests */
app.get(
  "/api/admin/withdrawals",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data: admin, error: adminError } = await supabase
        .from("takapay_admins")
        .select("telegram_id")
        .eq("telegram_id", String(req.telegramUser.id))
        .maybeSingle();

      if (adminError || !admin) {
        return res.status(403).json({
          error: "admin_only"
        });
      }

      const { data, error } = await supabase
        .from("withdrawal_requests")
        .select(`
          id,
          telegram_id,
          amount,
          method,
          account_number,
          status,
          created_at
        `)
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) {
        console.error("Withdrawal list failed:", error.message);
        return res.status(500).json({
          error: "withdrawal_list_failed"
        });
      }

      const ids = [...new Set(
        (data || []).map(item => String(item.telegram_id))
      )];

      let profiles = [];

      if (ids.length) {
        const result = await supabase
          .from("profiles")
          .select("telegram_id, full_name, username")
          .in("telegram_id", ids);

        if (result.error) {
          console.error("Profile lookup failed:", result.error.message);
          return res.status(500).json({
            error: "profile_lookup_failed"
          });
        }

        profiles = result.data || [];
      }

      const profileMap = new Map(
        profiles.map(profile => [
          String(profile.telegram_id),
          profile
        ])
      );

      return res.json({
        success: true,
        withdrawals: (data || []).map(item => {
          const profile = profileMap.get(
            String(item.telegram_id)
          );

          return {
            ...item,
            full_name: profile?.full_name || "নাম পাওয়া যায়নি",
            username: profile?.username || null
          };
        })
      });
    } catch (error) {
      console.error("Withdrawal list API error:", error.message);
      return res.status(500).json({
        error: "server_error"
      });
    }
  }
);

/* Admin API: Get pending withdrawal count */
app.get(
  "/api/admin/withdrawal/pending-count",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data: admin, error: adminError } = await supabase
        .from("takapay_admins")
        .select("telegram_id")
        .eq("telegram_id", String(req.telegramUser.id))
        .maybeSingle();

      if (adminError || !admin) {
        return res.status(403).json({
          error: "admin_only"
        });
      }

      const { count, error } = await supabase
        .from("withdrawal_requests")
        .select("id", { count: "exact", head: true })
        .eq("status", "pending");

      if (error) {
        console.error("Pending withdrawal count failed:", error.message);
        return res.status(500).json({
          error: "pending_count_failed"
        });
      }

      return res.json({
        success: true,
        pending_count: count ?? 0
      });
    } catch (error) {
      console.error("Pending count API error:", error.message);
      return res.status(500).json({
        error: "server_error"
      });
    }
  }
);

/* Admin API: Save a new task */
app.post(
  "/api/admin/tasks",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const telegramId = String(req.telegramUser.id);
      const title = String(req.body?.title || "").trim();
      const reward = Number(req.body?.reward);
      const url = String(req.body?.url || "").trim();

      
let channelUsername = "";

try {
  const parsedUrl = new URL(url);

  if (
    parsedUrl.protocol !== "https:" ||
    parsedUrl.hostname !== "t.me" ||
    parsedUrl.pathname.split("/").filter(Boolean).length !== 1
  ) {
    throw new Error("invalid_channel_url");
  }

  channelUsername = parsedUrl.pathname
    .split("/")
    .filter(Boolean)[0];

  if (!/^[A-Za-z0-9_]{5,32}$/.test(channelUsername)) {
    throw new Error("invalid_channel_username");
  }
} catch {
  return res.status(400).json({
    success: false,
    error: "invalid_telegram_channel_url"
  });
}

if (
  !title ||
  title.length > 200 ||
  !Number.isFinite(reward) ||
  reward <= 0 ||
  reward > 100000
) {
  return res.status(400).json({
    success: false,
    error: "invalid_task"
  });
}


      const { data: admin, error: adminError } = await supabase
        .from("takapay_admins")
        .select("telegram_id")
        .eq("telegram_id", telegramId)
        .maybeSingle();

      if (adminError || !admin) {
        return res.status(403).json({
          success: false,
          error: "admin_only"
        });
      }

      const { data: task, error } = await supabase
.from("tasks")
.insert({
  title,
  reward,
  url,
  is_active: true
})
        .select("id, title, reward, is_active, created_at")
        .single();

      if (error) {
        console.error("Task save failed:", error.message);
        return res.status(500).json({
          success: false,
          error: "task_save_failed"
        });
      }

      return res.status(201).json({
        success: true,
        task
      });
    } catch (error) {
      console.error("Admin task API error:", error.message);
      return res.status(500).json({
        success: false,
        error: "server_error"
      });
    }
  }
);

/* Verify channel membership and reward an admin task */
app.post(
  "/api/tasks/claim-channel",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const telegramId = String(req.telegramUser.id);
      const taskId = Number(req.body?.task_id);

      if (!Number.isSafeInteger(taskId) || taskId <= 0) {
        return res.status(400).json({
          success: false,
          error: "invalid_task_id"
        });
      }

      // Load the task from the database
      const { data: task, error: taskError } = await supabase
        .from("tasks")
        .select("id, title, reward, url, is_active")
        .eq("id", taskId)
        .eq("is_active", true)
        .maybeSingle();

      if (taskError) {
        console.error("Task lookup failed:", taskError.message);
        return res.status(500).json({
          success: false,
          error: "task_lookup_failed"
        });
      }

      if (!task) {
        return res.status(404).json({
          success: false,
          error: "task_not_found"
        });
      }

      // Accept only public Telegram channel links
      let channelUsername;

      try {
        const parsedUrl = new URL(String(task.url || ""));
        const parts = parsedUrl.pathname.split("/").filter(Boolean);

        if (
          parsedUrl.protocol !== "https:" ||
          parsedUrl.hostname !== "t.me" ||
          parsedUrl.search ||
          parsedUrl.hash ||
          parts.length !== 1 ||
          !/^[A-Za-z0-9_]{5,32}$/.test(parts[0])
        ) {
          throw new Error("invalid_channel_url");
        }

        channelUsername = parts[0];
      } catch {
        return res.status(400).json({
          success: false,
          error: "invalid_telegram_channel_url"
        });
      }

      // Verify actual Telegram membership
      const telegramApiUrl = new URL(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getChatMember`
      );

      telegramApiUrl.searchParams.set(
        "chat_id",
        `@${channelUsername}`
      );
      telegramApiUrl.searchParams.set("user_id", telegramId);

      const telegramResponse = await fetch(telegramApiUrl);
      const telegramResult = await telegramResponse.json();

      if (!telegramResponse.ok || !telegramResult.ok) {
        console.error(
          "Telegram membership check failed:",
          telegramResult.description || "unknown error"
        );

        return res.status(503).json({
          success: false,
          error: "membership_check_failed"
        });
      }

      const member = telegramResult.result;
      const joined =
        member.status === "creator" ||
        member.status === "administrator" ||
        member.status === "member" ||
        (member.status === "restricted" && member.is_member === true);

      if (!joined) {
        return res.status(403).json({
          success: false,
          error: "channel_not_joined"
        });
      }

      // Reward only after Telegram confirms membership
      const { data, error } = await supabase.rpc(
        "claim_admin_channel_task_reward",
        {
          p_telegram_id: telegramId,
          p_task_id: String(task.id)
        }
      );

      if (error) {
        console.error("Admin task reward failed:", error.message);
        return res.status(500).json({
          success: false,
          error: "reward_failed"
        });
      }

      if (data?.success === true) {
        return res.json({
          success: true,
          reward: data.reward
        });
      }

      if (data?.error === "already_claimed") {
        return res.status(409).json({
          success: false,
          error: "already_claimed"
        });
      }

      if (data?.error === "profile_not_found") {
        return res.status(404).json({
          success: false,
          error: "profile_not_found"
        });
      }

      if (data?.error === "task_not_found") {
        return res.status(404).json({
          success: false,
          error: "task_not_found"
        });
      }

      return res.status(500).json({
        success: false,
        error: "reward_failed"
      });
    } catch (error) {
      console.error("Admin channel task error:", error.message);
      return res.status(500).json({
        success: false,
        error: "server_error"
      });
    }
  }
);
          
/* Public API: Get active tasks */
app.get(
  "/api/tasks",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const { data: tasks, error } = await supabase
        .from("tasks")
        .select("id, title, reward, url, created_at")
        .eq("is_active", true)
        .order("created_at", { ascending: false });

      if (error) {
        console.error("Load tasks failed:", error.message);
        return res.status(500).json({
          success: false,
          error: "tasks_load_failed"
        });
      }

      return res.json({
        success: true,
        tasks: tasks || []
      });
    } catch (error) {
      console.error("Tasks API error:", error.message);
      return res.status(500).json({
        success: false,
        error: "server_error"
      });
    }
  }
);

  
/* Admin API: Delete a task */
app.delete(
  "/api/admin/tasks/:id",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const telegramId = String(req.telegramUser.id);
      const taskId = Number(req.params.id);

      if (!Number.isSafeInteger(taskId) || taskId <= 0) {
        return res.status(400).json({
          success: false,
          error: "invalid_task_id"
        });
      }

      const { data: admin, error: adminError } = await supabase
        .from("takapay_admins")
        .select("telegram_id")
        .eq("telegram_id", telegramId)
        .maybeSingle();

      if (adminError || !admin) {
        return res.status(403).json({
          success: false,
          error: "admin_only"
        });
      }

      const { data: task, error: deleteError } = await supabase
        .from("tasks")
        .update({ is_active: false })
        .eq("id", taskId)
        .select("id")
        .maybeSingle();

      if (deleteError) {
        console.error("Task delete failed:", deleteError.message);
        return res.status(500).json({
          success: false,
          error: "task_delete_failed"
        });
      }

      if (!task) {
        return res.status(404).json({
          success: false,
          error: "task_not_found"
        });
      }

      return res.json({ success: true });
    } catch (error) {
      console.error("Task delete API error:", error.message);
      return res.status(500).json({
        success: false,
        error: "server_error"
      });
    }
  }
);
// Admin API: Activate a user's plan
app.post(
  "/api/admin/activate-plan",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const adminId = String(req.telegramUser.id);
      const telegramId = String(req.body.telegram_id || "").trim();
      const plan = String(req.body.plan || "").trim().toLowerCase();

      const allowedPlans = [
        "premium",
        "diamond",
        "gold",
        "platinum",
        "vip"
      ];

      if (!/^\d+$/.test(telegramId) || !allowedPlans.includes(plan)) {
        return res.status(400).json({
          success: false,
          error: "invalid_user_or_plan"
        });
      }

      const { data: admin, error: adminError } = await supabase
        .from("takapay_admins")
        .select("telegram_id")
        .eq("telegram_id", adminId)
        .maybeSingle();

      if (adminError || !admin) {
        return res.status(403).json({
          success: false,
          error: "admin_only"
        });
      }

      const { data: profile, error: profileError } = await supabase
        .from("profiles")
        .update({
  active_plan: plan,
  plan_expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
})
        .eq("telegram_id", telegramId)
.select("telegram_id, username, active_plan, plan_expires_at")
        .maybeSingle();

      if (profileError) {
        console.error("Plan activation failed:", profileError.message);
        return res.status(500).json({
          success: false,
          error: "plan_activation_failed"
        });
      }

      if (!profile) {
        return res.status(404).json({
          success: false,
          error: "profile_not_found"
        });
      }

      return res.json({
        success: true,
        message: "plan_activated",
        profile
      });
    } catch (error) {
      console.error("Plan activation error:", error.message);
      return res.status(500).json({
        success: false,
        error: "server_error"
      });
    }
  }
);

app.post(
  "/api/plan-recharge",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const telegramId = String(req.telegramUser.id);
      const amount = Number(req.body.amount);
      const method = String(req.body.payment_method || "")
        .trim()
        .toLowerCase();
      const payerNumber = String(req.body.payer_number || "").trim();
      const transactionId = String(req.body.transaction_id || "").trim();

      if (
        !Number.isFinite(amount) ||
        !Number.isInteger(amount) ||
        amount < 199 ||
        amount > 1999 ||
        !["bkash", "nagad"].includes(method)
      ) {
        return res.status(400).json({
          success: false,
          error: "invalid_amount_or_payment_method",
          minimum: 199,
          maximum: 1999
        });
      }

      if (
        !/^01[3-9]\d{8}$/.test(payerNumber) ||
        !/^[A-Za-z0-9]{5,30}$/.test(transactionId)
      ) {
        return res.status(400).json({
          success: false,
          error: "invalid_payment_details"
        });
      }

      const { data, error } = await supabase
        .from("plan_recharge_requests")
        .insert({
          telegram_id: telegramId,
          plan: null,
          amount,
          payment_method: method,
          payer_number: payerNumber,
          transaction_id: transactionId,
          status: "pending"
        })
        .select(
          "id, amount, payment_method, status, created_at"
        )
        .single();

      if (error) {
        if (error.code === "23505") {
          return res.status(409).json({
            success: false,
            error: "transaction_already_submitted"
          });
        }

        console.error("Plan recharge request failed:", error.message);
        return res.status(500).json({
          success: false,
          error: "request_failed"
        });
      }

      return res.status(201).json({
        success: true,
        message: "payment_pending_verification",
        request: data
      });
    } catch (error) {
      console.error("Plan recharge error:", error.message);
      return res.status(500).json({
        success: false,
        error: "server_error"
      });
    
    }
  }
);


async function verifyRechargeAdmin(req, res) {
  const { data: admin, error } = await supabase
    .from("takapay_admins")
    .select("telegram_id")
    .eq("telegram_id", String(req.telegramUser.id))
    .maybeSingle();

  if (error || !admin) {
    res.status(403).json({
      success: false,
      error: "admin_only"
    });
    return false;
  }

  return true;
}

app.get(
  "/api/admin/recharges",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      if (!(await verifyRechargeAdmin(req, res))) return;

      const { data, error } = await supabase
        .from("plan_recharge_requests")
        .select(
          "id, telegram_id, amount, payment_method, payer_number, transaction_id, status, created_at"
        )
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) throw error;

      return res.json({ success: true, requests: data || [] });
    } catch (error) {
      console.error("Admin recharge list failed:", error.message);
      return res.status(500).json({
        success: false,
        error: "recharge_list_failed"
      });
    }
  }
);

app.post(
  "/api/admin/recharges/:id/approve",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      if (!(await verifyRechargeAdmin(req, res))) return;

      const requestId = Number(req.params.id);

      if (!Number.isSafeInteger(requestId) || requestId < 1) {
        return res.status(400).json({
          success: false,
          error: "invalid_request_id"
        });
      }

      const { data, error } = await supabase.rpc(
        "approve_plan_recharge",
        {
          p_request_id: requestId,
          p_reviewed_by: String(req.telegramUser.id)
        }
      );

      if (error) throw error;

      if (!data?.success) {
        return res.status(409).json(data || {
          success: false,
          error: "approval_failed"
        });
      }

      return res.json({ success: true });
    } catch (error) {
      console.error("Recharge approval failed:", error.message);
      return res.status(500).json({
        success: false,
        error: "approval_failed"
      });
    }
  }
);

app.post(
  "/api/admin/recharges/:id/reject",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      if (!(await verifyRechargeAdmin(req, res))) return;

      const requestId = Number(req.params.id);

      if (!Number.isSafeInteger(requestId) || requestId < 1) {
        return res.status(400).json({
          success: false,
          error: "invalid_request_id"
        });
      }

      const { data, error } = await supabase
        .from("plan_recharge_requests")
        .update({
          status: "rejected",
          reviewed_at: new Date().toISOString(),
          reviewed_by: String(req.telegramUser.id)
        })
        .eq("id", requestId)
        .eq("status", "pending")
        .select("id")
        .maybeSingle();

      if (error) throw error;

      if (!data) {
        return res.status(409).json({
          success: false,
          error: "request_not_pending"
        });
      }

      return res.json({ success: true });
    } catch (error) {
      console.error("Recharge rejection failed:", error.message);
      return res.status(500).json({
        success: false,
        error: "rejection_failed"
      });
    }
  }
);
   
app.post(
  "/api/admin/recharge-balance/add",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      if (!(await verifyRechargeAdmin(req, res))) return;

      const telegramId = String(req.body?.telegram_id || "").trim();
      const amount = Number(req.body?.amount);

      if (!/^[0-9]{1,30}$/.test(telegramId)) {
        return res.status(400).json({
          success: false,
          error: "invalid_telegram_id"
        });
      }

      if (
        !Number.isSafeInteger(amount) ||
        amount < 1 ||
        amount > 1000000
      ) {
        return res.status(400).json({
          success: false,
          error: "invalid_amount"
        });
      }

      const { data, error } = await supabase.rpc(
        "admin_add_recharge_balance",
        {
          p_telegram_id: telegramId,
          p_amount: amount
        }
      );

      if (error) throw error;

      if (!data?.success) {
        const errors = {
          invalid_telegram_id: 400,
          invalid_amount: 400,
          profile_not_found: 404
        };

        return res.status(errors[data?.error] || 400).json(data);
      }

      return res.json({ success: true, message: "রিচার্জ ব্যালেন্স যোগ হয়েছে।" });
    } catch (error) {
      console.error("Admin recharge balance add failed:", error.message);
      return res.status(500).json({
        success: false,
        error: "recharge_balance_add_failed"
      });
    }
  }
);
  // General balance recharge requests
app.get(
  "/api/admin/balance-recharges",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      if (!(await verifyRechargeAdmin(req, res))) return;

      const { data, error } = await supabase
        .from("recharge_requests")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) throw error;

      return res.json({ success: true, requests: data || [] });
    } catch (error) {
      console.error("Balance recharge list failed:", error.message);
      return res.status(500).json({
        success: false,
        error: "recharge_list_failed"
      });
    }
  }
);

app.post(
  "/api/admin/balance-recharges/:id/approve",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      if (!(await verifyRechargeAdmin(req, res))) return;

      const requestId = Number(req.params.id);

      if (!Number.isSafeInteger(requestId) || requestId < 1) {
        return res.status(400).json({
          success: false,
          error: "invalid_request_id"
        });
      }

      const { data, error } = await supabase.rpc(
        "approve_balance_recharge",
        {
          p_request_id: requestId,
          p_reviewed_by: String(req.telegramUser.id)
        }
      );

      if (error) throw error;

      if (!data?.success) {
        return res.status(409).json(data);
      }

      return res.json({ success: true });
    } catch (error) {
      console.error("Balance recharge approval failed:", error.message);
      return res.status(500).json({
        success: false,
        error: "approval_failed"
      });
    }
  }
);

app.post(
  "/api/admin/balance-recharges/:id/reject",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      if (!(await verifyRechargeAdmin(req, res))) return;

      const requestId = Number(req.params.id);

      if (!Number.isSafeInteger(requestId) || requestId < 1) {
        return res.status(400).json({
          success: false,
          error: "invalid_request_id"
        });
      }

      const { data, error } = await supabase.rpc(
        "reject_balance_recharge",
        {
          p_request_id: requestId,
          p_reviewed_by: String(req.telegramUser.id)
        }
      );

      if (error) throw error;

      if (!data?.success) {
        return res.status(409).json(data);
      }

      return res.json({ success: true });
    } catch (error) {
      console.error("Balance recharge rejection failed:", error.message);
      return res.status(500).json({
        success: false,
        error: "rejection_failed"
      });
    }
  }
);  

app.post(
  "/api/plans/purchase",
  requireConfig,
  requireTelegram,
  async (req, res) => {
    try {
      const telegramId = String(req.telegramUser.id);
      const plan = String(req.body.plan || "").trim().toLowerCase();

      const { data, error } = await supabase.rpc(
        "purchase_plan_with_balance",
        {
          p_telegram_id: telegramId,
          p_plan: plan
        }
      );

      if (error) {
        console.error("Plan purchase failed:", error.message);
        return res.status(500).json({
          success: false,
          error: "purchase_failed"
        });
      }

      if (!data?.success) {
        const status = data?.error === "insufficient_balance" ? 400 : 409;
        return res.status(status).json(data);
      }

      return res.json({
        success: true,
        message: "plan_purchase_success",
        plan: data.plan,
        price: data.price
      });
    } catch (error) {
      console.error("Plan purchase error:", error.message);
      return res.status(500).json({
        success: false,
        error: "purchase_failed"
      });
    }
  }
);

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`TakaPay backend listening on port ${PORT}`);
});


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
          : null
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

app.post("/api/monetag/start", requireConfig, requireTelegram, async (req, res) => {
  try {
    const ymid = randomUUID();
    const telegramId = String(req.telegramUser.id);
      const zoneId = "12005665";
      const { data: allowed, error: limitError } =
        await supabase.rpc("start_monetag_ad", {
          p_ymid: ymid,
          p_telegram_id: telegramId,
          p_zone_id: zoneId,
          p_reward_amount: 1.00
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
      zoneId: "12005665"
    });
  } catch (error) {
    console.error("Monetag start error:", error.message);
    return res.status(500).json({ error: "ad_start_failed" });
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
    const zoneId = String(req.query.zone_id || "");
    const eventType = String(req.query.event_type || "");
    const rewardType = String(req.query.reward_event_type || "");
    console.log("Monetag postback received", {
  ymidPresent: Boolean(req.query.ymid),
  zoneId: String(req.query.zone_id || ""),
  eventType: String(req.query.event_type || ""),
  rewardType: String(req.query.reward_event_type || "")
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

    return res.status(200).send("Rewards temporarily paused");

    const { data: ad, error: lookupError } = await supabase
      .from("monetag_ad_views")
      .select("ymid, telegram_id, zone_id, rewarded_at")
      .eq("ymid", ymid)
      .maybeSingle();

    if (lookupError) {
      console.error("Monetag lookup failed:", lookupError.message);
      return res.status(500).send("Lookup failed");
    }

    if (!ad || ad.zone_id !== zoneId) {
      return res.status(404).send("Ad view not found");
    }

      const { data, error } = await supabase.rpc(
  "reward_monetag_ad",
  {
    p_ymid: ymid,
    p_telegram_id: ad.telegram_id,
    p_reward_amount: 1.00,
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

      
// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`TakaPay backend listening on port ${PORT}`);
});

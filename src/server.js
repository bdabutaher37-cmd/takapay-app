import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { createClient } from "@supabase/supabase-js";

const app = express();
const PORT = process.env.PORT || 3000;

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

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

const supabase =
  supabaseUrl && supabaseSecretKey
    ? createClient(supabaseUrl, supabaseSecretKey, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      })
    : null;

app.get("/", (req, res) => {
  res.json({
    app: "TakaPay Backend",
    status: "running"
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/api/db-status", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({
      status: "not_configured"
    });
  }

  try {
    const { error } = await supabase
      .from("profiles")
      .select("*", { head: true, count: "exact" });

    if (error) {
      console.error("Supabase check failed:", error.message);
      return res.status(503).json({
        status: "connection_error"
      });
    }

    return res.json({ status: "connected" });
  } catch (error) {
    console.error("Database check failed:", error.message);
    return res.status(503).json({
      status: "connection_error"
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`TakaPay backend listening on port ${PORT}`);
});

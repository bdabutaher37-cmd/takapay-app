
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";

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

app.get("/", (req, res) => {
  res.json({
    app: "TakaPay Backend",
    status: "running"
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/api/db-status", (req, res) => {
  res.status(503).json({
    status: "not_configured",
    message: "Database connection is not configured yet"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`TakaPay backend listening on port ${PORT}`);
});

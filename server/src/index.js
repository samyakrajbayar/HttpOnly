import express from "express";
import cors from "cors";
import helmet from "helmet";
import { z } from "zod";
import { scanTarget } from "./scanner/index.js";

const app = express();
const port = process.env.PORT || 4000;

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: process.env.CLIENT_ORIGIN || "http://localhost:5173" }));
app.use(express.json({ limit: "1mb" }));

const scanRequestSchema = z.object({
  target: z.string().trim().min(3).max(500)
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "lightweight-vulnerability-scanner" });
});

app.post("/api/scan", async (req, res) => {
  const parsed = scanRequestSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: "A valid URL or GitHub repository link is required."
    });
  }

  try {
    const report = await scanTarget(parsed.data.target);
    res.json(report);
  } catch (error) {
    const status = error.statusCode || 500;
    res.status(status).json({
      error: error.message || "The scan could not be completed."
    });
  }
});

app.use((_req, res) => {
  res.status(404).json({ error: "Route not found." });
});

app.listen(port, () => {
  console.log(`Scanner API listening on http://localhost:${port}`);
});

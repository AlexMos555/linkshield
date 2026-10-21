// Stand-in for the production API's public check endpoint, so e2e can render
// /check/<domain> without reaching api.cleanway.ai (rate-limited per IP).
// playwright.config.ts starts it and points the landing server's API_URL here.
// Only GET /api/v1/public/check/<host> answers; everything else is a 404,
// which the check page treats as "no result" — the same as a failed fetch.
import { createServer } from "node:http";

const PORT = Number(process.env.MOCK_API_PORT || 3999);

/** Hosts with a fixed verdict; any other host comes back safe. */
const VERDICTS = {
  "bank-verify-login.example": {
    level: "dangerous",
    score: 92,
    verdict: "Dangerous",
    signals: ["Domain registered recently", "Looks like a bank login page"],
    reason_codes: ["new_domain", "brand_impersonation"],
    confidence: "high",
    confidence_pct: 94,
  },
};

const SAFE = {
  level: "safe",
  score: 3,
  verdict: "Safe",
  signals: [],
  reason_codes: [],
  confidence: "high",
  confidence_pct: 97,
};

createServer((req, res) => {
  const match = /^\/api\/v1\/public\/check\/([^/?#]+)/.exec(req.url || "");
  if (req.method === "GET" && match) {
    const host = decodeURIComponent(match[1]).toLowerCase();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ domain: host, ...(VERDICTS[host] || SAFE) }));
    return;
  }
  if (req.url === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end('{"detail":"not found"}');
}).listen(PORT, "127.0.0.1");

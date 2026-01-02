import crypto from "crypto";

const SECRET = process.env.LINK_SECRET;
const PASSPHRASE = process.env.GENERATOR_KEY;

const DURATIONS = {
  "15m": 15 * 60,
  "30m": 30 * 60,
  "1h": 60 * 60,
  "5h": 5 * 60 * 60,
  "12h": 12 * 60 * 60,
  "24h": 24 * 60 * 60,
  "48h": 48 * 60 * 60,
  "72h": 72 * 60 * 60,
  "5d": 5 * 24 * 60 * 60
};

export async function handler(event) {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405 };
  }

  const { duration, key } = JSON.parse(event.body || "{}");

  if (key !== PASSPHRASE) {
    return { statusCode: 403, body: "Forbidden" };
  }

  if (!DURATIONS[duration]) {
    return { statusCode: 400, body: "Invalid duration" };
  }

  const payload = Buffer.from(JSON.stringify({
    exp: Date.now() + DURATIONS[duration] * 1000
  })).toString("base64");

  const sig = crypto
    .createHmac("sha256", SECRET)
    .update(payload)
    .digest("hex");

  return {
    statusCode: 200,
    body: JSON.stringify({ token: `${payload}.${sig}` })
  };
}

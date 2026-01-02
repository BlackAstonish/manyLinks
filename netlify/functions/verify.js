import crypto from "crypto";

const SECRET = process.env.LINK_SECRET;

export async function handler(event) {
  const token = event.queryStringParameters.t;
  if (!token) {
    return { statusCode: 401, body: "Missing token" };
  }

  try {
    const [payload, signature] = token.split(".");
    const expectedSig = crypto
      .createHmac("sha256", SECRET)
      .update(payload)
      .digest("hex");

    if (signature !== expectedSig) {
      return { statusCode: 403, body: "Invalid token" };
    }

    const data = JSON.parse(
      Buffer.from(payload, "base64").toString()
    );

    if (Date.now() > data.exp) {
      return { statusCode: 410, body: "Expired" };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ ok: true })
    };
  } catch {
    return { statusCode: 400, body: "Bad token" };
  }
}

// Mixed-load profile: full enrol -> confirm -> verify lifecycle per iteration.
// Every iteration uses a fresh factor, so no iteration can replay another.
//
//   export BANDALL_SERVICE_KEY=... TENANT_ID=...
//   bandall tenant create --config bandall.toml --name load   # once, prints id
//   k6 run --vus 20 --duration 2m tests/load/verify.js
//
// SLO under test (confirm on your hardware, never assumed): p99 < 100 ms,
// failure rate < 1%.
import http from "k6/http";
import { check } from "k6";
import crypto from "k6/crypto";

const BASE = __ENV.BANDALL_URL || "http://127.0.0.1:8080";
const SERVICE_KEY = __ENV.BANDALL_SERVICE_KEY || "";
const TENANT = __ENV.TENANT_ID || "";

export const options = {
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(99)<100"],
  },
};

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input) {
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of input.replace(/=+$/, "")) {
    const index = B32.indexOf(ch.toUpperCase());
    if (index < 0) {
      throw new Error("bad base32");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out).buffer;
}

// RFC 4226 dynamic truncation over HMAC-SHA-256 (matches default params).
function hotp(secretBase32, counter) {
  const key = base32Decode(secretBase32);
  const msg = new ArrayBuffer(8);
  new DataView(msg).setBigUint64(0, BigInt(counter));
  const mac = crypto.hmac("sha256", key, msg, "hex");
  const bytes = [];
  for (let i = 0; i < mac.length; i += 2) {
    bytes.push(parseInt(mac.slice(i, i + 2), 16));
  }
  const offset = bytes[bytes.length - 1] & 0x0f;
  const code =
    ((bytes[offset] & 0x7f) << 24) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3];
  return String(code % 1_000_000).padStart(6, "0");
}

function totpNow(secretBase32, skewSteps = 0) {
  const step = Math.floor(Date.now() / 1000 / 30) + skewSteps;
  return hotp(secretBase32, step);
}

function secretFromUri(uri) {
  const match = uri.match(/[?&]secret=([^&]+)/);
  if (!match) {
    throw new Error("no secret in uri");
  }
  return match[1];
}

function json(res) {
  return JSON.parse(res.body);
}

export default function () {
  const subject = `load-${__VU}-${__ITER}`;
  const started = http.post(
    `${BASE}/v1/factors/enroll/start`,
    JSON.stringify({
      tenant_id: TENANT,
      subject_external_id: subject,
      issuer: "BandAll",
      account: subject,
    }),
    { headers: { "Content-Type": "application/json", "x-service-key": SERVICE_KEY } },
  );
  check(started, { "enroll/start 200": (r) => r.status === 200 });
  if (started.status !== 200) {
    return;
  }
  const startedBody = json(started);
  const secret = secretFromUri(startedBody.otpauth_uri);

  const confirmed = http.post(
    `${BASE}/v1/factors/enroll/confirm`,
    JSON.stringify({
      tenant_id: TENANT,
      subject_id: startedBody.subject_id,
      factor_id: startedBody.factor_id,
      code: totpNow(secret),
    }),
    { headers: { "Content-Type": "application/json" } },
  );
  check(confirmed, { "enroll/confirm 200": (r) => r.status === 200 });
  if (confirmed.status !== 200) {
    return;
  }

  // Hot path under test: a fresh (next-step) code must verify.
  const verified = http.post(
    `${BASE}/v1/mfa/verify`,
    JSON.stringify({
      tenant_id: TENANT,
      subject_id: startedBody.subject_id,
      factor_id: startedBody.factor_id,
      code: totpNow(secret, 1),
    }),
    { headers: { "Content-Type": "application/json" } },
  );
  check(verified, { "mfa/verify 200": (r) => r.status === 200 });
}

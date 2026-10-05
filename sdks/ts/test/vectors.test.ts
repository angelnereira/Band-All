// Conformance: every SDK passes the same vectors (sdks/conformance).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyJwt } from "../src/jwt.js";
import { canonical, sign, verifySignature } from "../src/hmac.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const vectors = JSON.parse(readFileSync(join(root, "conformance", "vectors.json"), "utf8"));
const { now_secs: NOW, jwt, hmac } = vectors;

describe("jwt", () => {
  const options = { issuer: jwt.issuer, audience: jwt.audience, nowSecs: NOW };

  it("accepts the valid token", () => {
    const claims = verifyJwt(jwt.jwks, jwt.valid, options);
    assert.equal(claims.sub, "alice");
    assert.equal(claims.aal, 1);
  });

  it("rejects tampered, wrong-aud, expired and none-alg tokens", () => {
    for (const bad of [jwt.tampered, jwt.wrong_aud, jwt.expired, jwt.none_alg]) {
      assert.throws(() => verifyJwt(jwt.jwks, bad, options), Error);
    }
  });
});

describe("hmac", () => {
  const req = {
    method: hmac.method,
    path: hmac.path,
    query: hmac.query,
    body: hmac.body,
    timestamp: hmac.timestamp,
    nonce: hmac.nonce,
  };

  it("matches the canonical string and signature", () => {
    assert.equal(canonical(req), hmac.canonical);
    assert.equal(sign(hmac.key_hex, req), hmac.signature);
  });

  it("verifies and rejects replays", () => {
    const seen = new Map();
    const options = {
      nowSecs: NOW,
      isReplay: (n) => (seen.get(n) ?? 0) > NOW,
      remember: (n, exp) => void seen.set(n, exp),
    };
    verifySignature(hmac.key_hex, req, hmac.signature, options);
    assert.throws(() => verifySignature(hmac.key_hex, req, hmac.signature, options), Error);
  });

  it("rejects stale timestamps", () => {
    assert.throws(
      () =>
        verifySignature(hmac.key_hex, req, hmac.signature, {
          nowSecs: NOW + 10_000,
        }),
      Error,
    );
  });
});

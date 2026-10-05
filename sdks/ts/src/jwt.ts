// Offline JWT (EdDSA) verification against a JWKS document.
// Standard Node only: no dependencies.

import { createPublicKey, verify } from "node:crypto";

export interface Jwk {
  kty: string;
  crv: string;
  kid: string;
  x: string;
  use: string;
}

export interface Jwks {
  keys: Jwk[];
}

export interface Claims {
  iss: string;
  aud: string;
  sub: string;
  tenant: string;
  sid: string;
  amr: string[];
  aal: number;
  jti: string;
  iat: number;
  exp: number;
}

export interface VerifyOptions {
  issuer: string;
  audience: string;
  nowSecs: number;
  leewaySecs?: number;
}

function b64uDecode(input: string): Buffer {
  return Buffer.from(input, "base64url");
}

// SPKI DER prefix for Ed25519 (RFC 8410) + 32-byte raw key.
function spkiFromRawEd25519(raw: Buffer): Buffer {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return Buffer.concat([prefix, raw]);
}

function findKey(jwks: Jwks, kid: string): Jwk {
  const key = jwks.keys.find((k) => k.kid === kid && k.crv === "Ed25519");
  if (!key) {
    throw new Error("unknown kid");
  }
  return key;
}

/**
 * Verifies a BandAll access token strictly: fixed EdDSA algorithm, known kid,
 * valid signature, matching iss/aud and unexpired exp. Throws on anything
 * else (callers answer uniformly).
 */
export function verifyJwt(jwks: Jwks, token: string, options: VerifyOptions): Claims {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new Error("malformed token");
  }
  const [headerB64, claimsB64, sigB64] = parts;
  const header = JSON.parse(b64uDecode(headerB64).toString("utf8")) as {
    alg?: string;
    kid?: string;
  };
  if (header.alg !== "EdDSA" || typeof header.kid !== "string") {
    throw new Error("unexpected algorithm");
  }
  const jwk = findKey(jwks, header.kid);
  const publicKey = createPublicKey({
    key: spkiFromRawEd25519(b64uDecode(jwk.x)),
    format: "der",
    type: "spki",
  });
  const signingInput = Buffer.from(`${headerB64}.${claimsB64}`, "utf8");
  const signature = b64uDecode(sigB64);
  if (!verify(null, signingInput, publicKey, signature)) {
    throw new Error("bad signature");
  }
  const claims = JSON.parse(b64uDecode(claimsB64).toString("utf8")) as Claims;
  const leeway = options.leewaySecs ?? 60;
  if (claims.iss !== options.issuer || claims.aud !== options.audience) {
    throw new Error("bad iss/aud");
  }
  if (typeof claims.exp !== "number" || claims.exp + leeway <= options.nowSecs) {
    throw new Error("expired");
  }
  if (typeof claims.iat === "number" && claims.iat > options.nowSecs + leeway) {
    throw new Error("issued in the future");
  }
  return claims;
}

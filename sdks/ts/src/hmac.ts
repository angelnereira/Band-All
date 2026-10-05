// HMAC request signatures (blueprint §10): canonical string, sign, verify.
// Standard Node only: no dependencies.

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface SignRequest {
  method: string;
  path: string;
  query?: string;
  body?: string | Buffer;
  timestamp: number;
  nonce: string;
}

export interface VerifyOptions {
  nowSecs: number;
  clockToleranceSecs?: number;
  /** Returns true when the nonce was already seen (replay). */
  isReplay?: (nonce: string) => boolean;
  /** Records a fresh nonce. */
  remember?: (nonce: string, expiresAt: number) => void;
}

export const CLOCK_TOLERANCE_SECS = 300;

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Canonical string: METHOD\nPATH\nQUERY\nSHA256(body)\ntimestamp\nnonce. */
export function canonical(req: SignRequest): string {
  for (const field of [req.method, req.path, req.query ?? "", req.nonce]) {
    if (field.includes("\n") || field.includes("\r")) {
      throw new Error("malformed field");
    }
  }
  const body = typeof req.body === "string" ? Buffer.from(req.body, "utf8") : (req.body ?? Buffer.alloc(0));
  return [
    req.method.toUpperCase(),
    req.path,
    req.query ?? "",
    sha256Hex(body),
    String(req.timestamp),
    req.nonce,
  ].join("\n");
}

/** Signs the canonical string, returning `v1=<hex>`. */
export function sign(keyHex: string, req: SignRequest): string {
  const mac = createHmac("sha256", Buffer.from(keyHex, "hex"));
  mac.update(canonical(req), "utf8");
  return `v1=${mac.digest("hex")}`;
}

/** Fresh random nonce (hex, 128 bits). */
export function freshNonce(): string {
  return randomBytes(16).toString("hex");
}

/**
 * Verifies structure, clock tolerance and signature in constant time.
 * Throws uniformly on failure; nonce replay is delegated to the caller.
 */
export function verifySignature(
  keyHex: string,
  req: SignRequest,
  presented: string,
  options: VerifyOptions,
): void {
  const tolerance = options.clockToleranceSecs ?? CLOCK_TOLERANCE_SECS;
  const separator = presented.indexOf("=");
  if (separator < 0) {
    throw new Error("malformed signature");
  }
  if (presented.slice(0, separator) !== "v1" || presented.length === separator + 1) {
    throw new Error("malformed signature");
  }
  if (Math.abs(options.nowSecs - req.timestamp) > tolerance) {
    throw new Error("stale timestamp");
  }
  if (req.nonce.length === 0 || req.nonce.length > 128) {
    throw new Error("malformed nonce");
  }
  if (options.isReplay?.(req.nonce)) {
    throw new Error("reused nonce");
  }
  const expected = Buffer.from(sign(keyHex, req), "utf8");
  const got = Buffer.from(presented, "utf8");
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) {
    throw new Error("bad signature");
  }
  options.remember?.(req.nonce, options.nowSecs + tolerance);
}

"""Offline JWT (EdDSA) verification against a JWKS document."""

from __future__ import annotations

import base64
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_LEEWAY_SECS = 60


def _b64u_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _public_key(raw_b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64u_decode(raw_b64))


def verify_jwt(
    jwks: dict,
    token: str,
    issuer: str,
    audience: str,
    now_secs: int | None = None,
    leeway_secs: int = _LEEWAY_SECS,
) -> dict:
    """Verify a BandAll access token strictly; raise ``ValueError`` otherwise.

    Checks the fixed ``EdDSA`` algorithm, a known ``kid``, the signature and
    the ``iss``/``aud``/``exp`` claims. Callers answer failures uniformly.
    """
    now = int(time.time()) if now_secs is None else now_secs
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        header = json.loads(_b64u_decode(header_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("malformed token") from exc
    if header.get("alg") != "EdDSA" or not isinstance(header.get("kid"), str):
        raise ValueError("unexpected algorithm")
    key = next(
        (k for k in jwks.get("keys", []) if k.get("kid") == header["kid"] and k.get("crv") == "Ed25519"),
        None,
    )
    if key is None:
        raise ValueError("unknown kid")
    try:
        _public_key(key["x"]).verify(_b64u_decode(sig_b64), f"{header_b64}.{claims_b64}".encode())
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("bad signature") from exc
    try:
        claims = json.loads(_b64u_decode(claims_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("malformed claims") from exc
    if claims.get("iss") != issuer or claims.get("aud") != audience:
        raise ValueError("bad iss/aud")
    exp = claims.get("exp")
    if not isinstance(exp, int) or exp + leeway_secs <= now:
        raise ValueError("expired")
    iat = claims.get("iat")
    if isinstance(iat, int) and iat > now + leeway_secs:
        raise ValueError("issued in the future")
    return claims

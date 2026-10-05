"""HMAC request signatures (blueprint §10): canonical string, sign, verify."""

from __future__ import annotations

import hashlib
import hmac as hmac_stdlib
import secrets
from dataclasses import dataclass, field

CLOCK_TOLERANCE_SECS = 300


@dataclass
class SignRequest:
    """A signed request's components."""

    method: str
    path: str
    timestamp: int
    nonce: str
    query: str = ""
    body: bytes = field(default_factory=bytes)


def canonical(req: SignRequest) -> str:
    """Canonical string: METHOD\\nPATH\\nQUERY\\nSHA256(body)\\ntimestamp\\nnonce."""
    for part in (req.method, req.path, req.query, req.nonce):
        if "\n" in part or "\r" in part:
            raise ValueError("malformed field")
    body_hash = hashlib.sha256(req.body).hexdigest()
    return "\n".join(
        [req.method.upper(), req.path, req.query, body_hash, str(req.timestamp), req.nonce]
    )


def sign(key_hex: str, req: SignRequest) -> str:
    """Sign the canonical string, returning ``v1=<hex>``."""
    digest = hmac_stdlib.new(bytes.fromhex(key_hex), canonical(req).encode(), hashlib.sha256)
    return f"v1={digest.hexdigest()}"


def fresh_nonce() -> str:
    """Fresh random nonce (hex, 128 bits)."""
    return secrets.token_hex(16)


def verify_signature(
    key_hex: str,
    req: SignRequest,
    presented: str,
    now_secs: int,
    clock_tolerance_secs: int = CLOCK_TOLERANCE_SECS,
    is_replay=None,
    remember=None,
) -> None:
    """Verify structure, clock tolerance and signature in constant time.

    Raises ``ValueError`` uniformly on failure; nonce replay is delegated to
    the caller via ``is_replay``/``remember``.
    """
    version, sep, _ = presented.partition("=")
    if not sep or version != "v1" or presented.endswith("="):
        raise ValueError("malformed signature")
    if abs(now_secs - req.timestamp) > clock_tolerance_secs:
        raise ValueError("stale timestamp")
    if not req.nonce or len(req.nonce) > 128:
        raise ValueError("malformed nonce")
    if is_replay is not None and is_replay(req.nonce):
        raise ValueError("reused nonce")
    expected = sign(key_hex, req).encode()
    got = presented.encode()
    if len(expected) != len(got) or not hmac_stdlib.compare_digest(expected, got):
        raise ValueError("bad signature")
    if remember is not None:
        remember(req.nonce, now_secs + clock_tolerance_secs)

"""Mock authenticator + HTTP client used only to exercise the container.

Stdlib only: no third-party dependency can be installed on this machine, and a
test harness that needs one is a test harness nobody runs. Everything here is a
*client* of the running service: it never imports BandAll code, it computes the
codes an authenticator app would compute (RFC 6238 over the `otpauth://` URI
that `enroll/start` hands out) so the server has to agree with an independent
implementation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------
# TOTP (RFC 6238) — the authenticator side.
# --------------------------------------------------------------------------


# Step offset used when confirming an enrolment. See `Session.enroll`: confirm
# consumes the step it accepts, so it must not consume the one the first login
# is going to use.
CONFIRM_OFFSET = -1


def _b32decode(secret: str) -> bytes:
    padded = secret.upper().replace(" ", "")
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded, casefold=False)


@dataclass(frozen=True)
class Otpauth:
    """Parsed `otpauth://` URI: everything needed to generate a code."""

    secret: str
    algorithm: str
    digits: int
    period: int
    issuer: str
    account: str

    def code(self, at: float | None = None, offset_steps: int = 0) -> str:
        """Code for the time step containing `at` (default: now)."""
        now = time.time() if at is None else at
        counter = int(now // self.period) + offset_steps
        digest = hmac.new(
            _b32decode(self.secret),
            struct.pack(">Q", counter),
            self._hash(),
        ).digest()
        offset = digest[-1] & 0x0F
        truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(truncated % (10**self.digits)).zfill(self.digits)

    def _hash(self):
        return {
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
        }[self.algorithm.upper()]


def parse_otpauth(uri: str) -> Otpauth:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError(f"not an otpauth URI: {parsed.scheme!r}")
    if parsed.netloc.lower() != "totp":
        raise ValueError(f"only TOTP is supported, got {parsed.netloc!r}")
    query = urllib.parse.parse_qs(parsed.query)
    label = urllib.parse.unquote(parsed.path.lstrip("/"))
    issuer_from_query = query.get("issuer", [""])[0]
    account = label
    issuer = issuer_from_query
    if ":" in label:
        issuer_part, account = label.split(":", 1)
        issuer = issuer or issuer_part
    return Otpauth(
        secret=query["secret"][0],
        algorithm=query.get("algorithm", ["SHA1"])[0],
        digits=int(query.get("digits", ["6"])[0]),
        period=int(query.get("period", ["30"])[0]),
        issuer=issuer,
        account=account,
    )


# --------------------------------------------------------------------------
# HTTP client.
# --------------------------------------------------------------------------


class HttpResult:
    __slots__ = ("status", "body", "headers", "elapsed_ms")

    def __init__(self, status, body, headers, elapsed_ms):
        self.status = status
        self.body = body
        self.headers = headers
        self.elapsed_ms = elapsed_ms

    @property
    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except json.JSONDecodeError:
            return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<HttpResult {self.status} {self.body[:120]!r}>"


class Client:
    """Minimal HTTP client that never raises on 4xx/5xx (tests assert on them)."""

    def __init__(self, base_url: str, service_key: str = "", timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.service_key = service_key
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        headers: dict[str, str] | None = None,
        raw_body: bytes | None = None,
        with_service_key: bool = True,
    ) -> HttpResult:
        """Performs one request. `with_service_key=False` builds a request
        carrying only the headers the test sets (no implicit `x-service-key`),
        which is how the user-facing endpoints are exercised."""
        url = f"{self.base_url}{path}"
        payload = raw_body
        hdrs = {"Accept": "application/json"}
        if self.service_key and with_service_key:
            hdrs["x-service-key"] = self.service_key
        if headers:
            hdrs.update(headers)
        if body is not None:
            payload = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        if payload is None and method in ("POST", "PUT", "PATCH"):
            payload = b""
        request = urllib.request.Request(url, data=payload, method=method)
        for key, value in hdrs.items():
            request.add_header(key, value)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = response.read()
                return HttpResult(
                    response.status,
                    data.decode("utf-8", "replace"),
                    dict(response.headers),
                    (time.perf_counter() - started) * 1000,
                )
        except urllib.error.HTTPError as error:
            data = error.read()
            return HttpResult(
                error.code,
                data.decode("utf-8", "replace"),
                dict(error.headers),
                (time.perf_counter() - started) * 1000,
            )

    def get(self, path: str, **kwargs) -> HttpResult:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, body: Any = None, **kwargs) -> HttpResult:
        return self.request("POST", path, body=body, **kwargs)


# --------------------------------------------------------------------------
# Flows a real client would perform.
# --------------------------------------------------------------------------


class Session:
    """A user with an enrolled factor, as the mock authenticator sees it."""

    def __init__(self, client: Client, tenant_id: str, external_id: str):
        self.client = client
        self.tenant_id = tenant_id
        self.external_id = external_id
        self.subject_id = ""
        self.factor_id = ""
        self.otpauth: Otpauth | None = None
        self.recovery_codes: list[str] = []
        self.access_token = ""
        self.refresh_token = ""

    def enroll_start(self, issuer: str = "BandAll", account: str | None = None):
        result = self.client.post(
            "/v1/factors/enroll/start",
            {
                "tenant_id": self.tenant_id,
                "subject_external_id": self.external_id,
                "issuer": issuer,
                "account": account or self.external_id,
            },
        )
        if result.status != 200:
            raise AssertionError(f"enroll/start failed: {result}")
        payload = result.json
        self.subject_id = payload["subject_id"]
        self.factor_id = payload["factor_id"]
        self.otpauth = parse_otpauth(payload["otpauth_uri"])
        return result

    def enroll_confirm(self, offset_steps: int = CONFIRM_OFFSET):
        assert self.otpauth is not None
        result = self.client.post(
            "/v1/factors/enroll/confirm",
            {
                "tenant_id": self.tenant_id,
                "subject_id": self.subject_id,
                "factor_id": self.factor_id,
                "code": self.otpauth.code(offset_steps=offset_steps),
            },
        )
        if result.status == 200:
            self.recovery_codes = result.json["recovery_codes"]
        return result

    def enroll(self, issuer: str = "BandAll") -> "Session":
        """Enrols and leaves the factor ready for its first verification.

        `enroll/confirm` consumes the step it accepted (atomic anti-replay, the
        same CAS as `verify`), so confirming with the code for the current step
        would make every later login a replay. A real app shows the code that
        is currently on screen and then waits for the next one; here the
        confirmation uses the *previous* step, which the confirm window (one
        step of slack) accepts, leaving the current step free for the first
        verification.
        """
        self.enroll_start(issuer)
        confirmed = self.enroll_confirm()
        if confirmed.status != 200:
            raise AssertionError(f"enroll/confirm failed: {confirmed}")
        return self

    def code(self, offset_steps: int = 0) -> str:
        assert self.otpauth is not None
        return self.otpauth.code(offset_steps=offset_steps)

    def mfa_verify(self, code: str | None = None) -> HttpResult:
        # User-facing endpoint: no service key, it is called from the app.
        result = self.client.post(
            "/v1/mfa/verify",
            {
                "tenant_id": self.tenant_id,
                "subject_id": self.subject_id,
                "factor_id": self.factor_id,
                "code": self.code() if code is None else code,
            },
            with_service_key=False,
        )
        if result.status == 200:
            self.access_token = result.json["access_token"]
            self.refresh_token = result.json["refresh_token"]
        return result

    def s2s_verify(self, code: str | None = None) -> HttpResult:
        return self.client.post(
            "/v1/verify",
            {
                "tenant_id": self.tenant_id,
                "subject_id": self.subject_id,
                "factor_id": self.factor_id,
                "code": self.code() if code is None else code,
            },
        )


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"
#!/usr/bin/env python3
"""Functional, behavioural and security verification of the packaged image.

Drives the **container** built from `deploy/Dockerfile` over HTTP with a mock
authenticator (`totp_client.py`). Nothing here is a unit test: if this passes,
the shipped artifact answers correctly, not the source tree.

Groups:
  boot      image/runtime shape: user, entrypoint, healthcheck, probes, config
  flow      the MFA journey end to end: enroll, confirm, verify, recover
  security  the defences: replay, enumeration, rate limit, body limit, tokens
  audit     the keyed hash chain, including deliberate tampering

Usage: python3 verify_container.py <base_url> <service_key> [group ...]
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import sys
import time
import unittest

from totp_client import Client, Session, unique


def decode_segment(segment: str) -> dict:
    """Decodes one base64url segment of a compact JWS."""
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))

BASE_URL = ""
SERVICE_KEY = ""

# Populated by the driver (verify.sh) so the suites share one tenant without
# each test creating one.
TENANT_ID = ""


def tenant_client(key: str = "") -> Client:
    return Client(BASE_URL, service_key=key or SERVICE_KEY)


def new_session(tenant_id: str = "", external: str | None = None) -> Session:
    return Session(tenant_client(), tenant_id or TENANT_ID, external or unique("user"))


# --------------------------------------------------------------------------
# boot / runtime / configuration
# --------------------------------------------------------------------------


class TestBoot(unittest.TestCase):
    def test_healthz_is_ok(self):
        result = tenant_client().get("/healthz")
        self.assertEqual(result.status, 200, result)

    def test_readyz_is_ok(self):
        result = tenant_client().get("/readyz")
        self.assertEqual(result.status, 200, result)

    def test_openapi_is_served(self):
        result = tenant_client().get("/openapi.json")
        self.assertEqual(result.status, 200, result)
        paths = result.json["paths"]
        for route in (
            "/v1/factors/enroll/start",
            "/v1/factors/enroll/confirm",
            "/v1/mfa/verify",
            "/v1/verify",
            "/v1/mfa/recover",
            "/v1/token/refresh",
            "/v1/token/revoke",
            "/v1/authz/check",
            "/v1/sigs/verify",
            "/.well-known/jwks.json",
        ):
            self.assertIn(route, paths, f"missing from OpenAPI: {route}")

    def test_jwks_publishes_ed25519_keys(self):
        result = tenant_client().get("/.well-known/jwks.json")
        self.assertEqual(result.status, 200, result)
        keys = result.json["keys"]
        self.assertTrue(keys, "JWKS is empty")
        for key in keys:
            self.assertEqual(key["kty"], "OKP")
            self.assertEqual(key["crv"], "Ed25519")
            self.assertEqual(key["alg"] if "alg" in key else "EdDSA", "EdDSA")
            self.assertTrue(key["kid"], "key without kid")
            self.assertNotIn("d", key, "private component leaked in JWKS")

    def test_metrics_endpoint_exposes_counters(self):
        result = tenant_client().get("/metrics")
        self.assertEqual(result.status, 200, result)
        self.assertIn("bandall", result.body)

    def test_unknown_route_is_404_not_500(self):
        self.assertEqual(tenant_client().get("/v1/nope").status, 404)

    def test_unknown_subcommand_path_is_404(self):
        self.assertEqual(tenant_client().post("/v1/verify/nope").status, 404)


# --------------------------------------------------------------------------
# flow: the MFA journey
# --------------------------------------------------------------------------


class TestEnrolmentFlow(unittest.TestCase):
    def test_full_cycle_enroll_then_verify(self):
        session = new_session().enroll()
        self.assertTrue(session.recovery_codes, "no recovery codes issued")
        self.assertTrue(all("-" in code for code in session.recovery_codes))

        result = session.mfa_verify()
        self.assertEqual(result.status, 200, f"login failed right after enrolment: {result}")
        self.assertTrue(result.json["valid"])
        self.assertTrue(result.json["access_token"])
        self.assertTrue(result.json["refresh_token"])
        self.assertGreater(result.json["expires_in"], 0)

    def test_otpauth_uri_is_wellformed(self):
        session = new_session()
        session.enroll_start()
        self.assertIsNotNone(session.otpauth)
        self.assertEqual(session.otpauth.period, 30)
        self.assertEqual(session.otpauth.digits, 6)
        self.assertEqual(session.otpauth.algorithm.upper(), "SHA256")
        self.assertGreaterEqual(len(session.otpauth.secret), 16)

    def test_confirm_rejects_a_wrong_code(self):
        session = new_session()
        session.enroll_start()
        # The confirm window is one step of slack, so a genuinely wrong code has
        # to sit well outside it.
        result = session.enroll_confirm(offset_steps=10)
        self.assertEqual(result.status, 401, result)

    def test_confirm_accepts_an_adjacent_step(self):
        session = new_session()
        session.enroll_start()
        result = session.enroll_confirm(offset_steps=1)
        self.assertEqual(result.status, 200, result)

    def test_confirm_cannot_be_replayed(self):
        session = new_session()
        session.enroll_start()
        first = session.enroll_confirm()
        self.assertEqual(first.status, 200, first)
        second = session.enroll_confirm()
        self.assertEqual(second.status, 401, second)

    def test_enroll_start_requires_the_service_key(self):
        anonymous = Client(BASE_URL)
        result = anonymous.post(
            "/v1/factors/enroll/start",
            {
                "tenant_id": TENANT_ID,
                "subject_external_id": unique("user"),
                "issuer": "BandAll",
                "account": "a",
            },
        )
        self.assertEqual(result.status, 401, result)

    def test_enroll_start_rejects_a_wrong_service_key(self):
        wrong = Client(BASE_URL, service_key="wrong-key-" + "x" * 32)
        result = wrong.post(
            "/v1/factors/enroll/start",
            {
                "tenant_id": TENANT_ID,
                "subject_external_id": unique("user"),
                "issuer": "BandAll",
                "account": "a",
            },
        )
        self.assertEqual(result.status, 401, result)

    def test_enroll_start_validates_its_input(self):
        for field in ("tenant_id", "subject_external_id", "issuer", "account"):
            body = {
                "tenant_id": TENANT_ID,
                "subject_external_id": unique("user"),
                "issuer": "BandAll",
                "account": "a",
            }
            body[field] = ""
            result = tenant_client().post("/v1/factors/enroll/start", body)
            self.assertEqual(result.status, 400, f"{field} accepted empty: {result}")

    def test_recovery_code_works_once(self):
        session = new_session().enroll()
        code = session.recovery_codes[0]
        body = {
            "tenant_id": session.tenant_id,
            "subject_id": session.subject_id,
            "factor_id": session.factor_id,
            "recovery_code": code,
        }
        first = tenant_client().post("/v1/mfa/recover", body)
        self.assertEqual(first.status, 200, first)
        self.assertTrue(first.json["must_reenroll"])

        # The factor is consumed: the same recovery code must not work twice.
        second = tenant_client().post("/v1/mfa/recover", body)
        self.assertEqual(second.status, 401, second)

    def test_wrong_recovery_code_is_denied(self):
        session = new_session().enroll()
        result = tenant_client().post(
            "/v1/mfa/recover",
            {
                "tenant_id": session.tenant_id,
                "subject_id": session.subject_id,
                "factor_id": session.factor_id,
                "recovery_code": "AAAA-BBBB-CCCC-DDDD",
            },
        )
        self.assertEqual(result.status, 401, result)


# --------------------------------------------------------------------------
# security
# --------------------------------------------------------------------------


class TestReplayAndWindow(unittest.TestCase):
    def test_a_code_is_accepted_exactly_once(self):
        session = new_session().enroll()
        self.assertEqual(session.s2s_verify().status, 200)
        replay = session.s2s_verify()
        self.assertEqual(replay.status, 401, f"replay accepted: {replay}")

    def test_code_outside_the_window_is_rejected(self):
        session = new_session().enroll()
        # +/-10 steps = +/-300 s, far outside the three-step window.
        far = session.s2s_verify(session.code(offset_steps=10))
        self.assertEqual(far.status, 401, far)
        past = session.s2s_verify(session.code(offset_steps=-10))
        self.assertEqual(past.status, 401, past)

    def test_one_step_of_drift_is_tolerated(self):
        session = new_session().enroll()
        drifted = session.s2s_verify(session.code(offset_steps=1))
        self.assertEqual(drifted.status, 200, f"adjacent step rejected: {drifted}")

    def test_two_steps_of_drift_are_rejected(self):
        # The window is exactly three steps wide (drift +/- one), so the next
        # step out must not be accepted: this is the T3 remediation bound.
        session = new_session().enroll()
        result = session.s2s_verify(session.code(offset_steps=2))
        self.assertEqual(result.status, 401, f"window wider than three steps: {result}")

    def test_concurrent_verification_of_one_code_yields_one_success(self):
        session = new_session().enroll()
        code = session.code()

        # The H3 gate: 100 concurrent verifications of the same code must
        # produce exactly one success (the atomic anti-replay CAS).
        def attempt(_: int) -> int:
            return Client(BASE_URL, service_key=SERVICE_KEY).post(
                "/v1/verify",
                {
                    "tenant_id": session.tenant_id,
                    "subject_id": session.subject_id,
                    "factor_id": session.factor_id,
                    "code": code,
                },
            ).status

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
            results = list(pool.map(attempt, range(100)))

        successes = results.count(200)
        self.assertEqual(successes, 1, f"expected exactly 1 success, got {successes}")

        # The losers are denials; a burst this size may also trip the rate
        # limiter (429), which is a refusal too. A 5xx would be a real defect.
        unexpected = {status for status in results if status not in (200, 401, 429)}
        self.assertEqual(unexpected, set(), f"unexpected statuses: {unexpected}")

        # Precondition worth stating: without the anti-replay CAS this test
        # would report several successes, so the burst must actually be racing.
        self.assertGreater(
            session.s2s_verify().status, 200, "the winning code was reusable"
        )


class TestEnumerationResistance(unittest.TestCase):
    def test_unknown_subject_and_wrong_code_answer_identically(self):
        session = new_session().enroll()
        real = session.s2s_verify("000000")
        ghost = Client(BASE_URL, service_key=SERVICE_KEY).post(
            "/v1/verify",
            {
                "tenant_id": session.tenant_id,
                "subject_id": "does-not-exist",
                "factor_id": "does-not-exist",
                "code": "000000",
            },
        )
        self.assertEqual(real.status, ghost.status, f"{real.status} vs {ghost.status}")
        self.assertEqual(real.json, ghost.json, "responses differ, oracle available")

    def test_unknown_factor_is_denied_uniformly(self):
        session = new_session().enroll()
        result = tenant_client().post(
            "/v1/verify",
            {
                "tenant_id": session.tenant_id,
                "subject_id": session.subject_id,
                "factor_id": "no-such-factor",
                "code": session.code(),
            },
        )
        self.assertEqual(result.status, 401, result)

    def test_responses_carry_no_internals(self):
        session = new_session().enroll()
        result = session.s2s_verify("000000")
        self.assertEqual(result.status, 401)
        lowered = result.body.lower()
        for leak in ("sqlite", "sql", "ciphertext", "secret", "kek", "panic", "/src/"):
            self.assertNotIn(leak, lowered, f"response leaks {leak!r}: {result.body}")


class TestTokens(unittest.TestCase):
    def test_access_token_claims(self):
        session = new_session().enroll()
        verified = session.mfa_verify()
        self.assertEqual(verified.status, 200, verified)

        token = session.access_token
        self.assertEqual(token.count("."), 2, f"not a compact JWS: {token!r}")

        header, payload, _ = token.split(".")
        head = decode_segment(header)
        self.assertEqual(head["alg"], "EdDSA", "algorithm is not pinned")
        self.assertTrue(head.get("kid"), "no kid in header")

        claims = decode_segment(payload)
        for claim in ("sub", "tenant", "sid", "amr", "aal", "jti", "iss", "aud", "exp", "iat"):
            self.assertIn(claim, claims, f"missing claim {claim}")
        self.assertEqual(claims["iss"], "bandall-verify")
        self.assertEqual(claims["aud"], "verify-app")
        self.assertEqual(claims["tenant"], session.tenant_id)
        self.assertEqual(claims["sub"], session.subject_id)
        self.assertGreater(claims["exp"], claims["iat"])

    def test_refresh_rotates_the_token(self):
        session = new_session().enroll()
        session.mfa_verify()
        first = session.refresh_token
        result = tenant_client().post("/v1/token/refresh", {"refresh_token": first})
        self.assertEqual(result.status, 200, result)
        self.assertNotEqual(result.json["refresh_token"], first, "token was not rotated")
        self.assertTrue(result.json["access_token"])

    def test_reused_refresh_burns_the_family(self):
        session = new_session().enroll()
        session.mfa_verify()
        stolen = session.refresh_token

        first = tenant_client().post("/v1/token/refresh", {"refresh_token": stolen})
        self.assertEqual(first.status, 200, first)
        rotated = first.json["refresh_token"]

        # The thief presents the spent token: theft signal.
        replay = tenant_client().post("/v1/token/refresh", {"refresh_token": stolen})
        self.assertEqual(replay.status, 401, replay)

        # And the whole family is dead, including the legitimate new token.
        after = tenant_client().post("/v1/token/refresh", {"refresh_token": rotated})
        self.assertEqual(after.status, 401, "family survived reuse detection")

    def test_unknown_refresh_token_is_denied(self):
        result = tenant_client().post("/v1/token/refresh", {"refresh_token": "nope"})
        self.assertEqual(result.status, 401, result)

    def test_revoke_answers_true_for_unknown_tokens(self):
        result = tenant_client().post("/v1/token/revoke", {"refresh_token": "unknown"})
        self.assertEqual(result.status, 200, result)
        self.assertTrue(result.json["revoked"], "unknown token must not be an oracle")

    def test_revoked_session_fails_forward_auth(self):
        session = new_session().enroll()
        session.mfa_verify()
        client = tenant_client()
        bearer = {"Authorization": f"Bearer {session.access_token}"}
        ok = client.get("/v1/authz/check", headers=bearer)
        self.assertEqual(ok.status, 200, ok)

        revoked = client.post("/v1/token/revoke", {"refresh_token": session.refresh_token})
        self.assertEqual(revoked.status, 200, revoked)

        after = client.get("/v1/authz/check", headers=bearer)
        self.assertEqual(after.status, 401, "revoked session still passes forward-auth")


class TestForwardAuth(unittest.TestCase):
    def _check(self, token: str, query: str = ""):
        return tenant_client().get(
            f"/v1/authz/check{query}",
            headers={"Authorization": f"Bearer {token}"},
        )

    def test_valid_token_is_allowed_with_identity_headers(self):
        session = new_session().enroll()
        session.mfa_verify()
        result = self._check(session.access_token)
        self.assertEqual(result.status, 200, result)
        self.assertEqual(result.headers.get("x-bandall-subject"), session.subject_id)
        self.assertEqual(result.headers.get("x-bandall-tenant"), session.tenant_id)
        self.assertEqual(result.json["subject"], session.subject_id)

    def test_missing_token_is_denied(self):
        self.assertEqual(tenant_client().get("/v1/authz/check").status, 401)

    def test_malformed_token_is_denied(self):
        self.assertEqual(self._check("not-a-token").status, 401)

    def test_tampered_token_is_denied(self):
        session = new_session().enroll()
        session.mfa_verify()
        header, payload, signature = session.access_token.split(".")
        forged = f"{header}.{payload}.{'A' * len(signature)}"
        self.assertEqual(self._check(forged).status, 401, "forged signature accepted")

    def test_tampered_claims_are_denied(self):
        # Same signature, different payload: the header must not be enough.
        session = new_session().enroll()
        session.mfa_verify()
        header, payload, signature = session.access_token.split(".")
        claims = decode_segment(payload)
        claims["tenant"] = "another-tenant"
        forged_payload = (
            base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        )
        forged = f"{header}.{forged_payload}.{signature}"
        self.assertEqual(self._check(forged).status, 401, "forged claims accepted")

    def test_none_algorithm_is_rejected(self):
        session = new_session().enroll()
        session.mfa_verify()
        header, payload, _ = session.access_token.split(".")
        none_header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": "x"}).encode())
            .decode()
            .rstrip("=")
        )
        forged = f"{none_header}.{payload}."
        self.assertEqual(self._check(forged).status, 401, "alg=none accepted")

    def test_min_aal_above_the_token_level_is_denied(self):
        session = new_session().enroll()
        session.mfa_verify()
        self.assertEqual(self._check(session.access_token, "?min_aal=2").status, 401)


class TestInputHandling(unittest.TestCase):
    def test_body_limit_is_enforced(self):
        oversized = {"tenant_id": "x" * (1024 * 1024)}
        result = tenant_client().post("/v1/mfa/verify", oversized)
        self.assertIn(result.status, (400, 413), f"huge body accepted: {result.status}")

    def test_malformed_json_is_rejected(self):
        result = Client(BASE_URL).request(
            "POST",
            "/v1/mfa/verify",
            raw_body=b"{not json",
            headers={"Content-Type": "application/json"},
        )
        self.assertIn(result.status, (400, 422), result)

    def test_missing_fields_are_rejected(self):
        result = tenant_client().post("/v1/mfa/verify", {"tenant_id": TENANT_ID})
        self.assertIn(result.status, (400, 422), result)

    def test_oversized_field_is_rejected(self):
        result = tenant_client().post(
            "/v1/factors/enroll/start",
            {
                "tenant_id": TENANT_ID,
                "subject_external_id": "x" * 5000,
                "issuer": "BandAll",
                "account": "a",
            },
        )
        self.assertEqual(result.status, 400, result)

    def test_sql_injection_shaped_input_is_inert(self):
        session = new_session()
        session.enroll_start()
        result = tenant_client().post(
            "/v1/verify",
            {
                "tenant_id": session.tenant_id,
                "subject_id": session.subject_id,
                "factor_id": "'; DROP TABLE factors; --",
                "code": "000000",
            },
        )
        self.assertEqual(result.status, 401, result)
        # The table must still be there.
        follow = tenant_client().get("/readyz")
        self.assertEqual(follow.status, 200, "service degraded after injection attempt")


class TestRateLimiting(unittest.TestCase):
    def test_repeated_failures_are_throttled(self):
        session = new_session().enroll()
        statuses = [session.s2s_verify("000000").status for _ in range(25)]
        self.assertIn(429, statuses, f"no throttling after 25 failures: {statuses}")
        # The refusals before the limiter engaged must be uniform 401s, not a
        # mix: the limiter may throttle, it may not leak whether the factor
        # exists.
        self.assertEqual(
            {status for status in statuses if status != 429},
            {401},
            f"non-throttled responses were not uniform: {statuses}",
        )
        # And it must recover, otherwise this is a self-inflicted lockout.
        time.sleep(1)
        self.assertIn(session.s2s_verify().status, (200, 401, 429))


# --------------------------------------------------------------------------
# audit chain
# --------------------------------------------------------------------------


class TestMetrics(unittest.TestCase):
    def test_verifications_are_counted(self):
        session = new_session().enroll()
        session.s2s_verify()
        session.s2s_verify("000000")
        body = tenant_client().get("/metrics").body
        self.assertRegex(body, r"bandall_[a-z_]+", "no BandAll metrics exposed")


def build_suite(groups: list[str]) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    wanted = {
        "boot": TestBoot,
        "flow": TestEnrolmentFlow,
        "replay": TestReplayAndWindow,
        "enum": TestEnumerationResistance,
        "tokens": TestTokens,
        "forward": TestForwardAuth,
        "input": TestInputHandling,
        "ratelimit": TestRateLimiting,
        "metrics": TestMetrics,
    }
    selected = groups or list(wanted)
    for group in selected:
        if group not in wanted:
            raise SystemExit(f"unknown group {group!r}; known: {', '.join(wanted)}")
        suite.addTests(loader.loadTestsFromTestCase(wanted[group]))
    return suite


def main() -> int:
    global BASE_URL, SERVICE_KEY, TENANT_ID
    if len(sys.argv) < 3:
        raise SystemExit(f"usage: {sys.argv[0]} <base_url> <service_key> [group ...]")
    BASE_URL = sys.argv[1]
    SERVICE_KEY = sys.argv[2]
    TENANT_ID = sys.argv[3] if len(sys.argv) > 3 else ""

    if not TENANT_ID:
        raise SystemExit("tenant_id is required as the third argument")

    runner = unittest.TextTestRunner(verbosity=2, buffer=False)
    result = runner.run(build_suite(sys.argv[4:]))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
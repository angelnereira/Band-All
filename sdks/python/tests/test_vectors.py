"""Conformance: every SDK passes the same vectors (sdks/conformance)."""

import json
import unittest
from pathlib import Path

from bandall_sdk.hmac import SignRequest, canonical, sign, verify_signature
from bandall_sdk.jwt import verify_jwt

VECTORS = json.loads(Path(__file__).resolve().parent.parent.parent.joinpath("conformance", "vectors.json").read_text())
NOW = VECTORS["now_secs"]
JWT = VECTORS["jwt"]
HMAC_V = VECTORS["hmac"]


class JwtTest(unittest.TestCase):
    def options(self):
        return {"issuer": JWT["issuer"], "audience": JWT["audience"], "now_secs": NOW}

    def test_valid_token(self):
        claims = verify_jwt(JWT["jwks"], JWT["valid"], **self.options())
        self.assertEqual(claims["sub"], "alice")
        self.assertEqual(claims["aal"], 1)

    def test_rejections(self):
        for bad in (JWT["tampered"], JWT["wrong_aud"], JWT["expired"], JWT["none_alg"]):
            with self.assertRaises(ValueError, msg=bad[:20]):
                verify_jwt(JWT["jwks"], bad, **self.options())


class HmacTest(unittest.TestCase):
    def request(self):
        return SignRequest(
            method=HMAC_V["method"],
            path=HMAC_V["path"],
            query=HMAC_V["query"],
            body=HMAC_V["body"].encode(),
            timestamp=HMAC_V["timestamp"],
            nonce=HMAC_V["nonce"],
        )

    def test_canonical_and_signature(self):
        req = self.request()
        self.assertEqual(canonical(req), HMAC_V["canonical"])
        self.assertEqual(sign(HMAC_V["key_hex"], req), HMAC_V["signature"])

    def test_verify_and_replay(self):
        req = self.request()
        seen = {}
        options = {
            "now_secs": NOW,
            "is_replay": lambda n: seen.get(n, 0) > NOW,
            "remember": lambda n, exp: seen.update({n: exp}),
        }
        verify_signature(HMAC_V["key_hex"], req, HMAC_V["signature"], **options)
        with self.assertRaises(ValueError):
            verify_signature(HMAC_V["key_hex"], req, HMAC_V["signature"], **options)

    def test_stale(self):
        with self.assertRaises(ValueError):
            verify_signature(
                HMAC_V["key_hex"], self.request(), HMAC_V["signature"], NOW + 10_000
            )


if __name__ == "__main__":
    unittest.main()

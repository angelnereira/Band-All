#!/usr/bin/env python3
"""HMAC request-signature verification against the running container.

Creates a throwaway API client with `bandall apikey create`, then exercises
`POST /v1/sigs/verify` with a mock signer built from the canonical string the
spec defines. Asserts the property that matters: a signature verifies only over
the exact method/path/query/body/timestamp/nonce it was made for.

Usage: python3 verify_sigs.py <base_url> <key_id> <hex_key> [scope]
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import unittest
import uuid

from totp_client import Client

BASE_URL = ""
KEY_ID = ""
KEY = b""
SCOPE = "verify"

CLOCK_TOLERANCE = 300  # +/-5 min, per blueprint section 10


def canonical(method: str, path: str, query: str, body: str, timestamp: int, nonce: str) -> str:
    body_hash = hashlib.sha256(body.encode()).hexdigest()
    return f"{method.upper()}\n{path}\n{query}\n{body_hash}\n{timestamp}\n{nonce}"


def sign(key: bytes, method: str, path: str, query: str, body: str, timestamp: int, nonce: str) -> str:
    message = canonical(method, path, query, body, timestamp, nonce)
    return "v1=" + hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


class TestSignatures(unittest.TestCase):
    def _envelope(self, **overrides):
        nonce = overrides.pop("nonce", uuid.uuid4().hex)
        timestamp = overrides.pop("timestamp", int(time.time()))
        method = overrides.pop("method", "POST")
        path = overrides.pop("path", "/v1/orders")
        query = overrides.pop("query", "")
        body = overrides.pop("body", '{"amount":10}')
        signature = overrides.pop(
            "signature",
            sign(self.key, method, path, query, body, timestamp, nonce),
        )
        envelope = {
            "key_id": self.key_id,
            "method": method,
            "path": path,
            "query": query,
            "body": body,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
            "scope": SCOPE,
        }
        envelope.update(overrides)
        return envelope

    def setUp(self):
        self.key = KEY
        self.key_id = KEY_ID
        self.client = Client(BASE_URL)

    def _post(self, envelope):
        return self.client.post("/v1/sigs/verify", envelope)

    def test_valid_signature_is_accepted(self):
        result = self._post(self._envelope())
        self.assertEqual(result.status, 200, result)
        self.assertTrue(result.json["valid"])
        self.assertEqual(result.json["key_id"], self.key_id)

    def test_nonce_is_single_use(self):
        envelope = self._envelope()
        first = self._post(envelope)
        self.assertEqual(first.status, 200, first)
        second = self._post(envelope)
        self.assertEqual(second.status, 401, f"nonce replayed: {second}")

    def test_body_tampering_is_detected(self):
        envelope = self._envelope()
        envelope["body"] = '{"amount":1000}'
        result = self._post(envelope)
        self.assertEqual(result.status, 401, f"body change accepted: {result}")

    def test_path_tampering_is_detected(self):
        envelope = self._envelope()
        envelope["path"] = "/v1/admin"
        self.assertEqual(self._post(envelope).status, 401)

    def test_method_tampering_is_detected(self):
        envelope = self._envelope()
        envelope["method"] = "DELETE"
        self.assertEqual(self._post(envelope).status, 401)

    def test_signature_over_an_arbitrary_path_is_still_valid(self):
        # The counterpart of the test above: signing over whatever path you
        # actually mean must work, otherwise the tamper test above would pass
        # for the wrong reason (a broken canonical string rather than a
        # detected modification).
        envelope = self._envelope(path="/v1/admin")
        self.assertEqual(self._post(envelope).status, 200, envelope)

    def test_signature_over_an_empty_query_is_still_valid(self):
        envelope = self._envelope(query="")
        self.assertEqual(self._post(envelope).status, 200, envelope)

    def test_signature_over_a_present_query_is_still_valid(self):
        envelope = self._envelope(query="admin=1")
        self.assertEqual(self._post(envelope).status, 200, envelope)

    def test_query_tampering_is_detected(self):
        # Sign over an empty query, then append one: a proxy that adds
        # parameters must not be able to smuggle them past the signature.
        envelope = self._envelope()
        envelope["query"] = "admin=1"
        self.assertEqual(self._post(envelope).status, 401)

    def test_wrong_key_is_rejected(self):
        envelope = self._envelope()
        envelope["signature"] = sign(b"\x00" * 32, "POST", "/v1/orders", "", '{"amount":10}', envelope["timestamp"], envelope["nonce"])
        self.assertEqual(self._post(envelope).status, 401)

    def test_stale_timestamp_is_rejected(self):
        old = int(time.time()) - CLOCK_TOLERANCE - 60
        self.assertEqual(self._post(self._envelope(timestamp=old)).status, 401)

    def test_future_timestamp_is_rejected(self):
        ahead = int(time.time()) + CLOCK_TOLERANCE + 60
        self.assertEqual(self._post(self._envelope(timestamp=ahead)).status, 401)

    def test_unknown_key_id_is_denied(self):
        self.assertEqual(self._post(self._envelope(key_id="key-does-not-exist")).status, 401)

    def test_missing_scope_grant_is_denied(self):
        envelope = self._envelope(scope="admin")
        self.assertEqual(self._post(envelope).status, 401)

    def test_malformed_envelope_is_a_bad_request(self):
        result = self._post(self._envelope(signature="no-version-prefix"))
        self.assertEqual(result.status, 400, result)

    def test_header_injection_in_the_canonical_string_is_rejected(self):
        # A newline inside a signed field would otherwise let a signer forge
        # extra canonical lines.
        envelope = self._envelope(path="/v1/orders\nX-Injected: 1")
        self.assertIn(self._post(envelope).status, (400, 401), envelope)


def main() -> int:
    global BASE_URL, KEY_ID, KEY, SCOPE
    if len(sys.argv) < 4:
        raise SystemExit(f"usage: {sys.argv[0]} <base_url> <key_id> <hex_key> [scope]")
    BASE_URL, KEY_ID, KEY = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3])
    if len(sys.argv) > 4:
        SCOPE = sys.argv[4]

    suite = unittest.TestLoader().loadTestsFromTestCase(TestSignatures)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
from __future__ import annotations

import unittest

from reset_tokens import TokenIssuer, TokenPurpose, digest_token
from reset_tokens.errors import TokenInvalidError
from reset_tokens.tokens import TOKEN_PREFIX

from .base import TEST_TTL_MS, TokenLifecycleTestCase


class TokenIssuerTest(TokenLifecycleTestCase):
    def test_token_carries_required_prefix(self) -> None:
        raw_token, _ = self.issuer.issue("user-1", "a@example.com", self.clock())
        self.assertTrue(raw_token.startswith(TOKEN_PREFIX))

    def test_round_trip_preserves_all_claims(self) -> None:
        raw_token, token = self.issuer.issue(
            "user-7", "seven@example.com", self.clock()
        )
        parsed = self.issuer.verify(raw_token)
        self.assertEqual(parsed, token)
        self.assertEqual(parsed.user_id, "user-7")
        self.assertEqual(parsed.email, "seven@example.com")
        self.assertEqual(parsed.purpose, TokenPurpose.PASSWORD_RESET.value)
        self.assertEqual(parsed.issued_at_ms, self.clock())
        self.assertEqual(len(parsed.nonce), 32)

    def test_each_issue_gets_a_unique_nonce(self) -> None:
        first, token_a = self.issuer.issue("u", "u@example.com", self.clock())
        second, token_b = self.issuer.issue("u", "u@example.com", self.clock())
        self.assertNotEqual(first, second)
        self.assertNotEqual(token_a.nonce, token_b.nonce)
        self.assertNotEqual(digest_token(first), digest_token(second))

    def test_signature_tampering_is_rejected(self) -> None:
        raw_token, _ = self.issuer.issue("u", "u@example.com", self.clock())
        head, signature = raw_token.rsplit(".", 1)
        flipped = signature[:-1] + ("A" if signature[-1] != "A" else "B")
        with self.assertRaises(TokenInvalidError):
            self.issuer.verify(f"{head}.{flipped}")

    def test_payload_tampering_is_rejected(self) -> None:
        raw_token, _ = self.issuer.issue("u", "u@example.com", self.clock())
        _, signature = raw_token.rsplit(".", 1)
        payload = raw_token[len(TOKEN_PREFIX) :].split(".", 1)[0]
        tampered = payload[:-1] + ("A" if payload[-1] != "A" else "B")
        with self.assertRaises(TokenInvalidError):
            self.issuer.verify(f"{TOKEN_PREFIX}{tampered}.{signature}")

    def test_garbage_and_foreign_prefix_are_rejected(self) -> None:
        for garbage in ("", "not-a-token", "xyz.payload.sig", TOKEN_PREFIX + "onlyonepart"):
            with self.subTest(garbage=garbage):
                with self.assertRaises(TokenInvalidError):
                    self.issuer.verify(garbage)

    def test_secret_rotation_invalidates_old_signatures(self) -> None:
        raw_token, _ = self.issuer.issue("u", "u@example.com", self.clock())
        rotated = TokenIssuer("a-completely-different-secret", TEST_TTL_MS)
        with self.assertRaises(TokenInvalidError):
            rotated.verify(raw_token)

    def test_expiry_boundary_is_exclusive_at_ttl(self) -> None:
        raw_token, token = self.issuer.issue("u", "u@example.com", self.clock())
        self.issuer.verify(raw_token)
        self.assertFalse(self.issuer.is_expired(token, self.clock() + TEST_TTL_MS - 1))
        self.assertTrue(self.issuer.is_expired(token, self.clock() + TEST_TTL_MS))
        self.assertTrue(self.issuer.is_expired(token, self.clock() + TEST_TTL_MS + 1))


if __name__ == "__main__":
    unittest.main()

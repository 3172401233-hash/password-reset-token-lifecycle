from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from enum import Enum

from .errors import TokenInvalidError

TOKEN_PREFIX = "prt_"


class TokenPurpose(str, Enum):
    PASSWORD_RESET = "password_reset"


@dataclass(frozen=True)
class Token:
    user_id: str
    email: str
    purpose: str
    nonce: str
    issued_at_ms: int

    def to_claims(self) -> dict[str, object]:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "purpose": self.purpose,
            "nonce": self.nonce,
            "iat": self.issued_at_ms,
        }

    @classmethod
    def from_claims(cls, claims: object) -> "Token":
        if not isinstance(claims, dict):
            raise TokenInvalidError("token payload is not an object")
        required = ("user_id", "email", "purpose", "nonce", "iat")
        if any(key not in claims for key in required):
            raise TokenInvalidError("token payload is missing required claims")
        if not isinstance(claims["iat"], int) or isinstance(claims["iat"], bool):
            raise TokenInvalidError("token issued-at claim must be an integer")
        return cls(
            user_id=str(claims["user_id"]),
            email=str(claims["email"]),
            purpose=str(claims["purpose"]),
            nonce=str(claims["nonce"]),
            issued_at_ms=claims["iat"],
        )


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(encoded: str) -> bytes:
    try:
        padding = "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(encoded + padding)
    except (ValueError, TypeError) as exc:
        raise TokenInvalidError("token segment is not valid base64") from exc


def digest_token(raw_token: str) -> str:
    """Return the irreversible SHA-256 digest stored in the database."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class TokenIssuer:
    """Issues and verifies stateless, HMAC-signed reset tokens.

    A token binds together the user id, the email address it was requested
    for, its purpose, a per-token nonce and the issuance timestamp. Only the
    SHA-256 digest of a token ever lands in persistent storage.
    """

    NONCE_BYTES = 16

    def __init__(self, secret: bytes | str, ttl_ms: int):
        if not secret:
            raise ValueError("a non-empty HMAC secret is required")
        if ttl_ms <= 0:
            raise ValueError("ttl_ms must be positive")
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        self.ttl_ms = ttl_ms

    def issue(
        self,
        user_id: str,
        email: str,
        now_ms: int,
        purpose: TokenPurpose | str = TokenPurpose.PASSWORD_RESET,
    ) -> tuple[str, Token]:
        purpose_value = purpose.value if isinstance(purpose, TokenPurpose) else str(purpose)
        token = Token(
            user_id=str(user_id),
            email=str(email),
            purpose=purpose_value,
            nonce=secrets.token_hex(self.NONCE_BYTES),
            issued_at_ms=now_ms,
        )
        payload = _b64encode(
            json.dumps(token.to_claims(), separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signature = _b64encode(self._sign(payload))
        raw_token = f"{TOKEN_PREFIX}{payload}.{signature}"
        return raw_token, token

    def verify(self, raw_token: str) -> Token:
        if not isinstance(raw_token, str) or not raw_token.startswith(TOKEN_PREFIX):
            raise TokenInvalidError("unrecognised token prefix")
        body = raw_token[len(TOKEN_PREFIX) :]
        parts = body.split(".")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise TokenInvalidError("token must contain a payload and a signature")
        payload, signature = parts
        expected = self._sign(payload)
        provided = _b64decode(signature)
        if not hmac.compare_digest(expected, provided):
            raise TokenInvalidError("token signature does not match")
        try:
            claims = json.loads(_b64decode(payload).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TokenInvalidError("token payload is not valid JSON") from exc
        return Token.from_claims(claims)

    def is_expired(self, token: Token, now_ms: int) -> bool:
        return now_ms - token.issued_at_ms >= self.ttl_ms

    def _sign(self, payload: str) -> bytes:
        return hmac.new(self._secret, payload.encode("ascii"), hashlib.sha256).digest()

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from . import store as store_module
from .errors import (
    TokenBindingError,
    TokenConsumedError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from .tokens import TOKEN_PREFIX, Token, TokenIssuer, TokenPurpose, digest_token

logger = logging.getLogger("reset_tokens")


def now_epoch_ms() -> int:
    return int(time.time() * 1000)


def redact_token(raw_token: str) -> str:
    """Return a log-safe placeholder that never contains token material."""
    if not isinstance(raw_token, str) or not raw_token:
        return "<no-token>"
    return f"{TOKEN_PREFIX}***redacted***"


@dataclass(frozen=True)
class RedemptionResult:
    user_id: str
    email: str
    revoked_sessions: int
    revoked_tokens: int


@dataclass(frozen=True)
class EmailChangeResult:
    revoked_tokens: int


class ResetTokenService:
    """Application-facing facade for the reset-token lifecycle.

    Tokens are HMAC-signed by :class:`TokenIssuer`; only their SHA-256
    digests are persisted via :class:`SQLiteTokenStore`. Every log line uses
    a truncated digest reference, so a valid token can never appear in logs.
    """

    def __init__(
        self,
        issuer: TokenIssuer,
        store: store_module.SQLiteTokenStore,
        *,
        clock: Callable[[], int] = now_epoch_ms,
    ) -> None:
        self._issuer = issuer
        self._store = store
        self._clock = clock

    @staticmethod
    def _digest_ref(digest: str) -> str:
        return digest[:12]

    def request_reset(
        self,
        user_id: str,
        email: str,
        *,
        purpose: TokenPurpose | str = TokenPurpose.PASSWORD_RESET,
    ) -> str:
        """Issue a fresh reset token and persist its digest only."""
        now_ms = self._clock()
        raw_token, token = self._issuer.issue(user_id, email, now_ms, purpose)
        digest = digest_token(raw_token)
        self._store.save_token(token, digest, now_ms, now_ms + self._issuer.ttl_ms)
        logger.info(
            "reset token issued user_id=%s purpose=%s digest_ref=%s",
            user_id,
            token.purpose,
            self._digest_ref(digest),
        )
        return raw_token

    def redeem(
        self,
        raw_token: str,
        *,
        expected_user_id: str | None = None,
        expected_email: str | None = None,
        expected_purpose: TokenPurpose | str = TokenPurpose.PASSWORD_RESET,
    ) -> RedemptionResult:
        """Atomically consume a token or raise a typed error.

        On success all of the user's sessions and every other unused token
        are revoked inside the same database transaction.
        """
        token = self._issuer.verify(raw_token)
        now_ms = self._clock()
        if self._issuer.is_expired(token, now_ms):
            logger.info(
                "rejected expired reset token user_id=%s digest_ref=%s",
                token.user_id,
                self._digest_ref(digest_token(raw_token)),
            )
            raise TokenExpiredError("reset token has expired")

        purpose_value = (
            expected_purpose.value
            if isinstance(expected_purpose, TokenPurpose)
            else str(expected_purpose)
        )
        if expected_user_id is not None and token.user_id != str(expected_user_id):
            raise TokenBindingError("token is bound to a different user account")
        if expected_email is not None and token.email != str(expected_email):
            raise TokenBindingError("token is bound to a different email address")
        if token.purpose != purpose_value:
            raise TokenBindingError("token purpose does not match the requested operation")

        digest = digest_token(raw_token)
        outcome = self._store.consume_token(digest, token, now_ms)
        status = outcome["status"]
        digest_ref = self._digest_ref(digest)
        if status == store_module.CONSUME_OK:
            logger.info(
                "reset token consumed user_id=%s digest_ref=%s revoked_sessions=%d "
                "revoked_tokens=%d",
                token.user_id,
                digest_ref,
                outcome["revoked_sessions"],
                outcome["revoked_tokens"],
            )
            return RedemptionResult(
                user_id=token.user_id,
                email=token.email,
                revoked_sessions=outcome["revoked_sessions"],
                revoked_tokens=outcome["revoked_tokens"],
            )
        self._raise_for_failed_consumption(status, token, digest_ref)

    def _raise_for_failed_consumption(
        self, status: str, token: Token, digest_ref: str
    ) -> None:
        if status == store_module.CONSUME_UNKNOWN:
            logger.info("rejected unknown reset token digest_ref=%s", digest_ref)
            raise TokenInvalidError("reset token is not recognized")
        if status == store_module.CONSUME_BINDING_MISMATCH:
            logger.info(
                "rejected token with mismatched binding user_id=%s digest_ref=%s",
                token.user_id,
                digest_ref,
            )
            raise TokenBindingError("stored token binding does not match the presented token")
        if status == store_module.CONSUME_CONSUMED:
            logger.info(
                "rejected already-consumed reset token user_id=%s digest_ref=%s",
                token.user_id,
                digest_ref,
            )
            raise TokenConsumedError("reset token has already been used")
        if status == store_module.CONSUME_REVOKED:
            logger.info(
                "rejected revoked reset token user_id=%s digest_ref=%s",
                token.user_id,
                digest_ref,
            )
            raise TokenRevokedError("reset token has been revoked")
        if status == store_module.CONSUME_EXPIRED:
            logger.info(
                "rejected expired reset token at store boundary user_id=%s digest_ref=%s",
                token.user_id,
                digest_ref,
            )
            raise TokenExpiredError("reset token has expired")
        raise TokenInvalidError(f"unexpected token consumption status: {status}")  # pragma: no cover

    def on_email_changed(self, user_id: str, old_email: str, new_email: str) -> EmailChangeResult:
        """Revoke every unused token still bound to the user's old email."""
        if old_email == new_email:
            return EmailChangeResult(revoked_tokens=0)
        now_ms = self._clock()
        revoked = self._store.revoke_unused_tokens_for_email(user_id, old_email, now_ms)
        logger.info(
            "email change revoked outstanding reset tokens user_id=%s count=%d",
            user_id,
            revoked,
        )
        return EmailChangeResult(revoked_tokens=revoked)

    def prune_expired(self) -> int:
        revoked = self._store.prune_expired(self._clock())
        if revoked:
            logger.info("pruned expired reset tokens count=%d", revoked)
        return revoked

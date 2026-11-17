from __future__ import annotations

import sqlite3
import threading

from reset_tokens import (
    SQLiteTokenStore,
    ResetTokenService,
    StoreUnavailableError,
    TokenBindingError,
    TokenConsumedError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    digest_token,
)
from reset_tokens import store as store_module

from .base import FlakyDatabase, TokenLifecycleTestCase


class RedemptionFlowTest(TokenLifecycleTestCase):
    def test_happy_path_consumes_and_revokes_sessions(self) -> None:
        session_one = self.store.create_session("user-1", self.clock())
        session_two = self.store.create_session("user-1", self.clock())
        raw_token = self.service.request_reset("user-1", "old@example.com")

        result = self.service.redeem(raw_token)

        self.assertEqual(result.user_id, "user-1")
        self.assertEqual(result.email, "old@example.com")
        self.assertEqual(result.revoked_sessions, 2)
        self.assertTrue(self.store.is_session_revoked(session_one))
        self.assertTrue(self.store.is_session_revoked(session_two))
        self.assertEqual(
            self.store.get_token_state(digest_token(raw_token)),
            store_module.STATE_CONSUMED,
        )

    def test_duplicate_redemption_is_rejected(self) -> None:
        raw_token = self.service.request_reset("user-1", "old@example.com")
        self.service.redeem(raw_token)

        with self.assertRaises(TokenConsumedError):
            self.service.redeem(raw_token)

    def test_concurrent_redemption_only_one_wins(self) -> None:
        db_path = self.temp_db_path()
        service, store = self.build_service(db_path=db_path, retry_attempts=5)
        raw_token = service.request_reset("user-1", "old@example.com")
        errors: list[Exception] = []
        winners: list[object] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            try:
                winners.append(service.redeem(raw_token))
            except Exception as exc:  # noqa: BLE001 - assertions run on main thread
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(winners), 1)
        self.assertEqual(len(errors), 7)
        self.assertTrue(all(isinstance(err, TokenConsumedError) for err in errors))
        self.assertEqual(
            store.get_token_state(digest_token(raw_token)),
            store_module.STATE_CONSUMED,
        )
        store.close()

    def test_successful_consumption_invalidates_other_unused_tokens(self) -> None:
        first = self.service.request_reset("user-1", "old@example.com")
        second = self.service.request_reset("user-1", "old@example.com")
        third = self.service.request_reset("user-1", "old@example.com")

        result = self.service.redeem(second)

        self.assertEqual(result.revoked_tokens, 2)
        self.assertEqual(
            self.store.get_token_state(digest_token(first)),
            store_module.STATE_REVOKED,
        )
        self.assertEqual(
            self.store.get_token_state(digest_token(third)),
            store_module.STATE_REVOKED,
        )
        with self.assertRaises(TokenRevokedError):
            self.service.redeem(first)
        with self.assertRaises(TokenRevokedError):
            self.service.redeem(third)

    def test_other_users_tokens_and_sessions_are_untouched(self) -> None:
        own_token = self.service.request_reset("user-1", "one@example.com")
        other_token = self.service.request_reset("user-2", "two@example.com")
        other_session = self.store.create_session("user-2", self.clock())

        self.service.redeem(own_token)

        self.assertEqual(
            self.store.get_token_state(digest_token(other_token)),
            store_module.STATE_UNUSED,
        )
        self.assertFalse(self.store.is_session_revoked(other_session))

    def test_expired_token_rejected_at_boundary(self) -> None:
        raw_token = self.service.request_reset("user-1", "old@example.com")
        self.clock.advance(self.issuer.ttl_ms - 1)
        self.assertEqual(self.service.redeem(raw_token).user_id, "user-1")

        second = self.service.request_reset("user-1", "old@example.com")
        self.clock.advance(self.issuer.ttl_ms)
        with self.assertRaises(TokenExpiredError):
            self.service.redeem(second)

    def test_store_level_expiry_still_blocks_consumption(self) -> None:
        raw_token = self.service.request_reset("user-1", "old@example.com")
        # Simulate clock skew: issuer check passes but the stored TTL has lapsed.
        self.store.prune_expired(self.clock() + self.issuer.ttl_ms + 1)
        with self.assertRaises(TokenRevokedError):
            self.service.redeem(raw_token)

    def test_unknown_digest_is_invalid(self) -> None:
        foreign_store = SQLiteTokenStore(retry_backoff_ms=1)
        foreign_service = ResetTokenService(
            self.issuer, foreign_store, clock=self.clock
        )
        raw_token = self.service.request_reset("user-1", "old@example.com")
        with self.assertRaises(TokenInvalidError):
            foreign_service.redeem(raw_token)
        foreign_store.close()

    def test_wrong_account_binding_is_rejected(self) -> None:
        raw_token = self.service.request_reset("user-1", "old@example.com")
        with self.assertRaises(TokenBindingError):
            self.service.redeem(raw_token, expected_user_id="user-2")
        with self.assertRaises(TokenBindingError):
            self.service.redeem(raw_token, expected_email="attacker@example.com")
        self.assertEqual(
            self.store.get_token_state(digest_token(raw_token)),
            store_module.STATE_UNUSED,
        )

    def test_repeated_requests_remain_usable_until_consumption(self) -> None:
        tokens = [
            self.service.request_reset("user-1", "old@example.com") for _ in range(3)
        ]
        self.assertEqual(self.store.count_tokens_for_user("user-1"), 3)
        self.assertEqual(
            {self.store.get_token_state(digest_token(token)) for token in tokens},
            {store_module.STATE_UNUSED},
        )
        result = self.service.redeem(tokens[1])
        self.assertEqual(result.revoked_tokens, 2)


class RetryTest(TokenLifecycleTestCase):
    def test_transient_lock_errors_are_retried_and_succeed(self) -> None:
        flaky = FlakyDatabase(fail_times=2, operation="consume_token")
        service, store = self.build_service(failure_injector=flaky, retry_attempts=4)
        raw_token = service.request_reset("user-1", "old@example.com")

        result = service.redeem(raw_token)

        self.assertEqual(result.user_id, "user-1")
        self.assertEqual(flaky.calls, 3)
        store.close()

    def test_exhausted_retries_raise_store_unavailable(self) -> None:
        flaky = FlakyDatabase(fail_times=10, operation="save_token")
        service, store = self.build_service(failure_injector=flaky, retry_attempts=3)
        with self.assertRaises(StoreUnavailableError):
            service.request_reset("user-1", "old@example.com")
        self.assertEqual(flaky.calls, 3)
        store.close()

    def test_successful_retry_still_enforces_single_consumption(self) -> None:
        flaky = FlakyDatabase(fail_times=1, operation="consume_token")
        service, store = self.build_service(failure_injector=flaky, retry_attempts=3)
        raw_token = service.request_reset("user-1", "old@example.com")
        service.redeem(raw_token)
        with self.assertRaises(TokenConsumedError):
            service.redeem(raw_token)
        store.close()

    def test_real_sql_lock_between_threads_is_serialized(self) -> None:
        db_path = self.temp_db_path()
        service, store = self.build_service(db_path=db_path, retry_attempts=6)
        raw_token = service.request_reset("user-1", "old@example.com")
        outcomes: list[str] = []

        def worker() -> None:
            try:
                service.redeem(raw_token)
                outcomes.append("ok")
            except TokenConsumedError:
                outcomes.append("consumed")
            except sqlite3.OperationalError:
                outcomes.append("locked")

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sorted(outcomes), ["consumed", "consumed", "consumed", "ok"])
        store.close()

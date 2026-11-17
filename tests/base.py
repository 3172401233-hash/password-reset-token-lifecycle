from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from reset_tokens import ResetTokenService, SQLiteTokenStore, TokenIssuer

TEST_SECRET = "unit-test-hmac-secret-please-do-not-use-in-prod"
TEST_TTL_MS = 15 * 60 * 1000


class MovableClock:
    def __init__(self, start_ms: int = 1_700_000_000_000) -> None:
        self.now_ms = start_ms

    def __call__(self) -> int:
        return self.now_ms

    def advance(self, delta_ms: int) -> None:
        self.now_ms += delta_ms


class FlakyDatabase:
    """Injects sqlite3.OperationalError for the first ``fail_times`` calls."""

    def __init__(self, fail_times: int, operation: str = "consume_token") -> None:
        self.fail_times = fail_times
        self.operation = operation
        self.calls = 0

    def __call__(self, operation: str, attempt: int) -> None:
        if operation == self.operation:
            self.calls += 1
            if self.calls <= self.fail_times:
                raise sqlite3.OperationalError("database is locked")


class TokenLifecycleTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MovableClock()
        self.issuer = TokenIssuer(TEST_SECRET, TEST_TTL_MS)
        self.store = SQLiteTokenStore(
            ":memory:", retry_attempts=4, retry_backoff_ms=1
        )
        self.service = ResetTokenService(self.issuer, self.store, clock=self.clock)

    def tearDown(self) -> None:
        self.store.close()

    def build_service(
        self, *, failure_injector=None, retry_attempts: int = 4, db_path: str = ":memory:"
    ) -> tuple[ResetTokenService, SQLiteTokenStore]:
        store = SQLiteTokenStore(
            db_path,
            retry_attempts=retry_attempts,
            retry_backoff_ms=1,
            failure_injector=failure_injector,
        )
        return ResetTokenService(self.issuer, store, clock=self.clock), store

    @staticmethod
    def temp_db_path() -> str:
        handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        handle.close()
        path = Path(handle.name)
        path.unlink(missing_ok=True)
        return str(path)

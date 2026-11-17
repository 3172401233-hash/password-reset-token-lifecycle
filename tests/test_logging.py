from __future__ import annotations

import logging
import sqlite3

from reset_tokens import (
    TokenConsumedError,
    TokenInvalidError,
    digest_token,
)
from reset_tokens.service import redact_token
from reset_tokens.tokens import TOKEN_PREFIX

from .base import TokenLifecycleTestCase


class LogSafetyTest(TokenLifecycleTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.log_records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                self.records.append(record)

        capture = _Capture()
        capture.records = self.log_records
        self.capture = capture
        self.logger = logging.getLogger("reset_tokens")
        self.logger.addHandler(capture)
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self) -> None:
        self.logger.removeHandler(self.capture)
        super().tearDown()

    def _all_log_text(self) -> str:
        return "\n".join(
            self.capture.format(record) for record in self.log_records
        )

    def test_logs_never_contain_valid_token_material(self) -> None:
        tokens = [
            self.service.request_reset("user-1", "old@example.com")
            for _ in range(3)
        ]
        self.service.redeem(tokens[0])
        try:
            self.service.redeem(tokens[0])
        except TokenConsumedError:
            pass
        try:
            self.service.redeem(TOKEN_PREFIX + "garbage.garbage")
        except TokenInvalidError:
            pass

        log_text = self._all_log_text()
        for raw_token in tokens:
            self.assertNotIn(raw_token, log_text)
            self.assertNotIn(raw_token[len(TOKEN_PREFIX) :], log_text)
        for record in self.log_records:
            self.assertNotIn(TOKEN_PREFIX + "garbage.garbage", record.getMessage())

    def test_logs_reference_only_truncated_digests(self) -> None:
        raw_token = self.service.request_reset("user-1", "old@example.com")
        digest = digest_token(raw_token)
        self.service.redeem(raw_token)

        log_text = self._all_log_text()
        self.assertIn(digest[:12], log_text)
        self.assertNotIn(digest[12:], log_text)

    def test_exception_messages_do_not_leak_tokens(self) -> None:
        raw_token = self.service.request_reset("user-1", "old@example.com")
        self.service.redeem(raw_token)
        try:
            self.service.redeem(raw_token)
        except TokenConsumedError as exc:
            self.assertNotIn(raw_token, str(exc))
        else:  # pragma: no cover
            self.fail("expected TokenConsumedError")

    def test_database_contains_digests_but_never_raw_tokens(self) -> None:
        raw_token = self.service.request_reset("user-1", "old@example.com")
        db_path = self.temp_db_path()
        service, store = self.build_service(db_path=db_path)
        token_on_disk = service.request_reset("user-9", "nine@example.com")

        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute("SELECT * FROM reset_tokens").fetchall()
        finally:
            conn.close()
        blob = repr(rows)
        self.assertNotIn(token_on_disk, blob)
        self.assertNotIn(raw_token, blob)
        self.assertIn(digest_token(token_on_disk), blob)
        store.close()

    def test_redaction_helper_masks_everything_after_prefix(self) -> None:
        raw_token = self.service.request_reset("user-1", "old@example.com")
        redacted = redact_token(raw_token)
        self.assertTrue(redacted.startswith(TOKEN_PREFIX))
        self.assertNotIn(raw_token, redacted)
        self.assertEqual(redact_token(""), "<no-token>")

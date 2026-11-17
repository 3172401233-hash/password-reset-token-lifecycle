from __future__ import annotations

from reset_tokens import TokenRevokedError, digest_token
from reset_tokens import store as store_module

from .base import TokenLifecycleTestCase


class EmailChangeTest(TokenLifecycleTestCase):
    def test_old_email_tokens_are_revoked_after_email_change(self) -> None:
        old_token = self.service.request_reset("user-1", "old@example.com")
        self.service.on_email_changed(
            "user-1", "old@example.com", "new@example.com"
        )

        self.assertEqual(
            self.store.get_token_state(digest_token(old_token)),
            store_module.STATE_REVOKED,
        )
        with self.assertRaises(TokenRevokedError):
            self.service.redeem(old_token)

    def test_token_issued_before_change_cannot_reset_account_after_change(self) -> None:
        # Reproduces the reported incident: token requested against the old
        # mailbox must not survive the email change and reset the account.
        stale_token = self.service.request_reset("user-1", "old@example.com")
        change = self.service.on_email_changed(
            "user-1", "old@example.com", "new@example.com"
        )
        self.assertEqual(change.revoked_tokens, 1)

        new_token = self.service.request_reset("user-1", "new@example.com")
        with self.assertRaises(TokenRevokedError):
            self.service.redeem(stale_token)
        result = self.service.redeem(new_token)
        self.assertEqual(result.email, "new@example.com")

    def test_email_change_is_scoped_to_target_user_and_old_email(self) -> None:
        stale = self.service.request_reset("user-1", "old@example.com")
        same_email_other_user = self.service.request_reset(
            "user-2", "old@example.com"
        )
        already_new = self.service.request_reset("user-1", "new@example.com")

        self.service.on_email_changed(
            "user-1", "old@example.com", "new@example.com"
        )

        self.assertEqual(
            self.store.get_token_state(digest_token(stale)),
            store_module.STATE_REVOKED,
        )
        self.assertEqual(
            self.store.get_token_state(digest_token(same_email_other_user)),
            store_module.STATE_UNUSED,
        )
        self.assertEqual(
            self.store.get_token_state(digest_token(already_new)),
            store_module.STATE_UNUSED,
        )

    def test_unchanged_email_is_a_noop(self) -> None:
        token = self.service.request_reset("user-1", "same@example.com")
        change = self.service.on_email_changed(
            "user-1", "same@example.com", "same@example.com"
        )
        self.assertEqual(change.revoked_tokens, 0)
        self.assertEqual(
            self.store.get_token_state(digest_token(token)),
            store_module.STATE_UNUSED,
        )

    def test_consumed_and_revoked_tokens_are_not_double_counted(self) -> None:
        first = self.service.request_reset("user-1", "old@example.com")
        second = self.service.request_reset("user-1", "old@example.com")
        third = self.service.request_reset("user-1", "old@example.com")
        self.service.redeem(first)
        self.assertEqual(
            self.store.get_token_state(digest_token(second)),
            store_module.STATE_REVOKED,
        )

        change = self.service.on_email_changed(
            "user-1", "old@example.com", "new@example.com"
        )

        self.assertEqual(change.revoked_tokens, 0)
        self.assertEqual(
            self.store.get_token_state(digest_token(third)),
            store_module.STATE_REVOKED,
        )

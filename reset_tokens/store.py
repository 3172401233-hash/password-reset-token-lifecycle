from __future__ import annotations

import sqlite3
import time
import uuid
from itertools import count
from collections.abc import Callable
from typing import Any

from .errors import StoreUnavailableError
from .tokens import Token

STATE_UNUSED = "unused"
STATE_CONSUMED = "consumed"
STATE_REVOKED = "revoked"

CONSUME_OK = "ok"
CONSUME_UNKNOWN = "unknown"
CONSUME_CONSUMED = "consumed"
CONSUME_REVOKED = "revoked"
CONSUME_EXPIRED = "expired"
CONSUME_BINDING_MISMATCH = "binding_mismatch"

_STORE_SEQ = count()


class SQLiteTokenStore:
    """SQLite-backed storage for token digests and user sessions.

    Only the irreversible SHA-256 digest of a token is persisted; the raw
    token value never touches the database. Redemption runs inside a single
    ``BEGIN IMMEDIATE`` transaction so that double-clicks and concurrent tabs
    can never consume the same token twice.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        *,
        retry_attempts: int = 3,
        retry_backoff_ms: int = 20,
        lock_timeout_seconds: float = 5.0,
        failure_injector: Callable[[str, int], None] | None = None,
    ) -> None:
        if retry_attempts < 1:
            raise ValueError("retry_attempts must be >= 1")
        self._db_path = db_path
        self._retry_attempts = retry_attempts
        self._retry_backoff_seconds = retry_backoff_ms / 1000.0
        self._lock_timeout_seconds = lock_timeout_seconds
        self._failure_injector = failure_injector
        self._mem_name = f"reset_tokens_lifecycle_mem_{next(_STORE_SEQ)}"
        self._sentinel = self._connect()
        self._create_schema()

    def close(self) -> None:
        self._sentinel.close()

    def _connect(self) -> sqlite3.Connection:
        if self._db_path == ":memory:":
            uri = f"file:{self._mem_name}?mode=memory&cache=shared"
            conn = sqlite3.connect(
                uri,
                uri=True,
                timeout=self._lock_timeout_seconds,
                check_same_thread=False,
            )
        else:
            conn = sqlite3.connect(
                self._db_path,
                timeout=self._lock_timeout_seconds,
                check_same_thread=False,
            )
        conn.row_factory = sqlite3.Row
        return conn

    def _create_schema(self) -> None:
        with self._sentinel:
            self._sentinel.execute(
                """
                CREATE TABLE IF NOT EXISTS reset_tokens (
                    token_digest   TEXT PRIMARY KEY,
                    user_id        TEXT NOT NULL,
                    email          TEXT NOT NULL,
                    purpose        TEXT NOT NULL,
                    nonce          TEXT NOT NULL,
                    issued_at_ms   INTEGER NOT NULL,
                    expires_at_ms  INTEGER NOT NULL,
                    state          TEXT NOT NULL
                                   CHECK (state IN ('unused', 'consumed', 'revoked')),
                    consumed_at_ms INTEGER,
                    revoked_at_ms  INTEGER,
                    created_at_ms  INTEGER NOT NULL
                )
                """
            )
            self._sentinel.execute(
                "CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON reset_tokens(user_id)"
            )
            self._sentinel.execute(
                "CREATE INDEX IF NOT EXISTS idx_reset_tokens_email ON reset_tokens(email)"
            )
            self._sentinel.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id     TEXT PRIMARY KEY,
                    user_id        TEXT NOT NULL,
                    revoked        INTEGER NOT NULL DEFAULT 0,
                    created_at_ms  INTEGER NOT NULL,
                    revoked_at_ms  INTEGER
                )
                """
            )
            self._sentinel.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)"
            )

    def _with_retry(self, operation: str, work: Callable[[sqlite3.Connection], Any]) -> Any:
        last_error: sqlite3.OperationalError | None = None
        for attempt in range(1, self._retry_attempts + 1):
            conn = self._connect()
            try:
                if self._failure_injector is not None:
                    self._failure_injector(operation, attempt)
                return work(conn)
            except sqlite3.OperationalError as exc:
                last_error = exc
                if attempt >= self._retry_attempts:
                    break
                if self._retry_backoff_seconds:
                    time.sleep(self._retry_backoff_seconds * attempt)
            finally:
                conn.close()
        raise StoreUnavailableError(
            f"database operation {operation!r} failed after {self._retry_attempts} attempts: "
            f"{last_error}"
        ) from last_error

    def save_token(self, token: Token, digest: str, now_ms: int, expires_at_ms: int) -> None:
        def _work(conn: sqlite3.Connection) -> None:
            with conn:
                conn.execute(
                    """
                    INSERT INTO reset_tokens (
                        token_digest, user_id, email, purpose, nonce,
                        issued_at_ms, expires_at_ms, state, created_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        digest,
                        token.user_id,
                        token.email,
                        token.purpose,
                        token.nonce,
                        token.issued_at_ms,
                        expires_at_ms,
                        STATE_UNUSED,
                        now_ms,
                    ),
                )

        self._with_retry("save_token", _work)

    def get_token_row(self, digest: str) -> sqlite3.Row | None:
        def _work(conn: sqlite3.Connection) -> sqlite3.Row | None:
            return conn.execute(
                "SELECT * FROM reset_tokens WHERE token_digest = ?", (digest,)
            ).fetchone()

        return self._with_retry("get_token_row", _work)

    def get_token_state(self, digest: str) -> str | None:
        row = self.get_token_row(digest)
        return None if row is None else row["state"]

    def consume_token(
        self, token_digest: str, token: Token, now_ms: int
    ) -> dict[str, Any]:
        """Atomically consume a token and cascade the revocation side effects.

        Within one ``BEGIN IMMEDIATE`` transaction this: marks the presented
        token consumed, revokes every other unused token of the same user and
        revokes all of the user's active sessions. Returns a result dict whose
        ``status`` is one of the ``CONSUME_*`` constants.
        """

        def _work(conn: sqlite3.Connection) -> dict[str, Any]:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    """
                    SELECT state, expires_at_ms, user_id, email, purpose
                    FROM reset_tokens
                    WHERE token_digest = ?
                    """,
                    (token_digest,),
                ).fetchone()
                if row is None:
                    result = {"status": CONSUME_UNKNOWN}
                elif (
                    row["user_id"] != token.user_id
                    or row["email"] != token.email
                    or row["purpose"] != token.purpose
                ):
                    result = {"status": CONSUME_BINDING_MISMATCH}
                elif row["state"] == STATE_CONSUMED:
                    result = {"status": CONSUME_CONSUMED}
                elif row["state"] == STATE_REVOKED:
                    result = {"status": CONSUME_REVOKED}
                elif now_ms >= row["expires_at_ms"]:
                    result = {"status": CONSUME_EXPIRED}
                else:
                    conn.execute(
                        """
                        UPDATE reset_tokens
                        SET state = ?, consumed_at_ms = ?
                        WHERE token_digest = ?
                        """,
                        (STATE_CONSUMED, now_ms, token_digest),
                    )
                    revoked_tokens = conn.execute(
                        """
                        UPDATE reset_tokens
                        SET state = ?, revoked_at_ms = ?
                        WHERE user_id = ? AND state = ? AND token_digest != ?
                        """,
                        (STATE_REVOKED, now_ms, token.user_id, STATE_UNUSED, token_digest),
                    ).rowcount
                    revoked_sessions = conn.execute(
                        """
                        UPDATE sessions
                        SET revoked = 1, revoked_at_ms = ?
                        WHERE user_id = ? AND revoked = 0
                        """,
                        (now_ms, token.user_id),
                    ).rowcount
                    result = {
                        "status": CONSUME_OK,
                        "revoked_tokens": revoked_tokens,
                        "revoked_sessions": revoked_sessions,
                    }
                conn.execute("COMMIT")
                return result
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self._with_retry("consume_token", _work)

    def revoke_unused_tokens_for_user(self, user_id: str, now_ms: int) -> int:
        def _work(conn: sqlite3.Connection) -> int:
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE reset_tokens
                    SET state = ?, revoked_at_ms = ?
                    WHERE user_id = ? AND state = ?
                    """,
                    (STATE_REVOKED, now_ms, user_id, STATE_UNUSED),
                )
                return cursor.rowcount

        return self._with_retry("revoke_unused_tokens_for_user", _work)

    def revoke_unused_tokens_for_email(
        self, user_id: str, email: str, now_ms: int
    ) -> int:
        def _work(conn: sqlite3.Connection) -> int:
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE reset_tokens
                    SET state = ?, revoked_at_ms = ?
                    WHERE user_id = ? AND email = ? AND state = ?
                    """,
                    (STATE_REVOKED, now_ms, user_id, email, STATE_UNUSED),
                )
                return cursor.rowcount

        return self._with_retry("revoke_unused_tokens_for_email", _work)

    def count_tokens_for_user(self, user_id: str) -> int:
        def _work(conn: sqlite3.Connection) -> int:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM reset_tokens WHERE user_id = ?", (user_id,)
            ).fetchone()
            return int(row["n"])

        return self._with_retry("count_tokens_for_user", _work)

    def prune_expired(self, now_ms: int) -> int:
        def _work(conn: sqlite3.Connection) -> int:
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE reset_tokens
                    SET state = ?, revoked_at_ms = ?
                    WHERE state = ? AND expires_at_ms <= ?
                    """,
                    (STATE_REVOKED, now_ms, STATE_UNUSED, now_ms),
                )
                return cursor.rowcount

        return self._with_retry("prune_expired", _work)

    def create_session(self, user_id: str, now_ms: int) -> str:
        session_id = uuid.uuid4().hex

        def _work(conn: sqlite3.Connection) -> str:
            with conn:
                conn.execute(
                    """
                    INSERT INTO sessions (session_id, user_id, revoked, created_at_ms)
                    VALUES (?, ?, 0, ?)
                    """,
                    (session_id, user_id, now_ms),
                )
            return session_id

        return self._with_retry("create_session", _work)

    def revoke_user_sessions(self, user_id: str, now_ms: int) -> int:
        def _work(conn: sqlite3.Connection) -> int:
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE sessions
                    SET revoked = 1, revoked_at_ms = ?
                    WHERE user_id = ? AND revoked = 0
                    """,
                    (now_ms, user_id),
                )
                return cursor.rowcount

        return self._with_retry("revoke_user_sessions", _work)

    def is_session_revoked(self, session_id: str) -> bool:
        def _work(conn: sqlite3.Connection) -> bool:
            row = conn.execute(
                "SELECT revoked FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            return True if row is None else bool(row["revoked"])

        return self._with_retry("is_session_revoked", _work)

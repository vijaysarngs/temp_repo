"""Storage for users, sessions, credentials and runs: Oracle (production) or SQLite (local).

Both use the table and column names of aegis_simplified_schema.sql (schema_oracle.sql here),
with named binds (:name) that both drivers accept. Timestamps are timezone-aware UTC
datetimes in Python; SQLite stores them as ISO 8601 text.

    AEGIS_AUTH_DB=sqlite (default)  AEGIS_AUTH_DB_PATH=<repo>/.aegis/auth.db
    AEGIS_AUTH_DB=oracle            ORACLE23AI_USER / PASSWORD / HOST / PORT / SERVICE
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SQLITE = ROOT / ".aegis" / "auth.db"
TIME_COLUMNS = {"created_at", "updated_at", "last_seen_at", "expires_at", "revoked_at",
                "password_changed_at", "locked_until", "last_login_at", "started_at", "completed_at"}

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS aegis_users (
    user_id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, display_name TEXT,
    user_role TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'DISABLED', 'LOCKED')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS aegis_user_sessions (
    session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES aegis_users(user_id),
    session_token_hash TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
    client_ip TEXT, user_agent TEXT, created_at TEXT NOT NULL, last_seen_at TEXT,
    expires_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS aegis_user_credentials (
    user_id TEXT PRIMARY KEY REFERENCES aegis_users(user_id), password_hash TEXT NOT NULL,
    password_changed_at TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT, last_login_at TEXT);
CREATE TABLE IF NOT EXISTS aegis_runs (
    run_id TEXT PRIMARY KEY, initiated_by_session_id TEXT REFERENCES aegis_user_sessions(session_id),
    source_file_name TEXT, status TEXT NOT NULL, started_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    completed_at TEXT);
CREATE INDEX IF NOT EXISTS ix_sessions_user_status ON aegis_user_sessions (user_id, status);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Store:
    """execute / query with named binds; rows come back as dicts with lower-case keys."""

    kind = "base"

    def execute(self, sql: str, params: dict | None = None) -> int:
        raise NotImplementedError

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        raise NotImplementedError

    def one(self, sql: str, params: dict | None = None) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def transaction(self):
        """Context manager: several statements on one connection, committed together (rolled back on error)."""
        raise NotImplementedError

    def execute_many(self, sql: str, rows: list[dict], clobs=()) -> None:
        """One statement for many rows (bulk insert); `clobs` names the long-text binds."""
        raise NotImplementedError

    def query_text(self, sql: str, params: dict | None = None) -> list[dict]:
        """query, with long text (CLOB) returned as plain strings; for reading many rows."""
        return self.query(sql, params)


class _SQLiteTransaction:
    """The lock is already held by SQLiteStore.transaction, so statements go straight to the connection."""

    def __init__(self, store):
        self._store = store

    def execute(self, sql, params=None):
        return self._store._connection.execute(sql, self._store._bind(params)).rowcount

    def query(self, sql, params=None):
        cursor = self._store._connection.execute(sql, self._store._bind(params))
        return [self._store._row(cursor, row) for row in cursor.fetchall()]

    def one(self, sql, params=None):
        rows = self.query(sql, params)
        return rows[0] if rows else None


class SQLiteStore(Store):
    kind = "sqlite"

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.executescript(SQLITE_SCHEMA)

    @staticmethod
    def _bind(params):
        return {key: (value.astimezone(timezone.utc).isoformat() if isinstance(value, datetime) else value)
                for key, value in (params or {}).items()}

    @staticmethod
    def _row(cursor, row):
        out = {}
        for (name, *_), value in zip(cursor.description, row):
            key = name.lower()
            if key in TIME_COLUMNS and isinstance(value, str) and value:
                value = datetime.fromisoformat(value)
            out[key] = value
        return out

    def execute(self, sql, params=None):
        with self._lock:
            return self._connection.execute(sql, self._bind(params)).rowcount

    @contextmanager
    def transaction(self):
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield _SQLiteTransaction(self)
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")

    def query(self, sql, params=None):
        with self._lock:
            cursor = self._connection.execute(sql, self._bind(params))
            return [self._row(cursor, row) for row in cursor.fetchall()]

    def execute_many(self, sql, rows, clobs=()):
        if not rows:
            return
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.executemany(sql, [self._bind(row) for row in rows])
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
            self._connection.execute("COMMIT")


def _oracledb():
    import oracledb
    return oracledb


class _OracleTransaction:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, sql, params=None):
        with self._connection.cursor() as cursor:
            OracleStore._run(cursor, sql, params)
            return cursor.rowcount

    def query(self, sql, params=None):
        with self._connection.cursor() as cursor:
            OracleStore._run(cursor, sql, params)
            return OracleStore._rows(cursor)

    def one(self, sql, params=None):
        rows = self.query(sql, params)
        return rows[0] if rows else None


class OracleStore(Store):
    kind = "oracle"

    def __init__(self):
        import oracledb
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env", override=False)
        missing = [name for name in ("ORACLE23AI_USER", "ORACLE23AI_PASSWORD", "ORACLE23AI_HOST",
                                     "ORACLE23AI_SERVICE") if not (os.getenv(name) or "").strip()]
        if missing:
            raise ValueError("Set " + ", ".join(missing) + " for AEGIS_AUTH_DB=oracle.")
        dsn = f"{os.environ['ORACLE23AI_HOST'].strip()}:{os.getenv('ORACLE23AI_PORT', '1521')}/" \
              f"{os.environ['ORACLE23AI_SERVICE'].strip()}"
        self._pool = oracledb.create_pool(user=os.environ["ORACLE23AI_USER"].strip(),
                                          password=os.environ["ORACLE23AI_PASSWORD"].strip(),
                                          dsn=dsn, min=1, max=6, increment=1)

    @staticmethod
    def _run(cursor, sql, params):
        params = params or {}
        # Long text (saved jobs and runs) is bound as a CLOB; plain strings stop at 32 KB.
        long_text = {name: _oracledb().DB_TYPE_CLOB for name, value in params.items()
                     if isinstance(value, str) and len(value) > 4000}
        if long_text:
            cursor.setinputsizes(**long_text)
        cursor.execute(sql, params)

    @staticmethod
    def _rows(cursor):
        names = [d[0].lower() for d in cursor.description]
        rows = []
        for row in cursor.fetchall():
            item = {}
            for name, value in zip(names, row):
                if hasattr(value, "read"):            # CLOB
                    value = value.read()
                if isinstance(value, datetime) and value.tzinfo is None:
                    value = value.replace(tzinfo=timezone.utc)
                item[name] = value
            rows.append(item)
        return rows

    def execute(self, sql, params=None):
        with self._pool.acquire() as connection, connection.cursor() as cursor:
            self._run(cursor, sql, params)
            connection.commit()
            return cursor.rowcount

    def query(self, sql, params=None):
        with self._pool.acquire() as connection, connection.cursor() as cursor:
            self._run(cursor, sql, params)
            return self._rows(cursor)

    def execute_many(self, sql, rows, clobs=(), batch=1000):
        if not rows:
            return
        oracledb = _oracledb()
        with self._pool.acquire() as connection:
            try:
                with connection.cursor() as cursor:
                    if clobs:
                        cursor.setinputsizes(**{name: oracledb.DB_TYPE_CLOB for name in clobs})
                    for start in range(0, len(rows), batch):
                        cursor.executemany(sql, rows[start:start + batch])
            except BaseException:
                connection.rollback()
                raise
            connection.commit()

    def query_text(self, sql, params=None):
        oracledb = _oracledb()

        def as_text(cursor, metadata):
            # Fetching each CLOB as a locator costs a round trip per value; as text it does not.
            if metadata.type_code is oracledb.DB_TYPE_CLOB:
                return cursor.var(oracledb.DB_TYPE_LONG, arraysize=cursor.arraysize)

        with self._pool.acquire() as connection, connection.cursor() as cursor:
            cursor.arraysize = 1000
            cursor.outputtypehandler = as_text
            self._run(cursor, sql, params)
            return self._rows(cursor)

    @contextmanager
    def transaction(self):
        with self._pool.acquire() as connection:
            try:
                yield _OracleTransaction(connection)
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def create_schema(self) -> list[str]:
        """Run schema_oracle.sql; tables that already exist are reported, not recreated."""
        notes = []
        sql = (Path(__file__).with_name("schema_oracle.sql")).read_text(encoding="utf-8")
        statements = [s.strip() for s in "\n".join(
            line for line in sql.splitlines() if not line.strip().startswith("--")).split(";") if s.strip()]
        for statement in statements:
            try:
                self.execute(statement)
                notes.append("created: " + " ".join(statement.split()[:3]))
            except Exception as exc:  # noqa: BLE001 - ORA-00955: name is already used
                notes.append(f"skipped ({str(exc).splitlines()[0][:80]}): " + " ".join(statement.split()[:3]))
        return notes


_store: Store | None = None
_store_lock = threading.Lock()


def get_store() -> Store:
    global _store
    with _store_lock:
        if _store is None:
            try:    # the CLI (python -m aegis_auth) must use the same database as the app
                from dotenv import load_dotenv
                load_dotenv(ROOT / ".env", override=False)
            except ImportError:
                pass
            backend = os.getenv("AEGIS_AUTH_DB", "sqlite").strip().casefold()
            if backend == "oracle":
                _store = OracleStore()
                _store.create_schema()      # idempotent: existing tables are skipped
            else:
                _store = SQLiteStore(os.getenv("AEGIS_AUTH_DB_PATH") or DEFAULT_SQLITE)
        return _store


def set_store(store: Store | None) -> None:
    """Tests: use this store (or None to rebuild from the environment)."""
    global _store
    with _store_lock:
        _store = store

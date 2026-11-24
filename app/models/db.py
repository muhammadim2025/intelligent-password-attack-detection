"""Database connection helpers, schema initialization, and backend selection.

Supports local SQLite (default) and PostgreSQL when DATABASE_URL is configured.
Existing SQLite behavior is preserved for local development and explicit
SQLite database paths.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.config import database_path, database_url as configured_database_url

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    username TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    attempted_at TEXT NOT NULL,
    hour_of_day INTEGER NOT NULL,
    failed_attempts_last_15m INTEGER NOT NULL,
    distinct_usernames_from_ip_15m INTEGER NOT NULL,
    seconds_since_previous_attempt INTEGER NOT NULL,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    suspicious INTEGER NOT NULL CHECK (suspicious IN (0, 1)),
    model_prediction INTEGER,
    model_probability REAL,
    alert_status TEXT NOT NULL DEFAULT 'none',
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY,
    event_id INTEGER,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    explanation TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'open'
        CHECK (review_status IN ('open', 'reviewed')),
    created_at TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES login_events (id)
);

CREATE TABLE IF NOT EXISTS synthetic_test_events (
    id INTEGER PRIMARY KEY,
    administrator_id INTEGER NOT NULL,
    administrator_username TEXT NOT NULL,
    scenario TEXT NOT NULL
        CHECK (scenario IN ('normal', 'suspicious')),
    tested_at TEXT NOT NULL,
    failed_attempts_5min INTEGER NOT NULL,
    login_attempts_5min INTEGER NOT NULL,
    unique_accounts_5min INTEGER NOT NULL,
    new_device INTEGER NOT NULL CHECK (new_device IN (0, 1)),
    login_hour INTEGER NOT NULL,
    source_failure_rate REAL NOT NULL,
    time_since_last_login INTEGER NOT NULL,
    recent_account_failure_count INTEGER NOT NULL,
    unique_ips_5min INTEGER NOT NULL DEFAULT 1,
    unusual_login_time INTEGER NOT NULL DEFAULT 0,
    model_prediction INTEGER NOT NULL CHECK (model_prediction IN (0, 1)),
    model_probability REAL NOT NULL,
    label_origin TEXT NOT NULL DEFAULT 'synthetic_manual_test',
    FOREIGN KEY (administrator_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS synthetic_test_alerts (
    id INTEGER PRIMARY KEY,
    test_event_id INTEGER NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('medium', 'high')),
    explanation TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'open'
        CHECK (review_status IN ('open', 'reviewed')),
    created_at TEXT NOT NULL,
    FOREIGN KEY (test_event_id) REFERENCES synthetic_test_events (id)
);

CREATE INDEX IF NOT EXISTS idx_login_events_username
    ON login_events (username);
CREATE INDEX IF NOT EXISTS idx_login_events_attempted_at
    ON login_events (attempted_at);
"""

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_events (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users (id),
    username TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    attempted_at TEXT NOT NULL,
    hour_of_day INTEGER NOT NULL,
    failed_attempts_last_15m INTEGER NOT NULL,
    distinct_usernames_from_ip_15m INTEGER NOT NULL,
    seconds_since_previous_attempt INTEGER NOT NULL,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    suspicious INTEGER NOT NULL CHECK (suspicious IN (0, 1)),
    model_prediction INTEGER,
    model_probability DOUBLE PRECISION,
    alert_status TEXT NOT NULL DEFAULT 'none',
    failed_attempts_5min INTEGER,
    login_attempts_5min INTEGER,
    unique_accounts_5min INTEGER,
    new_device INTEGER,
    login_hour INTEGER,
    source_failure_rate DOUBLE PRECISION,
    time_since_last_login INTEGER,
    recent_account_failure_count INTEGER
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id BIGSERIAL PRIMARY KEY,
    event_id BIGINT REFERENCES login_events (id),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    explanation TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'open'
        CHECK (review_status IN ('open', 'reviewed')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS synthetic_test_events (
    id BIGSERIAL PRIMARY KEY,
    administrator_id BIGINT NOT NULL REFERENCES users (id),
    administrator_username TEXT NOT NULL,
    scenario TEXT NOT NULL
        CHECK (scenario IN ('normal', 'suspicious')),
    tested_at TEXT NOT NULL,
    failed_attempts_5min INTEGER NOT NULL,
    login_attempts_5min INTEGER NOT NULL,
    unique_accounts_5min INTEGER NOT NULL,
    new_device INTEGER NOT NULL CHECK (new_device IN (0, 1)),
    login_hour INTEGER NOT NULL,
    source_failure_rate DOUBLE PRECISION NOT NULL,
    time_since_last_login INTEGER NOT NULL,
    recent_account_failure_count INTEGER NOT NULL,
    unique_ips_5min INTEGER NOT NULL DEFAULT 1,
    unusual_login_time INTEGER NOT NULL DEFAULT 0,
    model_prediction INTEGER NOT NULL CHECK (model_prediction IN (0, 1)),
    model_probability DOUBLE PRECISION NOT NULL,
    label_origin TEXT NOT NULL DEFAULT 'synthetic_manual_test'
);

CREATE TABLE IF NOT EXISTS synthetic_test_alerts (
    id BIGSERIAL PRIMARY KEY,
    test_event_id BIGINT NOT NULL REFERENCES synthetic_test_events (id),
    severity TEXT NOT NULL CHECK (severity IN ('medium', 'high')),
    explanation TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'open'
        CHECK (review_status IN ('open', 'reviewed')),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_events_username
    ON login_events (username);
CREATE INDEX IF NOT EXISTS idx_login_events_attempted_at
    ON login_events (attempted_at);
"""

LOGIN_EVENT_COLUMNS = (
    ("model_prediction", "INTEGER"),
    ("model_probability", "DOUBLE PRECISION"),
    ("alert_status", "TEXT NOT NULL DEFAULT 'none'"),
    ("failed_attempts_5min", "INTEGER"),
    ("login_attempts_5min", "INTEGER"),
    ("unique_accounts_5min", "INTEGER"),
    ("new_device", "INTEGER"),
    ("login_hour", "INTEGER"),
    ("source_failure_rate", "DOUBLE PRECISION"),
    ("time_since_last_login", "INTEGER"),
    ("recent_account_failure_count", "INTEGER"),
    ("unique_ips_5min", "INTEGER"),
    ("unusual_login_time", "INTEGER"),
)


def database_url() -> str | None:
    """Return the configured PostgreSQL connection URL, if any."""
    return configured_database_url()


def is_postgres_target(target: Any = None) -> bool:
    if isinstance(target, str) and target.startswith(("postgres://", "postgresql://")):
        return True
    if target is None:
        return database_url() is not None
    return False


def is_postgres_connection(connection: Any) -> bool:
    return bool(getattr(connection, "is_postgres", False))


class CompatRow(Mapping[str, Any], Sequence[Any]):
    """Row wrapper supporting both key and index access."""

    def __init__(self, columns: Sequence[str], values: Sequence[Any]):
        self._columns = list(columns)
        self._values = tuple(values)
        self._mapping = dict(zip(self._columns, self._values))

    def __getitem__(self, key: Any) -> Any:  # type: ignore[override]
        if isinstance(key, int):
            return self._values[key]
        return self._mapping[key]

    def __iter__(self):  # type: ignore[override]
        return iter(self._mapping)

    def __len__(self) -> int:
        return len(self._mapping)

    def keys(self):
        return self._mapping.keys()

    def items(self):
        return self._mapping.items()

    def values(self):
        return self._mapping.values()

    def get(self, key: Any, default: Any = None) -> Any:
        if isinstance(key, int):
            try:
                return self._values[key]
            except IndexError:
                return default
        return self._mapping.get(key, default)


class SQLiteCompatCursor:
    def __init__(self, cursor: sqlite3.Cursor):
        self._cursor = cursor

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


class SQLiteCompatConnection:
    is_postgres = False

    def __init__(self, connection: sqlite3.Connection):
        self._connection = connection

    def execute(self, sql: str, params: Sequence[Any] | None = None):
        if params is None:
            return SQLiteCompatCursor(self._connection.execute(sql))
        return SQLiteCompatCursor(self._connection.execute(sql, tuple(params)))

    def executemany(self, sql: str, seq_of_params: Sequence[Sequence[Any]]):
        return SQLiteCompatCursor(
            self._connection.executemany(sql, [tuple(p) for p in seq_of_params])
        )

    def executescript(self, script: str):
        return self._connection.executescript(script)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


class PostgresCompatCursor:
    def __init__(self, cursor: Any, inserted_id: int | None = None):
        self._cursor = cursor
        self._inserted_id = inserted_id

    @property
    def lastrowid(self):
        if self._inserted_id is not None:
            return self._inserted_id
        return getattr(self._cursor, "lastrowid", None)

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def _wrap_row(self, row: Any):
        if row is None:
            return None
        if isinstance(row, CompatRow):
            return row
        if isinstance(row, Mapping):
            return CompatRow(list(row.keys()), list(row.values()))
        description = getattr(self._cursor, "description", None)
        if description and not isinstance(row, (tuple, list)):
            # already a custom row type with mapping support
            return row
        if description:
            columns = [col[0] for col in description]
            return CompatRow(columns, list(row))
        return row

    def fetchone(self):
        return self._wrap_row(self._cursor.fetchone())

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [self._wrap_row(row) for row in rows]


def _translate_sql(sql: str) -> str:
    # Existing application queries use qmark placeholders exclusively.
    return sql.replace("?", "%s")


def _is_insert_without_returning(sql: str) -> bool:
    stripped = sql.lstrip().lower()
    return stripped.startswith("insert") and "returning" not in stripped.lower()


class PostgresCompatConnection:
    is_postgres = True

    def __init__(self, connection: Any):
        self._connection = connection

    def execute(self, sql: str, params: Sequence[Any] | None = None):
        translated = _translate_sql(sql)
        wants_id = _is_insert_without_returning(translated)
        if wants_id:
            translated = translated.rstrip().rstrip(";") + " RETURNING id"
        cursor = self._connection.cursor()
        cursor.execute(translated, tuple(params) if params is not None else None)
        inserted_id = None
        if wants_id:
            row = cursor.fetchone()
            if row is not None:
                inserted_id = int(row[0])
        return PostgresCompatCursor(cursor, inserted_id=inserted_id)

    def executemany(self, sql: str, seq_of_params: Sequence[Sequence[Any]]):
        translated = _translate_sql(sql)
        cursor = self._connection.cursor()
        cursor.executemany(translated, [tuple(p) for p in seq_of_params])
        return PostgresCompatCursor(cursor)

    def executescript(self, script: str):
        cursor = self._connection.cursor()
        statements = [s.strip() for s in script.split(";") if s.strip()]
        for statement in statements:
            cursor.execute(statement)
        return PostgresCompatCursor(cursor)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


def _default_postgres_url() -> str:
    url = database_url()
    if not url:
        raise RuntimeError("DATABASE_URL must be set when using PostgreSQL.")
    # Neon/Render commonly provide postgres://; psycopg accepts postgresql://
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url


def connect(target: Any = None):
    """Open a database connection.

    - PostgreSQL URL target or `DATABASE_URL` configured with no explicit SQLite
      path target: PostgreSQL connection.
    - Path/str path target (or default local mode): SQLite connection.
    """
    if is_postgres_target(target):
        try:
            import psycopg  # type: ignore
        except ImportError as error:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "PostgreSQL support requires the 'psycopg' package to be installed."
            ) from error
        url = target if isinstance(target, str) else _default_postgres_url()
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        connection = psycopg.connect(url)
        return PostgresCompatConnection(connection)

    db_path = Path(target or database_path())
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return SQLiteCompatConnection(connection)


def _sqlite_columns(connection: SQLiteCompatConnection, table: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    return {row["name"] for row in rows}


def _postgres_columns(connection: PostgresCompatConnection, table: str) -> set[str]:
    rows = connection.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = ?
        """,
        (table,),
    ).fetchall()
    return {row["column_name"] for row in rows}


def initialize(connection: Any) -> None:
    """Create required tables and apply idempotent column migrations."""
    if is_postgres_connection(connection):
        connection.executescript(POSTGRES_SCHEMA)
        columns = _postgres_columns(connection, "users")
        if "is_admin" not in columns:
            connection.execute(
                """
                ALTER TABLE users
                ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0
                CHECK (is_admin IN (0, 1))
                """
            )
        event_columns = _postgres_columns(connection, "login_events")
        for name, definition in LOGIN_EVENT_COLUMNS:
            if name not in event_columns:
                connection.execute(
                    f"ALTER TABLE login_events ADD COLUMN {name} {definition}"
                )
        synthetic_event_columns = _postgres_columns(connection, "synthetic_test_events")
        for name, definition in (
            ("unique_ips_5min", "INTEGER NOT NULL DEFAULT 1"),
            ("unusual_login_time", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if name not in synthetic_event_columns:
                connection.execute(
                    f"ALTER TABLE synthetic_test_events ADD COLUMN {name} {definition}"
                )
        connection.commit()
        return

    connection.executescript(SQLITE_SCHEMA)
    columns = _sqlite_columns(connection, "users")
    if "is_admin" not in columns:
        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0
            CHECK (is_admin IN (0, 1))
            """
        )
    event_columns = _sqlite_columns(connection, "login_events")
    for name, definition in (
        ("model_prediction", "INTEGER"),
        ("model_probability", "REAL"),
        ("alert_status", "TEXT NOT NULL DEFAULT 'none'"),
        ("failed_attempts_5min", "INTEGER"),
        ("login_attempts_5min", "INTEGER"),
        ("unique_accounts_5min", "INTEGER"),
        ("new_device", "INTEGER"),
        ("login_hour", "INTEGER"),
        ("source_failure_rate", "REAL"),
        ("time_since_last_login", "INTEGER"),
        ("recent_account_failure_count", "INTEGER"),
        ("unique_ips_5min", "INTEGER"),
        ("unusual_login_time", "INTEGER"),
    ):
        if name not in event_columns:
            connection.execute(
                f"ALTER TABLE login_events ADD COLUMN {name} {definition}"
            )

    synthetic_event_columns = _sqlite_columns(connection, "synthetic_test_events")
    for name, definition in (
        ("unique_ips_5min", "INTEGER NOT NULL DEFAULT 1"),
        ("unusual_login_time", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in synthetic_event_columns:
            connection.execute(
                f"ALTER TABLE synthetic_test_events ADD COLUMN {name} {definition}"
            )
    connection.commit()


def get_user_by_id(connection: Any, user_id: int):
    return connection.execute(
        "SELECT id, username, password_hash, is_admin, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def get_user_by_username(connection: Any, username: str):
    return connection.execute(
        "SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ?",
        (username.strip(),),
    ).fetchone()

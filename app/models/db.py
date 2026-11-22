"""SQLite connection helpers and table definitions."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from app.config import database_path

SCHEMA = """
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


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open the research database, creating parent folders when needed."""
    db_path = Path(path or database_path())
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize(connection: sqlite3.Connection) -> None:
    """Create the test-account and login-event tables."""
    connection.executescript(SCHEMA)
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(users)").fetchall()
    }
    if "is_admin" not in columns:
        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0
            CHECK (is_admin IN (0, 1))
            """
        )
    event_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(login_events)"
        ).fetchall()
    }
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
    ):
        if name not in event_columns:
            connection.execute(
                f"ALTER TABLE login_events ADD COLUMN {name} {definition}"
            )
    connection.commit()


def get_user_by_id(connection: sqlite3.Connection, user_id: int):
    return connection.execute(
        "SELECT id, username, password_hash, is_admin, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def get_user_by_username(connection: sqlite3.Connection, username: str):
    return connection.execute(
        "SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ?",
        (username.strip(),),
    ).fetchone()

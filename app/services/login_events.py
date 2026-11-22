"""Store test accounts and synthetic login events."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.auth.hashing import hash_password, verify_password
from app.detection.features import LABEL_COLUMN, feature_values, synthetic_suspicious_label


@dataclass(frozen=True)
class LoginEvent:
    """One simulated login attempt. No password is stored on the event."""

    username: str
    source_ip: str
    attempted_at: str
    hour_of_day: int
    failed_attempts_last_15m: int
    distinct_usernames_from_ip_15m: int
    seconds_since_previous_attempt: int
    success: int
    suspicious: int
    user_id: int | None = None


def create_test_account(
    connection: sqlite3.Connection,
    username: str,
    password: str,
    *,
    is_admin: bool = False,
) -> int:
    """Insert a local test account and store only the Argon2id hash."""
    cleaned = username.strip()
    if not cleaned:
        raise ValueError("Username must not be empty.")
    password_hash = hash_password(password)
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = connection.execute(
        """
        INSERT INTO users (username, password_hash, is_admin, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (cleaned, password_hash, 1 if is_admin else 0, created_at),
    )
    connection.commit()
    return int(cursor.lastrowid)


def password_matches(
    connection: sqlite3.Connection, username: str, password: str
) -> bool:
    """Check a password against the stored Argon2id hash for a test account."""
    row = connection.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username.strip(),),
    ).fetchone()
    if row is None:
        return False
    return verify_password(row["password_hash"], password)


def record_login_event(connection: sqlite3.Connection, event: LoginEvent) -> int:
    """Insert one synthetic login event after checking its label."""
    _require_consistent_label(event)
    cursor = connection.execute(
        """
        INSERT INTO login_events (
            user_id,
            username,
            source_ip,
            attempted_at,
            hour_of_day,
            failed_attempts_last_15m,
            distinct_usernames_from_ip_15m,
            seconds_since_previous_attempt,
            success,
            suspicious
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.user_id,
            event.username,
            event.source_ip,
            event.attempted_at,
            event.hour_of_day,
            event.failed_attempts_last_15m,
            event.distinct_usernames_from_ip_15m,
            event.seconds_since_previous_attempt,
            event.success,
            event.suspicious,
        ),
    )
    connection.commit()
    return int(cursor.lastrowid)


def record_login_events(
    connection: sqlite3.Connection, events: list[LoginEvent]
) -> int:
    """Insert many synthetic login events in one transaction."""
    rows = []
    for event in events:
        _require_consistent_label(event)
        rows.append(
            (
                event.user_id,
                event.username,
                event.source_ip,
                event.attempted_at,
                event.hour_of_day,
                event.failed_attempts_last_15m,
                event.distinct_usernames_from_ip_15m,
                event.seconds_since_previous_attempt,
                event.success,
                event.suspicious,
            )
        )
    connection.executemany(
        """
        INSERT INTO login_events (
            user_id,
            username,
            source_ip,
            attempted_at,
            hour_of_day,
            failed_attempts_last_15m,
            distinct_usernames_from_ip_15m,
            seconds_since_previous_attempt,
            success,
            suspicious
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    connection.commit()
    return len(rows)


def dataset_counts(connection: sqlite3.Connection) -> dict[str, int]:
    """Return how many accounts and labeled events are stored."""
    users = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
    events = connection.execute(
        "SELECT COUNT(*) AS count FROM login_events"
    ).fetchone()
    suspicious = connection.execute(
        "SELECT COUNT(*) AS count FROM login_events WHERE suspicious = 1"
    ).fetchone()
    return {
        "users": int(users["count"]),
        "events": int(events["count"]),
        "suspicious_events": int(suspicious["count"]),
    }


def record_authentication_event(
    connection: sqlite3.Connection,
    *,
    username: str,
    source_ip: str,
    success: int,
    user_id: int | None = None,
) -> tuple[int, dict[str, int | float]]:
    """Record one live login result with derived, non-secret features."""
    attempted_at = datetime.now(timezone.utc).isoformat()
    attempted = datetime.now(timezone.utc)
    hour_of_day = attempted.hour

    window_start = (attempted - timedelta(minutes=5)).isoformat()
    failed_row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM login_events
        WHERE source_ip = ? AND success = 0
          AND attempted_at >= ?
        """,
        (source_ip, window_start),
    ).fetchone()
    failed_attempts = int(failed_row["count"]) + (1 if success == 0 else 0)

    attempts_row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM login_events
        WHERE source_ip = ? AND attempted_at >= ?
        """,
        (source_ip, window_start),
    ).fetchone()
    login_attempts = int(attempts_row["count"]) + 1

    distinct_row = connection.execute(
        """
        SELECT COUNT(DISTINCT username) AS count
        FROM login_events
        WHERE source_ip = ?
          AND attempted_at >= ?
        """,
        (source_ip, window_start),
    ).fetchone()
    distinct_usernames = int(distinct_row["count"])
    if username not in [
        row["username"]
        for row in connection.execute(
            """
            SELECT DISTINCT username
            FROM login_events
            WHERE source_ip = ? AND attempted_at >= ?
            """,
            (source_ip, window_start),
        ).fetchall()
    ]:
        distinct_usernames += 1

    previous = connection.execute(
        """
        SELECT attempted_at
        FROM login_events
        WHERE source_ip = ?
        ORDER BY attempted_at DESC
        LIMIT 1
        """,
        (source_ip,),
    ).fetchone()
    if previous is None:
        seconds_since_previous = 3600
    else:
        try:
            previous_at = datetime.fromisoformat(previous["attempted_at"])
            seconds_since_previous = max(
                0, int((attempted - previous_at).total_seconds())
            )
        except (TypeError, ValueError):
            seconds_since_previous = 3600

    account_failed_row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM login_events
        WHERE username = ? AND success = 0
          AND attempted_at >= ?
        """,
        (username, window_start),
    ).fetchone()
    recent_account_failures = int(account_failed_row["count"]) + (
        1 if success == 0 else 0
    )

    prior_success = connection.execute(
        """
        SELECT attempted_at
        FROM login_events
        WHERE username = ? AND source_ip = ? AND success = 1
        ORDER BY attempted_at DESC
        LIMIT 1
        """,
        (username, source_ip),
    ).fetchone()
    new_device = 0 if prior_success is not None else 1
    if success == 1:
        prior_success = connection.execute(
            """
            SELECT attempted_at
            FROM login_events
            WHERE username = ? AND success = 1
            ORDER BY attempted_at DESC
            LIMIT 1
            """,
            (username,),
        ).fetchone()
        if prior_success is not None:
            try:
                prior_at = datetime.fromisoformat(prior_success["attempted_at"])
                seconds_since_previous = max(
                    0, int((attempted - prior_at).total_seconds())
                )
            except (TypeError, ValueError):
                pass

    features = {
        "hour_of_day": hour_of_day,
        "failed_attempts_last_15m": failed_attempts,
        "distinct_usernames_from_ip_15m": distinct_usernames,
        "seconds_since_previous_attempt": seconds_since_previous,
        "success": success,
    }
    label = synthetic_suspicious_label(**features)
    event = LoginEvent(
        user_id=user_id,
        username=username,
        source_ip=source_ip,
        attempted_at=attempted_at,
        suspicious=label,
        **features,
    )
    event_id = record_login_event(connection, event)
    research_features = {
        "failed_attempts_5min": failed_attempts,
        "login_attempts_5min": login_attempts,
        "unique_accounts_5min": distinct_usernames,
        "new_device": new_device,
        "login_hour": hour_of_day,
        "source_failure_rate": (
            failed_attempts / max(1, login_attempts)
        ),
        "time_since_last_login": seconds_since_previous,
        "recent_account_failure_count": recent_account_failures,
    }
    connection.execute(
        """
        UPDATE login_events
        SET failed_attempts_5min = ?,
            login_attempts_5min = ?,
            unique_accounts_5min = ?,
            new_device = ?,
            login_hour = ?,
            source_failure_rate = ?,
            time_since_last_login = ?,
            recent_account_failure_count = ?
        WHERE id = ?
        """,
        (
            research_features["failed_attempts_5min"],
            research_features["login_attempts_5min"],
            research_features["unique_accounts_5min"],
            research_features["new_device"],
            research_features["login_hour"],
            research_features["source_failure_rate"],
            research_features["time_since_last_login"],
            research_features["recent_account_failure_count"],
            event_id,
        ),
    )
    connection.commit()
    return event_id, research_features


def purge_expired_authentication_events(
    connection: sqlite3.Connection,
    *,
    retention_days: int,
    now: datetime | None = None,
) -> int:
    """Delete login events and linked alerts older than the configured period."""
    if retention_days < 1:
        raise ValueError("Retention period must be at least one day.")
    current = now or datetime.now(timezone.utc)
    cutoff = (current - timedelta(days=retention_days)).isoformat()
    expired = connection.execute(
        "SELECT id FROM login_events WHERE attempted_at < ?",
        (cutoff,),
    ).fetchall()
    if not expired:
        return 0
    event_ids = [int(row["id"]) for row in expired]
    placeholders = ",".join("?" for _ in event_ids)
    connection.execute(
        f"DELETE FROM security_alerts WHERE event_id IN ({placeholders})",
        event_ids,
    )
    cursor = connection.execute(
        f"DELETE FROM login_events WHERE id IN ({placeholders})",
        event_ids,
    )
    connection.commit()
    return cursor.rowcount


def _require_consistent_label(event: LoginEvent) -> None:
    features = feature_values(event.__dict__)
    expected = synthetic_suspicious_label(**features)
    actual = int(getattr(event, LABEL_COLUMN))
    if actual != expected:
        raise ValueError("Login event label does not match the synthetic rule.")
    if event.success not in (0, 1):
        raise ValueError("Success must be 0 or 1.")

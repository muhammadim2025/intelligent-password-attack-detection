"""Create and review synthetic/authorized security alerts."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def create_alert(
    connection: sqlite3.Connection,
    *,
    event_id: int,
    severity: str,
    explanation: str,
) -> int:
    if severity not in ("low", "medium", "high"):
        raise ValueError("Invalid alert severity.")
    cursor = connection.execute(
        """
        INSERT INTO security_alerts (
            event_id, severity, explanation, review_status, created_at
        ) VALUES (?, ?, ?, 'open', ?)
        """,
        (event_id, severity, explanation, datetime.now(timezone.utc).isoformat()),
    )
    connection.execute(
        "UPDATE login_events SET alert_status = 'open' WHERE id = ?",
        (event_id,),
    )
    connection.commit()
    return int(cursor.lastrowid)


def mark_alert_reviewed(connection: sqlite3.Connection, alert_id: int) -> bool:
    alert = connection.execute(
        "SELECT event_id FROM security_alerts WHERE id = ?",
        (alert_id,),
    ).fetchone()
    if alert is None:
        return False
    cursor = connection.execute(
        """
        UPDATE security_alerts
        SET review_status = 'reviewed'
        WHERE id = ?
        """,
        (alert_id,),
    )
    connection.execute(
        "UPDATE login_events SET alert_status = 'reviewed' WHERE id = ?",
        (int(alert["event_id"]),),
    )
    connection.commit()
    return cursor.rowcount == 1

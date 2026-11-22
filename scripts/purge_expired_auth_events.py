"""Apply configured authentication-event retention to the local SQLite database."""

from __future__ import annotations

import sys

PROJECT_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import auth_event_retention_days, auth_event_retention_enabled
from app.models.db import connect, initialize
from app.services.login_events import purge_expired_authentication_events


def main() -> None:
    if not auth_event_retention_enabled():
        raise SystemExit(
            "Set AUTH_EVENT_RETENTION_ENABLED=true before purging authentication events."
        )
    connection = connect()
    try:
        initialize(connection)
        deleted = purge_expired_authentication_events(
            connection,
            retention_days=auth_event_retention_days(),
        )
        print(f"Deleted {deleted} expired authentication event(s).")
    finally:
        connection.close()


if __name__ == "__main__":
    main()

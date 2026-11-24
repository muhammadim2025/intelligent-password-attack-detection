#!/usr/bin/env python3
"""Create and initialize a fresh production database without touching local data.

Supports SQLite paths and PostgreSQL when DATABASE_URL is configured. This script
initializes schema only and never copies local users, events, or other records.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import database_url
from app.models.db import connect, initialize, is_postgres_target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize a fresh production database for deployment."
    )
    parser.add_argument(
        "--database-path",
        help="Target SQLite database path (e.g. /var/data/app.db).",
    )
    parser.add_argument(
        "--use-database-url",
        action="store_true",
        help="Initialize the PostgreSQL database configured by DATABASE_URL.",
    )
    args = parser.parse_args(argv)

    configured_url = database_url()
    if args.use_database_url or (configured_url and not args.database_path):
        target = configured_url
        if not target or not is_postgres_target(target):
            raise SystemExit(
                "DATABASE_URL must be set to a PostgreSQL URL when initializing PostgreSQL."
            )
    else:
        if not args.database_path:
            raise SystemExit(
                "Provide --database-path for SQLite or --use-database-url/DATABASE_URL for PostgreSQL."
            )
        target = Path(args.database_path).expanduser()
        if not target.is_absolute():
            target = (Path.cwd() / target).resolve()

        local_research = (PROJECT_ROOT / "instance" / "research.db").resolve()
        if target == local_research:
            raise SystemExit(
                "Refusing to target instance/research.db. Choose a fresh production database path."
            )

    connection = connect(target)
    try:
        initialize(connection)
    finally:
        connection.close()

    label = "configured PostgreSQL database" if is_postgres_target(target) else str(target)
    print(f"Initialized production database schema at: {label}")
    print("No existing local databases were modified, deleted, or copied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

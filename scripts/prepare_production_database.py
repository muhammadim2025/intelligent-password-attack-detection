#!/usr/bin/env python3
"""Create and initialize a fresh production database without touching local data.

This script is intentionally separate from deployment and does not modify or delete
the existing local SQLite databases (including instance/research.db).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.models.db import connect, initialize


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize a fresh SQLite database for deployment."
    )
    parser.add_argument(
        "--database-path",
        required=True,
        help="Target SQLite database path (e.g. /var/data/app.db).",
    )
    args = parser.parse_args(argv)

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

    print(f"Initialized production database schema at: {target}")
    print("No existing local databases were modified or deleted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

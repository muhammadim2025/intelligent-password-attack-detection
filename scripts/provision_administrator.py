"""Controlled local CLI for provisioning an administrator account."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import re

PROJECT_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.auth.hashing import password_strength_error
from app.models.db import connect, initialize
from app.services.login_events import create_test_account
from app.auth.hashing import hash_password


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,64}$")


def provision_administrator(
    connection,
    *,
    username: str,
    password: str,
) -> str:
    """Create or explicitly promote an administrator in a separate controlled process."""
    cleaned = username.strip()
    if not USERNAME_PATTERN.fullmatch(cleaned):
        raise ValueError("Invalid username.")
    strength_error = password_strength_error(password)
    if strength_error:
        raise ValueError(strength_error)
    existing = connection.execute(
        "SELECT id FROM users WHERE username = ?",
        (cleaned,),
    ).fetchone()
    if existing:
        connection.execute(
            "UPDATE users SET password_hash = ?, is_admin = 1 WHERE id = ?",
            (hash_password(password), int(existing["id"])),
        )
        connection.commit()
        return "promoted"
    create_test_account(
        connection,
        cleaned,
        password,
        is_admin=True,
    )
    return "created"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--database-path",
        help="Optional SQLite database file path. If omitted, the configured database target is used.",
    )
    parser.add_argument(
        "--use-database-url",
        action="store_true",
        help="Provision the administrator in the PostgreSQL database configured by DATABASE_URL.",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicit confirmation that administrator access is intended.",
    )
    args = parser.parse_args()

    if not args.confirm:
        raise SystemExit("Refusing to provision an administrator without --confirm.")
    required_code = os.getenv("ADMIN_PROVISIONING_CODE")
    if not required_code:
        raise SystemExit("Set ADMIN_PROVISIONING_CODE before provisioning.")
    provided_code = getpass.getpass("Administrator provisioning code: ")
    if provided_code != required_code:
        raise SystemExit("Administrator provisioning code rejected.")

    username = args.username.strip()
    password = getpass.getpass("New administrator password: ")
    confirmation = getpass.getpass("Confirm administrator password: ")
    if password != confirmation:
        raise SystemExit("Password confirmation did not match.")
    strength_error = password_strength_error(password)
    if strength_error:
        raise SystemExit(strength_error)

    if args.database_path:
        target = args.database_path
    elif args.use_database_url:
        target = os.getenv("DATABASE_URL", "").strip() or None
    else:
        target = None

    connection = connect(target)
    try:
        initialize(connection)
        result = provision_administrator(
            connection,
            username=username,
            password=password,
        )
        print(
            "Existing account promoted to administrator."
            if result == "promoted"
            else "Administrator account created."
        )
    finally:
        connection.close()


if __name__ == "__main__":
    main()

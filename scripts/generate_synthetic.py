"""Create local test accounts and a synthetic login-event dataset.

Accounts receive random passwords. Only Argon2id hashes are written to SQLite.
A separate gitignored file keeps the generated passwords so a later demo can
sign in as those lab accounts. The event export contains behavioral features
and labels, never passwords.
"""

from __future__ import annotations

import argparse
import csv
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from random import Random

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import database_path
from app.detection.features import FEATURE_COLUMNS, synthetic_suspicious_label
from app.models.db import connect, initialize
from app.services.login_events import (
    LoginEvent,
    create_test_account,
    dataset_counts,
    password_matches,
    record_login_events,
)

DEFAULT_USERS = 12
DEFAULT_EVENTS = 360
DEFAULT_SEED = 42
# Documentation addresses from RFC 5737. They are not routable targets.
TEST_NETS = ("198.51.100.", "203.0.113.")


@dataclass(frozen=True)
class GeneratedAccount:
    user_id: int
    username: str
    password: str


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--users", type=int, default=DEFAULT_USERS)
    parser.add_argument("--events", type=int, default=DEFAULT_EVENTS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    if args.users < 1:
        raise SystemExit("Create at least one test account.")
    if args.events < 1:
        raise SystemExit("Create at least one login event.")

    db_path = database_path()
    _require_project_path(db_path)
    if db_path.exists():
        db_path.unlink()

    randomizer = Random(args.seed)
    connection = connect(db_path)
    try:
        initialize(connection)
        accounts = [
            _create_account(connection, index) for index in range(1, args.users + 1)
        ]
        _check_one_account(connection, accounts[0])
        events = _build_events(randomizer, accounts, args.events)
        stored = record_login_events(connection, events)
        counts = dataset_counts(connection)
    finally:
        connection.close()

    password_file = PROJECT_ROOT / "instance" / "test_accounts.csv"
    event_file = PROJECT_ROOT / "data" / "synthetic" / "login_events.csv"
    _write_passwords(password_file, accounts)
    _write_events(event_file, events)

    print(f"Database: {db_path}")
    print(f"Test accounts: {counts['users']} (passwords in {password_file})")
    print(
        f"Login events: {stored} "
        f"({counts['suspicious_events']} labeled suspicious) in {event_file}"
    )


def _create_account(connection, index: int) -> GeneratedAccount:
    username = f"lab-user-{index:02d}"
    password = secrets.token_urlsafe(18)
    user_id = create_test_account(connection, username, password)
    return GeneratedAccount(user_id=user_id, username=username, password=password)


def _check_one_account(connection, account: GeneratedAccount) -> None:
    if not password_matches(connection, account.username, account.password):
        raise RuntimeError("Stored Argon2id hash did not match the test password.")
    if password_matches(connection, account.username, "wrong-password-value"):
        raise RuntimeError("Stored hash matched a password that was not set.")


def _build_events(
    randomizer: Random, accounts: list[GeneratedAccount], count: int
) -> list[LoginEvent]:
    events: list[LoginEvent] = []
    for _ in range(count):
        account = randomizer.choice(accounts)
        if randomizer.random() < 0.7:
            features = _benign_features(randomizer)
        else:
            features = _suspicious_features(randomizer)
        label = synthetic_suspicious_label(**features)
        hour = features["hour_of_day"]
        events.append(
            LoginEvent(
                user_id=account.user_id,
                username=account.username,
                source_ip=_source_ip(randomizer),
                attempted_at=_timestamp(randomizer, hour),
                suspicious=label,
                **features,
            )
        )
    return events


def _benign_features(randomizer: Random) -> dict[str, int]:
    return {
        "hour_of_day": randomizer.randint(8, 20),
        "failed_attempts_last_15m": randomizer.choice((0, 0, 1)),
        "distinct_usernames_from_ip_15m": 1,
        "seconds_since_previous_attempt": randomizer.randint(45, 4000),
        "success": 1,
    }


def _suspicious_features(randomizer: Random) -> dict[str, int]:
    kind = randomizer.randrange(4)
    if kind == 0:
        features = {
            "hour_of_day": randomizer.randint(8, 20),
            "failed_attempts_last_15m": randomizer.randint(5, 12),
            "distinct_usernames_from_ip_15m": randomizer.randint(1, 3),
            "seconds_since_previous_attempt": randomizer.randint(3, 40),
            "success": 0,
        }
    elif kind == 1:
        features = {
            "hour_of_day": randomizer.randint(8, 20),
            "failed_attempts_last_15m": randomizer.randint(0, 3),
            "distinct_usernames_from_ip_15m": randomizer.randint(4, 8),
            "seconds_since_previous_attempt": randomizer.randint(3, 60),
            "success": 0,
        }
    elif kind == 2:
        features = {
            "hour_of_day": randomizer.randint(9, 18),
            "failed_attempts_last_15m": randomizer.randint(0, 3),
            "distinct_usernames_from_ip_15m": 1,
            "seconds_since_previous_attempt": randomizer.choice((0, 1, 2)),
            "success": 0,
        }
    else:
        features = {
            "hour_of_day": randomizer.randint(0, 4),
            "failed_attempts_last_15m": randomizer.randint(2, 4),
            "distinct_usernames_from_ip_15m": 1,
            "seconds_since_previous_attempt": randomizer.randint(30, 600),
            "success": 0,
        }
    if synthetic_suspicious_label(**features) != 1:
        raise RuntimeError("A suspicious scenario did not receive that label.")
    return features


def _source_ip(randomizer: Random) -> str:
    prefix = randomizer.choice(TEST_NETS)
    return f"{prefix}{randomizer.randint(1, 254)}"


def _timestamp(randomizer: Random, hour: int) -> str:
    moment = datetime(
        2026,
        3,
        randomizer.randint(1, 28),
        hour,
        randomizer.randint(0, 59),
        randomizer.randint(0, 59),
        tzinfo=timezone.utc,
    )
    return moment.isoformat()


def _write_passwords(path: Path, accounts: list[GeneratedAccount]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("username", "password"))
        writer.writeheader()
        for account in accounts:
            writer.writerow(
                {"username": account.username, "password": account.password}
            )


def _write_events(path: Path, events: list[LoginEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ("username", "source_ip", "attempted_at", *FEATURE_COLUMNS, "suspicious")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            writer.writerow(
                {
                    "username": event.username,
                    "source_ip": event.source_ip,
                    "attempted_at": event.attempted_at,
                    "suspicious": event.suspicious,
                    **{name: getattr(event, name) for name in FEATURE_COLUMNS},
                }
            )


def _require_project_path(path: Path) -> None:
    resolved = path.resolve()
    root = PROJECT_ROOT.resolve()
    if resolved != root and root not in resolved.parents:
        raise SystemExit("Refusing to write the database outside the project folder.")


if __name__ == "__main__":
    main()

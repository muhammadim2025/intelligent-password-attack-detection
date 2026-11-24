"""Generate isolated synthetic SOC dashboard demonstration records."""

from __future__ import annotations

import argparse
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.auth.hashing import hash_password
from app.detection.predictor import ModelUnavailableError, predict
from app.models.db import connect, initialize

DEFAULT_OUTPUT = PROJECT_ROOT / "instance" / "soc_demo.db"
DEMO_ACCOUNTS = 24


def generate(output: Path, count: int, seed: int) -> dict:
    real_database = (PROJECT_ROOT / "instance" / "research.db").resolve()
    if output.resolve() == real_database or output.name == "research.db":
        raise SystemExit("Refusing to overwrite the real research database.")

    rng = Random(seed)
    if output.exists():
        output.unlink()

    connection = connect(output)
    initialize(connection)

    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    admin_password = secrets.token_urlsafe(18)
    cursor = connection.execute(
        """
        INSERT INTO users (username, password_hash, is_admin, created_at)
        VALUES (?, ?, 1, ?)
        """,
        ("demo-admin", hash_password(admin_password), now.isoformat()),
    )
    admin_id = int(cursor.lastrowid)
    account_ids = {"demo-admin": admin_id}

    for index in range(1, DEMO_ACCOUNTS + 1):
        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, is_admin, created_at)
            VALUES (?, ?, 0, ?)
            """,
            (
                f"demo-user-{index:02d}",
                hash_password(secrets.token_urlsafe(18)),
                now.isoformat(),
            ),
        )
        account_ids[f"demo-user-{index:02d}"] = int(cursor.lastrowid)

    counts = {
        "events": 0,
        "success": 0,
        "failure": 0,
        "normal": 0,
        "suspicious": 0,
        "alerts": 0,
        "reviewed_alerts": 0,
    }

    for index in range(count):
        day_offset = rng.randrange(7)
        hour = rng.choices(
            (
                rng.randint(0, 5),
                rng.randint(6, 12),
                rng.randint(13, 18),
                rng.randint(19, 23),
            ),
            weights=(12, 28, 38, 22),
            k=1,
        )[0]
        minute = rng.randint(0, 59)
        attempted = (
            now
            - timedelta(
                days=day_offset,
                hours=rng.randint(0, 2),
                minutes=rng.randint(0, 15),
            )
        ).replace(hour=hour, minute=minute)

        source = f"synthetic-source-{rng.randint(1, 18):02d}"
        mode = rng.random()
        username = rng.choice(
            [name for name in account_ids if name != "demo-admin"]
        )

        if mode < 0.58:
            success = 1 if rng.random() < 0.94 else 0
            failed_attempts = rng.choice((0, 0, 1, 1, 2))
            login_attempts = rng.randint(max(1, failed_attempts), 5)
            unique_accounts = 1
            new_device = 1 if rng.random() < 0.10 else 0
            source_failure_rate = round(rng.uniform(0.0, 0.35), 3)
            time_since_last = rng.randint(300, 7200)
            account_failures = rng.randint(0, 2)
        elif mode < 0.82:
            success = 1 if rng.random() < 0.68 else 0
            failed_attempts = rng.randint(2, 6)
            login_attempts = rng.randint(
                max(3, failed_attempts),
                failed_attempts + 6,
            )
            unique_accounts = rng.randint(1, 3)
            new_device = 1 if rng.random() < 0.35 else 0
            source_failure_rate = round(rng.uniform(0.35, 0.72), 3)
            time_since_last = rng.randint(30, 900)
            account_failures = rng.randint(1, 5)
        else:
            success = 1 if rng.random() < 0.18 else 0
            failed_attempts = rng.randint(5, 12)
            login_attempts = rng.randint(
                max(7, failed_attempts),
                failed_attempts + 8,
            )
            unique_accounts = rng.randint(2, 6)
            new_device = 1 if rng.random() < 0.75 else 0
            source_failure_rate = round(rng.uniform(0.72, 1.0), 3)
            time_since_last = rng.randint(0, 300)
            account_failures = rng.randint(4, 10)

        if mode < 0.58:
            unique_ips_5min = 1 if rng.random() < 0.92 else 2
            unusual_login_time = 1 if rng.random() < 0.05 else 0
        elif mode < 0.82:
            unique_ips_5min = 1 if rng.random() < 0.55 else rng.randint(2, 3)
            unusual_login_time = 1 if rng.random() < 0.35 else 0
        else:
            unique_ips_5min = rng.randint(2, 6)
            unusual_login_time = 1 if rng.random() < 0.70 else 0

        features = {
            "failed_attempts_5min": failed_attempts,
            "login_attempts_5min": login_attempts,
            "unique_accounts_5min": unique_accounts,
            "new_device": new_device,
            "login_hour": attempted.hour,
            "source_failure_rate": source_failure_rate,
            "time_since_last_login": time_since_last,
            "recent_account_failure_count": account_failures,
            "unique_ips_5min": unique_ips_5min,
            "unusual_login_time": unusual_login_time,
        }

        try:
            prediction, probability = predict(features)
        except ModelUnavailableError:
            prediction, probability = 0, 0.0

        cursor = connection.execute(
            """
            INSERT INTO login_events (
                user_id, username, source_ip, attempted_at,
                hour_of_day, failed_attempts_last_15m,
                distinct_usernames_from_ip_15m,
                seconds_since_previous_attempt, success, suspicious,
                model_prediction, model_probability, alert_status,
                failed_attempts_5min, login_attempts_5min,
                unique_accounts_5min, new_device, login_hour,
                source_failure_rate, time_since_last_login,
                recent_account_failure_count, unique_ips_5min,
                unusual_login_time
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                account_ids[username],
                username,
                source,
                attempted.isoformat(),
                attempted.hour,
                failed_attempts,
                unique_accounts,
                time_since_last,
                success,
                prediction,
                prediction,
                probability,
                "open" if prediction else "none",
                failed_attempts,
                login_attempts,
                unique_accounts,
                new_device,
                attempted.hour,
                source_failure_rate,
                time_since_last,
                account_failures,
                unique_ips_5min,
                unusual_login_time,
            ),
        )
        event_id = int(cursor.lastrowid)

        if prediction:
            review_status = "reviewed" if rng.random() < 0.35 else "open"
            severity = "high" if probability >= 0.8 else "medium"
            connection.execute(
                """
                INSERT INTO security_alerts (
                    event_id, severity, explanation, review_status, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    severity,
                    "Synthetic model classified this demonstration event as suspicious.",
                    review_status,
                    attempted.isoformat(),
                ),
            )
            connection.execute(
                "UPDATE login_events SET alert_status = ? WHERE id = ?",
                (review_status, event_id),
            )
            counts["alerts"] += 1
            if review_status == "reviewed":
                counts["reviewed_alerts"] += 1

        counts["events"] += 1
        counts["success" if success else "failure"] += 1
        counts["suspicious" if prediction else "normal"] += 1

    connection.commit()
    connection.close()
    return {
        **counts,
        "database": str(output),
        "admin_username": "demo-admin",
        "admin_password": admin_password,
        "synthetic_accounts": DEMO_ACCOUNTS,
        "seed": seed,
    }


def verify(output: Path) -> dict:
    connection = connect(output)
    try:
        initialize(connection)
        event_count = connection.execute(
            "SELECT COUNT(*) FROM login_events"
        ).fetchone()[0]
        success_count = connection.execute(
            "SELECT COUNT(*) FROM login_events WHERE success = 1"
        ).fetchone()[0]
        failure_count = connection.execute(
            "SELECT COUNT(*) FROM login_events WHERE success = 0"
        ).fetchone()[0]
        normal_count = connection.execute(
            "SELECT COUNT(*) FROM login_events WHERE model_prediction = 0"
        ).fetchone()[0]
        suspicious_count = connection.execute(
            "SELECT COUNT(*) FROM login_events WHERE model_prediction = 1"
        ).fetchone()[0]
        alert_count = connection.execute(
            "SELECT COUNT(*) FROM security_alerts"
        ).fetchone()[0]
        invalid_alert_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_alerts a
            JOIN login_events e ON e.id = a.event_id
            WHERE e.model_prediction <> 1
            """
        ).fetchone()[0]
        reviewed_count = connection.execute(
            "SELECT COUNT(*) FROM security_alerts WHERE review_status = 'reviewed'"
        ).fetchone()[0]
        return {
            "events": event_count,
            "success": success_count,
            "failure": failure_count,
            "normal": normal_count,
            "suspicious": suspicious_count,
            "alerts": alert_count,
            "reviewed_alerts": reviewed_count,
            "invalid_alert_count": invalid_alert_count,
        }
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=160)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.count < 100 or args.count > 300:
        raise SystemExit("Demo event count must be between 100 and 300.")

    result = generate(args.output, args.count, args.seed)
    verified = verify(args.output)
    print("Synthetic SOC demonstration database created.")
    print(f"Database: {result['database']}")
    print(f"Synthetic admin username: {result['admin_username']}")
    print(
        "Synthetic admin password "
        "(copy now; it is not written to a file): "
        f"{result['admin_password']}"
    )
    print(f"Seed: {result['seed']}")
    print(f"Verification: {verified}")
    print(
        "Local demo mode: set SOC_DEMO_MODE=true and run "
        '"python -m flask --app app run"'
    )


if __name__ == "__main__":
    main()

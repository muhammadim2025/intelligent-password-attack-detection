"""Generate a reproducible 10,000-row synthetic authentication dataset."""

from __future__ import annotations

import argparse
import csv
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = PROJECT_ROOT / "data" / "synthetic" / "authentication_events.csv"

FEATURE_COLUMNS = (
    "failed_attempts_5min",
    "login_attempts_5min",
    "unique_accounts_5min",
    "new_device",
    "login_hour",
    "source_failure_rate",
    "time_since_last_login",
    "recent_account_failure_count",
    "unique_ips_5min",
    "unusual_login_time",
)


def synthetic_label(rng: Random, features: dict[str, int | float]) -> int:
    score = 0.0
    score += max(0.0, (float(features["failed_attempts_5min"]) - 2) * 0.18)
    score += max(0.0, (float(features["login_attempts_5min"]) - 4) * 0.07)
    score += max(0.0, (float(features["unique_accounts_5min"]) - 2) * 0.22)
    score += float(features["new_device"]) * 0.12
    score += max(0.0, float(features["source_failure_rate"]) - 0.35) * 0.55
    score += max(0.0, 180.0 - float(features["time_since_last_login"])) / 180.0 * 0.12
    score += max(0.0, float(features["recent_account_failure_count"]) - 1) * 0.10
    score += max(0.0, (float(features["unique_ips_5min"]) - 1) * 0.20)
    score += float(features["unusual_login_time"]) * 0.16
    suspicious = 1 if score >= 1.05 else 0

    # Controlled overlapping/noisy labels prevent any single feature from being a perfect shortcut.
    if rng.random() < 0.06:
        suspicious = 1 - suspicious
    return suspicious


def generate(count: int, seed: int, output: Path) -> dict[str, int]:
    rng = Random(seed)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    normal_count = 0
    suspicious_count = 0
    output.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = (
        "event_id",
        "source_id",
        "account_id",
        "attempted_at",
        *FEATURE_COLUMNS,
        "suspicious",
    )
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for index in range(count):
            attempted_at = start + timedelta(seconds=index * 37)
            attack = rng.random() < 0.25
            if attack:
                failed = rng.randint(3, 14)
                attempts = rng.randint(max(5, failed), failed + 12)
                unique_accounts = rng.randint(2, 9)
                new_device = 1 if rng.random() < 0.65 else 0
                # Realistic attack windows: distributed across hours, including off-pattern times.
                hour = rng.choice(
                    (rng.randint(0, 5), rng.randint(6, 11), rng.randint(20, 23))
                )
                source_failure_rate = round(rng.uniform(0.55, 1.0), 3)
                time_since_last = rng.randint(0, 240)
                account_failures = rng.randint(2, 12)
                # Multiple-IP activity for same username in 5 minutes (behavioural signal).
                unique_ips_5min = (
                    rng.randint(2, 6) if rng.random() < 0.75 else 1
                )
                # Unusual timing relative to learned user pattern: 1=unusual, 0=usual/safe.
                unusual_login_time = 1 if rng.random() < 0.70 else 0
            else:
                failed = rng.choice((0, 0, 0, 1, 2))
                attempts = rng.randint(max(1, failed), 5)
                unique_accounts = 1
                new_device = 1 if rng.random() < 0.12 else 0
                hour = rng.randint(6, 20)
                source_failure_rate = round(rng.uniform(0.0, 0.42), 3)
                time_since_last = rng.randint(120, 7200)
                account_failures = rng.randint(0, 2)
                # Normal activity typically comes from one or few known sources.
                unique_ips_5min = 1 if rng.random() < 0.93 else rng.randint(2, 3)
                # Insufficient/normal history is represented safely as 0 by extraction;
                # synthetic data includes mostly usual/safe timing with occasional edge cases.
                unusual_login_time = 1 if rng.random() < 0.05 else 0

            features = {
                "failed_attempts_5min": failed,
                "login_attempts_5min": attempts,
                "unique_accounts_5min": unique_accounts,
                "new_device": new_device,
                "login_hour": hour,
                "source_failure_rate": source_failure_rate,
                "time_since_last_login": time_since_last,
                "recent_account_failure_count": account_failures,
                "unique_ips_5min": unique_ips_5min,
                "unusual_login_time": unusual_login_time,
            }
            label = synthetic_label(rng, features)
            if label:
                suspicious_count += 1
            else:
                normal_count += 1
            source_id = f"source-{rng.randint(1, 200):03d}"
            account_id = f"account-{rng.randint(1, 80):03d}"
            writer.writerow(
                {
                    "event_id": index + 1,
                    "source_id": source_id,
                    "account_id": account_id,
                    "attempted_at": attempted_at.isoformat(),
                    **features,
                    "suspicious": label,
                }
            )

    return {
        "rows": count,
        "normal": normal_count,
        "suspicious": suspicious_count,
    }


def validate(path: Path) -> None:
    with path.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise RuntimeError("The synthetic dataset is empty.")
    if set(rows[0]) != {
        "event_id",
        "source_id",
        "account_id",
        "attempted_at",
        *FEATURE_COLUMNS,
        "suspicious",
    }:
        raise RuntimeError("The synthetic dataset has an unexpected schema.")
    labels = {int(row["suspicious"]) for row in rows}
    if labels != {0, 1}:
        raise RuntimeError("The synthetic dataset does not contain both target classes.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.count < 100:
        raise SystemExit("The dataset must contain at least 100 events.")
    counts = generate(args.count, args.seed, args.output)
    validate(args.output)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(f"Dataset: {args.output}")
    print(
        f"Rows: {counts['rows']} "
        f"(normal={counts['normal']}, suspicious={counts['suspicious']})"
    )
    print(f"Seed: {args.seed}")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()

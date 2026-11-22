"""Generate coherent Version 2 synthetic authentication sequences."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "research" / "v2"
OUTPUT = OUTPUT_DIR / "dataset.csv"

FEATURE_COLUMNS = (
    "failed_attempts_5min",
    "login_attempts_5min",
    "unique_accounts_5min",
    "new_device",
    "login_hour",
    "source_failure_rate",
    "time_since_last_login",
    "recent_account_failure_count",
)


def _prune(history: deque[tuple[datetime, bool]], moment: datetime, minutes: int) -> None:
    cutoff = moment - timedelta(minutes=minutes)
    while history and history[0][0] < cutoff:
        history.popleft()


def generate(count: int, seed: int, output: Path) -> dict:
    rng = Random(seed)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    moment = start

    accounts = [f"account-{index:03d}" for index in range(1, 401)]
    sources = [f"source-{index:03d}" for index in range(1, 241)]
    holdout_sources = set(rng.sample(sources, 48))

    known_pairs: set[tuple[str, str]] = set()
    source_history: dict[str, deque[tuple[datetime, str, bool]]] = defaultdict(deque)
    account_history: dict[str, deque[tuple[datetime, str, bool]]] = defaultdict(deque)

    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = (
        "event_id",
        "scenario",
        "scenario_variant",
        "session_id",
        "source_id",
        "account_id",
        "attempted_at",
        *FEATURE_COLUMNS,
        "suspicious",
        "source_group_holdout",
    )

    scenario_counts = defaultdict(int)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for event_id in range(1, count + 1):
            moment += timedelta(seconds=rng.randint(8, 90))
            roll = rng.random()

            if roll < 0.18:
                scenario = "suspicious"
                variant_roll = rng.random()
                if variant_roll < 0.34:
                    scenario_variant = "credential_burst"
                    source = rng.choice(sources)
                    account = rng.choice(accounts)
                    success = rng.random() < 0.12
                    pair_new = (source, account) not in known_pairs
                    session_id = f"s{event_id:06d}-{source}"
                elif variant_roll < 0.67:
                    scenario_variant = "account_spray"
                    source = rng.choice(sources)
                    account = rng.choice(accounts)
                    success = rng.random() < 0.08
                    pair_new = (source, account) not in known_pairs
                    session_id = f"s{event_id:06d}-{source}"
                else:
                    scenario_variant = "suspicious_new_device"
                    source = rng.choice(sources)
                    account = rng.choice(accounts)
                    success = rng.random() < 0.28
                    pair_new = True
                    session_id = f"s{event_id:06d}-{source}"
            elif roll < 0.28:
                scenario = "unusual_legitimate"
                scenario_variant = rng.choice(
                    ("new_device", "night_activity", "travel_pattern", "repeated_failure")
                )
                source = rng.choice(sources)
                account = rng.choice(accounts)
                if scenario_variant == "repeated_failure":
                    success = rng.random() < 0.48
                elif scenario_variant == "night_activity":
                    success = rng.random() < 0.82
                else:
                    success = rng.random() < 0.72
                pair_new = (source, account) not in known_pairs
                session_id = f"s{event_id:06d}-{source}"
            else:
                scenario = "normal"
                scenario_variant = rng.choice(
                    ("routine", "occasional_failure", "known_device")
                )
                account = rng.choice(accounts)
                source = rng.choice(sources)
                if scenario_variant == "occasional_failure":
                    success = rng.random() < 0.72
                else:
                    success = rng.random() < 0.94
                pair_new = (source, account) not in known_pairs
                session_id = f"s{event_id:06d}-{source}"

            for history in (source_history[source], account_history[account]):
                _prune(history, moment, 5)

            source_events = list(source_history[source])
            account_events = list(account_history[account])
            failed_attempts = sum(1 for _, _, success_flag in source_events if not success_flag)
            login_attempts = len(source_events) + 1
            unique_accounts = len({account_id for _, account_id, _ in source_events})
            if account not in {account_id for _, account_id, _ in source_events}:
                unique_accounts += 1

            source_failures = sum(1 for _, _, success_flag in source_events if not success_flag)
            source_failure_rate = (
                (source_failures + (0 if success else 1)) / max(1, login_attempts)
            )

            account_failures = sum(
                1 for _, _, success_flag in account_events if not success_flag
            )
            if not success:
                account_failures += 1

            source_history[source].append((moment, account, success))
            account_history[account].append((moment, source, success))

            prior_source_account = (source, account) in known_pairs
            new_device = 0 if prior_source_account else 1
            known_pairs.add((source, account))

            if account_events:
                time_since_last_login = max(
                    0,
                    int((moment - account_events[-1][0]).total_seconds()),
                )
            else:
                time_since_last_login = rng.randint(600, 7200)

            hour = moment.hour

            # Scenario ground truth is independent of this feature calculation.
            label = 1 if scenario == "suspicious" else 0

            scenario_counts[(scenario, scenario_variant)] += 1
            writer.writerow(
                {
                    "event_id": event_id,
                    "scenario": scenario,
                    "scenario_variant": scenario_variant,
                    "session_id": session_id,
                    "source_id": source,
                    "account_id": account,
                    "attempted_at": moment.isoformat(),
                    "failed_attempts_5min": failed_attempts + (0 if success else 1),
                    "login_attempts_5min": login_attempts,
                    "unique_accounts_5min": unique_accounts,
                    "new_device": new_device,
                    "login_hour": hour,
                    "source_failure_rate": round(source_failure_rate, 6),
                    "time_since_last_login": time_since_last_login,
                    "recent_account_failure_count": account_failures,
                    "suspicious": label,
                    "source_group_holdout": int(source in holdout_sources),
                }
            )

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    config = {
        "version": 2,
        "seed": seed,
        "rows": count,
        "accounts": 400,
        "sources": 240,
        "holdout_source_count": 48,
        "feature_columns": list(FEATURE_COLUMNS),
        "ground_truth": "Scenario-based: suspicious for the suspicious scenario; normal for normal and unusual-legitimate scenarios.",
        "uncertainty_model": "No random label inversion. Scenario overlap is created through stochastic behavior and shared histories.",
        "rolling_windows": "5-minute rolling windows using event history with timestamps <= the current event.",
        "new_device": "1 only when the source-account pair has not appeared before.",
        "time_since_last_login": "Seconds since the account's previous event; no future events.",
        "split": "Chronological 75/25 primary split plus a 48-source holdout group-disjoint evaluation.",
        "scenario_counts": {
            f"{scenario}|{variant}": count
            for (scenario, variant), count in sorted(scenario_counts.items())
        },
        "dataset_sha256": digest,
    }
    (output.parent / "generation_config.json").write_text(
        json.dumps(config, indent=2),
        encoding="utf-8",
    )
    (output.parent / "dataset_sha256.txt").write_text(digest + "\n", encoding="ascii")
    return config


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.count < 1000:
        raise SystemExit("Use at least 1000 events for a useful split.")
    config = generate(args.count, args.seed, args.output)
    print(json.dumps(config, indent=2))


if __name__ == "__main__":
    main()

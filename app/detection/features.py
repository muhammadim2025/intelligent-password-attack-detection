"""Feature names and the synthetic ground-truth rule.

The Decision Tree itself is still a later phase. This module only names the
columns that describe a login event and stamps a synthetic label on them.
"""

from __future__ import annotations

from collections.abc import Mapping

FEATURE_COLUMNS = (
    "hour_of_day",
    "failed_attempts_last_15m",
    "distinct_usernames_from_ip_15m",
    "seconds_since_previous_attempt",
    "success",
)

RESEARCH_FEATURE_COLUMNS = (
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

LABEL_COLUMN = "suspicious"


def feature_values(event: Mapping[str, int]) -> dict[str, int]:
    """Copy the numeric feature columns from a login event."""
    return {name: int(event[name]) for name in FEATURE_COLUMNS}


def synthetic_suspicious_label(
    *,
    hour_of_day: int,
    failed_attempts_last_15m: int,
    distinct_usernames_from_ip_15m: int,
    seconds_since_previous_attempt: int,
    success: int,
) -> int:
    """Return 1 when a synthetic login event matches the lab labeling rule.

    The rule is the ground truth for generated rows. It is not a trained model.
    A row is labeled suspicious when it shows many recent failures, many
    account names from one address, a very short gap between failures, or
    repeated failures during the late-night hours used in this dataset.
    """
    if failed_attempts_last_15m >= 5:
        return 1
    if distinct_usernames_from_ip_15m >= 4:
        return 1
    if success == 0 and seconds_since_previous_attempt <= 2:
        return 1
    if hour_of_day <= 4 and failed_attempts_last_15m >= 2:
        return 1
    return 0

"""Synthetic dataset, model, and Argon2 verifier tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from app.auth.hashing import (
    hash_password,
    needs_rehash,
    password_strength_error,
    verify_password,
)
from app.detection.features import RESEARCH_FEATURE_COLUMNS
from app.detection.predictor import load_model, predict
from app.models.db import connect, initialize
from app.privacy import pseudonymize_source
from app.services.login_events import (
    create_test_account,
    purge_expired_authentication_events,
    record_authentication_event,
)
from scripts.generate_research_dataset import FEATURE_COLUMNS, generate, validate
from scripts.generate_soc_demo import generate as generate_soc_demo
from scripts.generate_soc_demo import verify as verify_soc_demo
from scripts.provision_administrator import provision_administrator


def test_argon2_hashes_are_unique_and_malformed_hashes_are_safe() -> None:
    first = hash_password("same-lab-password")
    second = hash_password("same-lab-password")
    assert first != second
    assert verify_password(first, "same-lab-password")
    assert not verify_password(first, "incorrect-password")
    assert not verify_password("malformed-verifier", "same-lab-password")
    assert needs_rehash(first) is False


def test_research_dataset_is_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    generate(1000, 42, first)
    generate(1000, 42, second)
    assert first.read_bytes() == second.read_bytes()
    validate(first)
    frame = pd.read_csv(first)
    assert len(frame) == 1000
    assert set(frame["suspicious"]) == {0, 1}
    assert set(FEATURE_COLUMNS).issubset(frame.columns)
    assert list(FEATURE_COLUMNS) == list(RESEARCH_FEATURE_COLUMNS)
    assert tuple(FEATURE_COLUMNS[-2:]) == ("unique_ips_5min", "unusual_login_time")


def test_trained_model_artifact_matches_feature_schema() -> None:
    model_path = (
        Path(__file__).resolve().parents[1] / "instance" / "decision_tree.joblib"
    )
    if not model_path.is_file():
        raise AssertionError("Expected the trained synthetic model artifact.")
    artifact = load_model(model_path)
    assert artifact["synthetic"] is True
    assert artifact["feature_columns"] == list(RESEARCH_FEATURE_COLUMNS)
    assert len(artifact["feature_columns"]) == 10


def test_model_prediction_returns_binary_label_and_probability() -> None:
    model_path = (
        Path(__file__).resolve().parents[1] / "instance" / "decision_tree.joblib"
    )
    if not model_path.is_file():
        raise AssertionError("Expected the trained synthetic model artifact.")
    prediction, probability = predict(
        {
            "failed_attempts_5min": 8,
            "login_attempts_5min": 12,
            "unique_accounts_5min": 6,
            "new_device": 1,
            "login_hour": 2,
            "source_failure_rate": 0.9,
            "time_since_last_login": 10,
            "recent_account_failure_count": 8,
            "unique_ips_5min": 4,
            "unusual_login_time": 1,
        },
        model_path,
    )
    assert prediction in (0, 1)
    assert 0.0 <= probability <= 1.0


def test_password_strength_policy_rejects_weak_passwords() -> None:
    assert password_strength_error("weakpass") is not None
    assert password_strength_error("alllowercasepassword") is not None
    assert password_strength_error("Lab-password-2026!") is None


def test_source_pseudonymization_is_keyed_and_stable() -> None:
    first = pseudonymize_source("198.51.100.10", "secret-one")
    assert first == pseudonymize_source("198.51.100.10", "secret-one")
    assert first != pseudonymize_source("198.51.100.10", "secret-two")
    assert "198.51.100.10" not in first


def test_auth_event_retention_preserves_users_and_deletes_expired(tmp_path: Path) -> None:
    connection = connect(tmp_path / "retention.db")
    try:
        initialize(connection)
        connection.execute(
            """
            INSERT INTO users (username, password_hash, is_admin, created_at)
            VALUES ('retention-user', 'verifier-placeholder', 0, '2026-01-01T00:00:00+00:00')
            """
        )
        connection.execute(
            """
            INSERT INTO login_events (
                username, source_ip, attempted_at, hour_of_day,
                failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                seconds_since_previous_attempt, success, suspicious
            ) VALUES (
                'retention-user', 'source:pseudonymized',
                '2025-01-01T00:00:00+00:00', 0, 0, 1, 3600, 1, 0
            )
            """
        )
        connection.commit()
        deleted = purge_expired_authentication_events(
            connection,
            retention_days=30,
            now=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        assert deleted == 1
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM users"
        ).fetchone()["count"] == 1
        assert connection.execute(
            "SELECT COUNT(*) AS count FROM login_events"
        ).fetchone()["count"] == 0
    finally:
        connection.close()


def test_controlled_administrator_provisioning(tmp_path: Path) -> None:
    connection = connect(tmp_path / "admin.db")
    try:
        initialize(connection)
        create_test_account(
            connection,
            "controlled-user",
            "Controlled-password-2026!",
        )
        result = provision_administrator(
            connection,
            username="controlled-user",
            password="New-admin-password-2026!",
        )
        assert result == "promoted"
        row = connection.execute(
            "SELECT is_admin FROM users WHERE username = 'controlled-user'"
        ).fetchone()
        assert row["is_admin"] == 1
    finally:
        connection.close()


def test_soc_demo_database_is_isolated_and_internal(tmp_path: Path) -> None:
    demo = tmp_path / "soc_demo.db"
    generated = generate_soc_demo(demo, 100, 2026)
    checked = verify_soc_demo(demo)

    assert checked["events"] == 100
    assert checked["success"] + checked["failure"] == 100
    assert checked["normal"] + checked["suspicious"] == 100
    assert checked["invalid_alert_count"] == 0
    assert checked["alerts"] == checked["suspicious"]
    assert generated["admin_username"] == "demo-admin"
    assert demo.is_file()


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        fixed = datetime(2026, 5, 20, 14, 30, tzinfo=timezone.utc)
        if tz is None:
            return fixed.replace(tzinfo=None)
        return fixed.astimezone(tz)


def test_behavioural_features_unique_ips_unusual_time_and_defaults(tmp_path: Path) -> None:
    connection = connect(tmp_path / "behaviour.db")
    try:
        initialize(connection)

        # Insufficient history: unusual_login_time must remain default-safe (0)
        with patch("app.services.login_events.datetime", _FixedDateTime), patch.dict(
            "os.environ", {"UNUSUAL_LOGIN_MIN_HISTORY": "5"}
        ):
            _, features = record_authentication_event(
                connection,
                username="new-user",
                source_ip="src-a",
                success=1,
                user_id=None,
            )
        assert features["unique_ips_5min"] == 1
        assert features["unusual_login_time"] == 0

        # Seed successful history at 09:00 UTC to make 14:30 UTC unusual when history is sufficient
        for day in (10, 11, 12, 13, 14):
            connection.execute(
                """
                INSERT INTO login_events (
                    username, source_ip, attempted_at, hour_of_day,
                    failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                    seconds_since_previous_attempt, success, suspicious
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "history-user",
                    "src-h",
                    f"2026-05-{day}T09:00:00+00:00",
                    9,
                    0,
                    1,
                    3600,
                    1,
                    0,
                ),
            )
        # Recent successful history at 14:00 UTC for usual-time case
        for day in (15, 16, 17, 18, 19):
            connection.execute(
                """
                INSERT INTO login_events (
                    username, source_ip, attempted_at, hour_of_day,
                    failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                    seconds_since_previous_attempt, success, suspicious
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "usual-user",
                    "src-u",
                    f"2026-05-{day}T14:10:00+00:00",
                    14,
                    0,
                    1,
                    3600,
                    1,
                    0,
                ),
            )
        # Multiple distinct pseudonymized sources in previous 5 minutes for same username
        for src in ("src-1", "src-2", "src-3"):
            connection.execute(
                """
                INSERT INTO login_events (
                    username, source_ip, attempted_at, hour_of_day,
                    failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                    seconds_since_previous_attempt, success, suspicious
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "multi-user",
                    src,
                    "2026-05-20T14:28:00+00:00",
                    14,
                    1,
                    1,
                    60,
                    0,
                    0,
                ),
            )
        connection.commit()

        with patch("app.services.login_events.datetime", _FixedDateTime), patch.dict(
            "os.environ", {"UNUSUAL_LOGIN_MIN_HISTORY": "5"}
        ):
            _, unusual_features = record_authentication_event(
                connection,
                username="history-user",
                source_ip="src-h",
                success=1,
                user_id=None,
            )
            _, usual_features = record_authentication_event(
                connection,
                username="usual-user",
                source_ip="src-u",
                success=1,
                user_id=None,
            )
            _, multi_features = record_authentication_event(
                connection,
                username="multi-user",
                source_ip="src-4",
                success=0,
                user_id=None,
            )

        assert unusual_features["unusual_login_time"] == 1
        assert usual_features["unusual_login_time"] == 0
        assert multi_features["unique_ips_5min"] >= 4

        # Missing/unavailable IP information must be handled safely
        with patch("app.services.login_events.datetime", _FixedDateTime), patch.dict(
            "os.environ", {"UNUSUAL_LOGIN_MIN_HISTORY": "5"}
        ):
            _, missing_ip_features = record_authentication_event(
                connection,
                username="missing-ip-user",
                source_ip="",
                success=1,
                user_id=None,
            )
        assert missing_ip_features["unique_ips_5min"] >= 1
        assert missing_ip_features["unusual_login_time"] == 0
    finally:
        connection.close()
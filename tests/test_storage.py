"""Checks for Argon2id storage and the synthetic login tables."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.auth.hashing import hash_password, verify_password
from app.detection.features import synthetic_suspicious_label
from app.models.db import connect, initialize
from app.services.login_events import LoginEvent, create_test_account, password_matches, record_login_event


class HashingTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        stored = hash_password("lab-password-one")
        self.assertTrue(stored.startswith("$argon2id$"))
        self.assertTrue(verify_password(stored, "lab-password-one"))

    def test_rejects_other_password(self) -> None:
        stored = hash_password("lab-password-one")
        self.assertFalse(verify_password(stored, "lab-password-two"))

    def test_rejects_short_password(self) -> None:
        with self.assertRaises(ValueError):
            hash_password("short")


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.connection = connect(Path(self.directory.name) / "research.db")
        initialize(self.connection)

    def tearDown(self) -> None:
        self.connection.close()
        self.directory.cleanup()

    def test_account_stores_hash_only(self) -> None:
        create_test_account(self.connection, "lab-user-01", "lab-password-one")
        row = self.connection.execute(
            "SELECT username, password_hash FROM users"
        ).fetchone()
        self.assertEqual(row["username"], "lab-user-01")
        self.assertNotIn("lab-password-one", row["password_hash"])
        self.assertTrue(password_matches(self.connection, "lab-user-01", "lab-password-one"))
        self.assertFalse(password_matches(self.connection, "lab-user-01", "lab-password-two"))

    def test_login_event_keeps_matching_label(self) -> None:
        features = {
            "hour_of_day": 14,
            "failed_attempts_last_15m": 6,
            "distinct_usernames_from_ip_15m": 1,
            "seconds_since_previous_attempt": 20,
            "success": 0,
        }
        event = LoginEvent(
            username="lab-user-01",
            source_ip="198.51.100.10",
            attempted_at="2026-03-01T14:00:00+00:00",
            suspicious=synthetic_suspicious_label(**features),
            **features,
        )
        record_login_event(self.connection, event)
        row = self.connection.execute(
            "SELECT suspicious, success FROM login_events"
        ).fetchone()
        self.assertEqual(row["suspicious"], 1)
        self.assertEqual(row["success"], 0)

    def test_rejects_mislabeled_event(self) -> None:
        event = LoginEvent(
            username="lab-user-01",
            source_ip="198.51.100.10",
            attempted_at="2026-03-01T14:00:00+00:00",
            hour_of_day=14,
            failed_attempts_last_15m=0,
            distinct_usernames_from_ip_15m=1,
            seconds_since_previous_attempt=120,
            success=1,
            suspicious=1,
        )
        with self.assertRaises(ValueError):
            record_login_event(self.connection, event)


if __name__ == "__main__":
    unittest.main()

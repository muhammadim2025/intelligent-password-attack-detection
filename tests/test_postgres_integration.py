from __future__ import annotations

import os

import pytest

from app import create_app
from app.models.db import connect, initialize


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL", "").strip()

pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is not configured; PostgreSQL integration tests were not run.",
)


@pytest.fixture
def postgres_app():
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "postgres-test-secret",
            "PRIVACY_HMAC_KEY": "postgres-test-privacy-secret",
            "DATABASE_URL": TEST_DATABASE_URL,
            "DB_TARGET": TEST_DATABASE_URL,
            "RATELIMIT_ENABLED": False,
            "WTF_CSRF_ENABLED": False,
            "MANUAL_DETECTION_LAB": False,
        }
    )
    connection = connect(TEST_DATABASE_URL)
    try:
        initialize(connection)
        for table in (
            "synthetic_test_alerts",
            "synthetic_test_events",
            "security_alerts",
            "login_events",
            "users",
        ):
            connection.execute(f"DELETE FROM {table}")
        connection.commit()
    finally:
        connection.close()
    yield app


@pytest.fixture
def postgres_client(postgres_app):
    return postgres_app.test_client()


def _admin_exists(app, username: str) -> bool:
    connection = connect(app.config["DB_TARGET"])
    try:
        row = connection.execute(
            "SELECT is_admin FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return bool(row and int(row["is_admin"]) == 1)
    finally:
        connection.close()


def test_postgres_registration_and_login(postgres_client, postgres_app):
    register = postgres_client.post(
        "/register",
        data={
            "username": "pg_user",
            "password": "StrongPass!12345",
            "confirmation": "StrongPass!12345",
        },
        follow_redirects=False,
    )
    assert register.status_code == 302

    login = postgres_client.post(
        "/login",
        data={"username": "pg_user", "password": "StrongPass!12345"},
        follow_redirects=False,
    )
    assert login.status_code == 302

    connection = connect(postgres_app.config["DB_TARGET"])
    try:
        user = connection.execute(
            "SELECT username, is_admin FROM users WHERE username = ?",
            ("pg_user",),
        ).fetchone()
        assert user is not None
        assert user["username"] == "pg_user"
        assert int(user["is_admin"]) == 0
        event_count = connection.execute(
            "SELECT COUNT(*) AS count FROM login_events WHERE username = ?",
            ("pg_user",),
        ).fetchone()["count"]
        assert int(event_count) >= 1
    finally:
        connection.close()


def test_postgres_admin_authorization(postgres_client, postgres_app):
    # Create a normal user and promote directly in the test database.
    postgres_client.post(
        "/register",
        data={
            "username": "pg_admin",
            "password": "StrongPass!12345",
            "confirmation": "StrongPass!12345",
        },
    )
    connection = connect(postgres_app.config["DB_TARGET"])
    try:
        connection.execute(
            "UPDATE users SET is_admin = 1 WHERE username = ?",
            ("pg_admin",),
        )
        connection.commit()
    finally:
        connection.close()
    assert _admin_exists(postgres_app, "pg_admin")

    login = postgres_client.post(
        "/login",
        data={"username": "pg_admin", "password": "StrongPass!12345"},
        follow_redirects=False,
    )
    assert login.status_code == 302
    response = postgres_client.get("/admin")
    assert response.status_code == 200

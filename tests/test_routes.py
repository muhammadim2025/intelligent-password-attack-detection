"""Route-level tests for the local Flask authentication flow."""

from __future__ import annotations

import json
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import create_app
from app.detection.predictor import ModelUnavailableError, predict
from app.models.db import connect, initialize
from app.services.alerts import create_alert, mark_alert_reviewed
from app.services.login_events import create_test_account


@pytest.fixture()
def temp_app(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "pytest-only-secret-key",
            "DATABASE_PATH": tmp_path / "research.db",
            "WTF_CSRF_ENABLED": True,
            "SESSION_COOKIE_SECURE": False,
            "RATELIMIT_ENABLED": True,
            "MANUAL_DETECTION_LAB": True,
        }
    )
    connection = connect(app.config["DATABASE_PATH"])
    try:
        initialize(connection)
    finally:
        connection.close()
    return app


@pytest.fixture()
def client(temp_app):
    return temp_app.test_client()


def csrf_token(client, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match is not None
    return match.group(1)


def test_registration_hashes_password_and_never_grants_admin(
    temp_app, client
) -> None:
    token = csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": token,
            "username": "lab-user-one",
            "password": "lab-password-one",
            "confirmation": "lab-password-one",
        },
    )
    assert response.status_code == 302

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        row = connection.execute(
            "SELECT password_hash, is_admin FROM users WHERE username = ?",
            ("lab-user-one",),
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row["password_hash"].startswith("$argon2id$")
    assert row["is_admin"] == 0


def test_registration_rejects_weak_password(temp_app, client) -> None:
    token = csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": token,
            "username": "weak-password-user",
            "password": "weakpass",
            "confirmation": "weakpass",
        },
    )
    assert response.status_code == 400

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM users WHERE username = ?",
            ("weak-password-user",),
        ).fetchone()
    finally:
        connection.close()
    assert row["count"] == 0


def test_csrf_rejection(client) -> None:
    response = client.post(
        "/login",
        data={"username": "nobody", "password": "a-long-enough-password"},
    )
    assert response.status_code == 400


def test_security_headers_are_added(client) -> None:
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_failed_login_is_generic_and_records_event(temp_app, client) -> None:
    token = csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "missing-user",
            "password": "never-store-this-plaintext",
        },
    )
    assert response.status_code == 401
    body = response.get_data(as_text=True)
    assert "Invalid username or password." in body
    assert "never-store-this-plaintext" not in body

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        event = connection.execute(
            "SELECT username, success, suspicious FROM login_events"
        ).fetchone()
    finally:
        connection.close()
    assert event is not None
    assert event["username"] == "missing-user"
    assert event["success"] == 0


def test_successful_login_logout_and_event_recording(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "lab-user-login",
            "lab-password-login",
        )
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "lab-user-login",
            "password": "lab-password-login",
        },
    )
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert "_user_id" in session

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        event = connection.execute(
            "SELECT success FROM login_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        connection.close()
    assert event["success"] == 1

    token = csrf_token(client, "/login")
    response = client.post(
        "/logout",
        data={"csrf_token": token},
    )
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_dashboard_route_is_role_specific(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "route-normal",
            "route-normal-password",
        )
        create_test_account(
            connection,
            "route-admin",
            "route-admin-password",
            is_admin=True,
        )
    finally:
        connection.close()

    normal_token = csrf_token(client, "/login")
    normal_login = client.post(
        "/login",
        data={
            "csrf_token": normal_token,
            "username": "route-normal",
            "password": "route-normal-password",
        },
    )
    assert normal_login.status_code == 302
    assert client.get("/dashboard").status_code == 200
    assert "Recent account activity" in client.get("/dashboard").get_data(as_text=True)

    logout_token = csrf_token(client, "/login")
    client.post("/logout", data={"csrf_token": logout_token})

    admin_token = csrf_token(client, "/login")
    admin_login = client.post(
        "/login",
        data={
            "csrf_token": admin_token,
            "username": "route-admin",
            "password": "route-admin-password",
        },
    )
    assert admin_login.status_code == 302
    admin_dashboard = client.get("/dashboard")
    assert admin_dashboard.status_code == 302
    assert admin_dashboard.location.endswith("/admin")
    assert client.get("/admin").status_code == 200


def test_admin_dashboard_authorization(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "lab-admin",
            "lab-admin-password",
            is_admin=True,
        )
        create_test_account(
            connection,
            "lab-normal",
            "lab-normal-password",
        )
    finally:
        connection.close()

    response = client.get("/admin")
    assert response.status_code == 302

    token = csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "lab-normal",
            "password": "lab-normal-password",
        },
    )
    assert response.status_code == 302
    assert client.get("/admin").status_code == 403

    token = csrf_token(client, "/login")
    client.post(
        "/logout",
        data={"csrf_token": token},
    )

    token = csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "lab-admin",
            "password": "lab-admin-password",
        },
    )
    assert response.status_code == 302
    assert client.get("/admin").status_code == 200


def test_login_is_rate_limited(temp_app, client) -> None:
    token = csrf_token(client, "/login")
    status_codes = []
    for _ in range(6):
        response = client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "missing-user",
                "password": "not-a-real-password",
            },
        )
        status_codes.append(response.status_code)
    assert 429 in status_codes

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        event_count = connection.execute(
            "SELECT COUNT(*) AS count FROM login_events"
        ).fetchone()["count"]
    finally:
        connection.close()
    assert event_count >= 1


def test_model_loading_failure_is_safe(tmp_path: Path) -> None:
    with pytest.raises(ModelUnavailableError):
        predict(
            {
                "failed_attempts_5min": 0,
                "login_attempts_5min": 1,
                "unique_accounts_5min": 1,
                "new_device": 0,
                "login_hour": 12,
                "source_failure_rate": 0.1,
                "time_since_last_login": 1000,
                "recent_account_failure_count": 0,
            },
            tmp_path / "missing.joblib",
        )


def test_security_alert_review_authorization(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "lab-admin-alert",
            "lab-admin-password",
            is_admin=True,
        )
        cursor = connection.execute(
            """
            INSERT INTO login_events (
                user_id, username, source_ip, attempted_at, hour_of_day,
                failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                seconds_since_previous_attempt, success, suspicious
            ) VALUES (NULL, 'lab-admin-alert', '127.0.0.1', '2026-03-01T12:00:00+00:00',
                      12, 6, 1, 30, 0, 1)
            """
        )
        event_id = int(cursor.lastrowid)
        alert_id = create_alert(
            connection,
            event_id=event_id,
            severity="medium",
            explanation="Synthetic test alert.",
        )
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "lab-admin-alert",
            "password": "lab-admin-password",
        },
    )
    response = client.post(
        f"/admin/alerts/{alert_id}/review",
        data={"csrf_token": csrf_token(client, "/login")},
    )
    assert response.status_code == 302

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        row = connection.execute(
            "SELECT review_status FROM security_alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        event_row = connection.execute(
            "SELECT alert_status FROM login_events WHERE id = ?",
            (event_id,),
        ).fetchone()
    finally:
        connection.close()
    assert row["review_status"] == "reviewed"
    assert event_row["alert_status"] == "reviewed"


def test_live_ai_normal_and_suspicious_login_workflow(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "live-normal",
            "live-normal-password",
        )
        create_test_account(
            connection,
            "live-admin",
            "live-admin-password",
            is_admin=True,
        )
    finally:
        connection.close()

    remote_ip = "198.51.100.77"
    login_token = csrf_token(client, "/login")
    normal = client.post(
        "/login",
        data={
            "csrf_token": login_token,
            "username": "live-normal",
            "password": "live-normal-password",
        },
        environ_base={"REMOTE_ADDR": remote_ip},
    )
    assert normal.status_code == 302

    for username in ("missing-target-one", "missing-target-two"):
        login_token = csrf_token(client, "/login")
        response = client.post(
            "/login",
            data={
                "csrf_token": login_token,
                "username": username,
                "password": "not-a-real-password",
            },
            environ_base={"REMOTE_ADDR": remote_ip},
        )
        assert response.status_code == 401

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        event_count = connection.execute(
            "SELECT COUNT(*) AS count FROM login_events"
        ).fetchone()["count"]
        normal_event = connection.execute(
            """
            SELECT model_prediction, model_probability
            FROM login_events
            WHERE username = 'live-normal'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        suspicious_event = connection.execute(
            """
            SELECT id, model_prediction, model_probability
            FROM login_events
            WHERE username = 'missing-target-two'
            LIMIT 1
            """
        ).fetchone()
        alerts = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_alerts
            WHERE event_id = ?
            """,
            (suspicious_event["id"],),
        ).fetchone()["count"]
    finally:
        connection.close()

    assert event_count == 3
    assert normal_event["model_prediction"] == 0
    assert suspicious_event["model_prediction"] == 1
    assert 0.0 <= suspicious_event["model_probability"] <= 1.0
    assert alerts == 1

    logout_token = csrf_token(client, "/login")
    client.post("/logout", data={"csrf_token": logout_token})
    admin_token = csrf_token(client, "/login")
    admin_login = client.post(
        "/login",
        data={
            "csrf_token": admin_token,
            "username": "live-admin",
            "password": "live-admin-password",
        },
        environ_base={"REMOTE_ADDR": remote_ip},
    )
    assert admin_login.status_code == 302
    with client.session_transaction() as session:
        assert "_user_id" in session

    dashboard = client.get("/admin", environ_base={"REMOTE_ADDR": remote_ip})
    assert dashboard.status_code == 200, dashboard.location
    dashboard_body = dashboard.get_data(as_text=True)
    assert "missing-target-two" in dashboard_body
    assert "medium" in dashboard_body or "high" in dashboard_body
    assert "Synthetic Test" in dashboard_body


def test_research_dashboard_displays_measured_evaluation(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "research-admin",
            "research-admin-password",
            is_admin=True,
        )
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "research-admin",
            "password": "research-admin-password",
        },
    )
    assert response.status_code == 302
    research = client.get("/research")
    assert research.status_code == 200
    body = research.get_data(as_text=True)
    assert "10000" in body
    assert "0.8915" in body
    assert "0.7290" in body

    asset = client.get("/research-assets/metrics_comparison.png")
    assert asset.status_code == 200


def test_manual_detection_lab_is_admin_protected_and_separate(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "manual-admin",
            "manual-admin-password",
            is_admin=True,
        )
        create_test_account(
            connection,
            "manual-normal",
            "manual-normal-password",
        )
        real_event_count = connection.execute(
            "SELECT COUNT(*) FROM login_events"
        ).fetchone()[0]
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    normal_login = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "manual-normal",
            "password": "manual-normal-password",
        },
    )
    assert normal_login.status_code == 302
    assert client.get("/admin/manual-detection").status_code == 403

    logout_token = csrf_token(client, "/login")
    client.post("/logout", data={"csrf_token": logout_token})

    admin_token = csrf_token(client, "/login")
    admin_login = client.post(
        "/login",
        data={
            "csrf_token": admin_token,
            "username": "manual-admin",
            "password": "manual-admin-password",
        },
    )
    assert admin_login.status_code == 302
    lab = client.get("/admin/manual-detection")
    assert lab.status_code == 200
    lab_body = lab.get_data(as_text=True)
    assert "Test Normal Login Behavior" in lab_body
    assert "Test Suspicious Login Behavior" in lab_body

    normal_result = client.post(
        "/admin/manual-detection",
        data={
            "csrf_token": csrf_token(client, "/admin/manual-detection"),
            "scenario": "normal",
            "action": "predict",
        },
    )
    assert normal_result.status_code == 200
    normal_body = normal_result.get_data(as_text=True)
    assert "Save Synthetic Test Result" in normal_body
    assert "Prediction" in normal_body

    suspicious_result = client.post(
        "/admin/manual-detection",
        data={
            "csrf_token": csrf_token(client, "/admin/manual-detection"),
            "scenario": "suspicious",
            "action": "predict",
        },
    )
    assert suspicious_result.status_code == 200
    suspicious_body = suspicious_result.get_data(as_text=True)
    assert "Save Synthetic Test Result" in suspicious_body
    assert "Suspicious" in suspicious_body or "Normal" in suspicious_body

    saved_result = client.post(
        "/admin/manual-detection",
        data={
            "csrf_token": csrf_token(client, "/admin/manual-detection"),
            "scenario": "suspicious",
            "action": "save",
        },
    )
    assert saved_result.status_code == 200
    assert "/admin?source=synthetic" in saved_result.get_data(as_text=True)

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        synthetic = connection.execute(
            """
            SELECT scenario, model_prediction, model_probability
            FROM synthetic_test_events
            WHERE administrator_username = 'manual-admin'
            """
        ).fetchall()
        synthetic_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM synthetic_test_alerts a
            JOIN synthetic_test_events e ON e.id = a.test_event_id
            WHERE e.model_prediction = 1
            """
        ).fetchone()[0]
        current_real_event_count = connection.execute(
            "SELECT COUNT(*) FROM login_events"
        ).fetchone()[0]
    finally:
        connection.close()

    assert len(synthetic) == 1
    assert synthetic[0]["scenario"] == "suspicious"
    assert synthetic[0]["model_prediction"] in (0, 1)
    assert 0.0 <= synthetic[0]["model_probability"] <= 1.0
    assert synthetic_alerts == (
        1 if synthetic[0]["model_prediction"] == 1 else 0
    )
    assert current_real_event_count >= real_event_count


def test_soc_dashboard_contains_visible_chart_surfaces(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "soc-admin",
            "soc-admin-password",
            is_admin=True,
        )
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    login = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "soc-admin",
            "password": "soc-admin-password",
        },
    )
    assert login.status_code == 302
    dashboard = client.get("/admin")
    assert dashboard.status_code == 200
    body = dashboard.get_data(as_text=True)
    for canvas_id in (
        "activityChart",
        "distributionChart",
        "alertChart",
        "timelineChart",
        "hourChart",
    ):
        assert f'id="{canvas_id}"' in body
    assert "dashboard-data" in body
    assert "Security Operations Center" in body
    assert "Data Source" in body
    assert "Synthetic Detection Tests" in body
    script = client.get("/static/js/main.js")
    assert script.status_code == 200
    assert "socChartFallback" in script.get_data(as_text=True)


def test_synthetic_dashboard_uses_saved_tests_and_preserves_real_data(
    temp_app, client
) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        admin_id = create_test_account(
            connection,
            "synthetic-admin",
            "synthetic-admin-password",
            is_admin=True,
        )
        create_test_account(
            connection,
            "real-user",
            "real-user-password",
        )
        cursor = connection.execute(
            """
            INSERT INTO login_events (
                user_id, username, source_ip, attempted_at, hour_of_day,
                failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                seconds_since_previous_attempt, success, suspicious,
                model_prediction, model_probability, alert_status
            ) VALUES (?, 'real-user', 'src-real', '2026-11-20T10:00:00+00:00',
                      10, 0, 1, 3600, 1, 0, 0, 0.05, 'none')
            """,
            (None,),
        )
        real_event_id = int(cursor.lastrowid)
        connection.commit()
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    login = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "synthetic-admin",
            "password": "synthetic-admin-password",
        },
    )
    assert login.status_code == 302

    # Real dashboard baseline (includes the login event for synthetic-admin created by this login plus seeded row).
    real_before = client.get("/admin?source=real")
    assert real_before.status_code == 200
    real_before_body = real_before.get_data(as_text=True)
    assert "Real Authentication Events" in real_before_body
    assert 'dataSource": "real"' in real_before_body.replace(" ", "") or '"dataSource": "real"' in real_before_body

    # Save a normal synthetic prediction.
    normal_predict = client.post(
        "/admin/manual-detection",
        data={
            "csrf_token": csrf_token(client, "/admin/manual-detection"),
            "scenario": "normal",
            "action": "predict",
        },
    )
    assert normal_predict.status_code == 200
    normal_saved = client.post(
        "/admin/manual-detection",
        data={
            "csrf_token": csrf_token(client, "/admin/manual-detection"),
            "scenario": "normal",
            "action": "save",
        },
    )
    assert normal_saved.status_code == 200
    assert "/admin?source=synthetic" in normal_saved.get_data(as_text=True)

    # Save a suspicious synthetic prediction.
    suspicious_predict = client.post(
        "/admin/manual-detection",
        data={
            "csrf_token": csrf_token(client, "/admin/manual-detection"),
            "scenario": "suspicious",
            "action": "predict",
        },
    )
    assert suspicious_predict.status_code == 200
    suspicious_saved = client.post(
        "/admin/manual-detection",
        data={
            "csrf_token": csrf_token(client, "/admin/manual-detection"),
            "scenario": "suspicious",
            "action": "save",
        },
    )
    assert suspicious_saved.status_code == 200
    assert "/admin?source=synthetic" in suspicious_saved.get_data(as_text=True)

    synthetic_dashboard = client.get("/admin?source=synthetic")
    assert synthetic_dashboard.status_code == 200
    synthetic_body = synthetic_dashboard.get_data(as_text=True)
    assert "SYNTHETIC TEST DATA" in synthetic_body
    assert "Synthetic Detection Tests" in synthetic_body
    assert "Total synthetic tests" in synthetic_body
    assert "No saved suspicious synthetic tests." not in synthetic_body or "synthetic-admin" in synthetic_body
    assert '"dataSource": "synthetic"' in synthetic_body
    assert '"events": 2' in synthetic_body
    assert '"normal": 1' in synthetic_body or '"normal":1' in synthetic_body
    assert '"suspicious": 1' in synthetic_body or '"suspicious":1' in synthetic_body

    # Graph/chart payloads should reflect stored synthetic records.
    assert "synthetic_test_events" in synthetic_body
    assert "synthetic_test_alerts" in synthetic_body

    # Real dashboard remains based on real login events/alerts only and unchanged in totals by synthetic saves.
    real_after = client.get("/admin?source=real")
    assert real_after.status_code == 200
    real_after_body = real_after.get_data(as_text=True)
    assert '"dataSource": "real"' in real_after_body
    assert "Real Authentication Events" in real_after_body
    assert 'id="syntheticBanner"' not in real_after_body
    assert "Synthetic dashboard view" not in real_after_body

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        real_events_count = connection.execute(
            "SELECT COUNT(*) FROM login_events"
        ).fetchone()[0]
        seeded_event = connection.execute(
            "SELECT id, model_prediction, suspicious FROM login_events WHERE id = ?",
            (real_event_id,),
        ).fetchone()
        synthetic_counts = connection.execute(
            """
            SELECT COUNT(*) AS events,
                   SUM(CASE WHEN model_prediction = 0 THEN 1 ELSE 0 END) AS normal,
                   SUM(CASE WHEN model_prediction = 1 THEN 1 ELSE 0 END) AS suspicious
            FROM synthetic_test_events
            WHERE administrator_username = 'synthetic-admin'
            """
        ).fetchone()
        synthetic_alerts = connection.execute(
            """
            SELECT COUNT(*) FROM synthetic_test_alerts a
            JOIN synthetic_test_events e ON e.id = a.test_event_id
            WHERE e.administrator_username = 'synthetic-admin'
            """
        ).fetchone()[0]
    finally:
        connection.close()

    assert seeded_event is not None
    assert seeded_event["model_prediction"] == 0
    assert real_events_count >= 2  # seeded + admin login event(s)
    assert synthetic_counts["events"] == 2
    assert synthetic_counts["normal"] == 1
    assert synthetic_counts["suspicious"] == 1
    assert synthetic_alerts == 1
    # Real dashboard total events in payload should match login_events table, not include synthetic tests.
    assert f'"events": {real_events_count}' in real_after_body or f'"events":{real_events_count}' in real_after_body


def test_synthetic_dashboard_empty_state(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "empty-synth-admin",
            "empty-synth-password",
            is_admin=True,
        )
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    login = client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "empty-synth-admin",
            "password": "empty-synth-password",
        },
    )
    assert login.status_code == 302
    dashboard = client.get("/admin?source=synthetic")
    assert dashboard.status_code == 200
    body = dashboard.get_data(as_text=True)
    assert "SYNTHETIC TEST DATA" in body
    assert "No synthetic detection tests have been saved yet" in body
    payload = extract_dashboard_payload(body)
    assert payload["events"] == 0
    assert payload["suspicious"] == 0
    assert payload["timeline"] == []
    assert payload["syntheticActivity"]["single_nonempty_bucket"] is False
    assert "No saved suspicious synthetic tests." in body or "No saved suspicious synthetic tests" in body


def extract_dashboard_payload(body: str) -> dict:
    match = re.search(
        r'<script id="dashboard-data" type="application/json">\s*(\{.*?\})\s*</script>',
        body,
        re.DOTALL,
    )
    assert match, "dashboard-data payload not found"
    return json.loads(match.group(1))


def insert_synthetic_test(
    connection,
    *,
    admin_id: int,
    admin_username: str,
    tested_at: datetime,
    prediction: int,
    scenario: str | None = None,
) -> int:
    scenario_value = scenario or ("suspicious" if prediction == 1 else "normal")
    probability = 0.93 if prediction == 1 else 0.08
    cursor = connection.execute(
        """
        INSERT INTO synthetic_test_events (
            administrator_id, administrator_username, scenario, tested_at,
            failed_attempts_5min, login_attempts_5min,
            unique_accounts_5min, new_device, login_hour,
            source_failure_rate, time_since_last_login,
            recent_account_failure_count, model_prediction,
            model_probability, label_origin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            admin_id,
            admin_username,
            scenario_value,
            tested_at.isoformat(),
            8 if prediction == 1 else 0,
            12 if prediction == 1 else 1,
            6 if prediction == 1 else 1,
            1 if prediction == 1 else 0,
            tested_at.hour,
            0.9 if prediction == 1 else 0.1,
            10 if prediction == 1 else 3600,
            8 if prediction == 1 else 0,
            prediction,
            probability,
            "synthetic_manual_test",
        ),
    )
    event_id = int(cursor.lastrowid)
    if prediction == 1:
        connection.execute(
            """
            INSERT INTO synthetic_test_alerts (
                test_event_id, severity, explanation, review_status, created_at
            ) VALUES (?, 'high', 'Synthetic test alert.', 'open', ?)
            """,
            (event_id, tested_at.isoformat()),
        )
    return event_id


def test_synthetic_activity_chart_buckets_multiple_events_on_one_day(temp_app, client) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        admin_id = create_test_account(
            connection,
            "bucket-day-admin",
            "bucket-day-password",
            is_admin=True,
        )
        base = datetime(2026, 11, 21, 8, 0, tzinfo=timezone.utc)
        insert_synthetic_test(
            connection, admin_id=admin_id, admin_username="bucket-day-admin",
            tested_at=base, prediction=0,
        )
        insert_synthetic_test(
            connection, admin_id=admin_id, admin_username="bucket-day-admin",
            tested_at=base + timedelta(hours=3), prediction=1,
        )
        insert_synthetic_test(
            connection, admin_id=admin_id, admin_username="bucket-day-admin",
            tested_at=base + timedelta(hours=6), prediction=1,
        )
        connection.commit()
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    assert client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "bucket-day-admin",
            "password": "bucket-day-password",
        },
    ).status_code == 302
    body = client.get("/admin?source=synthetic").get_data(as_text=True)
    payload = extract_dashboard_payload(body)
    assert payload["dataSource"] == "synthetic"
    assert payload["syntheticActivity"]["bucketed_by_timestamp"] is True
    assert payload["syntheticActivity"]["nonempty_buckets"] >= 2
    assert sum(point["normal"] for point in payload["timeline"]) == 1
    assert sum(point["suspicious"] for point in payload["timeline"]) == 2
    assert all(point["normal"] + point["suspicious"] == point["attempts"] for point in payload["timeline"])


def test_synthetic_activity_chart_uses_smaller_buckets_for_events_within_one_hour(
    temp_app, client
) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        admin_id = create_test_account(
            connection,
            "bucket-hour-admin",
            "bucket-hour-password",
            is_admin=True,
        )
        base = datetime(2026, 11, 21, 9, 0, tzinfo=timezone.utc)
        insert_synthetic_test(
            connection, admin_id=admin_id, admin_username="bucket-hour-admin",
            tested_at=base, prediction=0,
        )
        insert_synthetic_test(
            connection, admin_id=admin_id, admin_username="bucket-hour-admin",
            tested_at=base + timedelta(minutes=6), prediction=1,
        )
        insert_synthetic_test(
            connection, admin_id=admin_id, admin_username="bucket-hour-admin",
            tested_at=base + timedelta(minutes=12), prediction=1,
        )
        connection.commit()
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    assert client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "bucket-hour-admin",
            "password": "bucket-hour-password",
        },
    ).status_code == 302
    body = client.get("/admin?source=synthetic").get_data(as_text=True)
    payload = extract_dashboard_payload(body)
    labels = [point["label"] for point in payload["timeline"]]
    assert payload["syntheticActivity"]["nonempty_buckets"] >= 2
    assert any(label.endswith(":00") or label.endswith(":05") or label.endswith(":10") or label.endswith(":15") for label in labels)
    assert ":" in labels[0]
    assert sum(point["normal"] for point in payload["timeline"]) == 1
    assert sum(point["suspicious"] for point in payload["timeline"]) == 2


def test_synthetic_activity_chart_single_bucket_uses_visible_representation(
    temp_app, client
) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        admin_id = create_test_account(
            connection,
            "bucket-single-admin",
            "bucket-single-password",
            is_admin=True,
        )
        tested_at = datetime(2026, 11, 21, 10, 5, tzinfo=timezone.utc)
        insert_synthetic_test(
            connection, admin_id=admin_id, admin_username="bucket-single-admin",
            tested_at=tested_at, prediction=1,
        )
        insert_synthetic_test(
            connection, admin_id=admin_id, admin_username="bucket-single-admin",
            tested_at=tested_at + timedelta(seconds=30), prediction=0,
        )
        connection.commit()
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    assert client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "bucket-single-admin",
            "password": "bucket-single-password",
        },
    ).status_code == 302
    body = client.get("/admin?source=synthetic").get_data(as_text=True)
    payload = extract_dashboard_payload(body)
    assert payload["syntheticActivity"]["single_nonempty_bucket"] is True
    assert sum(1 for point in payload["timeline"] if point["attempts"] > 0) == 1
    assert payload["events"] == 2
    assert payload["normal"] == 1
    assert payload["suspicious"] == 1
    assert "Normal predictions" in body
    assert "Suspicious predictions" in body


def test_real_dashboard_activity_remains_unchanged_with_synthetic_bucketing(
    temp_app, client
) -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(
            connection,
            "real-activity-admin",
            "real-activity-password",
            is_admin=True,
        )
        connection.execute(
            """
            INSERT INTO login_events (
                user_id, username, source_ip, attempted_at, hour_of_day,
                failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                seconds_since_previous_attempt, success, suspicious,
                model_prediction, model_probability, alert_status
            ) VALUES (NULL, 'real-user-a', 'src-a', '2026-11-20T10:00:00+00:00',
                      10, 0, 1, 3600, 1, 0, 0, 0.05, 'none')
            """
        )
        connection.execute(
            """
            INSERT INTO login_events (
                user_id, username, source_ip, attempted_at, hour_of_day,
                failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                seconds_since_previous_attempt, success, suspicious,
                model_prediction, model_probability, alert_status
            ) VALUES (NULL, 'real-user-b', 'src-b', '2026-11-20T11:00:00+00:00',
                      11, 2, 1, 60, 0, 1, 1, 0.92, 'open')
            """
        )
        connection.commit()
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    assert client.post(
        "/login",
        data={
            "csrf_token": token,
            "username": "real-activity-admin",
            "password": "real-activity-password",
        },
    ).status_code == 302
    body = client.get("/admin?source=real").get_data(as_text=True)
    payload = extract_dashboard_payload(body)
    assert payload["dataSource"] == "real"
    assert payload["syntheticActivity"]["bucketed_by_timestamp"] is False
    assert any(point.get("day") == "2026-11-20" for point in payload["timeline"])
    assert "SYNTHETIC TEST DATA — showing only saved records" not in body


def login_admin(client, username: str = "manual-admin", password: str = "manual-admin-password", temp_app=None) -> None:
    token = csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={"csrf_token": token, "username": username, "password": password},
    )
    assert response.status_code == 302


def create_admin(temp_app, username: str = "manual-admin", password: str = "manual-admin-password") -> None:
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(connection, username, password, is_admin=True)
    finally:
        connection.close()


def test_embedded_manual_detection_panel_present_in_admin_dashboard(temp_app, client) -> None:
    create_admin(temp_app, "embedded-admin", "embedded-admin-password")
    login_admin(client, "embedded-admin", "embedded-admin-password", temp_app)
    for source in ("real", "synthetic"):
        body = client.get(f"/admin?source={source}").get_data(as_text=True)
        assert "Manual Detection Test Lab" in body
        assert "Test Normal Login Behavior" in body
        assert "Test Suspicious Login Behavior" in body
        assert "Save Synthetic Test Result" in body
        assert "SYNTHETIC TEST DATA" in body
        assert 'id="manualDetectionLab"' in body
        assert 'data-predict-url="/admin/manual-detection/predict"' in body
        assert 'data-save-url="/admin/manual-detection/save"' in body
        assert "Switch to Synthetic Detection Tests" in body
        assert "Open Standalone Lab" in body


def test_manual_detection_api_admin_access_and_feature_gating(temp_app, client) -> None:
    create_admin(temp_app, "api-admin", "api-admin-password")
    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        create_test_account(connection, "api-user", "api-user-password", is_admin=False)
    finally:
        connection.close()

    token = csrf_token(client, "/login")
    response = client.post(
        "/admin/manual-detection/predict",
        json={"scenario": "normal"},
        headers={"X-CSRFToken": token},
    )
    assert response.status_code in {302, 401, 403}

    login_admin(client, "api-user", "api-user-password", temp_app)
    token = csrf_token(client, "/dashboard")
    response = client.post(
        "/admin/manual-detection/predict",
        json={"scenario": "normal"},
        headers={"X-CSRFToken": token},
    )
    assert response.status_code == 403
    client.get("/logout")

    disabled_app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "pytest-only-secret-key",
            "DATABASE_PATH": temp_app.config["DATABASE_PATH"],
            "WTF_CSRF_ENABLED": True,
            "SESSION_COOKIE_SECURE": False,
            "MANUAL_DETECTION_LAB": False,
        }
    )
    disabled_client = disabled_app.test_client()
    token = csrf_token(disabled_client, "/login")
    disabled_client.post(
        "/login",
        data={"csrf_token": token, "username": "api-admin", "password": "api-admin-password"},
    )
    token = csrf_token(disabled_client, "/admin")
    response = disabled_client.post(
        "/admin/manual-detection/predict",
        json={"scenario": "normal"},
        headers={"X-CSRFToken": token},
    )
    assert response.status_code == 404


def test_manual_detection_api_requires_csrf(temp_app, client) -> None:
    create_admin(temp_app, "csrf-api-admin", "csrf-api-password")
    login_admin(client, "csrf-api-admin", "csrf-api-password", temp_app)
    response = client.post(
        "/admin/manual-detection/predict",
        json={"scenario": "normal"},
    )
    assert response.status_code == 400
    body = response.get_json()
    assert body and body.get("ok") is False
    assert "security" in (body.get("error") or "").lower()


def test_manual_detection_async_predict_does_not_save_and_save_persists_synthetic_only(
    temp_app, client
) -> None:
    create_admin(temp_app, "async-admin", "async-admin-password")
    login_admin(client, "async-admin", "async-admin-password", temp_app)

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        connection.execute(
            """
            INSERT INTO login_events (
                user_id, username, source_ip, attempted_at, hour_of_day,
                failed_attempts_last_15m, distinct_usernames_from_ip_15m,
                seconds_since_previous_attempt, success, suspicious,
                model_prediction, model_probability, alert_status
            ) VALUES (NULL, 'real-existing', 'src-real', '2026-11-20T10:00:00+00:00',
                      10, 0, 1, 3600, 1, 0, 0, 0.05, 'none')
            """
        )
        connection.commit()
    finally:
        connection.close()

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        baseline_real_events = connection.execute("SELECT COUNT(*) AS count FROM login_events").fetchone()["count"]
        baseline_real_alerts = connection.execute("SELECT COUNT(*) AS count FROM security_alerts").fetchone()["count"]
    finally:
        connection.close()

    token = csrf_token(client, "/admin")
    for scenario, expected_prediction in (("normal", 0), ("suspicious", 1)):
        predicted = client.post(
            "/admin/manual-detection/predict",
            json={"scenario": scenario},
            headers={"X-CSRFToken": token, "X-Requested-With": "XMLHttpRequest"},
        )
        assert predicted.status_code == 200
        payload = predicted.get_json()
        assert payload["ok"] is True
        assert payload["saved"] is False
        assert payload["scenario"] == scenario
        assert payload["prediction"] == expected_prediction
        assert "probability" in payload
        assert len(payload["features"]) == 8

        connection = connect(temp_app.config["DATABASE_PATH"])
        try:
            synthetic_events = connection.execute("SELECT COUNT(*) AS count FROM synthetic_test_events").fetchone()["count"]
            synthetic_alerts = connection.execute("SELECT COUNT(*) AS count FROM synthetic_test_alerts").fetchone()["count"]
            real_events = connection.execute("SELECT COUNT(*) AS count FROM login_events").fetchone()["count"]
            real_alerts = connection.execute("SELECT COUNT(*) AS count FROM security_alerts").fetchone()["count"]
        finally:
            connection.close()
        assert synthetic_events == 0
        assert synthetic_alerts == 0
        assert real_events == baseline_real_events
        assert real_alerts == baseline_real_alerts

    token = csrf_token(client, "/admin")
    saved_normal = client.post(
        "/admin/manual-detection/save",
        json={"scenario": "normal"},
        headers={"X-CSRFToken": token, "X-Requested-With": "XMLHttpRequest"},
    )
    assert saved_normal.status_code == 200
    normal_payload = saved_normal.get_json()
    assert normal_payload["ok"] is True and normal_payload["saved"] is True
    assert normal_payload["prediction"] == 0
    assert normal_payload["synthetic_data"]["counts"]["events"] == 1
    assert normal_payload["synthetic_data"]["counts"]["normal"] == 1
    assert normal_payload["synthetic_data"]["counts"]["suspicious"] == 0

    token = csrf_token(client, "/admin")
    saved_suspicious = client.post(
        "/admin/manual-detection/save",
        json={"scenario": "suspicious"},
        headers={"X-CSRFToken": token, "X-Requested-With": "XMLHttpRequest"},
    )
    assert saved_suspicious.status_code == 200
    suspicious_payload = saved_suspicious.get_json()
    assert suspicious_payload["ok"] is True and suspicious_payload["saved"] is True
    assert suspicious_payload["prediction"] == 1
    synth = suspicious_payload["synthetic_data"]
    assert synth["counts"]["events"] == 2
    assert synth["counts"]["normal"] == 1
    assert synth["counts"]["suspicious"] == 1
    assert synth["alert_counts"]["open"] == 1
    assert len(synth["recent_events"]) == 1

    connection = connect(temp_app.config["DATABASE_PATH"])
    try:
        synthetic_events = connection.execute("SELECT scenario, model_prediction, label_origin FROM synthetic_test_events ORDER BY id").fetchall()
        synthetic_alerts = connection.execute("SELECT severity, review_status FROM synthetic_test_alerts ORDER BY id").fetchall()
        real_events = connection.execute("SELECT COUNT(*) AS count FROM login_events").fetchone()["count"]
        real_alerts = connection.execute("SELECT COUNT(*) AS count FROM security_alerts").fetchone()["count"]
    finally:
        connection.close()
    assert len(synthetic_events) == 2
    assert [row["scenario"] for row in synthetic_events] == ["normal", "suspicious"]
    assert [row["model_prediction"] for row in synthetic_events] == [0, 1]
    assert all(row["label_origin"] == "synthetic_manual_test" for row in synthetic_events)
    assert len(synthetic_alerts) == 1
    assert synthetic_alerts[0]["review_status"] == "open"
    assert real_events == baseline_real_events
    assert real_alerts == baseline_real_alerts

    synthetic_body = client.get("/admin?source=synthetic").get_data(as_text=True)
    synthetic_dashboard = extract_dashboard_payload(synthetic_body)
    assert synthetic_dashboard["events"] == 2
    assert synthetic_dashboard["normal"] == 1
    assert synthetic_dashboard["suspicious"] == 1
    assert "SYNTHETIC TEST DATA" in synthetic_body

    real_body = client.get("/admin?source=real").get_data(as_text=True)
    real_dashboard = extract_dashboard_payload(real_body)
    assert real_dashboard["events"] == baseline_real_events
    assert real_dashboard["dataSource"] == "real"

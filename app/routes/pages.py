"""Registration, login, logout, and administrator routes."""

from __future__ import annotations

import re
import sqlite3
import json
from datetime import datetime, timedelta, timezone

from flask import (
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFError

from app import limiter
from app.auth.hashing import password_strength_error, verify_password
from app.auth.user import User
from app.models.db import connect, get_user_by_username
from app.services.login_events import (
    create_test_account,
    record_authentication_event,
)
from app.detection.predictor import (
    ModelUnavailableError,
    feature_explanation,
    predict,
)
from app.services.alerts import create_alert, mark_alert_reviewed
from app.privacy import pseudonymize_source


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,64}$")


def register_routes(app) -> None:
    @app.teardown_appcontext
    def close_database(_error=None) -> None:
        connection = g.pop("database", None)
        if connection is not None:
            connection.close()

    @app.errorhandler(CSRFError)
    def csrf_error(_error):
        if request.path.startswith("/admin/manual-detection/") or request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "The security form expired. Please try again."}), 400
        flash("The security form expired. Please try again.")
        return redirect(request.referrer or url_for("login")), 400

    def database() -> sqlite3.Connection:
        if "database" not in g:
            g.database = connect(app.config["DATABASE_PATH"])
        return g.database

    @app.get("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard" if current_user.is_admin else "account_dashboard"))
        return render_template("home.html")

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirmation = request.form.get("confirmation", "")

            if not USERNAME_PATTERN.fullmatch(username):
                flash("Could not create account.")
                return render_template("register.html"), 400
            if password != confirmation:
                flash("Could not create account.")
                return render_template("register.html"), 400
            strength_error = password_strength_error(password)
            if strength_error:
                flash("Could not create account.")
                return render_template("register.html"), 400

            try:
                create_test_account(database(), username, password)
            except ValueError:
                flash("Could not create account.")
                return render_template("register.html"), 400
            except sqlite3.IntegrityError:
                flash("Could not create account.")
                return render_template("register.html"), 400

            flash("Account created. Sign in with this local test account.")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            source_ip = request.remote_addr or "unknown"
            source_identifier = pseudonymize_source(
                source_ip,
                str(app.config.get("PRIVACY_HMAC_KEY") or app.config["SECRET_KEY"]),
            )

            row = get_user_by_username(database(), username)
            valid = bool(
                row is not None
                and verify_password(row["password_hash"], password)
            )

            if not valid:
                event_id, research_features = record_authentication_event(
                    database(),
                    username=username,
                    source_ip=source_identifier,
                    success=0,
                    user_id=int(row["id"]) if row is not None else None,
                )
                try:
                    prediction, probability = predict(research_features)
                    database().execute(
                        "UPDATE login_events SET model_prediction = ?, model_probability = ? WHERE id = ?",
                        (prediction, probability, event_id),
                    )
                    if prediction == 1:
                        create_alert(
                            database(),
                            event_id=event_id,
                            severity="high" if probability >= 0.8 else "medium",
                            explanation=feature_explanation(research_features),
                        )
                    database().commit()
                except ModelUnavailableError:
                    pass
                flash("Invalid username or password.")
                return render_template("login.html"), 401

            user = User(
                id=int(row["id"]),
                username=row["username"],
                password_hash=row["password_hash"],
                is_admin=bool(row["is_admin"]),
            )
            login_user(user)
            event_id, research_features = record_authentication_event(
                database(),
                username=username,
                source_ip=source_identifier,
                success=1,
                user_id=user.id,
            )
            try:
                prediction, probability = predict(research_features)
                database().execute(
                    "UPDATE login_events SET model_prediction = ?, model_probability = ? WHERE id = ?",
                    (prediction, probability, event_id),
                )
                if prediction == 1:
                    create_alert(
                        database(),
                        event_id=event_id,
                        severity="high" if probability >= 0.8 else "medium",
                        explanation=feature_explanation(research_features),
                    )
                database().commit()
            except ModelUnavailableError:
                pass
            if user.is_admin:
                return redirect(url_for("dashboard"))
            return redirect(url_for("account_dashboard"))

        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Signed out.")
        return redirect(url_for("login"))

    MANUAL_DETECTION_VECTORS = {
        "normal": {
            "failed_attempts_5min": 0,
            "login_attempts_5min": 1,
            "unique_accounts_5min": 1,
            "new_device": 0,
            "login_hour": 12,
            "source_failure_rate": 0.10,
            "time_since_last_login": 3600,
            "recent_account_failure_count": 0,
        },
        "suspicious": {
            "failed_attempts_5min": 8,
            "login_attempts_5min": 12,
            "unique_accounts_5min": 6,
            "new_device": 1,
            "login_hour": 2,
            "source_failure_rate": 0.90,
            "time_since_last_login": 10,
            "recent_account_failure_count": 8,
        },
    }

    def manual_detection_enabled() -> bool:
        return bool(app.config.get("MANUAL_DETECTION_LAB", False))

    def ensure_manual_detection_access() -> None:
        if not manual_detection_enabled():
            abort(404)
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)

    def run_manual_detection_prediction(scenario: str) -> tuple[dict, int, float]:
        if scenario not in MANUAL_DETECTION_VECTORS:
            abort(400)
        features = MANUAL_DETECTION_VECTORS[scenario]
        prediction, probability = predict(features)
        return features, int(prediction), float(probability)

    def save_manual_detection_result(scenario: str, features: dict, prediction: int, probability: float) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cursor = database().execute(
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
                current_user.id,
                current_user.username,
                scenario,
                now,
                features["failed_attempts_5min"],
                features["login_attempts_5min"],
                features["unique_accounts_5min"],
                features["new_device"],
                features["login_hour"],
                features["source_failure_rate"],
                features["time_since_last_login"],
                features["recent_account_failure_count"],
                prediction,
                probability,
                "synthetic_manual_test",
            ),
        )
        test_event_id = int(cursor.lastrowid)
        if prediction == 1:
            severity = "high" if probability >= 0.8 else "medium"
            database().execute(
                """
                INSERT INTO synthetic_test_alerts (
                    test_event_id, severity, explanation,
                    review_status, created_at
                ) VALUES (?, ?, ?, 'open', ?)
                """,
                (
                    test_event_id,
                    severity,
                    "Synthetic administrator manual test predicted suspicious behavior.",
                    now,
                ),
            )
        database().commit()
        return test_event_id

    def build_synthetic_dashboard_payload() -> dict:
        counts = database().execute(
            """
            SELECT
                COUNT(*) AS events,
                COALESCE(
                    SUM(CASE WHEN model_prediction = 1 THEN 1 ELSE 0 END),
                    0
                ) AS suspicious,
                COALESCE(
                    SUM(CASE WHEN model_prediction = 0 THEN 1 ELSE 0 END),
                    0
                ) AS normal
            FROM synthetic_test_events
            """
        ).fetchone()
        synthetic_rows = database().execute(
            """
            SELECT tested_at, model_prediction
            FROM synthetic_test_events
            ORDER BY tested_at ASC, id ASC
            """
        ).fetchall()
        by_hour = database().execute(
            """
            SELECT CAST(strftime('%H', tested_at) AS INTEGER) AS hour,
                   COUNT(*) AS attempts
            FROM synthetic_test_events
            GROUP BY CAST(strftime('%H', tested_at) AS INTEGER)
            ORDER BY hour
            """
        ).fetchall()
        alert_counts = database().execute(
            """
            SELECT
                COALESCE(
                    SUM(CASE WHEN review_status = 'open' THEN 1 ELSE 0 END),
                    0
                ) AS open,
                COALESCE(
                    SUM(CASE WHEN review_status = 'reviewed' THEN 1 ELSE 0 END),
                    0
                ) AS reviewed
            FROM synthetic_test_alerts
            """
        ).fetchone()
        recent_incidents = database().execute(
            """
            SELECT e.id, e.administrator_username AS username,
                   e.scenario, e.tested_at AS attempted_at,
                   e.model_prediction, e.model_probability,
                   a.id AS alert_id, a.severity, a.review_status
            FROM synthetic_test_events e
            LEFT JOIN synthetic_test_alerts a ON a.test_event_id = e.id
            WHERE e.model_prediction = 1
            ORDER BY e.tested_at DESC
            LIMIT 8
            """
        ).fetchall()
        synthetic_tests = database().execute(
            """
            SELECT id, scenario, tested_at, model_prediction,
                   model_probability, administrator_username
            FROM synthetic_test_events
            ORDER BY tested_at DESC
            LIMIT 20
            """
        ).fetchall()

        def _parse_tested_at(value: str) -> datetime:
            parsed = datetime.fromisoformat(str(value))
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed

        def _floor_bucket(moment: datetime, minutes: int) -> datetime:
            if minutes >= 1440:
                return datetime(moment.year, moment.month, moment.day)
            total = moment.hour * 60 + moment.minute
            floored = (total // minutes) * minutes
            return datetime(
                moment.year,
                moment.month,
                moment.day,
                floored // 60,
                floored % 60,
            )

        dashboard_timeline = []
        nonempty_buckets = 0
        if synthetic_rows:
            parsed_rows = [
                (_parse_tested_at(row["tested_at"]), int(row["model_prediction"]))
                for row in synthetic_rows
            ]
            times = [moment for moment, _ in parsed_rows]
            span_seconds = max((times[-1] - times[0]).total_seconds(), 0.0)
            gaps = [
                (times[index] - times[index - 1]).total_seconds()
                for index in range(1, len(times))
            ]
            min_gap = min(gaps) if gaps else float("inf")
            hour_counts: dict[datetime, int] = {}
            for moment in times:
                hour_key = _floor_bucket(moment, 60)
                hour_counts[hour_key] = hour_counts.get(hour_key, 0) + 1
            max_hour_count = max(hour_counts.values(), default=0)

            if span_seconds > 48 * 3600:
                bucket_minutes = 1440
            elif span_seconds > 24 * 3600:
                bucket_minutes = 60
            elif span_seconds <= 300 or min_gap < 120:
                bucket_minutes = 1
            elif span_seconds <= 2 * 3600 or min_gap < 1800 or max_hour_count >= 2:
                bucket_minutes = 5
            else:
                bucket_minutes = 60

            start = _floor_bucket(times[0], bucket_minutes)
            end = _floor_bucket(times[-1], bucket_minutes)
            bucket_delta = timedelta(minutes=bucket_minutes)
            buckets: list[datetime] = []
            current = start
            limit = 240
            while current <= end and len(buckets) < limit:
                buckets.append(current)
                current += bucket_delta
            if not buckets or buckets[-1] != end:
                if not buckets:
                    buckets = [end]
                elif end not in buckets and len(buckets) < limit:
                    buckets.append(end)

            bucket_map = {
                bucket: {"normal": 0, "suspicious": 0}
                for bucket in buckets
            }
            for moment, prediction in parsed_rows:
                key = _floor_bucket(moment, bucket_minutes)
                if key not in bucket_map:
                    bucket_map[key] = {"normal": 0, "suspicious": 0}
                    buckets.append(key)
            buckets = sorted(set(buckets))
            for moment, prediction in parsed_rows:
                key = _floor_bucket(moment, bucket_minutes)
                if prediction == 1:
                    bucket_map[key]["suspicious"] += 1
                else:
                    bucket_map[key]["normal"] += 1

            spans_days = start.date() != end.date()
            for bucket in buckets:
                values = bucket_map[bucket]
                attempts = values["normal"] + values["suspicious"]
                if attempts > 0:
                    nonempty_buckets += 1
                if bucket_minutes >= 1440:
                    label = bucket.strftime("%Y-%m-%d")
                elif spans_days:
                    label = bucket.strftime("%m-%d %H:%M")
                else:
                    label = bucket.strftime("%H:%M")
                dashboard_timeline.append(
                    {
                        "day": label,
                        "label": label,
                        "bucket_start": bucket.isoformat(),
                        "attempts": attempts,
                        "successes": values["normal"],
                        "failures": values["suspicious"],
                        "suspicious": values["suspicious"],
                        "normal": values["normal"],
                    }
                )

        dashboard_counts = {
            "events": counts["events"] or 0,
            "suspicious": counts["suspicious"] or 0,
            "normal": counts["normal"] or 0,
            "successful": 0,
            "failed": 0,
            "users": 0,
        }
        dashboard_hours = [
            {
                "hour": row["hour"],
                "attempts": row["attempts"] or 0,
                "successes": 0,
                "failures": 0,
            }
            for row in by_hour
        ]
        return {
            "counts": dashboard_counts,
            "recent_events": [dict(row) for row in recent_incidents],
            "alerts": [],
            "by_hour": dashboard_hours,
            "timeline": dashboard_timeline,
            "alert_counts": {
                "open": alert_counts["open"] or 0,
                "reviewed": alert_counts["reviewed"] or 0,
            },
            "synthetic_tests": [dict(row) for row in synthetic_tests],
            "data_source": "synthetic",
            "synthetic_dashboard": True,
            "synthetic_has_data": (dashboard_counts["events"] > 0),
            "synthetic_activity": {
                "bucketed_by_timestamp": True,
                "nonempty_buckets": nonempty_buckets,
                "single_nonempty_bucket": (
                    dashboard_counts["events"] > 0 and nonempty_buckets <= 1
                ),
            },
        }

    @app.get("/admin")
    @login_required
    def dashboard():
        if not current_user.is_admin:
            abort(403)

        manual_lab = manual_detection_enabled()
        requested_source = request.args.get("source", "real")
        data_source = (
            "synthetic"
            if requested_source == "synthetic" and manual_lab
            else "real"
        )

        if data_source == "synthetic":
            payload = build_synthetic_dashboard_payload()
            return render_template(
                "dashboard.html",
                counts=payload["counts"],
                recent_events=payload["recent_events"],
                alerts=payload["alerts"],
                by_hour=payload["by_hour"],
                timeline=payload["timeline"],
                alert_counts=payload["alert_counts"],
                synthetic_tests=payload["synthetic_tests"],
                manual_detection_enabled=manual_lab,
                data_source="synthetic",
                synthetic_dashboard=True,
                synthetic_has_data=payload["synthetic_has_data"],
                synthetic_activity=payload["synthetic_activity"],
            )

        counts = database().execute(
            """
            SELECT
                (SELECT COUNT(*) FROM users) AS users,
                (SELECT COUNT(*) FROM login_events) AS events,
                (
                    SELECT COUNT(*) FROM login_events WHERE success = 1
                ) AS successful,
                (
                    SELECT COUNT(*) FROM login_events WHERE success = 0
                ) AS failed,
                (
                    SELECT COUNT(*) FROM login_events WHERE suspicious = 1
                ) AS suspicious
            """
        ).fetchone()
        recent_events = database().execute(
            """
            SELECT id, username, source_ip, attempted_at, success, suspicious,
                   model_prediction, model_probability, alert_status
            FROM login_events
            ORDER BY attempted_at DESC
            LIMIT 100
            """
        ).fetchall()
        alerts = database().execute(
            """
            SELECT id, event_id, severity, explanation, review_status, created_at
            FROM security_alerts
            ORDER BY created_at DESC
            LIMIT 100
            """
        ).fetchall()

        by_hour = database().execute(
            """
            SELECT hour_of_day AS hour,
                   COUNT(*) AS attempts,
                   SUM(success) AS successes,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failures
            FROM login_events
            GROUP BY hour_of_day
            ORDER BY hour_of_day
            """
        ).fetchall()
        timeline = database().execute(
            """
            SELECT substr(attempted_at, 1, 10) AS day,
                   COUNT(*) AS attempts,
                   SUM(success) AS successes,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failures,
                   SUM(suspicious) AS suspicious
            FROM login_events
            GROUP BY substr(attempted_at, 1, 10)
            ORDER BY day DESC
            LIMIT 14
            """
        ).fetchall()
        alert_counts = database().execute(
            """
            SELECT
                COALESCE(
                    SUM(CASE WHEN review_status = 'open' THEN 1 ELSE 0 END),
                    0
                ) AS open,
                COALESCE(
                    SUM(CASE WHEN review_status = 'reviewed' THEN 1 ELSE 0 END),
                    0
                ) AS reviewed
            FROM security_alerts
            """
        ).fetchone()
        synthetic_tests = database().execute(
            """
            SELECT id, scenario, tested_at, model_prediction,
                   model_probability, administrator_username
            FROM synthetic_test_events
            ORDER BY tested_at DESC
            LIMIT 20
            """
        ).fetchall()
        return render_template(
            "dashboard.html",
            counts=dict(counts),
            recent_events=recent_events,
            alerts=alerts,
            by_hour=[dict(row) for row in by_hour],
            timeline=[dict(row) for row in reversed(timeline)],
            alert_counts={
                "open": alert_counts["open"] or 0,
                "reviewed": alert_counts["reviewed"] or 0,
            },
            synthetic_tests=[dict(row) for row in synthetic_tests],
            manual_detection_enabled=manual_detection_enabled,
            data_source="real",
            synthetic_dashboard=False,
            synthetic_has_data=True,
            synthetic_activity={
                "bucketed_by_timestamp": False,
                "nonempty_buckets": 0,
                "single_nonempty_bucket": False,
            },
        )

    @app.post("/admin/alerts/<int:alert_id>/review")
    @login_required
    def review_alert(alert_id: int):
        if not current_user.is_admin:
            abort(403)
        mark_alert_reviewed(database(), alert_id)
        flash("Alert marked as reviewed.")
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    @login_required
    def account_dashboard():
        if current_user.is_admin:
            return redirect(url_for("dashboard"))
        events = database().execute(
            """
            SELECT attempted_at, success, suspicious
            FROM login_events
            WHERE user_id = ?
            ORDER BY attempted_at DESC
            LIMIT 50
            """,
            (current_user.id,),
        ).fetchall()
        return render_template("account_dashboard.html", events=events)

    @app.post("/admin/manual-detection/predict")
    @login_required
    def manual_detection_predict_api():
        ensure_manual_detection_access()
        payload = request.get_json(silent=True) or {}
        scenario = str(payload.get("scenario") or request.form.get("scenario") or "")
        if scenario not in MANUAL_DETECTION_VECTORS:
            return jsonify({"ok": False, "error": "Invalid scenario."}), 400
        try:
            features, prediction, probability = run_manual_detection_prediction(scenario)
        except ModelUnavailableError:
            return jsonify({"ok": False, "error": "The trusted model is unavailable."}), 503
        return jsonify(
            {
                "ok": True,
                "saved": False,
                "scenario": scenario,
                "features": features,
                "prediction": prediction,
                "probability": probability,
                "label": "Suspicious" if prediction == 1 else "Normal",
            }
        )

    @app.post("/admin/manual-detection/save")
    @login_required
    def manual_detection_save_api():
        ensure_manual_detection_access()
        payload = request.get_json(silent=True) or {}
        scenario = str(payload.get("scenario") or request.form.get("scenario") or "")
        if scenario not in MANUAL_DETECTION_VECTORS:
            return jsonify({"ok": False, "error": "Invalid scenario."}), 400
        try:
            features, prediction, probability = run_manual_detection_prediction(scenario)
        except ModelUnavailableError:
            return jsonify({"ok": False, "error": "The trusted model is unavailable."}), 503
        save_manual_detection_result(scenario, features, prediction, probability)
        return jsonify(
            {
                "ok": True,
                "saved": True,
                "scenario": scenario,
                "features": features,
                "prediction": prediction,
                "probability": probability,
                "label": "Suspicious" if prediction == 1 else "Normal",
                "synthetic_data": build_synthetic_dashboard_payload(),
                "message": "Synthetic test result saved. Synthetic Detection Tests dashboard data refreshed from stored records.",
            }
        )

    @app.get("/admin/manual-detection/synthetic-data")
    @login_required
    def manual_detection_synthetic_data_api():
        ensure_manual_detection_access()
        return jsonify({"ok": True, "synthetic_data": build_synthetic_dashboard_payload()})

    @app.route("/admin/manual-detection", methods=["GET", "POST"])
    @login_required
    def manual_detection_lab():
        ensure_manual_detection_access()
        vectors = MANUAL_DETECTION_VECTORS
        result = None
        if request.method == "POST":
            scenario = request.form.get("scenario", "")
            action = request.form.get("action", "predict")
            if scenario not in vectors:
                abort(400)
            try:
                features, prediction, probability = run_manual_detection_prediction(scenario)
            except ModelUnavailableError:
                flash("The trusted model is unavailable.")
                return render_template(
                    "manual_detection.html",
                    vectors=vectors,
                    result=None,
                ), 503

            saved = False
            if action == "save":
                save_manual_detection_result(scenario, features, prediction, probability)
                saved = True
                flash(
                    "Synthetic test result saved. View it in the SOC dashboard's "
                    "Synthetic Detection Tests data source."
                )

            result = {
                "scenario": scenario,
                "features": features,
                "prediction": prediction,
                "probability": probability,
                "saved": saved,
                "action": action,
            }

        return render_template(
            "manual_detection.html",
            vectors=vectors,
            result=result,
        )

    @app.get("/research")
    @login_required
    def research_dashboard():
        if not current_user.is_admin:
            abort(403)
        evaluation_path = app.root_path + "/../data/research/evaluation.json"
        v2_path = app.root_path + "/../data/research/v2/evaluation.json"
        from pathlib import Path
        evaluation = {}
        path = Path(evaluation_path)
        if path.is_file():
            evaluation = json.loads(path.read_text(encoding="utf-8"))
        v2_evaluation = {}
        v2 = Path(v2_path)
        if v2.is_file():
            v2_evaluation = json.loads(v2.read_text(encoding="utf-8"))
        return render_template(
            "research.html",
            evaluation=evaluation,
            v2_evaluation=v2_evaluation,
        )

    @app.get("/events")
    @login_required
    def authentication_events():
        if not current_user.is_admin:
            abort(403)
        events = database().execute(
            """
            SELECT id, username, source_ip, attempted_at, success, suspicious,
                   model_prediction, model_probability, alert_status
            FROM login_events
            ORDER BY attempted_at DESC
            LIMIT 250
            """
        ).fetchall()
        synthetic_tests = database().execute(
            """
            SELECT id, administrator_username, scenario, tested_at,
                   model_prediction, model_probability
            FROM synthetic_test_events
            ORDER BY tested_at DESC
            LIMIT 100
            """
        ).fetchall()
        return render_template(
            "events.html",
            events=events,
            synthetic_tests=synthetic_tests,
        )

    @app.get("/alerts")
    @login_required
    def security_alerts():
        if not current_user.is_admin:
            abort(403)
        alerts = database().execute(
            """
            SELECT id, event_id, severity, explanation, review_status, created_at
            FROM security_alerts
            ORDER BY created_at DESC
            """
        ).fetchall()
        return render_template("alerts.html", alerts=alerts)

    @app.get("/research-assets/<path:filename>")
    @login_required
    def research_asset(filename: str):
        if not current_user.is_admin:
            abort(403)
        from pathlib import Path
        directory = Path(app.root_path).parent / "data" / "research"
        if filename not in {"metrics_comparison.png", "decision_tree.png"}:
            abort(404)
        return send_from_directory(directory, filename)

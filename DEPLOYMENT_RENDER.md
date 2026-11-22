# Render Deployment Preparation

This project is a Flask application factory (`app.create_app`) with a Gunicorn-compatible WSGI entry point (`wsgi:app`). This document prepares the project for a secure Render deployment **without** deploying it, uploading it, or modifying the original local database.

## 1. WSGI entry point

- **Module:** `wsgi.py`
- **App object:** `app = create_app()`
- **Gunicorn target:** `wsgi:app`

Do not use `app:app`; the Flask app is created by the application factory.

## 2. Required model artifacts

The live authentication workflow uses the trusted local Decision Tree artifact:

- **Tracked deployment artifact:** `model_artifacts/decision_tree.joblib`
- **Legacy local path (still supported):** `instance/decision_tree.joblib`

`app.detection.predictor.load_model()` prefers the tracked deployment artifact when present and falls back to the legacy instance path. The tracked artifact is included so a Render build from the repository can load the model without deploying `instance/research.db`.

## 3. Production safety controls

The prepared configuration preserves:

- Administrator authentication and authorization (`is_admin`, admin-only routes, 403 handling)
- CSRF protection (`Flask-WTF` / `flask_wtf.csrf.CSRFProtect`)
- Rate limiting (`Flask-Limiter`, including login protections)
- Secure password hashing (Argon2id in `app.auth.hashing`)
- Login/session protection (`Flask-Login`, HTTP-only session cookie, SameSite=Lax)

Production hardening in this preparation:

- `DEBUG`/`TESTING` are disabled by default in the app factory.
- The Werkzeug development server/debugger is **not** used for Render; run Gunicorn only.
- Session cookies are secure by default when `FLASK_DEBUG` is not enabled (`SESSION_COOKIE_SECURE` can be set explicitly).
- `SECRET_KEY` is required from the environment in non-test runs (never hardcoded).
- `TRUST_PROXY_HEADERS` (or Render's `RENDER` environment) enables `ProxyFix` so forwarded proto/host/client data is handled correctly behind Render's proxy.
- A safe health check endpoint is available at `GET /health` (returns `{"status":"ok"}` with no sensitive data).

### Manual Detection Test Lab (local-only)

The Manual Detection Test Lab and its APIs must not be publicly accessible:

- Routes: `/admin/manual-detection`, `/admin/manual-detection/predict`, `/admin/manual-detection/save`, `/admin/manual-detection/synthetic-data`
- Enabled only when `MANUAL_DETECTION_LAB=true` **and** `FLASK_DEBUG` is enabled in local development.
- The app factory disables the lab when debug is not enabled, and routes enforce admin access plus feature gating (404 when disabled).

**For Render/public deployment, set `FLASK_DEBUG=0` and `MANUAL_DETECTION_LAB=false` (or omit it).**

## 4. Database strategy (SQLite) and original data protection

- **Current database:** SQLite (`DATABASE_PATH`, default `instance/research.db`)
- **Do not deploy:** `instance/research.db`, `instance/soc_demo.db`, `instance/test_accounts.csv`, `.env`, or any local credentials/authentication history.
- `.gitignore` excludes `.env*` (except `.env.example`), database files, credentials/keys, virtual environments, logs, and local instance contents.

### Safe persistent strategy for Render

Render's container filesystem is ephemeral. A SQLite database stored only in the app directory will be lost on redeploy/restart. For a safe production-like prototype on Render:

1. **Attach a Render Persistent Disk** to the web service (e.g. mount path `/var/data`).
2. **Use a fresh production database path on that disk**, e.g. `DATABASE_PATH=/var/data/app.db`.
3. **Never point production to `instance/research.db`** and never copy/upload the original local database.
4. On first use, the application initializes the required schema in the fresh database (`initialize()` runs during request startup). You can also pre-create it safely with:
   - `python scripts/prepare_production_database.py --database-path /var/data/app.db`
   - This script only creates/initializes the target database; it does **not** modify or delete `instance/research.db`.

### Migration considerations (prepare separately)

If future production use requires a managed database (recommended for multi-instance or higher durability), migrate to a server database (e.g. PostgreSQL) in a **separate** change:

- Keep the existing SQLite schema and data flow as the reference.
- Create a separate migration plan/script that reads from an explicit source and writes to an explicit target.
- Do not modify or delete the original `instance/research.db`.
- Validate admin provisioning, authentication events, alerts, CSRF/session behavior, and retention in the target environment before cutover.

## 5. Exact Render configuration

### Build command

```bash
pip install --upgrade pip && pip install -r requirements.txt
```

### Start command

```bash
gunicorn --bind 0.0.0.0:$PORT wsgi:app
```

### Environment variables

Set these in Render's environment/secret settings (not in the repository):

| Variable | Required | Example / guidance |
| --- | --- | --- |
| `SECRET_KEY` | Yes | Long random secret (e.g. 32+ bytes, hex/base64). Never hardcode. |
| `PRIVACY_HMAC_KEY` | Recommended | Separate long random secret for source pseudonymization. If unset, app falls back to `SECRET_KEY` for HMAC in existing behavior; set a distinct value in production. |
| `FLASK_DEBUG` | Yes | `0` |
| `DATABASE_PATH` | Yes (for persistence) | `/var/data/app.db` on a Render Persistent Disk (fresh DB only). |
| `SESSION_COOKIE_SECURE` | Recommended | `true` |
| `TRUST_PROXY_HEADERS` | Recommended | `true` (Render sets `RENDER`; app also honors `RENDER` for ProxyFix) |
| `MANUAL_DETECTION_LAB` | Yes | `false` |
| `SOC_DEMO_MODE` | Yes | `false` |
| `AUTH_EVENT_RETENTION_ENABLED` | Recommended | `true` (or as policy requires) |
| `AUTH_EVENT_RETENTION_DAYS` | Recommended | `90` (or as policy requires) |
| `WEB_CONCURRENCY` | Optional | Gunicorn worker count; tune for instance size (SQLite favors low concurrency). |

Do not set `FLASK_DEBUG=1`, do not enable demo/manual-lab modes, and do not provide paths to local development databases.

## 6. Deployment steps (Render)

1. **Prepare repository content (local, no upload performed by this task):**
   - Ensure `wsgi.py`, `requirements.txt` (includes `gunicorn`), `model_artifacts/decision_tree.joblib`, and this document are included.
   - Confirm `.env`, `instance/*.db`, credentials, logs, and virtual environments are not committed.
2. **Create a Render Web Service** from the repository/branch (Python runtime).
3. **Configure commands:**
   - Build: `pip install --upgrade pip && pip install -r requirements.txt`
   - Start: `gunicorn --bind 0.0.0.0:$PORT wsgi:app`
4. **Add a Persistent Disk** (recommended for SQLite durability), mount e.g. `/var/data`.
5. **Set environment variables** as listed above; generate strong random values for secrets.
6. **Provision the database path:** ensure `DATABASE_PATH` points to a fresh file on the persistent disk (not `instance/research.db`).
7. **Deploy and verify:**
   - Check `GET /health` returns `200 {"status":"ok"}`.
   - Confirm HTTPS is enforced by Render and secure cookies/HSTS behavior are correct.
   - Create/provision an administrator using the controlled CLI flow in a secure environment if needed (`scripts/provision_administrator.py`), never via public registration.
   - Verify admin login, dashboard access, non-admin restrictions, and that `/admin/manual-detection*` endpoints are not accessible.
8. **Post-deploy checks:** review logs, rate limiting, retention settings, and backup/restore for the persistent disk.

## 7. Security notes

- SQLite is suitable for a controlled prototype but has concurrency and durability limits on hosted platforms; use a persistent disk and keep worker/concurrency conservative, or migrate separately to a managed database for production needs.
- Public registration never grants admin privileges; administrator provisioning remains a separate controlled action.
- This preparation does not deploy to Render, upload to GitHub, or modify the original `instance/research.db`.

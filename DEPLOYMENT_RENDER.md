# Render Deployment Preparation (Neon PostgreSQL / free Render)

This project is a Flask application factory (`app.create_app`) with a Gunicorn-compatible WSGI entry point (`wsgi:app`). It supports **local SQLite by default** and **PostgreSQL when `DATABASE_URL` is configured**. This document prepares the project for a secure Render deployment using a **fresh Neon PostgreSQL database** **without** deploying it, uploading it, modifying `instance/research.db`, copying local users/records, or changing the trained Decision Tree.

## 1. WSGI entry point

- **Module:** `wsgi.py`
- **App object:** `app = create_app()`
- **Gunicorn target:** `wsgi:app`

Do not use `app:app`; the Flask app is created by the application factory.

## 2. Required model artifacts

The live authentication workflow uses the trusted local Decision Tree artifact and must remain unchanged:

- **Tracked deployment artifact:** `model_artifacts/decision_tree.joblib`
- **Legacy local path (still supported):** `instance/decision_tree.joblib`

`app.detection.predictor.load_model()` prefers the tracked deployment artifact when present and falls back to the legacy instance path. The tracked artifact is included so a Render build from the repository can load the model without deploying `instance/research.db`.

## 3. Database behavior (SQLite local + PostgreSQL production)

- **Local/default:** if `DATABASE_URL` is not configured, the app uses SQLite at `DATABASE_PATH` (default `instance/research.db`) and existing local SQLite behavior/databases are preserved.
- **Production (Render/Neon):** if `DATABASE_URL` is configured, the app uses PostgreSQL for application data (users, login events, security alerts, synthetic test tables).
- **No data copy/migration from local DB:** the production PostgreSQL database must start **fresh and empty**. Do not point production to `instance/research.db`, do not upload/copy local SQLite files, and do not import existing local users or records.
- **Safe initialization:** the app initializes required schema idempotently on startup/request (`app.models.db.initialize`). You can also pre-initialize explicitly (recommended for first deploy) with the provided script.
- **No default administrator:** no administrator account or password is created automatically.

### Neon PostgreSQL (recommended for free Render)

1. Create a Neon project/database and obtain its PostgreSQL connection string.
2. Use a **fresh, empty** database/branch for production (or a fresh schema/database name).
3. Store the connection string only in Render environment variables as `DATABASE_URL` (never commit it).
4. Ensure the connection string includes TLS as required by Neon (typically `sslmode=require`).

## 4. Production safety controls (preserved)

The prepared configuration preserves:

- Administrator authentication and authorization (`is_admin`, admin-only routes, 403 handling)
- CSRF protection (`Flask-WTF` / `flask_wtf.csrf.CSRFProtect`)
- Rate limiting (`Flask-Limiter`, including login protections)
- Secure password hashing (Argon2id in `app.auth.hashing`)
- Login/session protection (`Flask-Login`, HTTP-only session cookie, SameSite=Lax)
- Login event logging, security alerts, and synthetic-data separation (synthetic/manual-test data stored separately from live events)

Production hardening:

- `DEBUG`/`TESTING` are disabled by default in the app factory.
- The Werkzeug development server/debugger is **not** used for Render; run Gunicorn only.
- `SECRET_KEY` is required from the environment in non-test runs (never hardcoded).
- `TRUST_PROXY_HEADERS` (or Render's `RENDER` environment) enables `ProxyFix` behind Render's proxy.
- A safe health check endpoint is available at `GET /health` (returns `{"status":"ok"}` with no sensitive data).
- **Manual Detection Test Lab must remain unavailable in production:** routes `/admin/manual-detection*` are enabled only for explicit local debug testing (`MANUAL_DETECTION_LAB=true` and `FLASK_DEBUG` enabled) and are gated/404 in production. Set `FLASK_DEBUG=0` and `MANUAL_DETECTION_LAB=false` (or omit it).

## 5. Exact Render configuration

### Build command

```bash
pip install --upgrade pip && pip install -r requirements.txt
```

### Start command

```bash
gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 wsgi:app
```

- `PORT` is provided by Render at runtime; do not hardcode it.
- This start command is suitable for PostgreSQL-backed deployments. If using SQLite on a persistent disk instead, prefer `--workers 1 --threads 2 --timeout 120` to reduce lock contention.

### Environment variables

Set these in Render's environment/secret settings (not in the repository). `PORT` is injected by Render and should not be set manually.

| Variable | Required | Example / guidance |
| --- | --- | --- |
| `SECRET_KEY` | Yes | Long random secret (e.g. 32+ bytes, hex/base64). Never hardcode. |
| `PRIVACY_HMAC_KEY` | Recommended | Separate long random secret for source pseudonymization. If unset, the app falls back to `SECRET_KEY` for existing HMAC behavior; set a distinct value in production. |
| `DATABASE_URL` | Yes (Neon/PostgreSQL) | Neon PostgreSQL connection string for a **fresh, empty** database (e.g. `postgresql://...?...sslmode=require`). Never commit. |
| `FLASK_DEBUG` | Yes | `0` |
| `SESSION_COOKIE_SECURE` | Recommended | `true` |
| `TRUST_PROXY_HEADERS` | Recommended | `true` (`RENDER` is also honored by the app for proxy header trust). |
| `MANUAL_DETECTION_LAB` | Yes | `false` |
| `SOC_DEMO_MODE` | Yes | `false` |
| `AUTH_EVENT_RETENTION_ENABLED` | Recommended | `true` (or as policy requires) |
| `AUTH_EVENT_RETENTION_DAYS` | Recommended | `90` (or as policy requires) |
| `ADMIN_PROVISIONING_CODE` | Only if provisioning an admin | Strong one-time/shared provisioning code used by `scripts/provision_administrator.py --confirm`; do not reuse app secrets. |
| `DATABASE_PATH` | Not required for Neon | Local SQLite path only when `DATABASE_URL` is not set. Do not point to `instance/research.db` in production. |

Do not set `FLASK_DEBUG=1`, do not enable demo/manual-lab modes, and do not provide local database files or credentials.

## 6. Database setup steps (fresh Neon PostgreSQL)

1. **Create/select a fresh Neon database** (empty). Do not copy `instance/research.db` or any local records.
2. **Set `DATABASE_URL`** in Render to the Neon connection string.
3. **Initialize schema (safe, idempotent, no data copied):**
   - Automatic: the application initializes required tables when it starts handling requests.
   - Optional explicit pre-initialization in the Render environment with the same `DATABASE_URL`:
     ```bash
     python scripts/prepare_production_database.py --use-database-url
     ```
     (Or simply run the script with `DATABASE_URL` configured; it will initialize PostgreSQL when no SQLite `--database-path` is provided.)
4. **Provision an administrator only if required (controlled, explicit, no default password):**
   - Ensure `DATABASE_URL`, `SECRET_KEY`, and `ADMIN_PROVISIONING_CODE` are set in a secure Render shell/environment.
   - Run:
     ```bash
     python scripts/provision_administrator.py --username <admin-username> --confirm
     ```
   - Provide the provisioning code and a strong administrator password when prompted. No default administrator credentials exist.

## 7. Deployment steps (Render)

1. **Prepare repository content (local, no upload performed by this task):**
   - Ensure `wsgi.py`, `requirements.txt` (includes `gunicorn` and `psycopg[binary]`), `model_artifacts/decision_tree.joblib`, and this document are included.
   - Confirm `.env`, `instance/*.db`, credentials, logs, and virtual environments are not committed.
2. **Create a Render Web Service** from the repository/branch (Python runtime).
3. **Configure commands:**
   - Build: `pip install --upgrade pip && pip install -r requirements.txt`
   - Start: `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 wsgi:app`
4. **Set environment variables** as listed above (including `DATABASE_URL` for Neon); generate strong random values for secrets.
5. **Initialize/provision the database** as described in section 6 (fresh/empty schema, no copied data, no default admin).
6. **Deploy and verify:**
   - Check `GET /health` returns `200 {"status":"ok"}`.
   - Confirm HTTPS/secure cookies/proxy behavior.
   - Verify registration, login, admin authorization (admin-only access), and that `/admin/manual-detection*` endpoints are not accessible in production.
   - Verify login events/security alerts persist in the PostgreSQL database during validation (without importing local records).

## 8. Security notes

- PostgreSQL (Neon) is preferred over SQLite for Render durability and concurrency on hosted/free environments.
- Public registration never grants admin privileges; administrator provisioning remains a separate controlled action.
- `.gitignore` excludes `.env*` (except `.env.example`), database files, credentials/keys, virtual environments, logs, and local instance contents.
- This preparation does not deploy to Render, upload to GitHub, modify `instance/research.db`, or change the trained Decision Tree / existing local user accounts.

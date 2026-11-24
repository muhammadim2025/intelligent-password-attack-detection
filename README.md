# Decision Tree-Based AI System for Suspicious Login Classification

This project is a university cybersecurity research prototype that uses **Decision Tree classification**, **behavioural analysis**, and **Argon2id secure hashing** to analyze login activity on **local test accounts** and classify attempts as **suspicious** or **non-suspicious**. Training, evaluation, and dashboard demonstration data are **synthetic** or created inside the project unless explicitly labeled as live application data.

> **Research boundary:** Use this project in a controlled local/lab environment only. Do not load real user credentials, leaked password lists, or production authentication logs. Do not point it at a live identity system or deploy demo/manual-lab modes publicly.

## Official project title

**Decision Tree-Based AI System for Suspicious Login Classification**

## Core capabilities

- Flask authentication workflow for local test accounts (registration, login, logout, role-based access).
- Argon2id password hashing; passwords/plaintext secrets are not stored in login-event records.
- CSRF protection, login rate limiting, secure session handling, and administrator-only protected views.
- Live authentication-event logging with pseudonymized source identifiers (keyed HMAC), not raw IP addresses.
- Decision Tree-based AI classification of login attempts using 10 behavioural features.
- Security alert creation/review workflow for AI-predicted suspicious events.
- Admin/SOC **Security Analytics Dashboard** with database-backed KPIs, charts, behavioural analytics, and model analytics.
- Lightweight live dashboard updates (JSON polling every ~7 seconds) with animated KPI/chart updates, last successful update time, and connection/error status.
- Manual Detection Test Lab (optional, local debug-only) for synthetic feature-vector prediction/save in isolated synthetic tables.
- Synthetic research dataset generation, reproducible training/evaluation, and separate SOC demo database support.
- SQLite for local development and PostgreSQL-compatible schema/query paths where supported by the application.

## Final 10-feature Decision Tree input order

The same feature order is used consistently across live extraction, database storage, synthetic dataset generation, training, prediction, and dashboard/manual-lab display:

1. `failed_attempts_5min` — failed login attempts in the previous 5 minutes for the relevant source context.
2. `login_attempts_5min` — total login attempts in the previous 5 minutes for the relevant source context.
3. `unique_accounts_5min` — distinct usernames targeted from the same source in the previous 5 minutes.
4. `new_device` — whether the username/source combination has no prior successful login history (`1` = new/unseen device/source context).
5. `login_hour` — UTC hour of the login attempt (0–23).
6. `source_failure_rate` — failed attempts divided by total attempts in the recent window.
7. `time_since_last_login` — seconds since the relevant previous login context (safe fallback when unavailable).
8. `recent_account_failure_count` — recent failed attempts for the same username/account in the 5-minute window.
9. `unique_ips_5min` — number of distinct **pseudonymized** source IP identifiers associated with the same username within the previous 5 minutes (current source included when available; missing/unavailable IP handled safely).
10. `unusual_login_time` — binary behavioural feature indicating whether the current UTC login hour is outside the user’s learned usual successful-login hour pattern. Requires a configurable minimum history (`UNUSUAL_LOGIN_MIN_HISTORY`, default `5` successful logins). **Insufficient history/new users return a safe/default state (`0`) and are not automatically classified as suspicious.** Time handling is normalized to UTC.

**Important:** These are Decision Tree model inputs. Model predictions are distinct from any separate heuristic rules/labels and from alert-generation logic.

## Live dashboard and analytics

The admin dashboard is a database-backed Security Analytics Dashboard (no fake/random activity). It includes:

- **Animated KPI cards:** Total Login Attempts, Successful Login Attempts, Failed Login Attempts, AI-Classified Suspicious Attempts, Non-Suspicious Attempts, Detection Rate, Unique Source IPs, Recent Security Alerts.
- **Live login activity chart:** successful, failed, and AI-suspicious classifications over time from actual timestamps/records.
- **Classification analytics:** suspicious vs non-suspicious distribution, prediction confidence distribution, and suspicious activity trend.
- **Behavioural analytics:** multiple-IP activity, unusual login timing, repeated failed login attempts, and accounts experiencing unusual login activity (computed from stored behavioural features/events).
- **Decision Tree model analytics:** feature importance, classification/confidence summaries, and available model/training-evaluation metrics (clearly labeled as training/evaluation, not live production performance).

**Live update mechanism:** frontend polling every ~7 seconds to `/admin/dashboard/live-data?source=real|synthetic` (admin-only Flask JSON endpoint). KPI values and charts update dynamically without full-page reload; last successful update time and connection/error status are displayed. Polling payloads are lightweight (aggregates/charts/analytics/metadata; tables are rendered on page load).

**Data separation:** real authentication statistics (`login_events`, `security_alerts`) and synthetic/manual/demo statistics (`synthetic_test_events`, `synthetic_test_alerts` or demo DB) are queried separately and clearly labeled; they are never mixed.

## Project layout (key paths)

- `app/` — Flask app factory, config, routes, models, services, detection, templates, static assets
- `app/detection/features.py` — canonical research feature schema/order and label helpers
- `app/detection/predictor.py` — trusted model loading, schema validation, prediction, explanation
- `app/detection/tree.py` — Decision Tree construction helpers
- `app/services/login_events.py` — live authentication event recording and behavioural feature extraction
- `app/routes/pages.py` — auth routes, admin dashboard/live API, manual detection, events/alerts/research views
- `app/models/db.py` — SQLite/PostgreSQL schema, compatibility layer, migrations/initialization
- `scripts/generate_research_dataset.py` — reproducible v1 synthetic dataset (10 features)
- `scripts/train_decision_tree.py` — v1 model training/evaluation and artifact generation
- `scripts/generate_soc_demo.py` — isolated synthetic SOC demo database generator
- `scripts/generate_synthetic.py` — legacy synthetic event generation utility
- `data/synthetic/` — generated synthetic datasets (gitignored/generated outputs as applicable)
- `data/research/` — evaluation metrics and visualizations (generated)
- `instance/` — local DB/model artifacts (gitignored/local)
- `model_artifacts/` — deployment/runtime model artifact location (preferred by predictor when present)
- `tests/` — automated tests (pytest/unittest-compatible)

## Environment setup (Windows PowerShell)

1. Install **Python 3.11+** and (optionally) Git.
2. Create/activate a virtual environment:

```powershell
cd "C:\Users\<you>\intelligent-password-attack-detection"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install dependencies:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

4. Configure environment variables (copy `.env.example` to `.env` as needed). Set a strong `SECRET_KEY` and `PRIVACY_HMAC_KEY` for non-trivial use.

## Run locally

```powershell
$env:FLASK_DEBUG="1"
$env:SECRET_KEY="replace-with-a-local-random-secret"
$env:PRIVACY_HMAC_KEY="replace-with-a-local-random-privacy-key"
python -m flask --app app run --host 127.0.0.1
```

Initialize a fresh local/deployment database when needed:

```powershell
python scripts/prepare_production_database.py
```

## Generate dataset and train the Decision Tree (v1)

```powershell
python scripts/generate_research_dataset.py --count 10000 --seed 42
python scripts/train_decision_tree.py
```

Outputs (synthetic research artifacts):
- `data/synthetic/authentication_events.csv`
- `instance/decision_tree.joblib`
- `data/research/evaluation.json`, `data/research/metrics_comparison.png`, `data/research/decision_tree.png`

Measured metrics in `data/research/evaluation.json` are **synthetic held-out/training-evaluation results** for this dataset only and must not be presented as real-world detection performance.

## Safe SOC demonstration database

```powershell
python scripts/generate_soc_demo.py --count 160 --seed 2026
$env:SOC_DEMO_MODE="true"
$env:SECRET_KEY="replace-with-a-local-random-secret"
python -m flask --app app run --host 127.0.0.1
```

- Uses `instance/soc_demo.db` (isolated from `instance/research.db`).
- Creates synthetic demo users/admin and classified synthetic events/alerts.
- Never sends login requests and never reads/writes the real research DB.

Disable by setting `SOC_DEMO_MODE=false` and deleting `instance/soc_demo.db` if desired.

## Manual Detection Test Lab (local, admin-only)

```powershell
$env:FLASK_DEBUG="1"
$env:MANUAL_DETECTION_LAB="true"
python -m flask --app app run --host 127.0.0.1
```

- Available to explicitly provisioned admin accounts at `/admin/manual-detection`.
- Runs predictions on fixed synthetic feature vectors using the trusted Decision Tree (no login requests, no password guessing).
- Saved results go to separate `synthetic_test_events` / `synthetic_test_alerts` tables and are labeled synthetic.

## Security and privacy

- **Password hashing:** Argon2id (`app/auth/hashing.py`).
- **CSRF protection:** enabled for state-changing forms/actions.
- **Login rate limiting:** enforced on login attempts.
- **IP pseudonymization:** source IP values are pseudonymized with keyed HMAC before storage/display; raw IPs are not exposed in dashboard views.
- **Secrets/privacy:** do not log or display plaintext passwords, password hashes, session tokens, or unnecessary personal information.
- **Admin provisioning:** use controlled CLI provisioning (not public registration) for administrator accounts.
- **Retention:** authentication-event retention cleanup is configurable; disabled by default to preserve research data.

## Testing and validation

Run the test suite from the project root:

```powershell
python -m pytest -q
```

Validation should cover (as applicable): behavioural feature extraction (`unique_ips_5min`, `unusual_login_time`, insufficient history, missing IP), dashboard API/data calculations, SQLite/PostgreSQL compatibility paths, and UI behavior. Browser JavaScript console/layout checks may require manual verification in a browser environment.

## Limitations and notes

- This is a **research prototype**, not a production-hardened deployment.
- Model metrics are based on synthetic/research datasets unless explicitly stated otherwise; live dashboard statistics are separate DB-backed operational/test data.
- `unusual_login_time` uses a UTC hour-of-day learned pattern from prior successful logins with a configurable minimum-history threshold; insufficient history is treated as default-safe (`0`).
- Version 2 research scripts/artifacts under `scripts/*v2.py`, `data/research/v2/`, and `instance/v2/` are isolated experiments and are not loaded by the live Flask application.
- If no in-repository academic report document (e.g. `.docx`/`.pdf`) is present, documentation updates in code/markdown cannot replace editing that external report artifact.

## Deployment

See [DEPLOYMENT_RENDER.md](DEPLOYMENT_RENDER.md) for Render-oriented guidance and environment considerations. Production WSGI entry point: `wsgi:app`.
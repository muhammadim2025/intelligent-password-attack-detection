# Intelligent Password Attack Detection Using Decision Tree and Secure Hashing

Seventh-semester cybersecurity research prototype. The system will watch login behavior on **local test accounts**, label suspicious attempts with a **Decision Tree**, and store passwords with **Argon2id**. Data for training and demos will be **synthetic** or created inside this project.

Phase 3A is in place: Flask registration and login, Flask-Login sessions, CSRF protection,
live authentication-event logging, login rate limiting, and a protected administrator
dashboard. The Decision Tree remains a later implementation phase.

## Research boundary

Use this project in a controlled lab:

- Create test accounts yourself, or generate synthetic login records.
- Keep the database on this machine (`instance/`).
- Train and evaluate the Decision Tree on those synthetic records.

Do not load real user credentials, leaked password lists, or production authentication logs. Do not point the app at a live identity system.

## Stack

| Concern | Choice |
| --- | --- |
| Web application | Python, Flask |
| Detection model | scikit-learn Decision Tree |
| Password storage | Argon2id via `argon2-cffi` |
| Database | SQLite (Python standard library) |
| Interface | HTML, CSS, JavaScript |

## Project layout

```text
intelligent-password-attack-detection/
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── auth/
│   │   ├── __init__.py
│   │   └── hashing.py
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── features.py
│   │   └── tree.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── db.py
│   ├── routes/
│   │   ├── __init__.py
│   │   └── pages.py
│   ├── services/
│   │   ├── __init__.py
│   │   └── login_events.py
│   ├── static/
│   │   ├── css/main.css
│   │   └── js/main.js
│   └── templates/
├── data/synthetic/
├── instance/
├── scripts/generate_synthetic.py
└── tests/test_storage.py
```

### Root files

| File | Role |
| --- | --- |
| `README.md` | Project purpose, layout, and setup. |
| `requirements.txt` | Flask, scikit-learn, argon2-cffi, and python-dotenv. |
| `.env.example` | Sample environment variable names. Copy to `.env` when the app exists. `.env` is gitignored. |
| `.gitignore` | Keeps the virtual environment, secrets, the local SQLite file, and trained model files out of git. |

### `app/`

| File | Role |
| --- | --- |
| `app/__init__.py` | Flask application factory and security-extension setup. |
| `app/config.py` | Reads `DATABASE_PATH` from the environment. The default is `instance/research.db`. |
| `app/auth/__init__.py` | Exports the password helpers. |
| `app/auth/hashing.py` | Hashes and checks lab passwords with Argon2id (64 MiB, 3 iterations, 4 lanes). |
| `app/detection/__init__.py` | Package marker for the detection model. |
| `app/detection/features.py` | Names the login-event features and the synthetic suspicious label rule. |
| `app/detection/tree.py` | Placeholder. Decision Tree training is the following phase. |
| `app/models/__init__.py` | Exports the database helpers. |
| `app/models/db.py` | Opens SQLite and creates the `users` and `login_events` tables. |
| `app/routes/__init__.py` | Package marker for HTTP routes. |
| `app/routes/pages.py` | Registration, login, logout, and administrator dashboard routes. |
| `app/services/__init__.py` | Package marker for workflows that sit between routes and storage. |
| `app/services/login_events.py` | Creates a test account, checks its hash, and stores login events. |
| `app/static/css/main.css` | Later this will style the pages. |
| `app/static/js/main.js` | Later this will hold browser behavior for the pages. |
| `app/templates/.gitkeep` | Reserved for template resources. |

### Data, scripts, tests, and the database folder

| Path | Role |
| --- | --- |
| `data/synthetic/README.md` | Describes the generated event file. `login_events.csv` is created by the script and is gitignored. |
| `scripts/generate_synthetic.py` | Builds lab accounts and synthetic login events. |
| `tests/test_storage.py` | Checks hashing, the tables, and label consistency. |
| `instance/.gitkeep` | Holds the folder for the local database. The database and `test_accounts.csv` are gitignored. |

Page templates, CSS, and JavaScript are still placeholders.

## Environment setup (Windows PowerShell)

Python and Git were not available on the machine when this skeleton was created. Install them before the next phase.

1. Install **Python 3.11 or newer** from [python.org/downloads](https://www.python.org/downloads/). During setup, enable **Add python.exe to PATH**. Prefer the python.org installer. The Microsoft Store alias currently answers `python` on this PC and does not provide a real interpreter.
2. Close and reopen PowerShell, then check the interpreter:

```powershell
python --version
```

3. Install **Git** from [git-scm.com/download/win](https://git-scm.com/download/win) if you want version history. Then, from this folder:

```powershell
git init
```

4. Create and activate a virtual environment in the project folder:

```powershell
cd "C:\Users\Muhammad Imran\intelligent-password-attack-detection"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the activation script, allow local scripts for your user account and activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

5. Install the Phase 1 dependencies:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

6. Confirm the packages import:

```powershell
python -c "import flask, sklearn, argon2, dotenv; print('environment ok')"
```

Leave the virtual environment with `deactivate`.

## Generate the lab dataset

From the project folder, with the virtual environment active:

```powershell
python scripts/generate_synthetic.py
python -m unittest tests.test_storage -v
```

The generator replaces `instance/research.db` when it runs again. It writes:

| Output | Contents |
| --- | --- |
| `instance/research.db` | `users.password_hash` (Argon2id) and `login_events` rows. |
| `instance/test_accounts.csv` | Usernames and the random lab passwords. Git ignores this file. |
| `data/synthetic/login_events.csv` | Features and the suspicious label. No passwords. |

Default size: 12 accounts and 360 events, seed 42. Addresses use the documentation ranges `198.51.100.0/24` and `203.0.113.0/24`.

Optional arguments: `--users`, `--events`, and `--seed`.

A synthetic row is labeled suspicious when any of these is true:

- 5 or more failed attempts in the recorded 15-minute window
- 4 or more distinct usernames from the same address in that window
- a failed attempt within 2 seconds of the previous attempt
- 2 or more failures during hours 00–04

Other generated rows are labeled normal. This rule is the dataset’s ground truth. It is not the Decision Tree.

## Phase 3A status

The Flask authentication prototype is implemented for local, synthetic use:

- registration stores only Argon2id password hashes;
- login and logout use signed Flask sessions;
- registration and login forms use CSRF protection;
- successful and failed login attempts create login-event records;
- login requests are rate limited;
- only explicitly marked administrator accounts can open `/admin`;
- passwords and session tokens are not written to login-event records or exposed by dashboard views.

Do not proceed to production deployment or real credential collection. Decision Tree training
is implemented only as a synthetic research prototype.

## Research dataset and model

Generate the reproducible 10,000-event dataset:

```powershell
& ".\.venv312\Scripts\python.exe" scripts/generate_research_dataset.py --count 10000 --seed 42
& ".\.venv312\Scripts\python.exe" scripts/train_decision_tree.py
& ".\.venv312\Scripts\python.exe" -m pytest -q
```

Outputs:

| Output | Purpose |
| --- | --- |
| `data/synthetic/authentication_events.csv` | Reproducible synthetic feature dataset |
| `instance/decision_tree.joblib` | Trusted locally generated model artifact |
| `data/research/evaluation.json` | Measured Decision Tree and rule-baseline metrics |
| `data/research/metrics_comparison.png` | Metric comparison visualization |
| `data/research/decision_tree.png` | Decision Tree visualization |

The measured synthetic held-out results and confusion matrices are written by the training
script. They describe this synthetic dataset only and must not be presented as real-world
detection accuracy.

## Version 2 scientific experiment

Version 2 is isolated from the live Flask model and all Version 1 artifacts.

```powershell
& ".\.venv312\Scripts\python.exe" scripts/generate_research_dataset_v2.py --count 10000 --seed 2026
& ".\.venv312\Scripts\python.exe" scripts/train_decision_tree_v2.py
& ".\.venv312\Scripts\python.exe" scripts/run_v2_experiment.py --count 10000 --seeds 2026 2027 2028 2029 2030
& ".\.venv312\Scripts\python.exe" scripts/audit_research_v2.py
& ".\.venv312\Scripts\python.exe" -m pytest -q
```

Version 2 outputs are under `data/research/v2/` and `instance/v2/`. Labels are scenario-based:
normal and unusual-legitimate scenarios are normal, while suspicious scenarios are suspicious.
The eight model features are derived only from timestamped event history available before the
current prediction. Version 2 includes a chronological 75/25 evaluation and an explicit
48-source disjoint heldout evaluation.

The rule baseline is an independently specified multi-feature traditional detector. Its
thresholds are selected using only training folds. Neither baseline thresholds nor Decision
Tree hyperparameters are adjusted using the final test partition.

Version 2 remains a synthetic research experiment. It must not be loaded into the live Flask
authentication workflow or presented as real-world detection performance without external
validation.

## Safe SOC demonstration database

Generate 160 clearly synthetic dashboard events in a separate database:

```powershell
& ".\.venv312\Scripts\python.exe" scripts/generate_soc_demo.py --count 160 --seed 2026
```

The generator:

- creates `instance/soc_demo.db`;
- creates synthetic demo users and a `demo-admin` account;
- uses the existing trusted Decision Tree interface to classify feature vectors;
- creates alert rows only for model-predicted suspicious events;
- mixes successes, failures, normal classifications, suspicious classifications, open alerts,
  reviewed alerts, sources, and timestamps over the previous seven days;
- never requests or sends data to the Flask login endpoint;
- never reads from or writes to `instance/research.db`.

Demo mode is disabled by default. Start it only on local loopback:

```powershell
$env:SOC_DEMO_MODE="true"
$env:SECRET_KEY="replace-with-a-local-random-secret"
& ".\.venv312\Scripts\python.exe" -m flask --app app run --host 127.0.0.1
```

Use the one-time synthetic password printed by the generator to sign in as `demo-admin`.
The password is not written to a file or to the database. Remove the reversible demonstration
mode by setting `SOC_DEMO_MODE=false` and deleting only `instance/soc_demo.db`. Do not deploy
demo mode or synthetic credentials publicly.

## Manual Detection Test Lab

The administrator-only Manual Detection Test Lab is disabled by default. Enable it only
for local development:

```powershell
$env:FLASK_DEBUG="1"
$env:MANUAL_DETECTION_LAB="true"
$env:SECRET_KEY="replace-with-a-local-random-secret"
& ".\.venv312\Scripts\python.exe" -m flask --app app run --host 127.0.0.1
```

Sign in with an existing account whose `is_admin` value is `1`, then open:

`http://127.0.0.1:5000/admin/manual-detection`

The lab predicts fixed normal and suspicious feature vectors with the existing trusted
V1 Decision Tree. It sends no login requests and performs no password guessing. A prediction
can optionally be saved in separate `synthetic_test_events` and `synthetic_test_alerts`
tables. These rows are labeled synthetic and never modify `login_events` or
`security_alerts`.

Set `MANUAL_DETECTION_LAB=false` or unset it to disable the route. Explicit debug/local
configuration is required, so it is not enabled for normal production startup.

## Security and privacy configuration

Registration accepts passwords that are 12–128 characters and use characters from at least
three of: lowercase letters, uppercase letters, digits, and symbols. Weak passwords are
rejected before Argon2id hashing.

Live authentication events pseudonymize source IP values with a keyed HMAC before storage.
The source IP is not retained as plaintext. Password plaintext, password hashes, and
Flask session tokens are not written to authentication events or rendered in dashboards.

Authentication-event retention is disabled by default to avoid deleting research data.
To enable scheduled/policy-based cleanup:

```powershell
$env:AUTH_EVENT_RETENTION_ENABLED="true"
$env:AUTH_EVENT_RETENTION_DAYS="90"
& ".\.venv312\Scripts\python.exe" scripts/purge_expired_auth_events.py
```

Retention cleanup is intended to run within application startup/request initialization.
The purge removes expired events and linked alerts while preserving users and synthetic
research datasets outside `login_events`.

## Administrator provisioning

Do not grant administrator status through public registration. Use the separate controlled
CLI and require explicit confirmation:

```powershell
$env:ADMIN_PROVISIONING_CODE="replace-with-a-private-local-code"
& ".\.venv312\Scripts\python.exe" scripts/provision_administrator.py --username admin-name --confirm
```

The script prompts for the provisioning code and password without accepting the password
as a command-line argument. It can create an administrator or explicitly promote an existing
account. Registration always creates `is_admin = 0`.

## Local development and secure deployment

Local development may run over loopback HTTP with:

- a private `.env` file,
- `FLASK_DEBUG=1`,
- test SQLite databases,
- synthetic accounts and synthetic data,
- `AUTH_EVENT_RETENTION_ENABLED=false` unless explicit cleanup is desired.

The repository is a university prototype, not a verified production deployment. Before any
internet exposure:

1. Serve the application only behind HTTPS with a valid certificate and redirect HTTP to HTTPS.
2. Set a long random `SECRET_KEY` and a separate `PRIVACY_HMAC_KEY` in an external secret manager.
3. Never commit `.env`, private keys, database files, lab passwords, or model credentials.
4. Run behind an authenticated reverse proxy/WSGI server with OS-level database permissions.
5. Set `FLASK_DEBUG=0`, restrict allowed hosts, set secure proxy headers, and verify secure cookies.
6. Use encrypted storage/backups and define organization-approved retention and incident procedures.
7. Replace Bootstrap CDN assets with pinned local assets if the interface must work offline.
8. Audit dependencies, logging, reverse proxy trust, backup recovery, and authorization before deployment.

The application sends HSTS only outside test mode and applies nonce-free browser hardening
headers. HSTS does not create HTTPS; HTTPS must be configured and verified externally.

For Render-specific preparation, exact build/start commands, environment variables, and
database guidance, see [DEPLOYMENT_RENDER.md](DEPLOYMENT_RENDER.md). The production WSGI
entry point is `wsgi:app` (`gunicorn --bind 0.0.0.0:$PORT wsgi:app`). A safe helper to
initialize a fresh deployment database without modifying `instance/research.db` is
`scripts/prepare_production_database.py`.


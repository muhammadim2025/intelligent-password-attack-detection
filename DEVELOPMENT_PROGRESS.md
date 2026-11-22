# Development Progress

## Completed

- Python 3.12 `.venv312` setup and dependency installation
- Flask application factory
- Argon2id registration and password verification
- Flask-Login login/logout and signed sessions
- CSRF protection and login rate limiting
- SQLite users, authentication events, and security alerts
- Administrator role separation and protected routes
- Live login event feature capture and model-prediction integration
- Safe behavior when the trusted model artifact is unavailable
- Reproducible 10,000-row synthetic authentication dataset
- Chronological held-out Decision Tree evaluation
- Rule-based baseline comparison
- Model and visualization artifacts
- User, administrator, and research dashboards
- Automated storage, route, model, dataset, and alert tests
- Separate scenario-based Version 2 synthetic experiment
- Version 2 chronological and source-disjoint evaluation
- Version 2 multi-seed uncertainty and scientific audit

## Current Verification

The complete pytest suite currently reports **31 passing tests**.

The latest synthetic experiment uses 10,000 rows, a 75/25 chronological split,
and a rule baseline independent of the trained model. Its actual metrics are in:

- `data/research/evaluation.json`
- `data/research/metrics_comparison.png`
- `data/research/decision_tree.png`

## Remaining Before a Formal Submission

- Password-strength policy, keyed source pseudonymization, configurable retention, and a
  separate administrator provisioning CLI are implemented.
- Bootstrap is still loaded from a CDN; production/offline demonstrations can replace it with local assets.
- External HTTPS termination and a verified WSGI/reverse-proxy deployment remain untested.
- Dependency and production vulnerability audits remain to be performed.
- Access, retention, and backup policies require academic/institutional approval.
- Conduct an external, literature-reviewed academic report and add verified citations.
- Add larger and more diverse datasets if real evaluation is later authorized.

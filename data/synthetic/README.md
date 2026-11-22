# Synthetic data

`scripts/generate_synthetic.py` writes `login_events.csv` here.

- The file contains behavioral features and the synthetic suspicious label.
- It does not contain passwords.
- Account passwords are random lab secrets stored as Argon2id hashes in `instance/research.db`. A copy of those lab passwords is written only to `instance/test_accounts.csv`, which git ignores.
- Do not place real usernames, real passwords, leaked password lists, or production logs in this folder.

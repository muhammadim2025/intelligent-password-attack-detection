# Synthetic data

This folder holds synthetic/research datasets for the **Decision Tree-Based AI System for Suspicious Login Classification**.

- `scripts/generate_research_dataset.py` writes the reproducible v1 training dataset `authentication_events.csv` here (10 behavioural Decision Tree features + label). No passwords.
- `scripts/generate_synthetic.py` is a legacy synthetic event generator that may write `login_events.csv` for local experiments. No passwords.
- Account passwords for generated lab accounts are stored only as Argon2id hashes in local databases (e.g. `instance/research.db` / demo DB). Any generated lab password lists (such as `instance/test_accounts.csv`) are local artifacts and must not be committed.
- Do not place real usernames, real passwords, leaked password lists, or production logs in this folder.
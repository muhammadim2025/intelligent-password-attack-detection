"""Runtime settings loaded from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def database_path() -> Path:
    """Return the SQLite path, relative paths resolved inside the project."""
    configured = os.getenv("DATABASE_PATH", "instance/research.db")
    path = Path(configured)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def database_url() -> str | None:
    """Return the configured PostgreSQL URL, if any."""
    value = os.getenv("DATABASE_URL", "").strip()
    return value or None


def database_target() -> str | Path:
    """Return the default database target for the current environment."""
    return database_url() or database_path()


def auth_event_retention_days() -> int:
    """Return the configured retention period, rejecting unsafe values."""
    raw = os.getenv("AUTH_EVENT_RETENTION_DAYS", "90")
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return 90
    return max(1, days)


def auth_event_retention_enabled() -> bool:
    return os.getenv("AUTH_EVENT_RETENTION_ENABLED", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def soc_demo_mode_enabled() -> bool:
    return os.getenv("SOC_DEMO_MODE", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def soc_demo_database_path() -> Path:
    return PROJECT_ROOT / "instance" / "soc_demo.db"


def manual_detection_lab_enabled() -> bool:
    """Enable only explicit local-development synthetic testing."""
    enabled = os.getenv("MANUAL_DETECTION_LAB", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    local_debug = os.getenv("FLASK_DEBUG", "0").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return enabled and local_debug


def unusual_login_min_history() -> int:
    """Return the minimum successful-login history required to learn usual hours."""
    raw = os.getenv("UNUSUAL_LOGIN_MIN_HISTORY", "5")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 5
    return max(1, value)

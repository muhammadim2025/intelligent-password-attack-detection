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

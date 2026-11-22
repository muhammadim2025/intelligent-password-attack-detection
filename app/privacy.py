"""Privacy helpers for authentication metadata."""

from __future__ import annotations

import hashlib
import hmac
import os


def pseudonymize_source(source: str, secret: str) -> str:
    """Return an irreversible keyed identifier for an IP or source label."""
    cleaned = (source or "unknown").strip().encode("utf-8")
    key = (secret or "local-development-only-key").encode("utf-8")
    digest = hmac.new(key, cleaned, hashlib.sha256).hexdigest()
    return f"source:{digest[:16]}"


def environment_secret(name: str, fallback: str) -> str:
    value = os.getenv(name)
    if value:
        return value
    return fallback

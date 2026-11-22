"""Flask-Login adapter for a local SQLite account."""

from __future__ import annotations

from dataclasses import dataclass

from flask_login import UserMixin


@dataclass(frozen=True)
class User(UserMixin):
    id: int
    username: str
    password_hash: str
    is_admin: bool

    def get_id(self) -> str:
        return str(self.id)

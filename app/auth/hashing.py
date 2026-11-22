"""Argon2id password hashing for accounts created inside this project."""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

# Parameters cited in the project report. These match the Argon2id settings
# commonly recommended for interactive login checks: 64 MiB, 3 iterations,
# and 4 parallel lanes.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


def password_strength_error(password: str) -> str | None:
    """Return a generic validation message when a password is insufficient."""
    if not isinstance(password, str):
        return "Password does not meet the strength requirement."
    if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        return "Password must be 12 to 128 characters."
    categories = sum(
        (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() for character in password),
        )
    )
    if categories < 2:
        return "Password must include characters from at least two of: lowercase, uppercase, digits, symbols."
    if password.lower() in {"password", "password123", "qwerty"}:
        return "Password is too common."
    return None


def hash_password(password: str) -> str:
    """Return an Argon2id hash. The plaintext password is not stored."""
    _validate_password(password)
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True when the password matches a stored Argon2id hash."""
    if not password_hash or not password:
        return False
    try:
        return bool(_hasher.verify(password_hash, password))
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Return True when an encoded verifier needs parameter migration."""
    if not password_hash:
        return False
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (VerificationError, InvalidHashError):
        return False


def _validate_password(password: str) -> None:
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    length = len(password)
    if length < MIN_PASSWORD_LENGTH or length > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"Password length must be between {MIN_PASSWORD_LENGTH} and "
            f"{MAX_PASSWORD_LENGTH} characters."
        )
    strength_error = password_strength_error(password)
    if strength_error:
        raise ValueError(strength_error)

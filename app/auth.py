from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path

from .core import atomic_json

SESSION_SECONDS = 12 * 60 * 60


def validate_username(value: str) -> str:
    username = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username):
        raise ValueError("Username must be 3–40 characters using letters, numbers, dots, dashes, or underscores")
    return username


def validate_password(value: str) -> None:
    if len(value) < 12:
        raise ValueError("Password must be at least 12 characters")
    checks = (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    if not all(re.search(pattern, value) for pattern in checks):
        raise ValueError("Password must include uppercase, lowercase, a number, and a symbol")


def hash_password(password: str, salt: bytes | None = None) -> dict:
    validate_password(password)
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, dklen=32)
    return {
        "algorithm": "pbkdf2-sha256-600000",
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(digest).decode(),
    }


def verify_password(password: str, record: dict) -> bool:
    try:
        salt = base64.b64decode(record["password"]["salt"])
        expected = base64.b64decode(record["password"]["hash"])
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, dklen=32)
        return hmac.compare_digest(actual, expected)
    except (KeyError, ValueError, TypeError):
        return False


def create_admin(path: Path, username: str, password: str) -> dict:
    if path.exists():
        raise ValueError("Administrator account is already configured")
    record = {"version": 1, "username": validate_username(username), "password": hash_password(password)}
    atomic_json(path, record)
    os.chmod(path, 0o600)
    return record


def new_session(username: str) -> tuple[str, dict]:
    token = secrets.token_urlsafe(32)
    return token, {"username": username, "csrf": secrets.token_urlsafe(24), "expires": time.time() + SESSION_SECONDS}

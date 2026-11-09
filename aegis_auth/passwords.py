"""Password hashing (PBKDF2-HMAC-SHA256, standard library) and session tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000            # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
MIN_LENGTH = 12
MAX_LENGTH = 256


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str, iterations: int | None = None) -> str:
    """'pbkdf2_sha256$<iterations>$<salt>$<hash>' (salt and hash base64)."""
    iterations = iterations or ITERATIONS
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != ALGORITHM:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                     base64.b64decode(salt), int(iterations))
        return hmac.compare_digest(_b64(digest), expected)
    except (ValueError, TypeError):
        return False


# Verified against when the e-mail is unknown, so a wrong e-mail takes as long as a wrong password.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16), iterations=ITERATIONS)


def password_problem(password: str, email: str | None = None) -> str | None:
    """Why a new password is not acceptable, or None."""
    if not isinstance(password, str) or len(password) < MIN_LENGTH:
        return f"The password must be at least {MIN_LENGTH} characters."
    if len(password) > MAX_LENGTH:
        return f"The password must be at most {MAX_LENGTH} characters."
    name = email.split("@", 1)[0].casefold() if email else ""
    # A 1-2 character e-mail name ("ab@x.com") would reject almost any password.
    if len(name) >= 3 and name in password.casefold():
        return f"The password must not contain your e-mail name (\"{name}\"). Choose one without it."
    if len(set(password)) < 5:
        return "The password is too repetitive."
    return None


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """Only this SHA-256 of the session token is stored (aegis_user_sessions.session_token_hash)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

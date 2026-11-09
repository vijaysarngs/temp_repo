"""Users, sign-in, sessions and run records (aegis_users, aegis_user_sessions, aegis_runs)."""
from __future__ import annotations

import os
import re
import uuid
from datetime import timedelta

from . import passwords
from .store import get_store, utcnow

ROLES = ("ADMIN", "ANALYST", "VIEWER")
USER_STATUSES = ("ACTIVE", "DISABLED", "LOCKED")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT = timedelta(minutes=15)
LAST_SEEN_EVERY = timedelta(seconds=60)


class AuthError(Exception):
    """A sign-in or account problem safe to show to the user."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _minutes(name: str, default: int) -> timedelta:
    try:
        return timedelta(minutes=max(1, int(os.getenv(name, default))))
    except ValueError:
        return timedelta(minutes=default)


def session_lifetime() -> timedelta:
    return _minutes("AEGIS_SESSION_MINUTES", 8 * 60)          # absolute: expires_at


def session_idle() -> timedelta:
    return _minutes("AEGIS_SESSION_IDLE_MINUTES", 60)         # since last_seen_at


def normalize_email(email: str) -> str:
    email = str(email or "").strip().casefold()
    if not EMAIL.match(email):
        raise AuthError("Enter a valid e-mail address.")
    return email


def public_user(row: dict) -> dict:
    return {key: row.get(key) for key in ("user_id", "email", "display_name", "user_role", "status")} | {
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None}


# ---------------------------------------------------------------- users

def users_exist() -> bool:
    return get_store().one("SELECT COUNT(*) AS n FROM aegis_users")["n"] > 0


def get_user(user_id: str) -> dict | None:
    return get_store().one("SELECT * FROM aegis_users WHERE user_id = :user_id", {"user_id": user_id})


def find_user(email: str) -> dict | None:
    return get_store().one("SELECT * FROM aegis_users WHERE email = :email", {"email": normalize_email(email)})


def create_user(email: str, password: str, role: str = "ANALYST", display_name: str | None = None,
                must_change_password: bool = True) -> dict:
    email = normalize_email(email)
    role = str(role or "").upper()
    if role not in ROLES:
        raise AuthError(f"Role must be one of {', '.join(ROLES)}.")
    problem = passwords.password_problem(password, email)
    if problem:
        raise AuthError(problem)
    if find_user(email):
        raise AuthError("A user with this e-mail already exists.", 409)
    now, user_id = utcnow(), str(uuid.uuid4())
    store = get_store()
    store.execute("INSERT INTO aegis_users (user_id, email, display_name, user_role, status, created_at, updated_at) "
                  "VALUES (:user_id, :email, :display_name, :user_role, 'ACTIVE', :now, :now)",
                  {"user_id": user_id, "email": email, "display_name": (display_name or "").strip()[:255] or None,
                   "user_role": role, "now": now})
    store.execute("INSERT INTO aegis_user_credentials (user_id, password_hash, password_changed_at, "
                  "must_change_password, failed_attempts) VALUES (:user_id, :hash, :now, :must, 0)",
                  {"user_id": user_id, "hash": passwords.hash_password(password), "now": now,
                   "must": 1 if must_change_password else 0})
    return get_user(user_id)


def list_users() -> list[dict]:
    rows = get_store().query(
        "SELECT u.user_id, u.email, u.display_name, u.user_role, u.status, u.created_at, "
        "c.last_login_at, c.must_change_password, c.locked_until, "
        "(SELECT COUNT(*) FROM aegis_user_sessions s WHERE s.user_id = u.user_id AND s.status = 'ACTIVE' "
        " AND s.expires_at > :now) AS active_sessions "
        "FROM aegis_users u LEFT JOIN aegis_user_credentials c ON c.user_id = u.user_id ORDER BY u.email",
        {"now": utcnow()})
    for row in rows:
        for key in ("created_at", "last_login_at", "locked_until"):
            row[key] = row[key].isoformat() if row.get(key) else None
        row["must_change_password"] = bool(row.get("must_change_password"))
    return rows


def _active_admins(excluding: str | None = None) -> int:
    return get_store().one("SELECT COUNT(*) AS n FROM aegis_users WHERE user_role = 'ADMIN' AND status = 'ACTIVE' "
                           "AND user_id <> :excluding", {"excluding": excluding or "-"})["n"]


def update_user(user_id: str, role: str | None = None, status: str | None = None,
                display_name: str | None = None) -> dict:
    user = get_user(user_id)
    if not user:
        raise AuthError("User not found.", 404)
    role = role.upper() if role else user["user_role"]
    status = status.upper() if status else user["status"]
    if role not in ROLES:
        raise AuthError(f"Role must be one of {', '.join(ROLES)}.")
    if status not in USER_STATUSES:
        raise AuthError(f"Status must be one of {', '.join(USER_STATUSES)}.")
    if user["user_role"] == "ADMIN" and (role != "ADMIN" or status != "ACTIVE") and not _active_admins(user_id):
        raise AuthError("At least one active administrator must remain.", 409)
    get_store().execute("UPDATE aegis_users SET user_role = :role, status = :status, display_name = :name, "
                        "updated_at = :now WHERE user_id = :user_id",
                        {"role": role, "status": status, "user_id": user_id, "now": utcnow(),
                         "name": (display_name if display_name is not None else user.get("display_name") or "")[:255] or None})
    if status != "ACTIVE":
        revoke_user_sessions(user_id)
    return get_user(user_id)


def set_password(user_id: str, new_password: str, must_change: bool) -> None:
    user = get_user(user_id)
    if not user:
        raise AuthError("User not found.", 404)
    problem = passwords.password_problem(new_password, user["email"])
    if problem:
        raise AuthError(problem)
    get_store().execute("UPDATE aegis_user_credentials SET password_hash = :hash, password_changed_at = :now, "
                        "must_change_password = :must, failed_attempts = 0, locked_until = NULL "
                        "WHERE user_id = :user_id",
                        {"hash": passwords.hash_password(new_password), "now": utcnow(),
                         "must": 1 if must_change else 0, "user_id": user_id})


def change_own_password(session: dict, current_password: str, new_password: str) -> None:
    credentials = get_store().one("SELECT password_hash FROM aegis_user_credentials WHERE user_id = :user_id",
                                  {"user_id": session["user_id"]})
    if not credentials or not passwords.verify_password(current_password or "", credentials["password_hash"]):
        raise AuthError("The current password is not correct.", 403)
    if current_password == new_password:
        raise AuthError("Choose a password different from the current one.")
    set_password(session["user_id"], new_password, must_change=False)
    _forget_initial_password(session["user_id"])
    # Every other session of this user ends; this one stays.
    revoke_user_sessions(session["user_id"], keep_session_id=session["session_id"])


# ---------------------------------------------------------------- first administrator

def initial_password_file():
    from .store import DEFAULT_SQLITE
    return DEFAULT_SQLITE.parent / "initial-admin-password.txt"


def bootstrap_admin() -> dict | None:
    """With no users at all, create one ADMIN with a random temporary password.

    The e-mail is AEGIS_BOOTSTRAP_ADMIN_EMAIL (default admin@aegis.local). The password is
    written to .aegis/initial-admin-password.txt (never logged); it must be changed at the
    first sign-in, and the file is deleted when it is.
    """
    if users_exist():
        return None
    import secrets
    import string
    email = os.getenv("AEGIS_BOOTSTRAP_ADMIN_EMAIL", "admin@aegis.local")
    alphabet = string.ascii_letters + string.digits + "-_.!@#%"
    password = "".join(secrets.choice(alphabet) for _ in range(20))
    user = create_user(email, password, "ADMIN", "Administrator", must_change_password=True)
    path = initial_password_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"AEGIS first administrator\nE-mail:   {user['email']}\nPassword: {password}\n"
                    "This password is temporary: you must choose a new one at the first sign-in,\n"
                    "and this file is deleted when you do.\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return user


def _forget_initial_password(user_id: str) -> None:
    path = initial_password_file()
    user = get_user(user_id)
    if path.exists() and user and user["email"] in path.read_text(encoding="utf-8", errors="replace"):
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------- sign-in and sessions

def authenticate(email: str, password: str) -> dict:
    """The user for these credentials; one generic message for every failure."""
    failure = AuthError("Invalid e-mail or password.", 401)
    try:
        user = find_user(email)
    except AuthError:
        user = None
    credentials = get_store().one("SELECT * FROM aegis_user_credentials WHERE user_id = :user_id",
                                  {"user_id": user["user_id"]}) if user else None
    if not credentials:
        passwords.verify_password(password or "", passwords.DUMMY_HASH)     # same time as a real check
        raise failure
    now = utcnow()
    if credentials.get("locked_until") and credentials["locked_until"] > now:
        passwords.verify_password(password or "", passwords.DUMMY_HASH)
        raise AuthError("Too many failed sign-ins. Try again in a few minutes.", 429)
    if not passwords.verify_password(password or "", credentials["password_hash"]):
        attempts = int(credentials.get("failed_attempts") or 0) + 1
        get_store().execute("UPDATE aegis_user_credentials SET failed_attempts = :attempts, locked_until = :until "
                            "WHERE user_id = :user_id",
                            {"attempts": 0 if attempts >= MAX_FAILED_ATTEMPTS else attempts,
                             "until": now + LOCKOUT if attempts >= MAX_FAILED_ATTEMPTS else None,
                             "user_id": user["user_id"]})
        raise failure
    if user["status"] != "ACTIVE":
        raise failure
    get_store().execute("UPDATE aegis_user_credentials SET failed_attempts = 0, locked_until = NULL, "
                        "last_login_at = :now WHERE user_id = :user_id", {"now": now, "user_id": user["user_id"]})
    return user


def create_session(user: dict, client_ip: str | None, user_agent: str | None) -> tuple[str, dict]:
    """(token for the cookie, session row). Only the token's SHA-256 is stored."""
    token, now = passwords.new_session_token(), utcnow()
    session_id = str(uuid.uuid4())
    get_store().execute(
        "INSERT INTO aegis_user_sessions (session_id, user_id, session_token_hash, status, client_ip, user_agent, "
        "created_at, last_seen_at, expires_at) VALUES (:session_id, :user_id, :hash, 'ACTIVE', :ip, :agent, :now, "
        ":now, :expires)",
        {"session_id": session_id, "user_id": user["user_id"], "hash": passwords.token_hash(token),
         "ip": (client_ip or "")[:64] or None, "agent": (user_agent or "")[:1000] or None, "now": now,
         "expires": now + session_lifetime()})
    return token, get_session(session_id)


def get_session(session_id: str) -> dict | None:
    return get_store().one("SELECT * FROM aegis_user_sessions WHERE session_id = :session_id",
                           {"session_id": session_id})


def resolve_session(token: str | None) -> tuple[dict, dict] | None:
    """(session, user) for a valid cookie token; an expired or idle session is marked EXPIRED."""
    if not token or len(token) > 200:
        return None
    store = get_store()
    session = store.one("SELECT * FROM aegis_user_sessions WHERE session_token_hash = :hash",
                        {"hash": passwords.token_hash(token)})
    if not session or session["status"] != "ACTIVE":
        return None
    now = utcnow()
    last_seen = session.get("last_seen_at") or session["created_at"]
    if session["expires_at"] <= now or last_seen + session_idle() <= now:
        store.execute("UPDATE aegis_user_sessions SET status = 'EXPIRED' WHERE session_id = :session_id",
                      {"session_id": session["session_id"]})
        return None
    user = get_user(session["user_id"])
    if not user or user["status"] != "ACTIVE":
        return None
    if now - last_seen >= LAST_SEEN_EVERY:
        store.execute("UPDATE aegis_user_sessions SET last_seen_at = :now WHERE session_id = :session_id",
                      {"now": now, "session_id": session["session_id"]})
        session["last_seen_at"] = now
    return session, user


def must_change_password(user_id: str) -> bool:
    row = get_store().one("SELECT must_change_password FROM aegis_user_credentials WHERE user_id = :user_id",
                          {"user_id": user_id})
    return bool(row and row.get("must_change_password"))


def revoke_session(session_id: str) -> None:
    get_store().execute("UPDATE aegis_user_sessions SET status = 'REVOKED', revoked_at = :now "
                        "WHERE session_id = :session_id AND status = 'ACTIVE'",
                        {"now": utcnow(), "session_id": session_id})


def expire_stale_sessions() -> int:
    """Mark ACTIVE sessions past their absolute or idle limit as EXPIRED (they are refused
    anyway; this keeps the table and the admin view accurate). Run at start-up."""
    now = utcnow()
    return get_store().execute(
        "UPDATE aegis_user_sessions SET status = 'EXPIRED' WHERE status = 'ACTIVE' "
        "AND (expires_at <= :now OR COALESCE(last_seen_at, created_at) <= :idle_cutoff)",
        {"now": now, "idle_cutoff": now - session_idle()})


def revoke_user_sessions(user_id: str, keep_session_id: str | None = None) -> int:
    return get_store().execute("UPDATE aegis_user_sessions SET status = 'REVOKED', revoked_at = :now "
                               "WHERE user_id = :user_id AND status = 'ACTIVE' AND session_id <> :keep",
                               {"now": utcnow(), "user_id": user_id, "keep": keep_session_id or "-"})


# ---------------------------------------------------------------- runs (aegis_runs)

def record_run(run_id: str, session_id: str | None, source_file_name: str | None, status: str) -> None:
    now = utcnow()
    get_store().execute("INSERT INTO aegis_runs (run_id, initiated_by_session_id, source_file_name, status, "
                        "started_at, updated_at) VALUES (:run_id, :session_id, :source_file, :status, :now, :now)",
                        {"run_id": run_id[:36], "session_id": session_id, "source_file": (source_file_name or "")[:255] or None,
                         "status": status, "now": now})


def update_run(run_id: str, status: str, completed: bool = False) -> None:
    now = utcnow()
    get_store().execute("UPDATE aegis_runs SET status = :status, updated_at = :now, "
                        "completed_at = :done WHERE run_id = :run_id",
                        {"status": status, "now": now, "done": now if completed else None,
                         "run_id": run_id[:36]})


def fail_interrupted_runs() -> int:
    """Runs a previous server process left queued / running can no longer finish: mark them
    failed in aegis_runs too (app_state.mark_interrupted does the same for the run state)."""
    now = utcnow()
    return get_store().execute("UPDATE aegis_runs SET status = 'failed', updated_at = :now, completed_at = :now "
                               "WHERE status IN ('queued', 'running')", {"now": now})


def list_runs(limit: int = 100) -> list[dict]:
    rows = get_store().query(
        "SELECT r.run_id, r.source_file_name, r.status, r.started_at, r.completed_at, "
        "u.email AS initiated_by FROM aegis_runs r LEFT JOIN aegis_user_sessions s "
        "ON s.session_id = r.initiated_by_session_id LEFT JOIN aegis_users u ON u.user_id = s.user_id "
        "ORDER BY r.started_at DESC")[:limit]
    for row in rows:
        for key in ("started_at", "completed_at"):
            row[key] = row[key].isoformat() if row.get(key) else None
    return rows

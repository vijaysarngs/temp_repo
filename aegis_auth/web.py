"""Authentication for the FastAPI app: sign-in endpoints, admin endpoints, and one check in
front of every /api request.

    Public:   GET /api/health, GET /api/auth/status, POST /api/auth/login,
              POST /api/auth/register (self sign-up, AEGIS_SELF_SIGNUP), the UI files
    VIEWER:   every GET; sign-out and own password
    ANALYST:  everything except /api/admin/*
    ADMIN:    everything, including user management

Uploads and runs belong to the user who started them (app.py may_access): a non-admin sees
only their own; an ADMIN sees every user's and everything from before owners were recorded.

Sessions are an HttpOnly, SameSite=Strict cookie; only the token's SHA-256 is stored.
Every state-changing /api request must carry the header X-AEGIS-Request: 1 (a page on
another site cannot send it without CORS, which this API does not allow), so cross-site
requests are refused even if a browser sent the cookie.

AEGIS_AUTH=off disables all of this (tests and single-user local use only; a warning is logged).
"""
from __future__ import annotations

import logging
import os
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse

from . import service
from .service import AuthError

log = logging.getLogger("aegis_auth")
COOKIE = "aegis_session"
CSRF_HEADER = "x-aegis-request"
PUBLIC = {("GET", "/api/health"), ("GET", "/api/auth/status"), ("POST", "/api/auth/login"),
          ("POST", "/api/auth/register")}
SELF_SERVICE = {("POST", "/api/auth/logout"), ("POST", "/api/auth/password"), ("GET", "/api/auth/me")}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
LOCAL_USER = {"user_id": "local", "email": "local", "display_name": "Local (sign-in disabled)",
              "user_role": "ADMIN", "status": "ACTIVE"}
LOGIN_LIMIT, LOGIN_WINDOW = 10, 60.0          # sign-in attempts per client address per minute
_attempts: dict[str, deque] = defaultdict(deque)

router = APIRouter()


def signup_enabled() -> bool:
    """Anyone who can reach the app may create their own account (AEGIS_SELF_SIGNUP, default on).
    A self-registered account is an ANALYST: it starts with no uploads or runs and never sees
    another user's, nor anything from before it existed; only an ADMIN sees those."""
    return os.getenv("AEGIS_SELF_SIGNUP", "on").strip().casefold() not in ("off", "false", "0", "no")


def enabled() -> bool:
    return os.getenv("AEGIS_AUTH", "on").strip().casefold() not in ("off", "false", "0", "no")


def _error(message: str, status: int) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _client_ip(request: Request) -> str:
    # Behind a trusted proxy set AEGIS_TRUST_PROXY=on to use X-Forwarded-For.
    if os.getenv("AEGIS_TRUST_PROXY", "off").casefold() in ("on", "1", "true", "yes"):
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.client.host if request.client else ""


def _secure_cookie(request: Request) -> bool:
    setting = os.getenv("AEGIS_COOKIE_SECURE", "auto").casefold()
    if setting in ("on", "true", "1", "yes"):
        return True
    if setting in ("off", "false", "0", "no"):
        return False
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


def allowed(role: str, method: str, path: str) -> bool:
    if path.startswith("/api/admin/"):
        return role == "ADMIN"
    if method in SAFE_METHODS or (method, path) in SELF_SERVICE:
        return role in service.ROLES
    return role in ("ADMIN", "ANALYST")


async def guard(request: Request, call_next):
    """Middleware: who is calling, and may they do this?"""
    path, method = request.url.path, request.method.upper()
    if not path.startswith("/api/"):
        return await call_next(request)
    if not enabled():
        request.state.user, request.state.session = LOCAL_USER, None
        return await call_next(request)
    if method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
        return _error("Request refused: missing X-AEGIS-Request header.", 403)
    if (method, path) in PUBLIC:
        return await call_next(request)
    resolved = service.resolve_session(request.cookies.get(COOKIE))
    if not resolved:
        return _error("Sign in to continue.", 401)
    session, user = resolved
    request.state.user, request.state.session = user, session
    if (method, path) not in SELF_SERVICE and service.must_change_password(user["user_id"]):
        return _error("Change your password to continue.", 403)
    if not allowed(user["user_role"], method, path):
        return _error("Your role does not allow this action.", 403)
    return await call_next(request)


def install(app) -> None:
    app.middleware("http")(guard)
    app.include_router(router)
    if not enabled():
        log.warning("AEGIS_AUTH=off: the API is open to anyone who can reach it.")
        return
    try:
        created = service.bootstrap_admin()
    except Exception as exc:  # noqa: BLE001 - the database may be unreachable at start-up
        log.warning("Could not check for a first administrator: %s", exc)
        return
    if created:
        message = (f"No users existed, so an administrator was created: {created['email']}. Its temporary "
                   f"password is in {service.initial_password_file()} (change it at the first sign-in).")
        log.warning(message)
        print(message, flush=True)


def current_session_id(request: Request) -> str | None:
    session = getattr(request.state, "session", None)
    return session["session_id"] if session else None


def _me(user: dict, session: dict | None) -> dict:
    return {"user": service.public_user(user) if session else LOCAL_USER, "auth_enabled": enabled(),
            "must_change_password": bool(session) and service.must_change_password(user["user_id"]),
            "session": ({"expires_at": session["expires_at"].isoformat(),
                         "idle_minutes": int(service.session_idle().total_seconds() // 60)} if session else None)}


# ---------------------------------------------------------------- sign-in

@router.get("/api/auth/status")
def auth_status():
    return {"auth_enabled": enabled(), "users_exist": service.users_exist() if enabled() else True,
            "signup_enabled": enabled() and signup_enabled()}


@router.post("/api/auth/login")
def login(request: Request, payload: dict | None = Body(default=None)):
    if not enabled():
        return {"user": LOCAL_USER, "auth_enabled": False}
    address = _client_ip(request)
    recent = _attempts[address]
    now = time.monotonic()
    while recent and now - recent[0] > LOGIN_WINDOW:
        recent.popleft()
    if len(recent) >= LOGIN_LIMIT:
        return _error("Too many sign-in attempts from this address. Wait a minute.", 429)
    recent.append(now)
    payload = payload or {}
    try:
        user = service.authenticate(payload.get("email"), payload.get("password"))
    except AuthError as exc:
        log.info("sign-in failed for %r from %s", str(payload.get("email"))[:80], address)
        return _error(str(exc), exc.status)
    token, session = service.create_session(user, address, request.headers.get("user-agent"))
    log.info("sign-in: %s (%s) from %s", user["email"], user["user_role"], address)
    response = JSONResponse(_me(user, session))
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=_secure_cookie(request),
                        max_age=int(service.session_lifetime().total_seconds()), path="/")
    return response


def _too_many(request: Request):
    address = _client_ip(request)
    recent = _attempts[address]
    now = time.monotonic()
    while recent and now - recent[0] > LOGIN_WINDOW:
        recent.popleft()
    if len(recent) >= LOGIN_LIMIT:
        return _error("Too many attempts from this address. Wait a minute.", 429)
    recent.append(now)
    return None


@router.post("/api/auth/register")
def register(request: Request, payload: dict | None = Body(default=None)):
    """Create your own account (ANALYST) and sign in with it."""
    if not enabled():
        return {"user": LOCAL_USER, "auth_enabled": False}
    if not signup_enabled():
        return _error("Creating an account is turned off here. Ask an administrator for one.", 403)
    limited = _too_many(request)
    if limited:
        return limited
    payload = payload or {}
    try:
        user = service.create_user(payload.get("email"), payload.get("password"), "ANALYST",
                                   payload.get("display_name"), must_change_password=False)
    except AuthError as exc:
        return _error(str(exc), exc.status)
    address = _client_ip(request)
    token, session = service.create_session(user, address, request.headers.get("user-agent"))
    log.info("account created: %s (ANALYST) from %s", user["email"], address)
    response = JSONResponse(_me(user, session), status_code=201)
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=_secure_cookie(request),
                        max_age=int(service.session_lifetime().total_seconds()), path="/")
    return response


@router.post("/api/auth/logout")
def logout(request: Request):
    session = getattr(request.state, "session", None)
    if session:
        service.revoke_session(session["session_id"])
    response = JSONResponse({"signed_out": True})
    response.delete_cookie(COOKIE, path="/")
    return response


@router.get("/api/auth/me")
def me(request: Request):
    return _me(request.state.user, getattr(request.state, "session", None))


@router.post("/api/auth/password")
def change_password(request: Request, payload: dict | None = Body(default=None)):
    session = getattr(request.state, "session", None)
    if not session:
        return _error("Sign-in is disabled; there is no password to change.", 400)
    payload = payload or {}
    try:
        service.change_own_password(session, payload.get("current_password"), payload.get("new_password"))
    except AuthError as exc:
        return _error(str(exc), exc.status)
    return {"changed": True}


# ---------------------------------------------------------------- administration

def _admin_result(callable_, *args, **kwargs):
    try:
        return callable_(*args, **kwargs)
    except AuthError as exc:
        return _error(str(exc), exc.status)


@router.get("/api/admin/users")
def admin_list_users():
    return {"users": service.list_users(), "roles": list(service.ROLES), "statuses": list(service.USER_STATUSES)}


@router.post("/api/admin/users")
def admin_create_user(request: Request, payload: dict | None = Body(default=None)):
    payload = payload or {}
    result = _admin_result(service.create_user, payload.get("email"), payload.get("temporary_password"),
                           payload.get("user_role") or "ANALYST", payload.get("display_name"), True)
    if isinstance(result, JSONResponse):
        return result
    log.info("user created: %s (%s) by %s", result["email"], result["user_role"], request.state.user["email"])
    return JSONResponse({"user": service.public_user(result)}, status_code=201)


@router.patch("/api/admin/users/{user_id}")
def admin_update_user(user_id: str, request: Request, payload: dict | None = Body(default=None)):
    payload = payload or {}
    result = _admin_result(service.update_user, user_id, payload.get("user_role"), payload.get("status"),
                           payload.get("display_name"))
    if isinstance(result, JSONResponse):
        return result
    log.info("user updated: %s -> %s/%s by %s", result["email"], result["user_role"], result["status"],
             request.state.user["email"])
    return {"user": service.public_user(result)}


@router.post("/api/admin/users/{user_id}/password")
def admin_reset_password(user_id: str, request: Request, payload: dict | None = Body(default=None)):
    result = _admin_result(service.set_password, user_id, (payload or {}).get("temporary_password"), True)
    if isinstance(result, JSONResponse):
        return result
    service.revoke_user_sessions(user_id)
    log.info("password reset for %s by %s", user_id, request.state.user["email"])
    return {"reset": True, "must_change_password": True}


@router.post("/api/admin/users/{user_id}/sessions/revoke")
def admin_revoke_sessions(user_id: str, request: Request):
    keep = current_session_id(request) if user_id == request.state.user["user_id"] else None
    return {"revoked": service.revoke_user_sessions(user_id, keep_session_id=keep)}


@router.get("/api/admin/runs")
def admin_runs():
    return {"runs": service.list_runs()}

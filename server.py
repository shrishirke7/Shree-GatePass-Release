"""Shree GatePass — Multi-Tenant SaaS Visitor Pass & Material Gate Management Server."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import zipfile
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
import xml.sax.saxutils as xml_esc
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, make_response, request, send_file, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

from xlsx_exporter import build_xlsx_bytes

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # Allows importing pure helper logic in host unit tests without psycopg
    psycopg = None
    dict_row = None

APP_DIR = Path(__file__).resolve().parent
SCHEMA_FILE = APP_DIR / "schema.sql"
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(APP_DIR / "uploads"))).resolve()
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", str(APP_DIR / "backups"))).resolve()
STATIC_DIR = APP_DIR / "static"
DOWNLOADS_DIR = STATIC_DIR / "downloads"
SECRETS_DIR = APP_DIR / "secrets"

DATABASE_URL = os.getenv("DATABASE_URL", "")
COOKIE_NAME = "gatepass_session"
SUPER_COOKIE_NAME = "gatepass_super_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").strip().lower() in ("1", "true", "yes")
DEFAULT_SITE_NAME = os.getenv("SITE_NAME", "gatepass.local")
SESSION_TTL_SECONDS = 7 * 24 * 3600
DEFAULT_ORG_ID = "org-default"

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024

# ---------------------------------------------------------------------------
# In-process live stream / per-tenant revision state
# ---------------------------------------------------------------------------
_SSE_LOCK = threading.Lock()
# subscriber_id -> (queue, org_id, username, dept, factory)
_SSE_SUBSCRIBERS: dict[str, tuple[queue.Queue, str, str, str, str]] = {}
_REVISIONS_LOCK = threading.Lock()
_ORG_REVISIONS: dict[str, dict[str, int]] = defaultdict(
    lambda: {"dataRev": 1, "visitorRev": 1, "gatepassRev": 1, "notifRev": 1}
)
_USER_NOTIF_REV: dict[tuple[str, str], int] = defaultdict(int)
_LOGIN_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
_DB_READY = False
_DB_INIT_LOCK = threading.Lock()


def _bump_rev(org_id: str, *keys: str, usernames: list[str] | None = None) -> None:
    with _REVISIONS_LOCK:
        revs = _ORG_REVISIONS[org_id]
        for k in keys:
            revs[k] = int(revs.get(k, 1)) + 1
        if usernames:
            for u in usernames:
                nu = str(u or "").strip().casefold()
                if nu:
                    _USER_NOTIF_REV[(org_id, nu)] = int(_USER_NOTIF_REV.get((org_id, nu), 0)) + 1


# ---------------------------------------------------------------------------
# Secrets & Auth Helpers
# ---------------------------------------------------------------------------
_SECRET_CACHE: bytes | None = None


def _get_app_secret() -> bytes:
    global _SECRET_CACHE
    if _SECRET_CACHE:
        return _SECRET_CACHE
    env_sec = os.getenv("APP_SECRET", "").strip()
    if env_sec:
        _SECRET_CACHE = env_sec.encode("utf-8")
        return _SECRET_CACHE
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    key_file = UPLOAD_DIR / ".gatepass_secret"
    if key_file.exists():
        raw = key_file.read_text(encoding="utf-8").strip()
        if raw:
            _SECRET_CACHE = raw.encode("utf-8")
            return _SECRET_CACHE
    generated = secrets.token_hex(48)
    key_file.write_text(generated, encoding="utf-8")
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    _SECRET_CACHE = generated.encode("utf-8")
    return _SECRET_CACHE


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def sign_session_token(
    username: str,
    auth_version: int,
    org_id: str = DEFAULT_ORG_ID,
    scope: str = "org",
) -> str:
    payload = json.dumps(
        {
            "u": username,
            "v": int(auth_version),
            "o": org_id,
            "s": scope,
            "exp": int(time.time()) + SESSION_TTL_SECONDS,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    b64 = _b64u_encode(payload)
    sig = hmac.new(_get_app_secret(), b64.encode("ascii"), hashlib.sha256).digest()
    return f"{b64}.{_b64u_encode(sig)}"


def verify_session_token(token: str, expected_scope: str | None = "org") -> dict | None:
    if not token or "." not in token:
        return None
    try:
        b64, sig_b64 = token.split(".", 1)
        expected = hmac.new(_get_app_secret(), b64.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64u_decode(sig_b64)):
            return None
        data = json.loads(_b64u_decode(b64).decode("utf-8"))
        if int(data.get("exp", 0)) < int(time.time()):
            return None
        if expected_scope and data.get("s", "org") != expected_scope:
            return None
        return data
    except Exception:
        return None


def _hash_answer(answer: str) -> str:
    norm = re.sub(r"\s+", " ", str(answer or "").strip().casefold())
    return generate_password_hash(norm)


def _check_answer(answer: str, stored_hash: str) -> bool:
    norm = re.sub(r"\s+", " ", str(answer or "").strip().casefold())
    return bool(stored_hash and check_password_hash(stored_hash, norm))


# ---------------------------------------------------------------------------
# Tenant / Slug Validation & Defaults
# ---------------------------------------------------------------------------
def normalize_slug(raw: str, fallback: str = "company") -> str:
    cleaned = re.sub(r"[^a-z0-9-]+", "-", str(raw or "").strip().lower()).strip("-")
    cleaned = re.sub(r"-{2,}", "-", cleaned)[:40]
    if len(cleaned) < 2:
        cleaned = re.sub(r"[^a-z0-9-]+", "-", fallback.lower()).strip("-") or "shree"
    return cleaned


def is_org_active(org: dict | None, now: datetime | None = None) -> tuple[bool, str]:
    """Return (allowed, reason) for an organization record."""
    if not org:
        return False, "Organization not found"
    if str(org.get("status") or "active").lower() != "active":
        return False, "Organization access is suspended — contact your service provider"
    exp = org.get("expires_at")
    if isinstance(exp, str) and exp.strip():
        try:
            exp = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        except ValueError:
            exp = None
    if isinstance(exp, datetime):
        ref = now or datetime.now(timezone.utc)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < ref:
            return False, "Organization subscription has expired — contact your service provider"
    return True, ""


DEFAULT_PERMS_BY_ROLE: dict[str, dict[str, str]] = {
    "Administrator": {
        "dashboard": "rw",
        "visitors": "rw",
        "gatepasses": "rw",
        "notifications": "rw",
        "users": "rw",
        "departments": "rw",
        "factories": "rw",
        "backups": "rw",
        "settings": "rw",
    },
    "Security Gate": {
        "dashboard": "rw",
        "visitors": "rw",
        "gatepasses": "rw",
        "notifications": "rw",
        "users": "none",
        "departments": "none",
        "factories": "none",
        "backups": "none",
        "settings": "none",
    },
    "Department Head": {
        "dashboard": "rw",
        "visitors": "rw",
        "gatepasses": "rw",
        "notifications": "rw",
        "users": "ro",
        "departments": "ro",
        "factories": "ro",
        "backups": "none",
        "settings": "none",
    },
    "Staff": {
        "dashboard": "rw",
        "visitors": "rw",
        "gatepasses": "rw",
        "notifications": "rw",
        "users": "none",
        "departments": "none",
        "factories": "none",
        "backups": "none",
        "settings": "none",
    },
}

DEFAULT_SETTINGS = {
    "company": "Shree GatePass",
    "site_name": DEFAULT_SITE_NAME,
    "portal_title": "Security Gate · Visitor & Material Entry",
    "font_family": "Plus Jakarta Sans",
    "font_size": "14px",
    "auto_checkout_hours": 0,
    "default_returnable_days": 7,
}

DEFAULT_SOUND_CONFIG = {
    "enabled": True,
    "desktop_notifications": True,
    "volume": 0.9,
    "visitor_entry": {"enabled": True, "silent": False, "sound": "chime"},
    "visitor_status": {"enabled": True, "silent": False, "sound": "gentle"},
    "material_entry": {"enabled": True, "silent": False, "sound": "double-ding"},
    "material_overdue": {"enabled": True, "silent": False, "sound": "urgent"},
    "quiet_hours": {"enabled": False, "start": "22:00", "end": "07:00"},
    "custom_ringtones": [],
}

DEFAULT_FACTORIES = [
    {"code": "UNIT-1", "name": "Unit 1 · Main Plant", "desc": "Primary manufacturing & main security gate"},
    {"code": "UNIT-2", "name": "Unit 2 · Warehouse", "desc": "Dispatch & logistics gate"},
]

DEFAULT_DEPARTMENTS = [
    "Administration",
    "Security Gate",
    "Stores & Dispatch",
    "Purchase",
    "Production",
    "Quality",
    "Accounts",
    "HR",
    "IT",
    "Maintenance",
]


def get_conn():
    if psycopg is None:
        raise RuntimeError("psycopg package is not installed")
    return psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row, connect_timeout=8)


def _get_app_state(conn, key: str, default=None):
    with conn.cursor() as cur:
        cur.execute("SELECT value FROM app_state WHERE key=%s", (key,))
        row = cur.fetchone()
        return row["value"] if row else default


def _set_app_state(conn, key: str, value) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO app_state (key, value, updated_at)
            VALUES (%s, %s::jsonb, NOW())
            ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()
            """,
            (key, json.dumps(value)),
        )


def _get_org_state(conn, org_id: str, key: str, default=None):
    with conn.cursor() as cur:
        cur.execute("SELECT value FROM org_state WHERE org_id=%s AND key=%s", (org_id, key))
        row = cur.fetchone()
        return row["value"] if row else default


def _set_org_state(conn, org_id: str, key: str, value) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO org_state (org_id, key, value, updated_at)
            VALUES (%s, %s, %s::jsonb, NOW())
            ON CONFLICT (org_id, key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()
            """,
            (org_id, key, json.dumps(value)),
        )


def _seed_org_defaults(conn, org_id: str, company_name: str, portal_title: str = "Security Gate · Visitor & Material Entry") -> None:
    defaults = {
        "manual_users": [],
        "factories": DEFAULT_FACTORIES,
        "factoryOrder": [f["code"] for f in DEFAULT_FACTORIES],
        "factoryDescs": {f["code"]: f["desc"] for f in DEFAULT_FACTORIES},
        "departments": DEFAULT_DEPARTMENTS,
        "settings": {**DEFAULT_SETTINGS, "company": company_name, "portal_title": portal_title},
        "sound_config": DEFAULT_SOUND_CONFIG,
    }
    with conn.cursor() as cur:
        for key, val in defaults.items():
            cur.execute(
                "INSERT INTO org_state (org_id, key, value) VALUES (%s, %s, %s::jsonb) ON CONFLICT (org_id, key) DO NOTHING",
                (org_id, key, json.dumps(val)),
            )


def _migrate_single_tenant_if_needed(conn) -> None:
    """Safely upgrade existing single-tenant installations into Multi-Tenant default org."""
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS cnt FROM organizations")
        org_cnt = int((cur.fetchone() or {}).get("cnt", 0))
        if org_cnt > 0:
            return
        legacy_users = _get_app_state(conn, "manual_users", []) or []
        if not legacy_users:
            return
        legacy_settings = _get_app_state(conn, "settings", dict(DEFAULT_SETTINGS)) or dict(DEFAULT_SETTINGS)
        comp_name = str(legacy_settings.get("company") or "Shree GatePass").strip() or "Shree GatePass"
        slug = normalize_slug(comp_name, "shree")
        cur.execute(
            """
            INSERT INTO organizations (id, slug, name, portal_title, status, max_users, plan_name)
            VALUES (%s, %s, %s, %s, 'active', 250, 'Enterprise')
            ON CONFLICT (id) DO NOTHING
            """,
            (DEFAULT_ORG_ID, slug, comp_name, legacy_settings.get("portal_title", DEFAULT_SETTINGS["portal_title"])),
        )
        for k in ("manual_users", "factories", "factoryOrder", "factoryDescs", "departments", "settings", "sound_config"):
            val = _get_app_state(conn, k)
            if val is not None:
                _set_org_state(conn, DEFAULT_ORG_ID, k, val)
        _seed_org_defaults(conn, DEFAULT_ORG_ID, comp_name)

        # Promote existing enabled administrators to initial super_admins if none exist
        supers = _get_app_state(conn, "super_admins", []) or []
        if not supers:
            admins = [
                {
                    "username": u["username"],
                    "full_name": u.get("full_name") or u["username"],
                    "password_hash": u["password_hash"],
                    "recovery_hashes": u.get("recovery_hashes") or [],
                    "auth_version": int(u.get("auth_version", 1) or 1),
                    "enabled": True,
                    "created_at": u.get("created_at") or datetime.now(timezone.utc).isoformat(),
                }
                for u in legacy_users
                if u.get("role") == "Administrator" and u.get("enabled", True)
            ]
            if admins:
                _set_app_state(conn, "super_admins", admins)

        # Move legacy flat gate_media uploads into org-default/gate_media if present
        old_media = UPLOAD_DIR / "gate_media"
        new_media = UPLOAD_DIR / DEFAULT_ORG_ID / "gate_media"
        if old_media.exists() and not new_media.exists():
            new_media.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(old_media, new_media, dirs_exist_ok=True)


def ensure_db_ready() -> None:
    global _DB_READY
    if _DB_READY or not DATABASE_URL or psycopg is None:
        return
    with _DB_INIT_LOCK:
        if _DB_READY:
            return
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        (UPLOAD_DIR / "org_logos").mkdir(parents=True, exist_ok=True)
        (UPLOAD_DIR / "ringtones").mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        schema_sql = SCHEMA_FILE.read_text(encoding="utf-8")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(schema_sql)
            _migrate_single_tenant_if_needed(conn)
        _DB_READY = True


def _audit(conn, org_id: str, actor: str, action: str, detail: str, meta: dict | None = None) -> None:
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_logs (org_id, actor, action, detail, meta) VALUES (%s, %s, %s, %s, %s::jsonb)",
                (org_id or DEFAULT_ORG_ID, actor or "system", action, detail, json.dumps(meta or {})),
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Organization Resolution & Serialization
# ---------------------------------------------------------------------------
def _serialize_org(row: dict) -> dict:
    ok, reason = is_org_active(row)
    return {
        "id": row["id"],
        "slug": row["slug"],
        "name": row["name"],
        "logoUrl": row.get("logo_url", ""),
        "portalTitle": row.get("portal_title", DEFAULT_SETTINGS["portal_title"]),
        "status": row.get("status", "active"),
        "active": ok,
        "inactiveReason": reason,
        "maxUsers": int(row.get("max_users") or 100),
        "planName": row.get("plan_name", "Standard"),
        "expiresAt": _iso(row.get("expires_at")),
        "contactName": row.get("contact_name", ""),
        "contactPhone": row.get("contact_phone", ""),
        "contactEmail": row.get("contact_email", ""),
        "notes": row.get("notes", ""),
        "createdAt": _iso(row.get("created_at")),
        "updatedAt": _iso(row.get("updated_at")),
    }


def _find_org_by_slug_or_id(conn, identifier: str) -> dict | None:
    key = str(identifier or "").strip().lower()
    if not key:
        return None
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM organizations WHERE LOWER(slug)=%s OR id=%s LIMIT 1", (key, identifier.strip()))
        return cur.fetchone()


def _resolve_public_org(conn, explicit_slug: str = "") -> tuple[dict | None, tuple[str, int, bool] | None]:
    """Resolve organization strictly from explicit slug/query/referer, or auto-pick ONLY if single active org."""
    slug = str(explicit_slug or "").strip()
    if not slug:
        slug = str(request.args.get("org") or "").strip()
    if not slug:
        ref = str(request.headers.get("Referer") or "")
        m = re.search(r"/c/([A-Za-z0-9-]+)(?:/portal)?", ref)
        if m:
            slug = m.group(1)

    if slug:
        org = _find_org_by_slug_or_id(conn, slug)
        if not org:
            return None, (f"Unknown organization code '{slug}'", 404, True)
        ok, reason = is_org_active(org)
        if not ok:
            return None, (reason, 403, False)
        return org, None

    with conn.cursor() as cur:
        cur.execute("SELECT * FROM organizations ORDER BY created_at ASC")
        all_orgs = cur.fetchall() or []
    active_orgs = [o for o in all_orgs if is_org_active(o)[0]]
    if len(active_orgs) == 1:
        return active_orgs[0], None
    if len(all_orgs) == 0:
        return None, ("Platform is not configured yet. Complete initial /setup first.", 503, True)
    return None, ("Please enter your Company Code (e.g. /c/company-code/portal)", 400, True)


# ---------------------------------------------------------------------------
# User / Permissions Normalization & Auth Decorators
# ---------------------------------------------------------------------------
def normalize_perms(role: str, raw_perms: dict | None) -> dict[str, str]:
    base = dict(DEFAULT_PERMS_BY_ROLE.get(role, DEFAULT_PERMS_BY_ROLE["Staff"]))
    if isinstance(raw_perms, dict):
        for mod, val in raw_perms.items():
            if mod in base and val in ("rw", "ro", "none"):
                base[mod] = val
    if role == "Administrator":
        for k in base:
            base[k] = "rw"
    return base


def _public_user_dict(user: dict, org_row: dict | None = None) -> dict:
    role = user.get("role") or "Staff"
    return {
        "username": user.get("username", ""),
        "full_name": user.get("full_name") or user.get("name") or user.get("username", ""),
        "role": role,
        "dept": user.get("dept") or user.get("department") or "",
        "department": user.get("dept") or user.get("department") or "",
        "factory": user.get("factory") or "",
        "phone": user.get("phone") or "",
        "email": user.get("email") or "",
        "gate_scope": user.get("gate_scope") or ("security" if role == "Security Gate" else "user"),
        "enabled": bool(user.get("enabled", True)),
        "perms": normalize_perms(role, user.get("perms")),
        "org_id": org_row["id"] if org_row else str(user.get("org_id") or DEFAULT_ORG_ID),
        "org_slug": org_row["slug"] if org_row else str(user.get("org_slug") or ""),
        "org_name": org_row["name"] if org_row else str(user.get("org_name") or ""),
        "created_at": user.get("created_at") or "",
    }


def _extract_bearer_or_cookie(cookie_name: str) -> str:
    token = request.cookies.get(cookie_name) or ""
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
    return token


def _get_current_user(conn) -> tuple[dict | None, dict | None]:
    data = verify_session_token(_extract_bearer_or_cookie(COOKIE_NAME), expected_scope="org")
    if not data:
        return None, None
    org_id = str(data.get("o") or "").strip()
    if not org_id:
        return None, None
    org = _find_org_by_slug_or_id(conn, org_id)
    if not org or not is_org_active(org)[0]:
        return None, None
    users = _get_org_state(conn, org_id, "manual_users", []) or []
    uname = str(data.get("u", "")).casefold()
    for u in users:
        if (
            str(u.get("username", "")).casefold() == uname
            and u.get("enabled", True)
            and int(u.get("auth_version", 1) or 1) == int(data.get("v", -1))
        ):
            return _public_user_dict(u, org), org
    return None, None


def _get_current_super_admin(conn) -> dict | None:
    data = verify_session_token(_extract_bearer_or_cookie(SUPER_COOKIE_NAME), expected_scope="super")
    if not data:
        return None
    supers = _get_app_state(conn, "super_admins", []) or []
    uname = str(data.get("u", "")).casefold()
    for s in supers:
        if (
            str(s.get("username", "")).casefold() == uname
            and s.get("enabled", True)
            and int(s.get("auth_version", 1) or 1) == int(data.get("v", -1))
        ):
            return {
                "username": s["username"],
                "full_name": s.get("full_name") or s["username"],
                "role": "Super Admin",
                "scope": "super",
            }
    return None


def _require_csrf_ok() -> bool:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    if request.path.startswith("/api/public/") or request.path in (
        "/api/login",
        "/api/setup",
        "/api/recovery/reset",
        "/api/super/login",
        "/api/super/recovery/reset",
    ):
        return True
    return bool(request.headers.get("X-Requested-With"))


def auth_required(mod: str | None = None, level: str = "ro"):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not _require_csrf_ok():
                return jsonify({"error": "Missing CSRF header"}), 403
            ensure_db_ready()
            with get_conn() as conn:
                user, org = _get_current_user(conn)
                if not user or not org:
                    return jsonify({"error": "Authentication required"}), 401
                if mod and user["role"] != "Administrator":
                    perm = user["perms"].get(mod, "none")
                    if perm == "none" or (level == "rw" and perm != "rw"):
                        return jsonify({"error": f"Insufficient permissions for {mod}"}), 403
                return fn(conn, org, user, *args, **kwargs)

        return wrapper

    return deco


def super_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _require_csrf_ok():
            return jsonify({"error": "Missing CSRF header"}), 403
        ensure_db_ready()
        with get_conn() as conn:
            sa = _get_current_super_admin(conn)
            if not sa:
                return jsonify({"error": "Super Admin authentication required"}), 401
            return fn(conn, sa, *args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# STRICT TENANT-SCOPED & USER/DEPT TARGETED NOTIFICATION ROUTING
# ---------------------------------------------------------------------------
def resolve_notification_targets(
    users: list[dict],
    target_username: str = "",
    target_department: str = "",
    factory: str = "",
    include_security: bool = False,
    fallback_admin_if_no_security: bool = False,
) -> tuple[list[str], str, bool]:
    """Compute exact recipient usernames + department broadcast flag within an org."""
    clean_user = str(target_username or "").strip().casefold()
    clean_dept = str(target_department or "").strip()
    clean_factory = str(factory or "").strip().casefold()

    enabled_users = [u for u in (users or []) if u.get("enabled", True)]
    recipients: set[str] = set()
    dept_broadcast = False

    def _matches_factory(u: dict) -> bool:
        uf = str(u.get("factory") or "").strip().casefold()
        return (not clean_factory) or (not uf) or (uf == clean_factory)

    if clean_user:
        recipients.add(clean_user)
    elif clean_dept:
        dept_broadcast = True
        dept_cf = clean_dept.casefold()
        for u in enabled_users:
            udept = str(u.get("dept") or u.get("department") or "").strip().casefold()
            if udept == dept_cf and _matches_factory(u):
                uname = str(u.get("username") or "").strip().casefold()
                if uname:
                    recipients.add(uname)
    else:
        include_security = True
        fallback_admin_if_no_security = True

    if include_security:
        sec_found = False
        for u in enabled_users:
            role = str(u.get("role") or "")
            scope = str(u.get("gate_scope") or "")
            if (role == "Security Gate" or scope == "security") and _matches_factory(u):
                uname = str(u.get("username") or "").strip().casefold()
                if uname:
                    recipients.add(uname)
                    sec_found = True
        if not sec_found and fallback_admin_if_no_security:
            for u in enabled_users:
                if u.get("role") == "Administrator":
                    uname = str(u.get("username") or "").strip().casefold()
                    if uname:
                        recipients.add(uname)

    return sorted(recipients), (clean_dept if dept_broadcast else ""), dept_broadcast


def event_visible_to_user(ev: dict, user: dict | None) -> bool:
    """Strictly determine whether a notification event belongs to `user` inside the SAME org."""
    if not user:
        return False
    ev_org = str(ev.get("org_id") or "").strip()
    u_org = str(user.get("org_id") or "").strip()
    if ev_org and u_org and ev_org != u_org:
        return False

    uname = str(user.get("username") or "").strip().casefold()
    udept = str(user.get("dept") or user.get("department") or "").strip().casefold()
    ufac = str(user.get("factory") or "").strip().casefold()
    ev_fac = str(ev.get("factory") or "").strip().casefold()
    if ufac and ev_fac and ufac != ev_fac:
        return False

    targets = [str(t or "").strip().casefold() for t in (ev.get("target_usernames") or []) if str(t or "").strip()]
    ev_dept = str(ev.get("target_department") or "").strip().casefold()
    meta = ev.get("meta") if isinstance(ev.get("meta"), dict) else {}
    dept_broadcast = bool(meta.get("dept_broadcast"))

    if targets and uname in targets:
        return True
    if dept_broadcast and ev_dept and udept and ev_dept == udept:
        return True
    if not targets and ev_dept and udept and ev_dept == udept:
        return True
    return False


def _push_sse_event(ev: dict) -> None:
    payload = f"event: alert\ndata: {json.dumps(ev)}\n\n"
    dead = []
    with _SSE_LOCK:
        items = list(_SSE_SUBSCRIBERS.items())
    for sid, (q_obj, sub_org, sub_user, sub_dept, sub_fac) in items:
        if sub_org != ev.get("org_id"):
            continue
        pseudo_user = {"org_id": sub_org, "username": sub_user, "dept": sub_dept, "factory": sub_fac}
        if event_visible_to_user(ev, pseudo_user):
            try:
                q_obj.put_nowait(payload)
            except Exception:
                dead.append(sid)
    if dead:
        with _SSE_LOCK:
            for sid in dead:
                _SSE_SUBSCRIBERS.pop(sid, None)


def emit_notification(
    conn,
    *,
    org_id: str,
    kind: str,
    level: str,
    title: str,
    body: str,
    factory: str = "",
    target_department: str = "",
    target_usernames: list[str] | None = None,
    dept_broadcast: bool = False,
    target_view: str = "visitors",
    target_id: str = "",
    meta: dict | None = None,
) -> dict:
    ev_id = f"notif-{uuid.uuid4().hex[:12]}"
    ev_meta = dict(meta or {})
    ev_meta["dept_broadcast"] = bool(dept_broadcast)
    targets = sorted({str(u).strip().casefold() for u in (target_usernames or []) if str(u).strip()})
    ev = {
        "id": ev_id,
        "org_id": org_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "level": level,
        "title": title,
        "body": body,
        "factory": factory,
        "target_department": target_department,
        "target_usernames": targets,
        "target_view": target_view,
        "target_id": target_id,
        "meta": ev_meta,
        "read_by": [],
    }
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO notification_events
                (id, org_id, ts, kind, level, title, body, factory, target_department, target_usernames, target_view, target_id, meta, read_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, '[]'::jsonb)
            """,
            (
                ev["id"],
                org_id,
                ev["ts"],
                kind,
                level,
                title,
                body,
                factory,
                target_department,
                json.dumps(targets),
                target_view,
                target_id,
                json.dumps(ev_meta),
            ),
        )
    _bump_rev(org_id, "notifRev", usernames=targets)
    _push_sse_event(ev)
    return ev


# ---------------------------------------------------------------------------
# Serialization Helpers
# ---------------------------------------------------------------------------
def _iso(val) -> str:
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val or "")


def _serialize_visitor(row: dict) -> dict:
    id_photos = row.get("id_card_photos") or []
    if row.get("id_card_photo") and row["id_card_photo"] not in id_photos:
        id_photos = [row["id_card_photo"], *id_photos]
    selfies = row.get("selfie_photos") or []
    if row.get("selfie_photo") and row["selfie_photo"] not in selfies:
        selfies = [row["selfie_photo"], *selfies]
    return {
        "id": row["id"],
        "orgId": row.get("org_id", DEFAULT_ORG_ID),
        "visitorName": row["visitor_name"],
        "company": row.get("company", ""),
        "phone": row.get("phone", ""),
        "address": row.get("address", ""),
        "purpose": row.get("purpose", ""),
        "vehicleNo": row.get("vehicle_no", ""),
        "factory": row.get("factory", ""),
        "department": row.get("department", ""),
        "hostUsername": row.get("host_username", ""),
        "hostName": row.get("host_name", ""),
        "idCardPhoto": row.get("id_card_photo", ""),
        "idCardPhotos": id_photos,
        "selfiePhoto": row.get("selfie_photo", ""),
        "selfiePhotos": selfies,
        "status": row.get("status", "Pending"),
        "entryTime": _iso(row.get("entry_time")),
        "approvedBy": row.get("approved_by", ""),
        "approvedAt": _iso(row.get("approved_at")),
        "checkedInBy": row.get("checked_in_by", ""),
        "checkedInAt": _iso(row.get("checked_in_at")),
        "checkedOutBy": row.get("checked_out_by", ""),
        "checkedOutAt": _iso(row.get("checked_out_at")),
        "rejectedReason": row.get("rejected_reason", ""),
        "notes": row.get("notes", ""),
        "createdBy": row.get("created_by", ""),
        "createdAt": _iso(row.get("created_at")),
        "updatedAt": _iso(row.get("updated_at")),
    }


def _serialize_gatepass(row: dict) -> dict:
    mat_photos = row.get("material_photos") or []
    if row.get("material_photo") and row["material_photo"] not in mat_photos:
        mat_photos = [row["material_photo"], *mat_photos]
    bill_photos = row.get("bill_photos") or []
    if row.get("bill_photo") and row["bill_photo"] not in bill_photos:
        bill_photos = [row["bill_photo"], *bill_photos]
    exp_ret = row.get("expected_return_at")
    ret_at = row.get("returned_at")
    is_ret = bool(row.get("is_returnable", False))
    overdue = bool(is_ret and not ret_at and isinstance(exp_ret, datetime) and exp_ret <= datetime.now(timezone.utc))
    return {
        "id": row["id"],
        "orgId": row.get("org_id", DEFAULT_ORG_ID),
        "direction": row.get("direction", "IN"),
        "materialType": row.get("material_type", ""),
        "materialName": row.get("material_name", ""),
        "quantity": row.get("quantity", "1"),
        "unit": row.get("unit", "Nos"),
        "vehicleNo": row.get("vehicle_no", ""),
        "driverName": row.get("driver_name", ""),
        "driverPhone": row.get("driver_phone", ""),
        "partyName": row.get("party_name", ""),
        "challanNo": row.get("challan_no", ""),
        "factory": row.get("factory", ""),
        "department": row.get("department", ""),
        "forUsername": row.get("for_username", ""),
        "forName": row.get("for_name", ""),
        "isReturnable": is_ret,
        "expectedDays": int(row.get("expected_days") or 0),
        "expectedReturnAt": _iso(exp_ret),
        "returnedAt": _iso(ret_at),
        "returnNote": row.get("return_note", ""),
        "overdue": overdue,
        "materialPhoto": row.get("material_photo", ""),
        "materialPhotos": mat_photos,
        "billPhoto": row.get("bill_photo", ""),
        "billPhotos": bill_photos,
        "status": "Overdue" if overdue else row.get("status", "Recorded"),
        "entryTime": _iso(row.get("entry_time")),
        "verifiedBy": row.get("verified_by", ""),
        "verifiedAt": _iso(row.get("verified_at")),
        "notes": row.get("notes", ""),
        "createdBy": row.get("created_by", ""),
        "createdAt": _iso(row.get("created_at")),
        "updatedAt": _iso(row.get("updated_at")),
    }


def _next_human_id(conn, org_id: str, prefix: str, table: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%y%m%d")
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS cnt FROM {table} WHERE org_id=%s AND id LIKE %s", (org_id, f"{prefix}-{stamp}-%"))
        cnt = int((cur.fetchone() or {}).get("cnt", 0)) + 1
    return f"{prefix}-{stamp}-{cnt:03d}-{secrets.token_hex(3).upper()}"


# ---------------------------------------------------------------------------
# Background Overdue Returnable Reminder Worker (Multi-Tenant Isolated)
# ---------------------------------------------------------------------------
def process_returnable_gatepass_reminders(conn) -> int:
    """Emit overdue alerts per active organization strictly within that org's users."""
    sent = 0
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM material_gate_passes
            WHERE is_returnable = TRUE
              AND returned_at IS NULL
              AND expected_return_at IS NOT NULL
              AND expected_return_at <= NOW()
              AND (last_reminder_at IS NULL OR last_reminder_at <= NOW() - INTERVAL '24 hours')
            ORDER BY expected_return_at ASC
            LIMIT 40
            """
        )
        rows = cur.fetchall() or []
        org_cache: dict[str, tuple[dict | None, list[dict]]] = {}
        for row in rows:
            oid = row.get("org_id") or DEFAULT_ORG_ID
            if oid not in org_cache:
                org_row = _find_org_by_slug_or_id(conn, oid)
                users_list = _get_org_state(conn, oid, "manual_users", []) or []
                org_cache[oid] = (org_row, users_list)
            org_row, users = org_cache[oid]
            if not is_org_active(org_row)[0]:
                continue
            gp_id = row["id"]
            direction_label = "Outward Returnable (Expecting Return IN)" if row["direction"] == "OUT" else "Inward Returnable (Send Back OUT)"
            targets, tgt_dept, dept_bcast = resolve_notification_targets(
                users,
                target_username=row.get("for_username", ""),
                target_department=row.get("department", ""),
                factory=row.get("factory", ""),
                include_security=True,
                fallback_admin_if_no_security=True,
            )
            emit_notification(
                conn,
                org_id=oid,
                kind="material_overdue",
                level="warning",
                title=f"Returnable Material Overdue: {row['material_name']} ({gp_id})",
                body=f"{direction_label} · Qty {row['quantity']} {row['unit']} for {row.get('for_name') or row.get('department') or 'Plant'} is overdue for return.",
                factory=row.get("factory", ""),
                target_department=tgt_dept,
                target_usernames=targets,
                dept_broadcast=dept_bcast,
                target_view="gatepasses",
                target_id=gp_id,
                meta={"direction": row["direction"], "gp_id": gp_id},
            )
            cur.execute("UPDATE material_gate_passes SET last_reminder_at=NOW(), updated_at=NOW() WHERE id=%s AND org_id=%s", (gp_id, oid))
            _bump_rev(oid, "gatepassRev")
            sent += 1
    return sent


def _reminder_loop() -> None:
    while True:
        time.sleep(60)
        try:
            ensure_db_ready()
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_try_advisory_lock(885801) AS locked")
                    row = cur.fetchone()
                    if row and row.get("locked"):
                        try:
                            process_returnable_gatepass_reminders(conn)
                        finally:
                            cur.execute("SELECT pg_advisory_unlock(885801)")
        except Exception:
            pass


_WORKER_STARTED = False


def _start_worker_once() -> None:
    global _WORKER_STARTED
    if _WORKER_STARTED or not DATABASE_URL or psycopg is None:
        return
    _WORKER_STARTED = True
    threading.Thread(target=_reminder_loop, daemon=True, name="gatepass-reminder-worker").start()


# ---------------------------------------------------------------------------
# Static Pages & Tenant-Aware Entry Routes
# ---------------------------------------------------------------------------
@app.get("/")
@app.get("/superadmin")
@app.get("/c/<org_slug>")
@app.get("/c/<org_slug>/")
def serve_index(org_slug: str = ""):
    ensure_db_ready()
    _start_worker_once()
    with get_conn() as conn:
        supers = _get_app_state(conn, "super_admins", []) or []
        if not supers:
            return send_file(APP_DIR / "setup.html")
    return send_file(APP_DIR / "index.html")


@app.get("/setup")
def serve_setup():
    ensure_db_ready()
    return send_file(APP_DIR / "setup.html")


@app.get("/portal")
@app.get("/kiosk")
@app.get("/c/<org_slug>/portal")
@app.get("/c/<org_slug>/kiosk")
def serve_portal(org_slug: str = ""):
    ensure_db_ready()
    _start_worker_once()
    return send_file(APP_DIR / "portal.html")


@app.get("/manifest.json")
def serve_manifest():
    return send_file(APP_DIR / "manifest.json", mimetype="application/manifest+json")


@app.get("/sw.js")
def serve_sw():
    resp = make_response(send_file(APP_DIR / "sw.js", mimetype="application/javascript"))
    resp.headers["Cache-Control"] = "no-store, must-revalidate"
    return resp


@app.get("/apple-touch-icon.png")
def serve_apple_icon():
    return send_file(APP_DIR / "apple-touch-icon.png")


@app.get("/favicon.ico")
def serve_favicon():
    return send_file(APP_DIR / "favicon.ico")


@app.get("/api/health")
def api_health():
    ensure_db_ready()
    return jsonify({"status": "ok", "app": "Shree GatePass Multi-Tenant SaaS"})


# ---------------------------------------------------------------------------
# Initial Setup & Authentication (Platform Super Admin + Org Users)
# ---------------------------------------------------------------------------
@app.get("/api/setup/status")
def api_setup_status():
    ensure_db_ready()
    org_hint = str(request.args.get("org") or "").strip()
    with get_conn() as conn:
        supers = _get_app_state(conn, "super_admins", []) or []
        cur = conn.cursor()
        cur.execute("SELECT id, slug, name, logo_url, portal_title, status, expires_at FROM organizations ORDER BY created_at ASC")
        orgs = cur.fetchall() or []

    matched_org = None
    if org_hint:
        matched_org = next((o for o in orgs if o["slug"].lower() == org_hint.lower() or o["id"] == org_hint), None)
    elif len(orgs) == 1:
        matched_org = orgs[0]

    return jsonify(
        {
            "configured": bool(supers),
            "multiTenant": True,
            "orgCount": len(orgs),
            "company": matched_org["name"] if matched_org else "Shree GatePass",
            "org": _serialize_org(matched_org) if matched_org else None,
        }
    )


@app.post("/api/setup")
def api_setup():
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    company = str(data.get("company") or "Shree GatePass").strip() or "Shree GatePass"
    org_slug = normalize_slug(data.get("org_slug") or company, "shree")
    site_name = str(data.get("site_name") or DEFAULT_SITE_NAME).strip() or DEFAULT_SITE_NAME
    full_name = str(data.get("full_name") or "").strip()
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    answers = data.get("recovery_answers") or []

    if len(username) < 3 or not re.match(r"^[A-Za-z0-9._@-]{3,80}$", username):
        return jsonify({"error": "Invalid username format"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(answers) != 3 or any(len(str(a or "").strip()) < 2 for a in answers):
        return jsonify({"error": "Please provide all 3 recovery answers"}), 400

    pw_hash = generate_password_hash(password)
    rec_hashes = [_hash_answer(a) for a in answers]
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_conn() as conn:
        existing_supers = _get_app_state(conn, "super_admins", []) or []
        if existing_supers:
            return jsonify({"error": "Platform is already initialized"}), 409

        super_admin = {
            "username": username,
            "full_name": full_name or username,
            "password_hash": pw_hash,
            "recovery_hashes": rec_hashes,
            "auth_version": 1,
            "enabled": True,
            "created_at": now_iso,
        }
        _set_app_state(conn, "super_admins", [super_admin])

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO organizations (id, slug, name, portal_title, status, max_users, plan_name)
                VALUES (%s, %s, %s, %s, 'active', 250, 'Enterprise')
                ON CONFLICT (id) DO UPDATE SET slug=EXCLUDED.slug, name=EXCLUDED.name
                """,
                (DEFAULT_ORG_ID, org_slug, company, DEFAULT_SETTINGS["portal_title"]),
            )
        _seed_org_defaults(conn, DEFAULT_ORG_ID, company)
        settings = _get_org_state(conn, DEFAULT_ORG_ID, "settings", dict(DEFAULT_SETTINGS)) or dict(DEFAULT_SETTINGS)
        settings["company"] = company
        settings["site_name"] = site_name
        _set_org_state(conn, DEFAULT_ORG_ID, "settings", settings)

        first_org_admin = {
            "username": username,
            "full_name": full_name or username,
            "role": "Administrator",
            "dept": "Administration",
            "factory": "",
            "phone": "",
            "email": "",
            "gate_scope": "all",
            "enabled": True,
            "perms": normalize_perms("Administrator", {}),
            "password_hash": pw_hash,
            "recovery_hashes": rec_hashes,
            "auth_version": 1,
            "created_at": now_iso,
        }
        _set_org_state(conn, DEFAULT_ORG_ID, "manual_users", [first_org_admin])
        _audit(conn, DEFAULT_ORG_ID, username, "setup", f"Initialized platform & primary organization '{org_slug}'")

    _bump_rev(DEFAULT_ORG_ID, "dataRev")
    return jsonify({"ok": True, "orgSlug": org_slug})


@app.post("/api/login")
def api_login():
    ensure_db_ready()
    _start_worker_once()
    ip = request.remote_addr or "unknown"
    now = time.time()
    recent = [t for t in _LOGIN_ATTEMPTS[ip] if now - t < 60]
    if len(recent) >= 25:
        return jsonify({"error": "Too many login attempts; wait 1 minute."}), 429
    recent.append(now)
    _LOGIN_ATTEMPTS[ip] = recent

    data = request.get_json(silent=True) or {}
    org_slug = str(data.get("org_slug") or data.get("orgSlug") or "").strip()
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")

    with get_conn() as conn:
        org = None
        if org_slug:
            org = _find_org_by_slug_or_id(conn, org_slug)
        else:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM organizations ORDER BY created_at ASC")
                all_orgs = cur.fetchall() or []
            if len(all_orgs) == 1:
                org = all_orgs[0]
            else:
                return jsonify({"error": "Company Code (Organization ID) is required"}), 400

        if not org:
            return jsonify({"error": "Company Code not found"}), 401
        ok, reason = is_org_active(org)
        if not ok:
            return jsonify({"error": reason}), 403

        users = _get_org_state(conn, org["id"], "manual_users", []) or []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
        if not account or not account.get("enabled", True):
            return jsonify({"error": "Invalid company code, username, or password"}), 401
        if not check_password_hash(str(account.get("password_hash") or ""), password):
            return jsonify({"error": "Invalid company code, username, or password"}), 401

        token = sign_session_token(account["username"], int(account.get("auth_version", 1) or 1), org_id=org["id"], scope="org")
        _audit(conn, org["id"], account["username"], "login", "Signed in")
        pub = _public_user_dict(account, org)

    resp = make_response(jsonify({"user": pub, "org": _serialize_org(org), "token": token}))
    resp.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, httponly=True, samesite="Lax", secure=COOKIE_SECURE, path="/")
    return resp


@app.post("/api/logout")
def api_logout():
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.post("/api/recovery/reset")
def api_recovery_reset():
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    org_slug = str(data.get("org_slug") or "").strip()
    username = str(data.get("username") or "").strip()
    answers = data.get("answers") or []
    new_pw = str(data.get("new_password") or "")
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    with get_conn() as conn:
        org = _find_org_by_slug_or_id(conn, org_slug) if org_slug else None
        if not org:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM organizations ORDER BY created_at ASC LIMIT 2")
                rows = cur.fetchall() or []
                if len(rows) == 1:
                    org = rows[0]
        if not org:
            return jsonify({"error": "Valid Company Code is required"}), 400
        users = _get_org_state(conn, org["id"], "manual_users", []) or []
        account = next(
            (u for u in users if str(u.get("username", "")).casefold() == username.casefold() and u.get("role") == "Administrator"),
            None,
        )
        hashes = account.get("recovery_hashes") if account else None
        if not account or not hashes or len(answers) != 3 or not all(_check_answer(a, h) for a, h in zip(answers, hashes)):
            return jsonify({"error": "Recovery verification failed"}), 403
        account["password_hash"] = generate_password_hash(new_pw)
        account["auth_version"] = int(account.get("auth_version", 1) or 1) + 1
        _set_org_state(conn, org["id"], "manual_users", users)
        _audit(conn, org["id"], account["username"], "recovery_reset", "Organization Admin password reset")
    return jsonify({"ok": True})


@app.get("/api/me")
@auth_required()
def api_me(conn, org, user):
    return jsonify({"user": user, "org": _serialize_org(org)})


@app.post("/api/account/password")
@auth_required()
def api_change_own_password(conn, org, user):
    data = request.get_json(silent=True) or {}
    cur_pw = str(data.get("current_password") or "")
    new_pw = str(data.get("new_password") or "")
    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    users = _get_org_state(conn, org["id"], "manual_users", []) or []
    account = next((u for u in users if str(u.get("username", "")).casefold() == user["username"].casefold()), None)
    if not account or not check_password_hash(str(account.get("password_hash") or ""), cur_pw):
        return jsonify({"error": "Current password is incorrect"}), 400
    account["password_hash"] = generate_password_hash(new_pw)
    account["auth_version"] = int(account.get("auth_version", 1) or 1) + 1
    _set_org_state(conn, org["id"], "manual_users", users)
    token = sign_session_token(account["username"], account["auth_version"], org_id=org["id"], scope="org")
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, httponly=True, samesite="Lax", secure=COOKIE_SECURE, path="/")
    return resp


# ---------------------------------------------------------------------------
# SUPER ADMIN SAAS MANAGEMENT APIs (/api/super/*)
# ---------------------------------------------------------------------------
@app.post("/api/super/login")
def api_super_login():
    ensure_db_ready()
    _start_worker_once()
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    with get_conn() as conn:
        supers = _get_app_state(conn, "super_admins", []) or []
        sa = next((s for s in supers if str(s.get("username", "")).casefold() == username.casefold()), None)
        if not sa or not sa.get("enabled", True) or not check_password_hash(str(sa.get("password_hash") or ""), password):
            return jsonify({"error": "Invalid Super Admin credentials"}), 401
        token = sign_session_token(sa["username"], int(sa.get("auth_version", 1) or 1), org_id="__super__", scope="super")
    resp = make_response(jsonify({"superAdmin": {"username": sa["username"], "full_name": sa.get("full_name") or sa["username"]}}))
    resp.set_cookie(SUPER_COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, httponly=True, samesite="Lax", secure=COOKIE_SECURE, path="/")
    return resp


@app.post("/api/super/logout")
def api_super_logout():
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(SUPER_COOKIE_NAME, path="/")
    return resp


@app.post("/api/super/recovery/reset")
def api_super_recovery_reset():
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip()
    answers = data.get("answers") or []
    new_pw = str(data.get("new_password") or "")
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    with get_conn() as conn:
        supers = _get_app_state(conn, "super_admins", []) or []
        sa = next((s for s in supers if str(s.get("username", "")).casefold() == username.casefold()), None)
        hashes = sa.get("recovery_hashes") if sa else None
        if not sa or not hashes or len(answers) != 3 or not all(_check_answer(a, h) for a, h in zip(answers, hashes)):
            return jsonify({"error": "Recovery verification failed"}), 403
        sa["password_hash"] = generate_password_hash(new_pw)
        sa["auth_version"] = int(sa.get("auth_version", 1) or 1) + 1
        _set_app_state(conn, "super_admins", supers)
    return jsonify({"ok": True})


@app.get("/api/super/me")
@super_required
def api_super_me(conn, sa):
    return jsonify({"superAdmin": sa})


@app.get("/api/super/orgs")
@super_required
def api_super_list_orgs(conn, sa):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM organizations ORDER BY created_at DESC")
        orgs = cur.fetchall() or []
        cur.execute("SELECT org_id, COUNT(*) AS cnt FROM visitor_passes GROUP BY org_id")
        v_counts = {r["org_id"]: int(r["cnt"]) for r in (cur.fetchall() or [])}
        cur.execute("SELECT org_id, COUNT(*) AS cnt FROM material_gate_passes GROUP BY org_id")
        g_counts = {r["org_id"]: int(r["cnt"]) for r in (cur.fetchall() or [])}
        cur.execute("SELECT org_id, value FROM org_state WHERE key='manual_users'")
        u_map = {r["org_id"]: (r["value"] or []) for r in (cur.fetchall() or [])}

    out = []
    for o in orgs:
        oid = o["id"]
        users = u_map.get(oid, [])
        admins = [u["username"] for u in users if u.get("role") == "Administrator"]
        item = _serialize_org(o)
        item["stats"] = {
            "users": len(users),
            "visitors": v_counts.get(oid, 0),
            "gatePasses": g_counts.get(oid, 0),
            "admins": admins,
        }
        out.append(item)
    return jsonify({"organizations": out, "superAdmin": sa})


@app.post("/api/super/orgs")
@super_required
def api_super_create_org(conn, sa):
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    if len(name) < 2:
        return jsonify({"error": "Organization name is required"}), 400
    slug = normalize_slug(data.get("slug") or name, "org")
    admin_user = str(data.get("adminUsername") or data.get("admin_username") or "admin").strip()
    admin_full = str(data.get("adminFullName") or data.get("admin_full_name") or f"{name} Admin").strip()
    admin_pw = str(data.get("adminPassword") or data.get("admin_password") or "")
    if not re.match(r"^[A-Za-z0-9._@-]{3,80}$", admin_user):
        return jsonify({"error": "Admin username must be 3-80 chars (letters/digits/._@-)"}), 400
    if len(admin_pw) < 6:
        return jsonify({"error": "Initial Admin password must be at least 6 characters"}), 400

    try:
        max_users = max(1, int(data.get("maxUsers") or 100))
    except (ValueError, TypeError):
        max_users = 100
    plan_name = str(data.get("planName") or "Standard").strip() or "Standard"
    exp_raw = str(data.get("expiresAt") or "").strip()
    expires_at = None
    if exp_raw:
        try:
            expires_at = datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
        except ValueError:
            expires_at = None

    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM organizations WHERE slug=%s", (slug,))
        if cur.fetchone():
            return jsonify({"error": f"Company code '{slug}' already exists"}), 409
        oid = f"org-{secrets.token_hex(4)}"
        cur.execute(
            """
            INSERT INTO organizations (
                id, slug, name, portal_title, status, max_users, plan_name, expires_at,
                contact_name, contact_phone, contact_email, notes
            ) VALUES (%s, %s, %s, %s, 'active', %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                oid,
                slug,
                name,
                str(data.get("portalTitle") or DEFAULT_SETTINGS["portal_title"]).strip(),
                max_users,
                plan_name,
                expires_at,
                str(data.get("contactName") or "").strip(),
                str(data.get("contactPhone") or "").strip(),
                str(data.get("contactEmail") or "").strip(),
                str(data.get("notes") or "").strip(),
            ),
        )
        org_row = cur.fetchone()

    _seed_org_defaults(conn, oid, name, org_row["portal_title"])
    first_admin = {
        "username": admin_user,
        "full_name": admin_full,
        "role": "Administrator",
        "dept": "Administration",
        "factory": "",
        "phone": str(data.get("contactPhone") or "").strip(),
        "email": str(data.get("contactEmail") or "").strip(),
        "gate_scope": "all",
        "enabled": True,
        "perms": normalize_perms("Administrator", {}),
        "password_hash": generate_password_hash(admin_pw),
        "auth_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _set_org_state(conn, oid, "manual_users", [first_admin])
    _audit(conn, oid, sa["username"], "create_org", f"Created organization {name} ({slug})")
    return jsonify({"organization": _serialize_org(org_row)}), 201


@app.post("/api/super/orgs/<org_id>/update")
@super_required
def api_super_update_org(conn, sa, org_id):
    data = request.get_json(silent=True) or {}
    org = _find_org_by_slug_or_id(conn, org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    name = str(data.get("name") or org["name"]).strip() or org["name"]
    slug = normalize_slug(data.get("slug") or org["slug"], org["slug"])
    status = str(data.get("status") or org["status"]).lower()
    if status not in ("active", "suspended"):
        status = "active"
    try:
        max_users = max(1, int(data.get("maxUsers") if "maxUsers" in data else org["max_users"]))
    except (ValueError, TypeError):
        max_users = org["max_users"]
    plan_name = str(data.get("planName") if "planName" in data else org["plan_name"]).strip()
    expires_at = org.get("expires_at")
    if "expiresAt" in data:
        eraw = str(data.get("expiresAt") or "").strip()
        if not eraw:
            expires_at = None
        else:
            try:
                expires_at = datetime.fromisoformat(eraw.replace("Z", "+00:00"))
            except ValueError:
                pass

    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM organizations WHERE slug=%s AND id<>%s", (slug, org["id"]))
        if cur.fetchone():
            return jsonify({"error": f"Company code '{slug}' is already used by another organization"}), 409
        cur.execute(
            """
            UPDATE organizations
               SET slug=%s, name=%s, status=%s, max_users=%s, plan_name=%s, expires_at=%s,
                   contact_name=%s, contact_phone=%s, contact_email=%s, notes=%s, updated_at=NOW()
             WHERE id=%s
            RETURNING *
            """,
            (
                slug,
                name,
                status,
                max_users,
                plan_name,
                expires_at,
                str(data.get("contactName", org.get("contact_name", ""))).strip(),
                str(data.get("contactPhone", org.get("contact_phone", ""))).strip(),
                str(data.get("contactEmail", org.get("contact_email", ""))).strip(),
                str(data.get("notes", org.get("notes", ""))).strip(),
                org["id"],
            ),
        )
        updated = cur.fetchone()
    settings = _get_org_state(conn, org["id"], "settings", dict(DEFAULT_SETTINGS)) or dict(DEFAULT_SETTINGS)
    settings["company"] = name
    _set_org_state(conn, org["id"], "settings", settings)
    _bump_rev(org["id"], "dataRev")
    return jsonify({"organization": _serialize_org(updated)})


@app.post("/api/super/orgs/<org_id>/reset-admin")
@super_required
def api_super_reset_org_admin(conn, sa, org_id):
    org = _find_org_by_slug_or_id(conn, org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip()
    new_pw = str(data.get("newPassword") or data.get("password") or "")
    if len(new_pw) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400
    users = _get_org_state(conn, org["id"], "manual_users", []) or []
    target = None
    if username:
        target = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
    if not target:
        target = next((u for u in users if u.get("role") == "Administrator"), None)
    if not target:
        uname = username or "admin"
        target = {
            "username": uname,
            "full_name": f"{org['name']} Admin",
            "role": "Administrator",
            "dept": "Administration",
            "factory": "",
            "gate_scope": "all",
            "enabled": True,
            "perms": normalize_perms("Administrator", {}),
            "auth_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        users.append(target)
    target["password_hash"] = generate_password_hash(new_pw)
    target["auth_version"] = int(target.get("auth_version", 1) or 1) + 1
    target["enabled"] = True
    _set_org_state(conn, org["id"], "manual_users", users)
    _audit(conn, org["id"], sa["username"], "super_reset_admin", f"Reset password for {target['username']}")
    return jsonify({"ok": True, "username": target["username"]})


def _save_org_logo_file(org_id: str, file_storage) -> str:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    logos_dir = UPLOAD_DIR / "org_logos"
    logos_dir.mkdir(parents=True, exist_ok=True)
    ext = Path(str(file_storage.filename or "logo.png")).suffix.lower()
    if ext not in (".png", ".jpg", ".jpeg", ".webp", ".svg"):
        ext = ".png"
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", org_id) or "org"
    for old in logos_dir.glob(f"{safe_org}-logo.*"):
        old.unlink(missing_ok=True)
    fname = f"{safe_org}-logo{ext}"
    file_storage.save(logos_dir / fname)
    return f"/api/public/org-logo/{safe_org}?v={int(time.time())}"


@app.post("/api/super/orgs/<org_id>/logo")
@super_required
def api_super_upload_org_logo(conn, sa, org_id):
    org = _find_org_by_slug_or_id(conn, org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404
    f = request.files.get("file") or next(iter(request.files.values()), None)
    if not f:
        return jsonify({"error": "No logo image attached"}), 400
    url = _save_org_logo_file(org["id"], f)
    with conn.cursor() as cur:
        cur.execute("UPDATE organizations SET logo_url=%s, updated_at=NOW() WHERE id=%s", (url, org["id"]))
    _bump_rev(org["id"], "dataRev")
    return jsonify({"logoUrl": url})


@app.delete("/api/super/orgs/<org_id>")
@super_required
def api_super_delete_org(conn, sa, org_id):
    org = _find_org_by_slug_or_id(conn, org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404
    oid = org["id"]
    with conn.cursor() as cur:
        for table in ("visitor_passes", "material_gate_passes", "notification_events", "user_notification_prefs", "org_state", "audit_logs"):
            cur.execute(f"DELETE FROM {table} WHERE org_id=%s", (oid,))
        cur.execute("DELETE FROM organizations WHERE id=%s", (oid,))
    org_media = (UPLOAD_DIR / Path(oid).name).resolve()
    if org_media.exists() and org_media.parent == UPLOAD_DIR.resolve():
        shutil.rmtree(org_media, ignore_errors=True)
    return jsonify({"ok": True})


@app.get("/api/super/backups")
@super_required
def api_super_list_backups(conn, sa):
    return _list_backups_resp()


@app.post("/api/super/backups")
@super_required
def api_super_run_backup(conn, sa):
    return _run_backup_resp(conn, DEFAULT_ORG_ID, sa["username"])


@app.get("/api/super/backups/<path:name>")
@super_required
def api_super_download_backup(conn, sa, name):
    return _download_backup_resp(name)


@app.post("/api/super/password")
@super_required
def api_super_change_pw(conn, sa):
    data = request.get_json(silent=True) or {}
    cur_pw = str(data.get("current_password") or "")
    new_pw = str(data.get("new_password") or "")
    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    supers = _get_app_state(conn, "super_admins", []) or []
    rec = next((s for s in supers if str(s.get("username", "")).casefold() == sa["username"].casefold()), None)
    if not rec or not check_password_hash(str(rec.get("password_hash") or ""), cur_pw):
        return jsonify({"error": "Current password incorrect"}), 400
    rec["password_hash"] = generate_password_hash(new_pw)
    rec["auth_version"] = int(rec.get("auth_version", 1) or 1) + 1
    _set_app_state(conn, "super_admins", supers)
    token = sign_session_token(rec["username"], rec["auth_version"], org_id="__super__", scope="super")
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(SUPER_COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, httponly=True, samesite="Lax", secure=COOKIE_SECURE, path="/")
    return resp


@app.get("/api/public/org-logo/<org_id>")
def api_serve_org_logo(org_id):
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", org_id) or "org"
    logos_dir = UPLOAD_DIR / "org_logos"
    for p in logos_dir.glob(f"{safe_org}-logo.*"):
        return send_file(p)
    return send_file(STATIC_DIR / "icons" / "icon-192.png")


# ---------------------------------------------------------------------------
# Organization Workspace Data + Users (with max_users enforcement) + Org Settings
# ---------------------------------------------------------------------------
@app.get("/api/data")
@auth_required()
def api_data(conn, org, user):
    oid = org["id"]
    factories = _get_org_state(conn, oid, "factories", DEFAULT_FACTORIES) or DEFAULT_FACTORIES
    factory_order = _get_org_state(conn, oid, "factoryOrder", [f["code"] for f in factories]) or []
    factory_descs = _get_org_state(conn, oid, "factoryDescs", {}) or {}
    departments = _get_org_state(conn, oid, "departments", None)
    if departments is None:
        departments = list(DEFAULT_DEPARTMENTS)
    settings = _get_org_state(conn, oid, "settings", dict(DEFAULT_SETTINGS)) or dict(DEFAULT_SETTINGS)
    sound_cfg = _get_org_state(conn, oid, "sound_config", dict(DEFAULT_SOUND_CONFIG)) or dict(DEFAULT_SOUND_CONFIG)
    raw_users = _get_org_state(conn, oid, "manual_users", []) or []
    directory = [
        {
            "username": u.get("username"),
            "full_name": u.get("full_name") or u.get("username"),
            "dept": u.get("dept") or u.get("department") or "",
            "factory": u.get("factory") or "",
            "role": u.get("role") or "Staff",
            "phone": u.get("phone") or "",
            "gate_scope": u.get("gate_scope") or ("security" if u.get("role") == "Security Gate" else "user"),
            "enabled": bool(u.get("enabled", True)),
        }
        for u in raw_users
    ]
    users_out = [_public_user_dict(u, org) for u in raw_users] if user["role"] == "Administrator" or user["perms"].get("users") != "none" else directory
    with conn.cursor() as cur:
        cur.execute("SELECT prefs FROM user_notification_prefs WHERE org_id=%s AND username=%s", (oid, user["username"]))
        row = cur.fetchone()
        user_prefs = row["prefs"] if row else {}
    return jsonify(
        {
            "user": user,
            "org": _serialize_org(org),
            "factories": factories,
            "factoryOrder": factory_order,
            "factoryDescs": factory_descs,
            "departments": departments,
            "settings": settings,
            "soundConfig": sound_cfg,
            "userNotifPrefs": user_prefs,
            "users": users_out,
            "directory": directory,
            "revisions": dict(_ORG_REVISIONS[oid]),
        }
    )


@app.post("/api/users")
@auth_required("users", "rw")
def api_save_user(conn, org, user):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip()
    if not username or not re.match(r"^[A-Za-z0-9._@-]{3,80}$", username):
        return jsonify({"error": "Valid username required (3-80 chars, letters/digits/._@-)"}), 400
    users = _get_org_state(conn, oid, "manual_users", []) or []
    existing = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
    max_users = int(org.get("max_users") or 100)
    if not existing and len(users) >= max_users:
        return jsonify({"error": f"User limit reached ({len(users)}/{max_users}). Contact your Platform Administrator to expand your plan."}), 403

    role = str(data.get("role") or (existing.get("role") if existing else "Staff") or "Staff")
    if role not in DEFAULT_PERMS_BY_ROLE:
        role = "Staff"
    raw_pw = str(data.get("password") or "")
    if not existing and len(raw_pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters for new users"}), 400

    entry = existing or {
        "username": username,
        "auth_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    entry["full_name"] = str(data.get("full_name") or entry.get("full_name") or username).strip()
    entry["role"] = role
    dept_val = str(data.get("dept") or data.get("department") or "").strip()
    entry["dept"] = dept_val
    entry["department"] = dept_val
    entry["factory"] = str(data.get("factory") or "").strip()
    entry["phone"] = str(data.get("phone") or "").strip()
    entry["email"] = str(data.get("email") or "").strip()
    entry["gate_scope"] = str(data.get("gate_scope") or ("security" if role == "Security Gate" else "user")).strip()
    entry["enabled"] = bool(data.get("enabled", True))
    entry["perms"] = normalize_perms(role, data.get("perms") or entry.get("perms"))
    if raw_pw:
        entry["password_hash"] = generate_password_hash(raw_pw)
        entry["auth_version"] = int(entry.get("auth_version", 1) or 1) + 1
    if not existing:
        users.append(entry)
    _set_org_state(conn, oid, "manual_users", users)
    _audit(conn, oid, user["username"], "save_user", f"Saved user {username} ({role})")
    _bump_rev(oid, "dataRev")
    return jsonify({"user": _public_user_dict(entry, org)})


@app.delete("/api/users/<username>")
@auth_required("users", "rw")
def api_delete_user(conn, org, user, username):
    if user.get("role") != "Administrator":
        return jsonify({"error": "Only Administrators are permitted to delete users"}), 403
    oid = org["id"]
    if username.casefold() == user["username"].casefold():
        return jsonify({"error": "You cannot delete your own active admin account"}), 400
    users = _get_org_state(conn, oid, "manual_users", []) or []
    filtered = [u for u in users if str(u.get("username", "")).casefold() != username.casefold()]
    if len(filtered) == len(users):
        return jsonify({"error": "User not found"}), 404
    _set_org_state(conn, oid, "manual_users", filtered)
    _audit(conn, oid, user["username"], "delete_user", f"Deleted user {username}")
    _bump_rev(oid, "dataRev")
    return jsonify({"ok": True})


@app.post("/api/users/bulk")
@auth_required("users", "rw")
def api_bulk_users(conn, org, user):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    rows = data.get("users") or []
    mode = str(data.get("mode") or "upsert").lower()
    default_pw = str(data.get("defaultPassword") or "Shree@12345").strip() or "Shree@12345"
    if not isinstance(rows, list) or not rows:
        return jsonify({"error": "No user rows provided"}), 400

    users = _get_org_state(conn, oid, "manual_users", []) or []
    max_users = int(org.get("max_users") or 100)
    by_uname = {str(u.get("username", "")).casefold(): u for u in users}
    departments = list(_get_org_state(conn, oid, "departments", DEFAULT_DEPARTMENTS) or DEFAULT_DEPARTMENTS)
    dept_set = {d.casefold() for d in departments}

    created = updated = skipped = 0
    errors: list[str] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            skipped += 1
            continue
        uname = str(row.get("username") or row.get("Username") or "").strip()
        if not uname or not re.match(r"^[A-Za-z0-9._@-]{3,80}$", uname):
            errors.append(f"Row {idx}: invalid username '{uname}'")
            skipped += 1
            continue
        key = uname.casefold()
        existing = by_uname.get(key)
        if existing and mode == "skip":
            skipped += 1
            continue
        if not existing and len(users) >= max_users:
            errors.append(f"Row {idx}: organization user limit ({max_users}) reached")
            skipped += 1
            continue
        role_raw = str(row.get("role") or row.get("Role") or "Staff").strip()
        role = role_raw if role_raw in DEFAULT_PERMS_BY_ROLE else "Staff"
        dept_val = str(row.get("dept") or row.get("department") or row.get("Department") or "").strip()
        if dept_val and dept_val.casefold() not in dept_set:
            departments.append(dept_val)
            dept_set.add(dept_val.casefold())
        pw_val = str(row.get("password") or row.get("Password") or "").strip()
        enabled_raw = row.get("enabled", True)
        enabled_val = enabled_raw.strip().lower() not in ("false", "0", "no", "disabled") if isinstance(enabled_raw, str) else bool(enabled_raw)

        rec = existing or {
            "username": uname,
            "auth_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "password_hash": generate_password_hash(pw_val if len(pw_val) >= 6 else default_pw),
        }
        rec["full_name"] = str(row.get("full_name") or row.get("Full Name") or row.get("name") or rec.get("full_name") or uname).strip()
        rec["role"] = role
        rec["dept"] = dept_val
        rec["department"] = dept_val
        rec["factory"] = str(row.get("factory") or row.get("Factory") or "").strip()
        rec["phone"] = str(row.get("phone") or row.get("Phone") or "").strip()
        rec["email"] = str(row.get("email") or row.get("Email") or "").strip()
        rec["gate_scope"] = str(row.get("gate_scope") or ("security" if role == "Security Gate" else "user")).strip()
        rec["enabled"] = enabled_val
        rec["perms"] = normalize_perms(role, row.get("perms") or rec.get("perms"))
        if existing and len(pw_val) >= 6:
            rec["password_hash"] = generate_password_hash(pw_val)
        if not existing:
            users.append(rec)
            by_uname[key] = rec
            created += 1
        else:
            updated += 1

    _set_org_state(conn, oid, "manual_users", users)
    _set_org_state(conn, oid, "departments", departments)
    _audit(conn, oid, user["username"], "bulk_users", f"Created {created}, updated {updated}, skipped {skipped}")
    _bump_rev(oid, "dataRev")
    return jsonify({"created": created, "updated": updated, "skipped": skipped, "errors": errors[:20]})


@app.post("/api/departments")
@auth_required("departments", "rw")
def api_save_departments(conn, org, user):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    raw = data.get("departments")
    if not isinstance(raw, list):
        return jsonify({"error": "departments list required"}), 400
    clean, seen = [], set()
    for d in raw:
        val = str(d or "").strip()
        if val and val.casefold() not in seen:
            seen.add(val.casefold())
            clean.append(val)
    _set_org_state(conn, oid, "departments", clean)
    _audit(conn, oid, user["username"], "save_departments", f"Updated {len(clean)} departments")
    _bump_rev(oid, "dataRev")
    return jsonify({"departments": clean})


@app.post("/api/factories")
@auth_required("factories", "rw")
def api_save_factories(conn, org, user):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    factories = data.get("factories")
    order = data.get("factoryOrder")
    descs = data.get("factoryDescs")
    if isinstance(factories, list):
        cleaned, seen = [], set()
        for f in factories:
            if not isinstance(f, dict):
                continue
            code = str(f.get("code") or "").strip().upper()
            name = str(f.get("name") or code).strip()
            desc = str(f.get("desc") or "").strip()
            if code and code not in seen:
                seen.add(code)
                cleaned.append({"code": code, "name": name or code, "desc": desc})
        _set_org_state(conn, oid, "factories", cleaned)
        if not isinstance(order, list):
            order = [f["code"] for f in cleaned]
        _set_org_state(conn, oid, "factoryDescs", {f["code"]: f["desc"] for f in cleaned})
    if isinstance(order, list):
        _set_org_state(conn, oid, "factoryOrder", [str(x).strip().upper() for x in order if str(x).strip()])
    if isinstance(descs, dict):
        _set_org_state(conn, oid, "factoryDescs", descs)
    _audit(conn, oid, user["username"], "save_factories", "Updated factory sites")
    _bump_rev(oid, "dataRev")
    return jsonify({"ok": True})


@app.post("/api/settings")
@auth_required("settings", "rw")
def api_save_settings(conn, org, user):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    cur_set = _get_org_state(conn, oid, "settings", dict(DEFAULT_SETTINGS)) or dict(DEFAULT_SETTINGS)
    for k in ("company", "site_name", "portal_title", "font_family", "font_size", "auto_checkout_hours", "default_returnable_days"):
        if k in data:
            cur_set[k] = data[k]
    _set_org_state(conn, oid, "settings", cur_set)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE organizations SET name=%s, portal_title=%s, updated_at=NOW() WHERE id=%s",
            (str(cur_set.get("company") or org["name"]), str(cur_set.get("portal_title") or org["portal_title"]), oid),
        )
    _audit(conn, oid, user["username"], "save_settings", "Updated organization settings")
    _bump_rev(oid, "dataRev")
    return jsonify({"settings": cur_set})


@app.post("/api/settings/logo")
@auth_required("settings", "rw")
def api_org_upload_logo(conn, org, user):
    f = request.files.get("file") or next(iter(request.files.values()), None)
    if not f:
        return jsonify({"error": "No logo image attached"}), 400
    url = _save_org_logo_file(org["id"], f)
    with conn.cursor() as cur:
        cur.execute("UPDATE organizations SET logo_url=%s, updated_at=NOW() WHERE id=%s", (url, org["id"]))
    _bump_rev(org["id"], "dataRev")
    return jsonify({"logoUrl": url})


# ---------------------------------------------------------------------------
# Public Kiosk Options & Tenant-Scoped Gate Media
# ---------------------------------------------------------------------------
@app.get("/api/public/portal-options")
def api_public_portal_options():
    ensure_db_ready()
    _start_worker_once()
    with get_conn() as conn:
        org, err = _resolve_public_org(conn)
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        oid = org["id"]
        factories = _get_org_state(conn, oid, "factories", DEFAULT_FACTORIES) or DEFAULT_FACTORIES
        order = _get_org_state(conn, oid, "factoryOrder", [f["code"] for f in factories]) or []
        departments = _get_org_state(conn, oid, "departments", None)
    if departments is None:
        departments = list(DEFAULT_DEPARTMENTS)
        settings = _get_org_state(conn, oid, "settings", dict(DEFAULT_SETTINGS)) or dict(DEFAULT_SETTINGS)
        users = _get_org_state(conn, oid, "manual_users", []) or []
    employees = [
        {
            "username": u.get("username", ""),
            "name": u.get("full_name") or u.get("username", ""),
            "dept": u.get("dept") or u.get("department") or "",
            "factory": u.get("factory") or "",
            "role": u.get("role") or "Staff",
        }
        for u in users
        if u.get("enabled", True)
    ]
    return jsonify(
        {
            "orgId": oid,
            "orgSlug": org["slug"],
            "company": settings.get("company") or org["name"],
            "logoUrl": org.get("logo_url", ""),
            "portalTitle": settings.get("portal_title") or org.get("portal_title", "Security Gate · Visitor & Material Entry"),
            "defaultReturnableDays": int(settings.get("default_returnable_days", 7) or 7),
            "factories": factories,
            "factoryOrder": order,
            "departments": departments,
            "employees": employees,
        }
    )


def _save_uploaded_photo_file(org_id: str, file_storage, prefix: str = "gate") -> str:
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", org_id) or DEFAULT_ORG_ID
    media_dir = UPLOAD_DIR / safe_org / "gate_media"
    media_dir.mkdir(parents=True, exist_ok=True)
    orig = str(file_storage.filename or "photo.jpg")
    ext = Path(orig).suffix.lower()
    if ext not in (".jpg", ".jpeg", ".png", ".webp", ".gif", ".pdf"):
        ext = ".jpg"
    fname = f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(6)}{ext}"
    file_storage.save(media_dir / fname)
    return f"/api/gate-media/{safe_org}/{fname}"


@app.post("/api/public/gate-media")
def api_public_upload_gate_media():
    ensure_db_ready()
    with get_conn() as conn:
        org, err = _resolve_public_org(conn, request.form.get("orgSlug") or request.form.get("org") or "")
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        oid = org["id"]
    files = request.files.getlist("files") or request.files.getlist("file") or list(request.files.values())
    if not files:
        return jsonify({"error": "No image or document files attached"}), 400
    prefix = re.sub(r"[^a-zA-Z0-9_-]", "", str(request.form.get("kind") or "gate"))[:20] or "gate"
    urls = [_save_uploaded_photo_file(oid, f, prefix=prefix) for f in files[:20]]
    return jsonify({"url": urls[0], "urls": urls})


@app.post("/api/gate-media")
@auth_required()
def api_auth_upload_gate_media(conn, org, user):
    files = request.files.getlist("files") or request.files.getlist("file") or list(request.files.values())
    if not files:
        return jsonify({"error": "No image or document files attached"}), 400
    prefix = re.sub(r"[^a-zA-Z0-9_-]", "", str(request.form.get("kind") or "gate"))[:20] or "gate"
    urls = [_save_uploaded_photo_file(org["id"], f, prefix=prefix) for f in files[:20]]
    return jsonify({"url": urls[0], "urls": urls})


@app.get("/api/gate-media/<org_id>/<path:filename>")
@app.get("/api/public/gate-media/<org_id>/<path:filename>")
def api_serve_gate_media(org_id, filename):
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", org_id) or DEFAULT_ORG_ID
    safe = Path(filename).name
    ensure_db_ready()
    with get_conn() as conn:
        user, _ = _get_current_user(conn)
        if user and user["org_id"] != safe_org:
            return jsonify({"error": "Forbidden for this organization"}), 403
    media_dir = UPLOAD_DIR / safe_org / "gate_media"
    target = (media_dir / safe).resolve()
    if not target.exists() or target.parent != media_dir.resolve():
        return jsonify({"error": "File not found"}), 404
    return send_from_directory(media_dir, safe)


# ---------------------------------------------------------------------------
# Visitor Pass Lifecycle API (Tenant-Scoped 4-Step Workflow)
# ---------------------------------------------------------------------------
def _create_visitor_pass(conn, org_id: str, data: dict, actor_label: str):
    visitor_name = str(data.get("visitorName") or data.get("visitor_name") or "").strip()
    if not visitor_name:
        return None, ("Visitor name is required", 400)
    factory = str(data.get("factory") or "").strip()
    department = str(data.get("department") or data.get("dept") or "").strip()
    host_username = str(data.get("hostUsername") or data.get("host_username") or "").strip()
    host_name = str(data.get("hostName") or data.get("host_name") or "").strip()

    users = _get_org_state(conn, org_id, "manual_users", []) or []
    if host_username and not host_name:
        matched = next((u for u in users if str(u.get("username", "")).casefold() == host_username.casefold()), None)
        if matched:
            host_name = matched.get("full_name") or matched.get("username") or host_username

    id_photos = [str(x).strip() for x in (data.get("idCardPhotos") or []) if str(x).strip()]
    id_photo = str(data.get("idCardPhoto") or (id_photos[0] if id_photos else "")).strip()
    if id_photo and id_photo not in id_photos:
        id_photos.insert(0, id_photo)

    selfie_photos = [str(x).strip() for x in (data.get("selfiePhotos") or []) if str(x).strip()]
    selfie_photo = str(data.get("selfiePhoto") or (selfie_photos[0] if selfie_photos else "")).strip()
    if selfie_photo and selfie_photo not in selfie_photos:
        selfie_photos.insert(0, selfie_photo)

    vid = _next_human_id(conn, org_id, "VP", "visitor_passes")
    now = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO visitor_passes (
                id, org_id, visitor_name, company, phone, address, purpose, vehicle_no,
                factory, department, host_username, host_name,
                id_card_photo, id_card_photos, selfie_photo, selfie_photos,
                status, entry_time, notes, created_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s::jsonb, %s, %s::jsonb,
                'Pending', %s, %s, %s
            )
            RETURNING *
            """,
            (
                vid,
                org_id,
                visitor_name,
                str(data.get("company") or "").strip(),
                str(data.get("phone") or "").strip(),
                str(data.get("address") or "").strip(),
                str(data.get("purpose") or "").strip(),
                str(data.get("vehicleNo") or data.get("vehicle_no") or "").strip(),
                factory,
                department,
                host_username,
                host_name,
                id_photo,
                json.dumps(id_photos),
                selfie_photo,
                json.dumps(selfie_photos),
                now,
                str(data.get("notes") or "").strip(),
                actor_label,
            ),
        )
        row = cur.fetchone()

    targets, tgt_dept, dept_bcast = resolve_notification_targets(
        users,
        target_username=host_username,
        target_department=department,
        factory=factory,
        include_security=False,
        fallback_admin_if_no_security=(not host_username and not department),
    )
    who_label = host_name or host_username or (f"{department} Dept" if department else "Reception")
    emit_notification(
        conn,
        org_id=org_id,
        kind="visitor_entry",
        level="info",
        title=f"Visitor Waiting at Gate: {visitor_name} ({vid})",
        body=f"From {row['company'] or 'Individual'} · To meet {who_label} · Purpose: {row['purpose'] or 'Visit'} — Please Approve or Reject.",
        factory=factory,
        target_department=tgt_dept,
        target_usernames=targets,
        dept_broadcast=dept_bcast,
        target_view="visitors",
        target_id=vid,
        meta={"visitor_id": vid, "step": "Pending", "host_username": host_username},
    )
    _bump_rev(org_id, "visitorRev")
    return _serialize_visitor(row), None


@app.get("/api/public/visitors")
def api_public_list_visitors():
    ensure_db_ready()
    factory = str(request.args.get("factory") or "").strip()
    with get_conn() as conn:
        org, err = _resolve_public_org(conn)
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        oid = org["id"]
        with conn.cursor() as cur:
            if factory:
                cur.execute("SELECT * FROM visitor_passes WHERE org_id=%s AND factory=%s ORDER BY entry_time DESC LIMIT 80", (oid, factory))
            else:
                cur.execute("SELECT * FROM visitor_passes WHERE org_id=%s ORDER BY entry_time DESC LIMIT 80", (oid,))
            rows = cur.fetchall()
    return jsonify({"visitors": [_serialize_visitor(r) for r in rows], "rev": _ORG_REVISIONS[oid]["visitorRev"]})


@app.post("/api/public/visitors")
def api_public_create_visitor():
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    with get_conn() as conn:
        org, err = _resolve_public_org(conn, str(data.get("orgSlug") or data.get("org_slug") or ""))
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        created, create_err = _create_visitor_pass(conn, org["id"], data, "Gate Kiosk")
        if create_err:
            return jsonify({"error": create_err[0]}), create_err[1]
    return jsonify({"visitor": created}), 201


@app.get("/api/visitors")
@auth_required("visitors", "ro")
def api_list_visitors(conn, org, user):
    oid = org["id"]
    factory = str(request.args.get("factory") or "").strip()
    status = str(request.args.get("status") or "").strip()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM visitor_passes WHERE org_id=%s ORDER BY entry_time DESC LIMIT 300", (oid,))
        rows = cur.fetchall()
    items = [_serialize_visitor(r) for r in rows]
    if factory:
        items = [v for v in items if not v["factory"] or v["factory"].casefold() == factory.casefold()]
    if status:
        items = [v for v in items if v["status"].casefold() == status.casefold()]
    return jsonify({"visitors": items, "rev": _ORG_REVISIONS[oid]["visitorRev"]})


@app.post("/api/visitors")
@auth_required("visitors", "rw")
def api_create_visitor(conn, org, user):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    created, err = _create_visitor_pass(conn, oid, data, user.get("full_name") or user["username"])
    if err:
        return jsonify({"error": err[0]}), err[1]
    _audit(conn, oid, user["username"], "create_visitor", f"Created visitor pass {created['id']}")
    return jsonify({"visitor": created}), 201


def _user_can_act_on_visitor(user: dict, v_row: dict) -> bool:
    role = user.get("role", "")
    if role in ("Administrator", "Security Gate") or user.get("gate_scope") == "security":
        return True
    uname = user["username"].casefold()
    host = str(v_row.get("host_username") or "").strip().casefold()
    if host and host == uname:
        return True
    udept = str(user.get("dept") or user.get("department") or "").strip().casefold()
    vdept = str(v_row.get("department") or "").strip().casefold()
    if (not host) and udept and vdept and udept == vdept:
        return True
    return user.get("perms", {}).get("visitors") == "rw"


@app.post("/api/visitors/<vid>/decision")
@auth_required()
def api_visitor_decision(conn, org, user, vid):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    decision = str(data.get("decision") or "").strip()
    reason = str(data.get("reason") or "").strip()
    if decision not in ("Approved", "Rejected"):
        return jsonify({"error": "decision must be Approved or Rejected"}), 400

    with conn.cursor() as cur:
        cur.execute("SELECT * FROM visitor_passes WHERE id=%s AND org_id=%s", (vid, oid))
        v_row = cur.fetchone()
        if not v_row:
            return jsonify({"error": "Visitor pass not found"}), 404
        if not _user_can_act_on_visitor(user, v_row):
            return jsonify({"error": "Only host user, department member, or Security/Admin can approve this visitor"}), 403
        if v_row["status"] in ("Checked In", "Checked Out"):
            return jsonify({"error": f"Visitor already {v_row['status']}"}), 409

        actor_name = user.get("full_name") or user["username"]
        cur.execute(
            """
            UPDATE visitor_passes
               SET status=%s, approved_by=%s, approved_at=NOW(), rejected_reason=%s, updated_at=NOW()
             WHERE id=%s AND org_id=%s
            RETURNING *
            """,
            (decision, actor_name, reason if decision == "Rejected" else "", vid, oid),
        )
        updated = cur.fetchone()

    users = _get_org_state(conn, oid, "manual_users", []) or []
    targets, tgt_dept, dept_bcast = resolve_notification_targets(
        users,
        target_username=updated.get("host_username") if (updated.get("host_username") or "").casefold() != user["username"].casefold() else "",
        target_department="",
        factory=updated.get("factory", ""),
        include_security=True,
        fallback_admin_if_no_security=True,
    )
    emit_notification(
        conn,
        org_id=oid,
        kind="visitor_status",
        level="success" if decision == "Approved" else "warning",
        title=f"Visitor {decision}: {updated['visitor_name']} ({vid})",
        body=(
            f"Approved by {actor_name} — Allow guest inside to meet {updated.get('host_name') or updated.get('department') or 'Host'}."
            if decision == "Approved"
            else f"Rejected by {actor_name}" + (f" · Reason: {reason}" if reason else "")
        ),
        factory=updated.get("factory", ""),
        target_department=tgt_dept,
        target_usernames=targets,
        dept_broadcast=dept_bcast,
        target_view="visitors",
        target_id=vid,
        meta={"visitor_id": vid, "step": decision},
    )
    _audit(conn, oid, user["username"], "visitor_decision", f"{vid} -> {decision}")
    _bump_rev(oid, "visitorRev")
    return jsonify({"visitor": _serialize_visitor(updated)})


@app.post("/api/visitors/<vid>/checkin")
@auth_required()
def api_visitor_checkin(conn, org, user, vid):
    oid = org["id"]
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM visitor_passes WHERE id=%s AND org_id=%s", (vid, oid))
        v_row = cur.fetchone()
        if not v_row:
            return jsonify({"error": "Visitor pass not found"}), 404
        if not _user_can_act_on_visitor(user, v_row):
            return jsonify({"error": "Not authorized to check in this visitor"}), 403
        if v_row["status"] == "Pending":
            return jsonify({"error": "Visitor must be Approved first before Check In"}), 400
        if v_row["status"] == "Rejected":
            return jsonify({"error": "Cannot Check In a Rejected visitor"}), 400
        if v_row["status"] == "Checked Out":
            return jsonify({"error": "Visitor has already Checked Out"}), 409

        actor_name = user.get("full_name") or user["username"]
        cur.execute(
            """
            UPDATE visitor_passes
               SET status='Checked In', checked_in_by=%s, checked_in_at=COALESCE(checked_in_at, NOW()), updated_at=NOW()
             WHERE id=%s AND org_id=%s
            RETURNING *
            """,
            (actor_name, vid, oid),
        )
        updated = cur.fetchone()

    users = _get_org_state(conn, oid, "manual_users", []) or []
    targets, tgt_dept, dept_bcast = resolve_notification_targets(
        users,
        target_username=updated.get("host_username") or "",
        target_department=updated.get("department") or "",
        factory=updated.get("factory", ""),
        include_security=True,
        fallback_admin_if_no_security=False,
    )
    emit_notification(
        conn,
        org_id=oid,
        kind="visitor_status",
        level="info",
        title=f"Visitor Checked In: {updated['visitor_name']} ({vid})",
        body=f"Meeting started / Checked In by {actor_name}.",
        factory=updated.get("factory", ""),
        target_department=tgt_dept,
        target_usernames=targets,
        dept_broadcast=dept_bcast,
        target_view="visitors",
        target_id=vid,
        meta={"visitor_id": vid, "step": "Checked In"},
    )
    _audit(conn, oid, user["username"], "visitor_checkin", f"Checked in {vid}")
    _bump_rev(oid, "visitorRev")
    return jsonify({"visitor": _serialize_visitor(updated)})


@app.post("/api/visitors/<vid>/checkout")
@auth_required()
def api_visitor_checkout(conn, org, user, vid):
    oid = org["id"]
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM visitor_passes WHERE id=%s AND org_id=%s", (vid, oid))
        v_row = cur.fetchone()
        if not v_row:
            return jsonify({"error": "Visitor pass not found"}), 404
        if not _user_can_act_on_visitor(user, v_row):
            return jsonify({"error": "Not authorized to check out this visitor"}), 403
        if v_row["status"] in ("Pending", "Rejected"):
            return jsonify({"error": f"Cannot Check Out a visitor with status '{v_row['status']}'"}), 400
        if v_row["status"] == "Checked Out":
            return jsonify({"visitor": _serialize_visitor(v_row)})

        actor_name = user.get("full_name") or user["username"]
        cur.execute(
            """
            UPDATE visitor_passes
               SET status='Checked Out', checked_out_by=%s, checked_out_at=NOW(), updated_at=NOW()
             WHERE id=%s AND org_id=%s
            RETURNING *
            """,
            (actor_name, vid, oid),
        )
        updated = cur.fetchone()

    users = _get_org_state(conn, oid, "manual_users", []) or []
    targets, tgt_dept, dept_bcast = resolve_notification_targets(
        users,
        target_username=updated.get("host_username") or "",
        target_department=updated.get("department") or "",
        factory=updated.get("factory", ""),
        include_security=True,
        fallback_admin_if_no_security=False,
    )
    emit_notification(
        conn,
        org_id=oid,
        kind="visitor_status",
        level="success",
        title=f"Visitor Checked Out: {updated['visitor_name']} ({vid})",
        body=f"Visit completed & exited · Recorded by {actor_name}.",
        factory=updated.get("factory", ""),
        target_department=tgt_dept,
        target_usernames=targets,
        dept_broadcast=dept_bcast,
        target_view="visitors",
        target_id=vid,
        meta={"visitor_id": vid, "step": "Checked Out"},
    )
    _audit(conn, oid, user["username"], "visitor_checkout", f"Checked out {vid}")
    _bump_rev(oid, "visitorRev")
    return jsonify({"visitor": _serialize_visitor(updated)})


def _delete_org_media_urls(org_id: str, urls: list[str]) -> None:
    """Safely delete uploaded media files belonging strictly to this organization."""
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", org_id) or DEFAULT_ORG_ID
    media_dir = (UPLOAD_DIR / safe_org / "gate_media").resolve()
    if not media_dir.exists():
        return
    for url in urls:
        u = str(url or "").strip()
        m = re.match(r"^/api/(?:public/)?gate-media/([A-Za-z0-9_-]+)/([A-Za-z0-9_.-]+)$", u)
        if not m or m.group(1) != safe_org:
            continue
        target = (media_dir / Path(m.group(2)).name).resolve()
        if target.parent == media_dir and target.is_file():
            target.unlink(missing_ok=True)


def _resolve_org_media_file(org_id: str, url: str) -> tuple[Path | None, str]:
    """Resolve a stored media URL under org gate_media to (path, ext)."""
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", org_id) or DEFAULT_ORG_ID
    m = re.match(r"^/api/(?:public/)?gate-media/([A-Za-z0-9_-]+)/([A-Za-z0-9_.-]+)$", str(url or "").strip())
    if not m or m.group(1) != safe_org:
        return None, ""
    media_dir = (UPLOAD_DIR / safe_org / "gate_media").resolve()
    target = (media_dir / Path(m.group(2)).name).resolve()
    if target.parent != media_dir or not target.is_file():
        return None, ""
    return target, target.suffix.lower().lstrip(".")


@app.delete("/api/visitors/<vid>")
@auth_required("visitors", "rw")
def api_delete_visitor(conn, org, user, vid):
    if user.get("role") != "Administrator":
        return jsonify({"error": "Only Administrators are permitted to delete visitor passes"}), 403
    oid = org["id"]
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM visitor_passes WHERE id=%s AND org_id=%s", (vid, oid))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Visitor pass not found"}), 404
        urls = [
            row.get("selfie_photo") or "",
            row.get("id_card_photo") or "",
            *(row.get("selfie_photos") or []),
            *(row.get("id_card_photos") or []),
        ]
        cur.execute("DELETE FROM visitor_passes WHERE id=%s AND org_id=%s", (vid, oid))
        cur.execute("DELETE FROM notification_events WHERE target_id=%s AND org_id=%s", (vid, oid))
    _delete_org_media_urls(oid, urls)
    _audit(conn, oid, user["username"], "delete_visitor", f"Deleted visitor pass {vid} ({row.get('visitor_name', '')})")
    _bump_rev(oid, "visitorRev", "notifRev")
    return jsonify({"ok": True, "id": vid})


@app.post("/api/public/visitors/<vid>/checkin-out")
def api_public_visitor_kiosk_action(vid):
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    action = str(data.get("action") or "checkout").lower()
    with get_conn() as conn:
        org, err = _resolve_public_org(conn, str(data.get("orgSlug") or data.get("org_slug") or ""))
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        oid = org["id"]
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM visitor_passes WHERE id=%s AND org_id=%s", (vid, oid))
            v_row = cur.fetchone()
            if not v_row:
                return jsonify({"error": "Visitor pass not found"}), 404
            if v_row["status"] in ("Pending", "Rejected"):
                return jsonify({"error": "Host approval is required first before gate check-in / check-out"}), 400
            if action == "checkin" and v_row["status"] == "Approved":
                cur.execute(
                    "UPDATE visitor_passes SET status='Checked In', checked_in_by='Gate Kiosk', checked_in_at=NOW(), updated_at=NOW() WHERE id=%s AND org_id=%s RETURNING *",
                    (vid, oid),
                )
            else:
                cur.execute(
                    "UPDATE visitor_passes SET status='Checked Out', checked_out_by='Gate Kiosk', checked_out_at=NOW(), updated_at=NOW() WHERE id=%s AND org_id=%s RETURNING *",
                    (vid, oid),
                )
            updated = cur.fetchone()
    _bump_rev(oid, "visitorRev")
    return jsonify({"visitor": _serialize_visitor(updated)})


@app.post("/api/visitors/<vid>/photos")
@auth_required("visitors", "rw")
def api_auth_append_visitor_photos(conn, org, user, vid):
    return _append_visitor_photos(conn, org["id"], vid, request.get_json(silent=True) or {})


@app.post("/api/public/visitors/<vid>/photos")
def api_public_append_visitor_photos(vid):
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    with get_conn() as conn:
        org, err = _resolve_public_org(conn, str(data.get("orgSlug") or data.get("org_slug") or ""))
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        return _append_visitor_photos(conn, org["id"], vid, data)


def _append_visitor_photos(conn, oid: str, vid: str, data: dict):
    kind = str(data.get("kind") or "selfie").lower()
    urls = [str(x).strip() for x in (data.get("urls") or []) if str(x).strip()]
    if not urls:
        return jsonify({"error": "No photo URLs provided"}), 400
    col = "id_card_photos" if kind in ("id", "idcard", "id_card") else "selfie_photos"
    single_col = "id_card_photo" if col == "id_card_photos" else "selfie_photo"
    with conn.cursor() as cur:
        cur.execute(f"SELECT {col}, {single_col} FROM visitor_passes WHERE id=%s AND org_id=%s", (vid, oid))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Visitor not found"}), 404
        merged = list(dict.fromkeys([*(row.get(col) or []), *urls]))
        primary = row.get(single_col) or merged[0]
        cur.execute(
            f"UPDATE visitor_passes SET {col}=%s::jsonb, {single_col}=%s, updated_at=NOW() WHERE id=%s AND org_id=%s RETURNING *",
            (json.dumps(merged), primary, vid, oid),
        )
        updated = cur.fetchone()
    _bump_rev(oid, "visitorRev")
    return jsonify({"visitor": _serialize_visitor(updated)})


# ---------------------------------------------------------------------------
# Material Gate Pass API (Tenant-Scoped IN / OUT + Returnable Tracker)
# ---------------------------------------------------------------------------
def _create_gate_pass(conn, org_id: str, data: dict, actor_label: str):
    material_name = str(data.get("materialName") or data.get("material_name") or "").strip()
    if not material_name:
        return None, ("Material description / name is required", 400)
    direction = str(data.get("direction") or "IN").strip().upper()
    if direction not in ("IN", "OUT"):
        direction = "IN"

    factory = str(data.get("factory") or "").strip()
    department = str(data.get("department") or "").strip()
    for_username = str(data.get("forUsername") or data.get("for_username") or "").strip()
    for_name = str(data.get("forName") or data.get("for_name") or "").strip()

    users = _get_org_state(conn, org_id, "manual_users", []) or []
    if for_username and not for_name:
        matched = next((u for u in users if str(u.get("username", "")).casefold() == for_username.casefold()), None)
        if matched:
            for_name = matched.get("full_name") or matched.get("username") or for_username

    is_returnable = bool(data.get("isReturnable") or data.get("is_returnable"))
    try:
        expected_days = max(0, int(data.get("expectedDays") or data.get("expected_days") or 0))
    except (ValueError, TypeError):
        expected_days = 0
    if is_returnable and expected_days <= 0:
        expected_days = 7

    now = datetime.now(timezone.utc)
    expected_return_at = None
    exp_raw = str(data.get("expectedReturnAt") or "").strip()
    if is_returnable:
        if exp_raw:
            try:
                expected_return_at = datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
            except ValueError:
                expected_return_at = now + timedelta(days=expected_days)
        else:
            expected_return_at = now + timedelta(days=expected_days)

    mat_photos = [str(x).strip() for x in (data.get("materialPhotos") or []) if str(x).strip()]
    mat_photo = str(data.get("materialPhoto") or (mat_photos[0] if mat_photos else "")).strip()
    if mat_photo and mat_photo not in mat_photos:
        mat_photos.insert(0, mat_photo)

    bill_photos = [str(x).strip() for x in (data.get("billPhotos") or []) if str(x).strip()]
    bill_photo = str(data.get("billPhoto") or (bill_photos[0] if bill_photos else "")).strip()
    if bill_photo and bill_photo not in bill_photos:
        bill_photos.insert(0, bill_photo)

    gp_id = _next_human_id(conn, org_id, f"GP-{direction}", "material_gate_passes")
    initial_status = "Pending Return" if is_returnable else "Recorded"

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO material_gate_passes (
                id, org_id, direction, material_type, material_name, quantity, unit,
                vehicle_no, driver_name, driver_phone, party_name, challan_no,
                factory, department, for_username, for_name,
                is_returnable, expected_days, expected_return_at,
                material_photo, material_photos, bill_photo, bill_photos,
                status, entry_time, notes, created_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s::jsonb, %s, %s::jsonb,
                %s, %s, %s, %s
            )
            RETURNING *
            """,
            (
                gp_id,
                org_id,
                direction,
                str(data.get("materialType") or "").strip(),
                material_name,
                str(data.get("quantity") or "1").strip(),
                str(data.get("unit") or "Nos").strip(),
                str(data.get("vehicleNo") or "").strip(),
                str(data.get("driverName") or "").strip(),
                str(data.get("driverPhone") or "").strip(),
                str(data.get("partyName") or "").strip(),
                str(data.get("challanNo") or "").strip(),
                factory,
                department,
                for_username,
                for_name,
                is_returnable,
                expected_days,
                expected_return_at,
                mat_photo,
                json.dumps(mat_photos),
                bill_photo,
                json.dumps(bill_photos),
                initial_status,
                now,
                str(data.get("notes") or "").strip(),
                actor_label,
            ),
        )
        row = cur.fetchone()

    targets, tgt_dept, dept_bcast = resolve_notification_targets(
        users,
        target_username=for_username,
        target_department=department,
        factory=factory,
        include_security=False,
        fallback_admin_if_no_security=(not for_username and not department),
    )
    dir_txt = "Material IN (Arrived)" if direction == "IN" else "Material OUT (Dispatched)"
    ret_txt = f" · Returnable in {expected_days}d" if is_returnable else ""
    emit_notification(
        conn,
        org_id=org_id,
        kind="material_entry",
        level="info",
        title=f"{dir_txt}: {material_name} ({gp_id})",
        body=f"Qty: {row['quantity']} {row['unit']} · Party: {row['party_name'] or 'N/A'}{ret_txt}",
        factory=factory,
        target_department=tgt_dept,
        target_usernames=targets,
        dept_broadcast=dept_bcast,
        target_view="gatepasses",
        target_id=gp_id,
        meta={"gp_id": gp_id, "direction": direction, "is_returnable": is_returnable},
    )
    _bump_rev(org_id, "gatepassRev")
    return _serialize_gatepass(row), None


@app.get("/api/public/gate-passes")
def api_public_list_gate_passes():
    ensure_db_ready()
    with get_conn() as conn:
        org, err = _resolve_public_org(conn)
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        oid = org["id"]
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM material_gate_passes WHERE org_id=%s ORDER BY entry_time DESC LIMIT 80", (oid,))
            rows = cur.fetchall()
    return jsonify({"gatePasses": [_serialize_gatepass(r) for r in rows], "rev": _ORG_REVISIONS[oid]["gatepassRev"]})


@app.post("/api/public/gate-passes")
def api_public_create_gate_pass():
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    with get_conn() as conn:
        org, err = _resolve_public_org(conn, str(data.get("orgSlug") or data.get("org_slug") or ""))
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        created, create_err = _create_gate_pass(conn, org["id"], data, "Gate Kiosk")
        if create_err:
            return jsonify({"error": create_err[0]}), create_err[1]
    return jsonify({"gatePass": created}), 201


@app.get("/api/gate-passes")
@auth_required("gatepasses", "ro")
def api_list_gate_passes(conn, org, user):
    oid = org["id"]
    factory = str(request.args.get("factory") or "").strip()
    direction = str(request.args.get("direction") or "").strip().upper()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM material_gate_passes WHERE org_id=%s ORDER BY entry_time DESC LIMIT 300", (oid,))
        rows = cur.fetchall()
    items = [_serialize_gatepass(r) for r in rows]
    if factory:
        items = [g for g in items if not g["factory"] or g["factory"].casefold() == factory.casefold()]
    if direction in ("IN", "OUT"):
        items = [g for g in items if g["direction"] == direction]
    return jsonify({"gatePasses": items, "rev": _ORG_REVISIONS[oid]["gatepassRev"]})


@app.post("/api/gate-passes")
@auth_required("gatepasses", "rw")
def api_create_gate_pass(conn, org, user):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    created, err = _create_gate_pass(conn, oid, data, user.get("full_name") or user["username"])
    if err:
        return jsonify({"error": err[0]}), err[1]
    _audit(conn, oid, user["username"], "create_gatepass", f"Created material gate pass {created['id']}")
    return jsonify({"gatePass": created}), 201


def _complete_gatepass_return(conn, oid: str, gid: str, actor: str, note: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE material_gate_passes
               SET status='Returned', returned_at=NOW(), return_note=%s, verified_by=%s, verified_at=NOW(), updated_at=NOW()
             WHERE id=%s AND org_id=%s
            RETURNING *
            """,
            (note, actor, gid, oid),
        )
        row = cur.fetchone()
    if not row:
        return None
    users = _get_org_state(conn, oid, "manual_users", []) or []
    targets, tgt_dept, dept_bcast = resolve_notification_targets(
        users,
        target_username=row.get("for_username") or "",
        target_department=row.get("department") or "",
        factory=row.get("factory", ""),
        include_security=True,
        fallback_admin_if_no_security=False,
    )
    emit_notification(
        conn,
        org_id=oid,
        kind="material_entry",
        level="success",
        title=f"Returnable Material Closed: {row['material_name']} ({gid})",
        body=f"Marked Returned by {actor}" + (f" · Note: {note}" if note else ""),
        factory=row.get("factory", ""),
        target_department=tgt_dept,
        target_usernames=targets,
        dept_broadcast=dept_bcast,
        target_view="gatepasses",
        target_id=gid,
        meta={"gp_id": gid, "returned": True},
    )
    _audit(conn, oid, actor, "return_gatepass", f"Returned {gid}")
    _bump_rev(oid, "gatepassRev")
    return _serialize_gatepass(row)


@app.post("/api/gate-passes/<gid>/return")
@auth_required("gatepasses", "rw")
def api_auth_return_gate_pass(conn, org, user, gid):
    data = request.get_json(silent=True) or {}
    note = str(data.get("note") or data.get("returnNote") or "").strip()
    actor = user.get("full_name") or user["username"]
    gp = _complete_gatepass_return(conn, org["id"], gid, actor, note)
    if not gp:
        return jsonify({"error": "Material gate pass not found"}), 404
    return jsonify({"gatePass": gp})


@app.post("/api/public/gate-passes/<gid>/return")
def api_public_return_gate_pass(gid):
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    note = str(data.get("note") or data.get("returnNote") or "").strip()
    with get_conn() as conn:
        org, err = _resolve_public_org(conn, str(data.get("orgSlug") or data.get("org_slug") or ""))
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        gp = _complete_gatepass_return(conn, org["id"], gid, "Gate Kiosk", note)
        if not gp:
            return jsonify({"error": "Material gate pass not found"}), 404
    return jsonify({"gatePass": gp})


@app.delete("/api/gate-passes/<gid>")
@auth_required("gatepasses", "rw")
def api_delete_gate_pass(conn, org, user, gid):
    if user.get("role") != "Administrator":
        return jsonify({"error": "Only Administrators are permitted to delete material gate passes"}), 403
    oid = org["id"]
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM material_gate_passes WHERE id=%s AND org_id=%s", (gid, oid))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Material gate pass not found"}), 404
        urls = [
            row.get("material_photo") or "",
            row.get("bill_photo") or "",
            *(row.get("material_photos") or []),
            *(row.get("bill_photos") or []),
        ]
        cur.execute("DELETE FROM material_gate_passes WHERE id=%s AND org_id=%s", (gid, oid))
        cur.execute("DELETE FROM notification_events WHERE target_id=%s AND org_id=%s", (gid, oid))
    _delete_org_media_urls(oid, urls)
    _audit(conn, oid, user["username"], "delete_gatepass", f"Deleted material gate pass {gid} ({row.get('material_name', '')})")
    _bump_rev(oid, "gatepassRev", "notifRev")
    return jsonify({"ok": True, "id": gid})


@app.post("/api/gate-passes/<gid>/status")
@auth_required("gatepasses", "rw")
def api_update_gate_pass_status(conn, org, user, gid):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    status = str(data.get("status") or "Verified").strip()
    actor = user.get("full_name") or user["username"]
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE material_gate_passes SET status=%s, verified_by=%s, verified_at=NOW(), updated_at=NOW() WHERE id=%s AND org_id=%s RETURNING *",
            (status, actor, gid, oid),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Material gate pass not found"}), 404
    _audit(conn, oid, user["username"], "gatepass_status", f"{gid} -> {status}")
    _bump_rev(oid, "gatepassRev")
    return jsonify({"gatePass": _serialize_gatepass(row)})


@app.post("/api/gate-passes/<gid>/photos")
@auth_required("gatepasses", "rw")
def api_auth_append_gp_photos(conn, org, user, gid):
    return _append_gp_photos(conn, org["id"], gid, request.get_json(silent=True) or {})


@app.post("/api/public/gate-passes/<gid>/photos")
def api_public_append_gp_photos(gid):
    ensure_db_ready()
    data = request.get_json(silent=True) or {}
    with get_conn() as conn:
        org, err = _resolve_public_org(conn, str(data.get("orgSlug") or data.get("org_slug") or ""))
        if err:
            return jsonify({"error": err[0], "needOrg": err[2]}), err[1]
        return _append_gp_photos(conn, org["id"], gid, data)


def _append_gp_photos(conn, oid: str, gid: str, data: dict):
    kind = str(data.get("kind") or "material").lower()
    urls = [str(x).strip() for x in (data.get("urls") or []) if str(x).strip()]
    if not urls:
        return jsonify({"error": "No photo URLs provided"}), 400
    col = "bill_photos" if kind in ("bill", "challan", "bill_photo") else "material_photos"
    single_col = "bill_photo" if col == "bill_photos" else "material_photo"
    with conn.cursor() as cur:
        cur.execute(f"SELECT {col}, {single_col} FROM material_gate_passes WHERE id=%s AND org_id=%s", (gid, oid))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Gate pass not found"}), 404
        merged = list(dict.fromkeys([*(row.get(col) or []), *urls]))
        primary = row.get(single_col) or merged[0]
        cur.execute(
            f"UPDATE material_gate_passes SET {col}=%s::jsonb, {single_col}=%s, updated_at=NOW() WHERE id=%s AND org_id=%s RETURNING *",
            (json.dumps(merged), primary, gid, oid),
        )
        updated = cur.fetchone()
    _bump_rev(oid, "gatepassRev")
    return jsonify({"gatePass": _serialize_gatepass(updated)})


# ---------------------------------------------------------------------------
# Notifications (Strictly Tenant + User/Dept Isolated) & Sound Config
# ---------------------------------------------------------------------------
def _serialize_notif_for_user(row: dict, username: str) -> dict:
    uname_cf = username.casefold()
    read_by = [str(x).casefold() for x in (row.get("read_by") or [])]
    return {
        "id": row["id"],
        "orgId": row.get("org_id", DEFAULT_ORG_ID),
        "ts": _iso(row.get("ts")),
        "kind": row.get("kind", "info"),
        "level": row.get("level", "info"),
        "title": row.get("title", ""),
        "body": row.get("body", ""),
        "factory": row.get("factory", ""),
        "targetDepartment": row.get("target_department", ""),
        "targetUsernames": row.get("target_usernames") or [],
        "targetView": row.get("target_view", "visitors"),
        "targetId": row.get("target_id", ""),
        "meta": row.get("meta") or {},
        "read": uname_cf in read_by,
    }


@app.get("/api/notifications/history")
@auth_required()
def api_notif_history(conn, org, user):
    oid = org["id"]
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM notification_events WHERE org_id=%s ORDER BY ts DESC LIMIT 400", (oid,))
        rows = cur.fetchall()
    visible = [_serialize_notif_for_user(r, user["username"]) for r in rows if event_visible_to_user(r, user)]
    return jsonify({"notifications": visible, "unread": sum(1 for n in visible if not n["read"])})


@app.post("/api/notifications/history")
@auth_required()
def api_notif_mark_read(conn, org, user):
    oid = org["id"]
    data = request.get_json(silent=True) or {}
    action = str(data.get("action") or "read").lower()
    nid = str(data.get("id") or "").strip()
    ids = [str(x).strip() for x in (data.get("ids") or []) if str(x).strip()]
    target_id = str(data.get("targetId") or "").strip()
    uname_cf = user["username"].casefold()
    with conn.cursor() as cur:
        if ids:
            cur.execute("SELECT id, org_id, target_usernames, target_department, factory, meta, read_by FROM notification_events WHERE org_id=%s AND id = ANY(%s)", (oid, ids))
            for row in cur.fetchall():
                if event_visible_to_user(row, user):
                    rb = list(dict.fromkeys([*(row.get("read_by") or []), uname_cf]))
                    cur.execute("UPDATE notification_events SET read_by=%s::jsonb WHERE id=%s AND org_id=%s", (json.dumps(rb), row["id"], oid))
        elif target_id:
            cur.execute("SELECT id, org_id, target_usernames, target_department, factory, meta, read_by FROM notification_events WHERE org_id=%s AND target_id=%s", (oid, target_id))
            for row in cur.fetchall():
                if event_visible_to_user(row, user):
                    rb = list(dict.fromkeys([*(row.get("read_by") or []), uname_cf]))
                    cur.execute("UPDATE notification_events SET read_by=%s::jsonb WHERE id=%s AND org_id=%s", (json.dumps(rb), row["id"], oid))
        elif action in ("clear_all", "read_all") or not nid:
            cur.execute("SELECT id, org_id, target_usernames, target_department, factory, meta, read_by FROM notification_events WHERE org_id=%s ORDER BY ts DESC LIMIT 500", (oid,))
            for row in cur.fetchall():
                if event_visible_to_user(row, user):
                    rb = list(dict.fromkeys([*(row.get("read_by") or []), uname_cf]))
                    cur.execute("UPDATE notification_events SET read_by=%s::jsonb WHERE id=%s AND org_id=%s", (json.dumps(rb), row["id"], oid))
        else:
            cur.execute("SELECT read_by FROM notification_events WHERE id=%s AND org_id=%s", (nid, oid))
            row = cur.fetchone()
            if row:
                rb = list(dict.fromkeys([*(row.get("read_by") or []), uname_cf]))
                cur.execute("UPDATE notification_events SET read_by=%s::jsonb WHERE id=%s AND org_id=%s", (json.dumps(rb), nid, oid))
    _bump_rev(oid, "notifRev", usernames=[user["username"]])
    return jsonify({"ok": True})


@app.get("/api/live-alerts-feed")
@auth_required()
def api_live_alerts_feed(conn, org, user):
    oid = org["id"]
    since_ts = str(request.args.get("since") or "").strip()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM notification_events WHERE org_id=%s ORDER BY ts DESC LIMIT 50", (oid,))
        rows = cur.fetchall()
    items = []
    for r in rows:
        if not event_visible_to_user(r, user):
            continue
        ser = _serialize_notif_for_user(r, user["username"])
        if since_ts and ser["ts"] <= since_ts:
            continue
        items.append(ser)
    return jsonify({"events": items, "serverTime": datetime.now(timezone.utc).isoformat()})


@app.get("/api/live-pulse")
@auth_required()
def api_live_pulse(conn, org, user):
    oid = org["id"]
    uname_cf = user["username"].casefold()
    with conn.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(updated_at)::text, '') AS mv, COUNT(*) AS vc FROM visitor_passes WHERE org_id=%s", (oid,))
        vrow = cur.fetchone() or {}
        cur.execute("SELECT COALESCE(MAX(updated_at)::text, '') AS mg, COUNT(*) AS gc FROM material_gate_passes WHERE org_id=%s", (oid,))
        grow = cur.fetchone() or {}
        cur.execute("SELECT id, org_id, ts, factory, target_department, target_usernames, meta, read_by FROM notification_events WHERE org_id=%s ORDER BY ts DESC LIMIT 100", (oid,))
        nrows = cur.fetchall() or []
    visible_notifs = [r for r in nrows if event_visible_to_user(r, user)]
    unread_ids = [r["id"] for r in visible_notifs if uname_cf not in [str(x).casefold() for x in (r.get("read_by") or [])]]
    latest_notif_id = visible_notifs[0]["id"] if visible_notifs else ""
    revs = _ORG_REVISIONS[oid]
    return jsonify(
        {
            "dataRev": revs["dataRev"],
            "visitorRev": f"{revs['visitorRev']}|{vrow.get('mv','')}|{vrow.get('vc',0)}",
            "gatepassRev": f"{revs['gatepassRev']}|{grow.get('mg','')}|{grow.get('gc',0)}",
            "notifRev": f"{int(_USER_NOTIF_REV.get((oid, uname_cf), 0)) + int(revs['notifRev'])}|{latest_notif_id}|{len(unread_ids)}",
            "unreadCount": len(unread_ids),
            "serverTime": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.get("/api/live-stream")
@auth_required()
def api_live_stream(conn, org, user):
    oid = org["id"]
    sid = uuid.uuid4().hex
    q_obj: queue.Queue = queue.Queue(maxsize=100)
    with _SSE_LOCK:
        _SSE_SUBSCRIBERS[sid] = (q_obj, oid, user["username"], user.get("dept") or "", user.get("factory") or "")

    def stream():
        try:
            yield f"event: hello\ndata: {json.dumps({'ok': True, 'user': user['username'], 'org': org['slug']})}\n\n"
            while True:
                try:
                    yield q_obj.get(timeout=20)
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            with _SSE_LOCK:
                _SSE_SUBSCRIBERS.pop(sid, None)

    resp = Response(stream(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


@app.get("/api/notifications/sounds")
@app.post("/api/notifications/sounds")
@auth_required()
def api_notif_sounds(conn, org, user):
    oid = org["id"]
    if request.method == "GET":
        global_cfg = _get_org_state(conn, oid, "sound_config", dict(DEFAULT_SOUND_CONFIG)) or dict(DEFAULT_SOUND_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT prefs FROM user_notification_prefs WHERE org_id=%s AND username=%s", (oid, user["username"]))
            row = cur.fetchone()
        return jsonify({"soundConfig": global_cfg, "userPrefs": row["prefs"] if row else {}})

    data = request.get_json(silent=True) or {}
    scope = str(data.get("scope") or ("global" if user["role"] == "Administrator" and data.get("applyGlobal") else "user"))
    if scope == "global" and user["role"] == "Administrator":
        cur_cfg = _get_org_state(conn, oid, "sound_config", dict(DEFAULT_SOUND_CONFIG)) or dict(DEFAULT_SOUND_CONFIG)
        for k in ("enabled", "desktop_notifications", "volume", "visitor_entry", "visitor_status", "material_entry", "material_overdue", "quiet_hours"):
            if k in data:
                cur_cfg[k] = data[k]
        _set_org_state(conn, oid, "sound_config", cur_cfg)
        _bump_rev(oid, "dataRev")
        return jsonify({"soundConfig": cur_cfg})

    with conn.cursor() as cur:
        cur.execute("SELECT prefs FROM user_notification_prefs WHERE org_id=%s AND username=%s", (oid, user["username"]))
        row = cur.fetchone()
        prefs = dict(row["prefs"]) if row and isinstance(row["prefs"], dict) else {}
        for k in ("enabled", "desktop_notifications", "volume", "visitor_entry", "visitor_status", "material_entry", "material_overdue", "quiet_hours"):
            if k in data:
                prefs[k] = data[k]
        cur.execute(
            """
            INSERT INTO user_notification_prefs (org_id, username, prefs, updated_at)
            VALUES (%s, %s, %s::jsonb, NOW())
            ON CONFLICT (org_id, username) DO UPDATE SET prefs=EXCLUDED.prefs, updated_at=NOW()
            """,
            (oid, user["username"], json.dumps(prefs)),
        )
    return jsonify({"userPrefs": prefs})


@app.post("/api/notifications/ringtones")
@auth_required()
def api_upload_ringtone(conn, org, user):
    oid = org["id"]
    f = request.files.get("file") or (next(iter(request.files.values()), None))
    if not f:
        return jsonify({"error": "No audio file selected"}), 400
    orig = str(f.filename or "tone.mp3")
    ext = Path(orig).suffix.lower()
    if ext not in (".mp3", ".wav", ".ogg", ".m4a", ".aac", ".webm"):
        return jsonify({"error": "Supported formats: mp3, wav, ogg, m4a, aac"}), 400
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", oid) or DEFAULT_ORG_ID
    ring_dir = UPLOAD_DIR / safe_org / "ringtones"
    ring_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = re.sub(r"[^a-zA-Z0-9_-]", "", Path(orig).stem)[:32] or "ringtone"
    fname = f"{safe_stem}-{secrets.token_hex(4)}{ext}"
    f.save(ring_dir / fname)
    cfg = _get_org_state(conn, oid, "sound_config", dict(DEFAULT_SOUND_CONFIG)) or dict(DEFAULT_SOUND_CONFIG)
    tones = list(cfg.get("custom_ringtones") or [])
    entry = {"id": fname, "name": Path(orig).stem[:40] or fname, "url": f"/api/notifications/ringtones/{safe_org}/{fname}"}
    tones.append(entry)
    cfg["custom_ringtones"] = tones[-20:]
    _set_org_state(conn, oid, "sound_config", cfg)
    _bump_rev(oid, "dataRev")
    return jsonify({"ringtone": entry, "custom_ringtones": cfg["custom_ringtones"]})


@app.get("/api/notifications/ringtones/<org_id>/<path:filename>")
def api_serve_ringtone(org_id, filename):
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", org_id) or DEFAULT_ORG_ID
    safe = Path(filename).name
    ring_dir = UPLOAD_DIR / safe_org / "ringtones"
    target = (ring_dir / safe).resolve()
    if not target.exists() or target.parent != ring_dir.resolve():
        return jsonify({"error": "Ringtone not found"}), 404
    return send_from_directory(ring_dir, safe)


# ---------------------------------------------------------------------------
# Backups (Platform Archive Helpers + Org Export)
# ---------------------------------------------------------------------------
def _list_backups_resp():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in sorted(BACKUP_DIR.glob("gatepass-*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True):
        st = p.stat()
        items.append({"name": p.name, "size": st.st_size, "created_at": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()})
    return jsonify({"backups": items})


def _run_backup_resp(conn, org_id: str, actor: str):
    try:
        res = subprocess.run([sys.executable, str(APP_DIR / "backup.py"), "manual"], capture_output=True, text=True, check=True, timeout=180)
        name = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "backup created"
        _audit(conn, org_id, actor, "backup", f"Created backup {name}")
        return jsonify({"ok": True, "name": name})
    except Exception as exc:
        return jsonify({"error": f"Backup failed: {exc}"}), 500


def _download_backup_resp(name: str):
    safe = Path(name).name
    target = (BACKUP_DIR / safe).resolve()
    if not target.exists() or target.parent != BACKUP_DIR.resolve():
        return jsonify({"error": "Backup archive not found"}), 404
    return send_file(target, as_attachment=True, download_name=safe)


@app.get("/api/backups")
@auth_required("backups", "ro")
def api_org_list_backups(conn, org, user):
    """Export tenant JSON snapshot info (only Super Admin accesses full cross-org DB tarball)."""
    oid = org["id"]
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS vc FROM visitor_passes WHERE org_id=%s", (oid,))
        vc = int((cur.fetchone() or {}).get("vc", 0))
        cur.execute("SELECT COUNT(*) AS gc FROM material_gate_passes WHERE org_id=%s", (oid,))
        gc = int((cur.fetchone() or {}).get("gc", 0))
    return jsonify({"orgBackupAvailable": True, "counts": {"visitors": vc, "gatePasses": gc}})


@app.get("/api/backups/export-json")
@auth_required("backups", "ro")
def api_org_export_json(conn, org, user):
    oid = org["id"]
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM visitor_passes WHERE org_id=%s ORDER BY entry_time DESC", (oid,))
        vs = [_serialize_visitor(r) for r in (cur.fetchall() or [])]
        cur.execute("SELECT * FROM material_gate_passes WHERE org_id=%s ORDER BY entry_time DESC", (oid,))
        gs = [_serialize_gatepass(r) for r in (cur.fetchall() or [])]
    payload = {
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "organization": _serialize_org(org),
        "departments": _get_org_state(conn, oid, "departments", []),
        "factories": _get_org_state(conn, oid, "factories", []),
        "visitors": vs,
        "gatePasses": gs,
    }
    raw = json.dumps(payload, indent=2).encode("utf-8")
    resp = make_response(raw)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = f'attachment; filename="gatepass-{org["slug"]}-export.json"'
    return resp


def _prepare_export_bundle(
    conn,
    org: dict,
    *,
    scope: str = "all",
    factory: str = "",
    status_filter: str = "",
    direction_filter: str = "",
    query_str: str = "",
    base_origin: str = "",
    relative_zip_links: bool = False,
) -> tuple[bytes, list[tuple[str, bytes]]]:
    """Build Excel workbook + extracted media attachments purely within this organization."""
    oid = org["id"]
    bundled_files: list[tuple[str, bytes]] = []
    sheets: list[dict] = []
    q_low = query_str.strip().lower()

    def _process_attachments(pass_id: str, label_prefix: str, urls: list[str], img_col_1: int) -> tuple[list[dict], list[tuple[str, str]]]:
        imgs: list[dict] = []
        links: list[tuple[str, str]] = []
        for idx, u in enumerate(urls, start=1):
            disk_path, ext = _resolve_org_media_file(oid, u)
            if not disk_path:
                continue
            raw_bytes = disk_path.read_bytes()
            safe_ext = ext or "bin"
            arc_rel = f"files/{pass_id}_{label_prefix}_{idx}.{safe_ext}"
            bundled_files.append((arc_rel, raw_bytes))
            link_url = arc_rel if relative_zip_links else (f"{base_origin}{u}" if base_origin else u)
            links.append((link_url, f"{pass_id}_{label_prefix}_{idx}.{safe_ext}"))
            if not imgs and safe_ext in ("jpg", "jpeg", "png"):
                imgs.append({"col_1": img_col_1, "bytes": raw_bytes, "ext": safe_ext})
        return imgs, links

    if scope in ("all", "visitors"):
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM visitor_passes WHERE org_id=%s ORDER BY entry_time DESC", (oid,))
            v_items = [_serialize_visitor(r) for r in (cur.fetchall() or [])]
        if factory:
            v_items = [v for v in v_items if not v["factory"] or v["factory"].casefold() == factory.casefold()]
        if status_filter and status_filter != "all":
            v_items = [v for v in v_items if v["status"].casefold() == status_filter.casefold()]
        if q_low:
            v_items = [
                v for v in v_items
                if q_low in f"{v['id']} {v['visitorName']} {v['phone']} {v['company']} {v['hostName']} {v['department']}".lower()
            ]

        v_rows = []
        for v in v_items:
            s_imgs, s_links = _process_attachments(v["id"], "selfie", v.get("selfiePhotos") or [], 15)
            id_imgs, id_links = _process_attachments(v["id"], "idcard", v.get("idCardPhotos") or [], 16)
            all_links = [*s_links, *id_links]
            row_imgs = [*s_imgs, *id_imgs]
            link_cell_1 = {"hyperlink": all_links[0][0], "label": all_links[0][1]} if len(all_links) >= 1 else ""
            link_cell_2 = {"hyperlink": all_links[1][0], "label": all_links[1][1]} if len(all_links) >= 2 else ""
            extra_summary = ", ".join(lbl for _, lbl in all_links) if all_links else "No photos"
            v_rows.append(
                {
                    "cells": [
                        v["id"],
                        v["status"],
                        v["entryTime"],
                        v["visitorName"],
                        v["phone"],
                        v["company"],
                        v["purpose"],
                        v["vehicleNo"],
                        v["factory"],
                        v["department"],
                        v["hostName"] or v["hostUsername"] or "Whole Dept",
                        f"{v['approvedBy']} ({v['approvedAt']})" if v["approvedBy"] else "",
                        f"{v['checkedInBy']} ({v['checkedInAt']})" if v["checkedInAt"] else "",
                        f"{v['checkedOutBy']} ({v['checkedOutAt']})" if v["checkedOutAt"] else "",
                        "" if s_imgs else ("No photo" if not s_links else s_links[0][1]),
                        "" if id_imgs else ("No photo" if not id_links else id_links[0][1]),
                        link_cell_1,
                        link_cell_2,
                        extra_summary,
                    ],
                    "images": row_imgs,
                }
            )
        sheets.append(
            {
                "name": "Visitor Passes",
                "headers": [
                    "Pass ID", "Status", "Entry Time", "Visitor Name", "Phone", "Company", "Purpose",
                    "Vehicle No", "Factory", "Department", "Whom to Meet", "Approved By / Time",
                    "Checked In By / Time", "Checked Out By / Time",
                    "Selfie Photo", "ID Card Photo", "Photo/Doc Link 1", "Photo/Doc Link 2", "All Files",
                ],
                "col_widths": [20, 14, 22, 22, 15, 20, 22, 15, 13, 16, 20, 26, 26, 26, 16, 16, 26, 26, 30],
                "rows": v_rows,
            }
        )

    if scope in ("all", "gatepasses"):
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM material_gate_passes WHERE org_id=%s ORDER BY entry_time DESC", (oid,))
            g_items = [_serialize_gatepass(r) for r in (cur.fetchall() or [])]
        if factory:
            g_items = [g for g in g_items if not g["factory"] or g["factory"].casefold() == factory.casefold()]
        if direction_filter in ("IN", "OUT"):
            g_items = [g for g in g_items if g["direction"] == direction_filter]
        elif status_filter == "IN":
            g_items = [g for g in g_items if g["direction"] == "IN"]
        elif status_filter == "OUT":
            g_items = [g for g in g_items if g["direction"] == "OUT"]
        elif status_filter == "PENDING_RET":
            g_items = [g for g in g_items if g["isReturnable"] and not g["returnedAt"]]
        elif status_filter == "OVERDUE":
            g_items = [g for g in g_items if g["overdue"]]
        elif status_filter == "RETURNED":
            g_items = [g for g in g_items if g["returnedAt"]]
        if q_low:
            g_items = [
                g for g in g_items
                if q_low in f"{g['id']} {g['materialName']} {g['partyName']} {g['challanNo']} {g['vehicleNo']} {g['forName']} {g['department']}".lower()
            ]

        g_rows = []
        for g in g_items:
            m_imgs, m_links = _process_attachments(g["id"], "material", g.get("materialPhotos") or [], 19)
            b_imgs, b_links = _process_attachments(g["id"], "billdoc", g.get("billPhotos") or [], 20)
            all_links = [*m_links, *b_links]
            row_imgs = [*m_imgs, *b_imgs]
            link_cell_1 = {"hyperlink": all_links[0][0], "label": all_links[0][1]} if len(all_links) >= 1 else ""
            link_cell_2 = {"hyperlink": all_links[1][0], "label": all_links[1][1]} if len(all_links) >= 2 else ""
            extra_summary = ", ".join(lbl for _, lbl in all_links) if all_links else "No files"
            g_rows.append(
                {
                    "cells": [
                        g["id"],
                        g["direction"],
                        g["entryTime"],
                        g["status"],
                        g["materialName"],
                        g["quantity"],
                        g["unit"],
                        g["partyName"],
                        g["challanNo"],
                        g["vehicleNo"],
                        g["driverName"],
                        g["factory"],
                        g["department"],
                        g["forName"] or g["forUsername"] or "Whole Dept",
                        "Yes" if g["isReturnable"] else "No",
                        str(g["expectedDays"] or ""),
                        g["expectedReturnAt"],
                        g["returnedAt"],
                        "" if m_imgs else ("No photo" if not m_links else m_links[0][1]),
                        "" if b_imgs else ("No doc" if not b_links else b_links[0][1]),
                        link_cell_1,
                        link_cell_2,
                        extra_summary,
                    ],
                    "images": row_imgs,
                }
            )
        sheets.append(
            {
                "name": "Material Gate Passes",
                "headers": [
                    "Pass ID", "Dir", "Entry Time", "Status", "Material Name", "Qty", "Unit",
                    "Party Name", "Challan No", "Vehicle No", "Driver", "Factory", "Department",
                    "Recipient", "Returnable", "Expected Days", "Due Date", "Returned At",
                    "Material Photo", "Bill / Challan", "Document/Photo 1", "Document/Photo 2", "All Files",
                ],
                "col_widths": [22, 8, 22, 16, 26, 9, 9, 22, 16, 15, 16, 13, 16, 20, 11, 13, 20, 20, 16, 16, 26, 26, 30],
                "rows": g_rows,
            }
        )

    xlsx_bytes = build_xlsx_bytes(sheets)
    return xlsx_bytes, bundled_files


@app.get("/api/export/excel")
@auth_required()
def api_export_excel_or_bundle(conn, org, user):
    scope = str(request.args.get("scope") or "all").lower()
    if scope not in ("all", "visitors", "gatepasses"):
        scope = "all"
    if user["role"] != "Administrator":
        if scope in ("all", "visitors") and user["perms"].get("visitors", "none") == "none":
            return jsonify({"error": "Insufficient permission to export Visitor Passes"}), 403
        if scope in ("all", "gatepasses") and user["perms"].get("gatepasses", "none") == "none":
            return jsonify({"error": "Insufficient permission to export Material Gate Passes"}), 403

    fmt = str(request.args.get("format") or "xlsx").lower()
    factory = str(request.args.get("factory") or "").strip()
    status_f = str(request.args.get("status") or "").strip()
    dir_f = str(request.args.get("direction") or "").strip().upper()
    q_str = str(request.args.get("q") or "").strip()

    proto = request.headers.get("X-Forwarded-Proto") or request.scheme or "https"
    host = request.headers.get("X-Forwarded-Host") or request.host
    origin = f"{proto}://{host}"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    slug = org["slug"]

    xlsx_bytes, files = _prepare_export_bundle(
        conn,
        org,
        scope=scope,
        factory=factory,
        status_filter=status_f,
        direction_filter=dir_f,
        query_str=q_str,
        base_origin=origin,
        relative_zip_links=(fmt == "zip"),
    )

    if fmt == "zip":
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"Shree-GatePass-{slug}-{scope}-{stamp}.xlsx", xlsx_bytes)
            for arc_rel, fbytes in files:
                zf.writestr(arc_rel, fbytes)
        resp = make_response(zbuf.getvalue())
        resp.headers["Content-Type"] = "application/zip"
        resp.headers["Content-Disposition"] = f'attachment; filename="Shree-GatePass-{slug}-{scope}-With-Photos-{stamp}.zip"'
        return resp

    resp = make_response(xlsx_bytes)
    resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    resp.headers["Content-Disposition"] = f'attachment; filename="Shree-GatePass-{slug}-{scope}-{stamp}.xlsx"'
    return resp


# ---------------------------------------------------------------------------
# Mobile Distribution (Android APK, Tenant-Aware .mobileconfig, iOS Xcode ZIP)
# ---------------------------------------------------------------------------
@app.get("/ca.crt")
@app.get("/shree-ca.crt")
def serve_ca_cert():
    for cand in (SECRETS_DIR / "ca.crt", Path("/app/secrets/ca.crt"), SECRETS_DIR / "nginx.crt"):
        if cand.exists():
            return send_file(cand, as_attachment=True, download_name="Shree-GatePass-CA.crt", mimetype="application/x-x509-ca-cert")
    return jsonify({"error": "CA certificate not found on server yet"}), 404


def _find_apk_path() -> Path | None:
    for cand in (DOWNLOADS_DIR / "shree-gatepass.apk", DOWNLOADS_DIR / "Shree-GatePass.apk", APP_DIR / "Shree-GatePass.apk"):
        if cand.exists() and cand.stat().st_size > 10000:
            return cand
    return None


@app.get("/api/public/apk-status")
def api_apk_status():
    apk = _find_apk_path()
    ios_zip = (DOWNLOADS_DIR / "shree-gatepass-ios.zip").exists()
    org_q = str(request.args.get("org") or "").strip()
    qs = f"?org={org_q}" if org_q else ""
    return jsonify(
        {
            "apkAvailable": bool(apk),
            "apkSizeBytes": apk.stat().st_size if apk else 0,
            "apkUrl": "/download/shree-gatepass.apk",
            "iosMobileconfigUrl": f"/download/shree-gatepass-ios.mobileconfig{qs}",
            "iosZipAvailable": ios_zip,
            "iosZipUrl": "/download/shree-gatepass-ios.zip",
        }
    )


@app.get("/download/shree-gatepass.apk")
def download_android_apk():
    apk = _find_apk_path()
    if not apk:
        return jsonify({"error": "Android APK has not been packaged on this server"}), 404
    return send_file(apk, as_attachment=True, download_name="Shree-GatePass.apk", mimetype="application/vnd.android.package-archive")


@app.get("/download/shree-gatepass-ios.zip")
def download_ios_zip():
    zpath = DOWNLOADS_DIR / "shree-gatepass-ios.zip"
    if not zpath.exists():
        return jsonify({"error": "iOS Xcode project archive not found"}), 404
    return send_file(zpath, as_attachment=True, download_name="Shree-GatePass-iOS-Xcode.zip")


def build_ios_mobileconfig(server_url: str, app_name: str = "Shree GatePass", icon_bytes: bytes | None = None, ca_bytes: bytes | None = None) -> bytes:
    clean_url = server_url.rstrip("/") + "/"
    icon_b64 = base64.b64encode(icon_bytes).decode("ascii") if icon_bytes else ""
    root_uuid = str(uuid.uuid4()).upper()
    clip_uuid = str(uuid.uuid4()).upper()
    ca_uuid = str(uuid.uuid4()).upper()

    icon_block = f"      <key>Icon</key>\n      <data>\n{icon_b64}\n      </data>\n" if icon_b64 else ""
    ca_payload = ""
    if ca_bytes:
        ca_b64 = base64.b64encode(ca_bytes).decode("ascii")
        ca_payload = f"""    <dict>
      <key>PayloadCertificateFileName</key>
      <string>Shree-GatePass-CA.cer</string>
      <key>PayloadContent</key>
      <data>
{ca_b64}
      </data>
      <key>PayloadDescription</key>
      <string>Trusts Shree GatePass local HTTPS server certificate on iPhone &amp; iPad</string>
      <key>PayloadDisplayName</key>
      <string>{xml_esc.escape(app_name)} Local Root CA</string>
      <key>PayloadIdentifier</key>
      <string>com.shree.gatepass.ca</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{ca_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
"""

    xml_doc = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>FullScreen</key>
      <true/>
      <key>IgnoreManifestScope</key>
      <false/>
      <key>IsRemovable</key>
      <true/>
{icon_block}      <key>Label</key>
      <string>{xml_esc.escape(app_name)}</string>
      <key>PayloadDescription</key>
      <string>Installs {xml_esc.escape(app_name)} standalone full-screen Visitor &amp; Material GatePass app</string>
      <key>PayloadDisplayName</key>
      <string>{xml_esc.escape(app_name)} Web App</string>
      <key>PayloadIdentifier</key>
      <string>com.shree.gatepass.webclip</string>
      <key>PayloadType</key>
      <string>com.apple.webClip.managed</string>
      <key>PayloadUUID</key>
      <string>{clip_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Precomposed</key>
      <true/>
      <key>URL</key>
      <string>{xml_esc.escape(clean_url)}</string>
    </dict>
{ca_payload}  </array>
  <key>PayloadDescription</key>
  <string>One-tap install for {xml_esc.escape(app_name)} (Visitor Pass &amp; Material Gate Management)</string>
  <key>PayloadDisplayName</key>
  <string>{xml_esc.escape(app_name)}</string>
  <key>PayloadIdentifier</key>
  <string>com.shree.gatepass.profile</string>
  <key>PayloadOrganization</key>
  <string>{xml_esc.escape(app_name)}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{root_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""
    return xml_doc.encode("utf-8")


@app.get("/download/shree-gatepass-ios.mobileconfig")
def download_ios_mobileconfig():
    proto = request.headers.get("X-Forwarded-Proto") or request.scheme or "https"
    host = request.headers.get("X-Forwarded-Host") or request.host
    org_q = str(request.args.get("org") or "").strip()
    app_title = "Shree GatePass"
    path_suffix = "/"
    if org_q:
        ensure_db_ready()
        with get_conn() as conn:
            org = _find_org_by_slug_or_id(conn, org_q)
            if org:
                app_title = org["name"]
                path_suffix = f"/c/{org['slug']}/"
    base_url = f"{proto}://{host}{path_suffix}"
    icon_bytes = (STATIC_DIR / "icons" / "icon-512.png").read_bytes() if (STATIC_DIR / "icons" / "icon-512.png").exists() else None
    ca_bytes = next((c.read_bytes() for c in (SECRETS_DIR / "ca.crt", Path("/app/secrets/ca.crt")) if c.exists()), None)
    profile = build_ios_mobileconfig(base_url, app_title, icon_bytes=icon_bytes, ca_bytes=ca_bytes)
    resp = make_response(profile)
    resp.headers["Content-Type"] = "application/x-apple-aspen-config"
    resp.headers["Content-Disposition"] = 'attachment; filename="Shree-GatePass-iPhone-iPad.mobileconfig"'
    return resp


if __name__ == "__main__":
    ensure_db_ready()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), threaded=True)

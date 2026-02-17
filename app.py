# app.py — Aftab CRM (Flask + SQLite) [FINAL: register with admin password + admin CRUD + migration]
import os
import sqlite3
import secrets
import json
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, session, send_from_directory

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "aftab_crm.sqlite3")

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "adminadmin"

app = Flask(__name__, static_folder="static", static_url_path="")

# ✅ ثابت برای اینکه با ریستارت سرور، کوکی سشن بی‌خودی نپره
app.secret_key = os.environ.get("AFTAB_SECRET_KEY") or "AFTAB_CRM_FIXED_SECRET_2026"


# ---------------- DB helpers ----------------
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def table_exists(cur, name: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None

def get_columns(cur, table: str):
    cur.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in cur.fetchall()}

def safe_alter_add_column(cur, table: str, col_def: str):
    cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")

def migrate_db():
    """
    Ensures schema matches the current app version (even if DB existed before).
    Prevents sqlite OperationalError => HTTP 500.
    """
    con = db()
    cur = con.cursor()

    # ---- USERS ----
    if not table_exists(cur, "users"):
        cur.execute("""
        CREATE TABLE users (
          id TEXT PRIMARY KEY,
          company TEXT NOT NULL,
          username TEXT NOT NULL UNIQUE,
          full_name TEXT NOT NULL,
          role TEXT NOT NULL,
          email TEXT NOT NULL,
          phone TEXT NOT NULL,
          password_plain TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          is_active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
        """)
    else:
        cols = get_columns(cur, "users")
        if "company" not in cols:
            safe_alter_add_column(cur, "users", "company TEXT NOT NULL DEFAULT 'AFTAB'")
        if "full_name" not in cols:
            safe_alter_add_column(cur, "users", "full_name TEXT NOT NULL DEFAULT ''")
        if "role" not in cols:
            safe_alter_add_column(cur, "users", "role TEXT NOT NULL DEFAULT 'staff'")
        if "email" not in cols:
            safe_alter_add_column(cur, "users", "email TEXT NOT NULL DEFAULT 'unknown@local'")
        if "phone" not in cols:
            safe_alter_add_column(cur, "users", "phone TEXT NOT NULL DEFAULT '+0000000000'")
        if "password_plain" not in cols:
            safe_alter_add_column(cur, "users", "password_plain TEXT NOT NULL DEFAULT ''")
        if "password_hash" not in cols:
            safe_alter_add_column(cur, "users", "password_hash TEXT NOT NULL DEFAULT ''")
        if "is_active" not in cols:
            safe_alter_add_column(cur, "users", "is_active INTEGER NOT NULL DEFAULT 1")
        if "created_at" not in cols:
            safe_alter_add_column(cur, "users", "created_at TEXT NOT NULL DEFAULT ''")
        if "updated_at" not in cols:
            safe_alter_add_column(cur, "users", "updated_at TEXT NOT NULL DEFAULT ''")

        # migrate old "password" -> password_plain
        cols = get_columns(cur, "users")
        if "password" in cols:
            try:
                cur.execute(
                    "UPDATE users SET password_plain = COALESCE(NULLIF(password_plain,''), password) WHERE password_plain=''"
                )
            except Exception:
                pass

    # ---- LOGS ----
    if not table_exists(cur, "logs"):
        cur.execute("""
        CREATE TABLE logs (
          id TEXT PRIMARY KEY,
          company TEXT,
          username TEXT,
          role TEXT,
          type TEXT NOT NULL,
          page TEXT,
          message TEXT,
          session_token TEXT,
          created_at TEXT NOT NULL
        )
        """)
    else:
        cols = get_columns(cur, "logs")
        if "company" not in cols:
            safe_alter_add_column(cur, "logs", "company TEXT")
        if "username" not in cols:
            safe_alter_add_column(cur, "logs", "username TEXT")
        if "role" not in cols:
            safe_alter_add_column(cur, "logs", "role TEXT")
        if "page" not in cols:
            safe_alter_add_column(cur, "logs", "page TEXT")
        if "message" not in cols:
            safe_alter_add_column(cur, "logs", "message TEXT")
        if "session_token" not in cols:
            safe_alter_add_column(cur, "logs", "session_token TEXT")
        if "created_at" not in cols:
            safe_alter_add_column(cur, "logs", "created_at TEXT NOT NULL DEFAULT ''")

    con.commit()
    con.close()

def ensure_admin():
    con = db()
    cur = con.cursor()

    cur.execute("SELECT 1 FROM users WHERE username=?", (ADMIN_USERNAME,))
    if cur.fetchone() is None:
        import hashlib
        pw_hash = hashlib.sha256(ADMIN_PASSWORD.encode("utf-8")).hexdigest()
        uid = secrets.token_hex(16)
        t = now_iso()
        cur.execute("""
          INSERT INTO users (id, company, username, full_name, role, email, phone,
                             password_plain, password_hash, is_active, created_at, updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (uid, "AFTAB", ADMIN_USERNAME, "Administrator", "admin",
              "admin@local", "+0000000000", ADMIN_PASSWORD, pw_hash, 1, t, t))
        con.commit()

    con.close()

def init_db():
    migrate_db()
    ensure_admin()

def log_event(type_, message="", page=""):
    try:
        con = db()
        cur = con.cursor()
        lid = secrets.token_hex(16)
        t = now_iso()
        cur.execute("""
          INSERT INTO logs (id, company, username, role, type, page, message, session_token, created_at)
          VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            lid,
            session.get("company", ""),
            session.get("username", ""),
            session.get("role", ""),
            type_,
            page or "",
            message or "",
            session.get("session_token", ""),
            t
        ))
        con.commit()
        con.close()
    except Exception:
        pass


# ---------------- Auth guards ----------------
def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        if session.get("role") != "admin":
            return jsonify({"ok": False, "error": "forbidden"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------- Utilities ----------------
def _normalize_payload(data):
    # Fix double-stringify or wrong payload types
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}
    if not isinstance(data, dict):
        data = {}
    return data

def _create_user_from_payload(data):
    data = _normalize_payload(data)

    username = (data.get("username") or "").strip().lower()

    password_plain = data.get("passwordPlain")
    if password_plain is None:
        password_plain = data.get("password")
    password_plain = str(password_plain or "").strip()

    if not username or not password_plain:
        return ({"ok": False, "error": "missing_fields"}, 400)

    if username == ADMIN_USERNAME:
        return ({"ok": False, "error": "reserved_username"}, 409)

    company = (data.get("company") or "AFTAB").strip() or "AFTAB"
    full_name = (data.get("fullName") or data.get("full_name") or username).strip() or username
    role = (data.get("role") or "staff").strip() or "staff"
    email = (data.get("email") or "unknown@local").strip() or "unknown@local"
    phone = (data.get("phone") or "+0000000000").strip() or "+0000000000"
    is_active = 1 if bool(data.get("isActive", True)) else 0

    import hashlib
    password_hash = hashlib.sha256(password_plain.encode("utf-8")).hexdigest()

    uid = secrets.token_hex(16)
    t = now_iso()

    try:
        con = db()
        cur = con.cursor()
        cur.execute("""
          INSERT INTO users (id, company, username, full_name, role, email, phone,
                             password_plain, password_hash, is_active, created_at, updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (uid, company, username, full_name, role, email, phone,
              password_plain, password_hash, is_active, t, t))
        con.commit()
        con.close()
        log_event("CREATE_USER", f"Created user {username}", "create_user")
        return ({"ok": True, "id": uid}, 200)
    except sqlite3.IntegrityError:
        return ({"ok": False, "error": "username_exists"}, 409)


# ---------------- Static routes ----------------
@app.get("/")
def root():
    return send_from_directory(app.static_folder, "login.html")

@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory(app.static_folder, filename)


# ---------------- API ----------------
@app.get("/api/me")
def api_me():
    if not session.get("username"):
        return jsonify({"ok": True, "authenticated": False})
    return jsonify({
        "ok": True,
        "authenticated": True,
        "username": session.get("username"),
        "role": session.get("role"),
        "company": session.get("company"),
    })

@app.post("/api/login")
def api_login():
    data = _normalize_payload(request.get_json(force=True, silent=True) or {})
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "missing_fields"}), 400

    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,))
    row = cur.fetchone()
    con.close()

    if row is None:
        return jsonify({"ok": False, "error": "invalid_credentials"}), 401

    import hashlib
    pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if pw_hash != row["password_hash"]:
        return jsonify({"ok": False, "error": "invalid_credentials"}), 401

    session.clear()
    session["username"] = row["username"]
    session["role"] = row["role"]
    session["company"] = row["company"]
    session["session_token"] = secrets.token_hex(16)

    log_event("LOGIN", "Login success", "api_login")
    return jsonify({"ok": True, "username": row["username"], "role": row["role"], "company": row["company"]})

@app.post("/api/logout")
@require_login
def api_logout():
    log_event("LOGOUT", "Logout", "api_logout")
    session.clear()
    return jsonify({"ok": True})


# ✅ Public register (from login.html) with REQUIRED admin password
@app.post("/api/register")
def api_register_with_admin_password():
    data = _normalize_payload(request.get_json(force=True, silent=True) or {})

    admin_pw = str(data.get("adminPassword") or "").strip()
    if not admin_pw:
        return jsonify({"ok": False, "error": "missing_admin_password"}), 400
    if admin_pw != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "invalid_admin_password"}), 403

    payload, status = _create_user_from_payload(data)
    return jsonify(payload), status


# ---------------- Admin endpoints (for users_db.html) ----------------
@app.post("/api/admin/users")
@require_admin
def api_admin_create_user():
    data = _normalize_payload(request.get_json(force=True, silent=True) or {})
    payload, status = _create_user_from_payload(data)
    return jsonify(payload), status

@app.post("/api/admin/users/clear")
@require_admin
def api_admin_clear_users_alias():
    return api_admin_clear_users()

@app.put("/api/admin/users/<user_id>")
@require_admin
def api_admin_update_user_alias(user_id):
    return api_admin_update_user(user_id)

@app.delete("/api/admin/users/<user_id>")
@require_admin
def api_admin_delete_user_alias(user_id):
    return api_admin_delete_user(user_id)


# ---------------- Users list / update / delete / clear (admin) ----------------
@app.get("/api/users")
@require_admin
def api_users():
    con = db()
    cur = con.cursor()
    cur.execute("""
      SELECT id, company, username, full_name as fullName, role, email, phone,
             password_plain as passwordPlain, password_hash as passwordHash,
             is_active as isActive, created_at as createdAt, updated_at as updatedAt
      FROM users
      ORDER BY created_at DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return jsonify({"ok": True, "users": rows})

@app.put("/api/users/<user_id>")
@require_admin
def api_admin_update_user(user_id):
    data = _normalize_payload(request.get_json(force=True, silent=True) or {})

    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    if row is None:
        con.close()
        return jsonify({"ok": False, "error": "not_found"}), 404

    company = (data.get("company") or row["company"]).strip()
    username = (data.get("username") or row["username"]).strip().lower()
    full_name = (data.get("fullName") or row["full_name"]).strip()
    role = (data.get("role") or row["role"]).strip()
    email = (data.get("email") or row["email"]).strip()
    phone = (data.get("phone") or row["phone"]).strip()
    is_active = 1 if bool(data.get("isActive", row["is_active"])) else 0

    password_plain = data.get("passwordPlain", row["password_plain"])
    if password_plain is None:
        password_plain = row["password_plain"]
    password_plain = str(password_plain).strip()

    import hashlib
    password_hash = hashlib.sha256(password_plain.encode("utf-8")).hexdigest()
    t = now_iso()

    try:
        cur.execute("""
          UPDATE users SET
            company=?,
            username=?,
            full_name=?,
            role=?,
            email=?,
            phone=?,
            password_plain=?,
            password_hash=?,
            is_active=?,
            updated_at=?
          WHERE id=?
        """, (company, username, full_name, role, email, phone,
              password_plain, password_hash, is_active, t, user_id))
        con.commit()
        con.close()
        log_event("ADMIN_UPDATE_USER", f"Updated user {username}", "api_admin_update_user")
        return jsonify({"ok": True})
    except sqlite3.IntegrityError:
        con.close()
        return jsonify({"ok": False, "error": "username_exists"}), 409

@app.delete("/api/users/<user_id>")
@require_admin
def api_admin_delete_user(user_id):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT username FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    if row is None:
        con.close()
        return jsonify({"ok": False, "error": "not_found"}), 404
    if row["username"] == ADMIN_USERNAME:
        con.close()
        return jsonify({"ok": False, "error": "cannot_delete_admin"}), 400

    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    con.commit()
    con.close()
    log_event("ADMIN_DELETE_USER", f"Deleted user id={user_id}", "api_admin_delete_user")
    return jsonify({"ok": True})

@app.post("/api/users/clear")
@require_admin
def api_admin_clear_users():
    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM users WHERE username<>?", (ADMIN_USERNAME,))
    con.commit()
    con.close()
    log_event("ADMIN_CLEAR_USERS", "Cleared all users except admin", "api_admin_clear_users")
    return jsonify({"ok": True})


# ---------------- Logs ----------------
@app.get("/api/users/<username>/logs")
@require_admin
def api_user_logs(username):
    username = (username or "").strip().lower()
    con = db()
    cur = con.cursor()
    cur.execute("""
      SELECT id, company, username, role, type, page, message, session_token as sessionToken, created_at as createdAt
      FROM logs
      WHERE lower(username)=?
      ORDER BY created_at DESC
      LIMIT 500
    """, (username,))
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return jsonify({"ok": True, "logs": rows})


# ---------------- main ----------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="127.0.0.1", port=port, debug=True)

"""
TraceGuard Admin Portal — Standalone app on port 5001

Usage:
  python app.py                   Normal run
  python app.py --force-setup     Wipe all users via direct DB connection,
                                  then show the setup page on next browser visit.

--force-setup connects directly to PostgreSQL (same credentials the backend uses)
so it works even if you've lost or forgotten the admin password.

Environment variables (all optional):
  EDR_BACKEND        Backend URL        (default: http://localhost:8080)
  TraceGuard_ADMIN_PORT    Web UI port        (default: 5001)
  TraceGuard_ADMIN_SECRET  Flask session key  (default: random, changes on restart)
  DB_HOST            Postgres host      (default: localhost)
  DB_PORT            Postgres port      (default: 5432)
  DB_NAME            Postgres db name   (default: edr)
  DB_USER            Postgres user      (default: edr)
  DB_PASSWORD        Postgres password  (default: edr)
"""
import os, sys, argparse, requests, secrets
from flask import (Flask, render_template, jsonify, request,
                   session, redirect, url_for)
from flask_wtf.csrf import CSRFProtect
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("TraceGuard_ADMIN_SECRET") or secrets.token_hex(32)
csrf = CSRFProtect(app)
BACKEND = os.environ.get("EDR_BACKEND", "http://localhost:8080")

# ── DB config (for --force-setup only) ───────────────────────────────────────

DB_HOST = os.environ.get("DB_HOST",     "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME",     "edr")
DB_USER = os.environ.get("DB_USER",     "edr")
DB_PASS = os.environ.get("DB_PASSWORD", "edr")

# ── startup ───────────────────────────────────────────────────────────────────

def _force_reset_via_db():
    """
    Directly connects to PostgreSQL and deletes all rows from the users table.
    No JWT or admin password required — uses the DB credentials directly.
    Returns (deleted_count, error_string|None).
    """
    try:
        import psycopg2
    except ImportError:
        return 0, ("psycopg2 not installed.\n"
                   "  Run: pip install psycopg2-binary\n"
                   "  Then retry: python app.py --force-setup")

    dsn = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_USER} password={DB_PASS} sslmode=disable"
    try:
        conn = psycopg2.connect(dsn)
        conn.autocommit = False
        cur  = conn.cursor()

        # Fetch user list first so we can print names
        cur.execute("SELECT id, username, role FROM users ORDER BY created_at")
        users = cur.fetchall()

        if not users:
            conn.close()
            return 0, None

        # Print them
        print(f"  Found {len(users)} user(s):")
        for uid, uname, role in users:
            print(f"    • {uname:<22} role={role}")

        # Delete all
        cur.execute("DELETE FROM users")
        count = cur.rowcount
        conn.commit()
        conn.close()
        return count, None

    except Exception as e:
        return 0, str(e)

def _startup(force_setup=False):
    SEP = "─" * 56
    print(f"\n{SEP}")
    print(f"  TraceGuard Admin Portal")
    print(f"  Backend : {BACKEND}")
    print(SEP)

    # Check backend reachability
    try:
        r = requests.get(f"{BACKEND}/health", timeout=5)
        print(f"  Backend  : {'✓ reachable' if r.status_code == 200 else f'⚠ HTTP {r.status_code}'}")
    except Exception as e:
        print(f"  Backend  : ✗ unreachable — {e}")
        print(f"  Start the backend first, then re-run this app.")
        print(SEP + "\n")
        sys.exit(1)

    # Get setup status
    try:
        r   = requests.get(f"{BACKEND}/api/v1/setup/status", timeout=5)
        data = r.json() if r.status_code == 200 else {}
        user_count   = data.get("user_count", 0)
        setup_needed = data.get("setup_needed", True)
    except Exception as e:
        print(f"  Status   : ✗ {e}")
        print(SEP + "\n")
        return

    if not force_setup:
        if setup_needed or user_count == 0:
            print("  Users    : none — setup required")
            print(f"\n  Open http://localhost:5001 to create your admin account.")
        else:
            print(f"  Users    : {user_count} user(s) in backend")
            print(f"\n  Open http://localhost:5001 to sign in.")
            print(f"  To reset: python app.py --force-setup")
        print(SEP + "\n")
        return

    # ── --force-setup ─────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  --force-setup: delete ALL users via direct DB connection")
    print(f"  DB: {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(SEP)

    if setup_needed or user_count == 0:
        print("  No users found — nothing to reset.")
        print("  Open http://localhost:5001 to run first-time setup.")
        print(SEP + "\n")
        return

    print(f"  {user_count} user(s) will be permanently deleted.\n")
    try:
        confirm = input("  Type  yes  to confirm: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = ""

    if confirm != "yes":
        print("  Aborted — no users were deleted.")
        print(SEP + "\n")
        return

    print("  Deleting…", end=" ", flush=True)
    count, err = _force_reset_via_db()
    if err:
        print(f"\n  ✗ {err}")
    else:
        print(f"✓  {count} user(s) deleted.")
        print("  Open http://localhost:5001 — setup page will appear.")
    print(SEP + "\n")

# ── backend helper ────────────────────────────────────────────────────────────

def _headers():
    t = session.get("token", "")
    h = {"Content-Type": "application/json"}
    if t:
        h["Authorization"] = f"Bearer {t}"
    return h

def _backend(path, method="GET", body=None, timeout=8):
    url = BACKEND + path
    qs  = request.query_string.decode()
    if qs:
        url += "?" + qs
    try:
        r = requests.request(method, url, json=body, headers=_headers(), timeout=timeout)
        try:
            data = r.json()
        except Exception:
            data = {"error": r.text or "empty response"}
        return r.status_code, data
    except requests.exceptions.ConnectionError:
        return 503, {"error": f"Cannot reach backend at {BACKEND}"}
    except Exception as e:
        return 500, {"error": str(e)}

def _setup_status():
    """Returns (setup_needed: bool, error: str|None)."""
    try:
        r = requests.get(f"{BACKEND}/api/v1/setup/status", timeout=5)
        if r.status_code == 200:
            d = r.json()
            return d.get("setup_needed", True), None
        return True, f"Backend returned HTTP {r.status_code}"
    except requests.exceptions.ConnectionError:
        return False, f"Cannot reach backend at {BACKEND}. Is it running?"
    except Exception as e:
        return False, str(e)

# ── decorators ────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthenticated"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper

# ── web routes ────────────────────────────────────────────────────────────────

@app.route("/")
def root():
    setup_needed, err = _setup_status()
    if err:
        return render_template("error.html", message=err), 503
    if setup_needed:
        return redirect(url_for("setup_page"))
    if session.get("logged_in"):
        return redirect(url_for("portal"))
    return redirect(url_for("login_page"))

@app.route("/setup", methods=["GET"])
def setup_page():
    setup_needed, err = _setup_status()
    if err:
        return render_template("error.html", message=err), 503
    if not setup_needed:
        return redirect(url_for("login_page"))
    return render_template("setup.html")

@app.route("/setup", methods=["POST"])
def do_setup():
    setup_needed, err = _setup_status()
    if err:
        return render_template("setup.html", error=err)
    if not setup_needed:
        return redirect(url_for("login_page"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm",  "")

    if not username:
        return render_template("setup.html", error="Username is required.", username=username)
    if len(password) < 8:
        return render_template("setup.html",
                               error="Password must be at least 8 characters.",
                               username=username)
    if password != confirm:
        return render_template("setup.html", error="Passwords do not match.", username=username)

    try:
        r = requests.post(
            f"{BACKEND}/api/v1/setup",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        data = r.json()
    except requests.exceptions.ConnectionError:
        return render_template("setup.html",
                               error=f"Cannot reach backend at {BACKEND}.",
                               username=username)
    except Exception as e:
        return render_template("setup.html", error=str(e), username=username)

    if r.status_code not in (200, 201):
        return render_template("setup.html",
                               error=data.get("error", f"Backend error {r.status_code}"),
                               username=username)
    return redirect(url_for("login_page", setup="1"))

@app.route("/login", methods=["GET"])
def login_page():
    setup_needed, err = _setup_status()
    if err:
        return render_template("error.html", message=err), 503
    if setup_needed:
        return redirect(url_for("setup_page"))
    if session.get("logged_in"):
        return redirect(url_for("portal"))
    return render_template("login.html",
                           error=request.args.get("error"),
                           setup_done=request.args.get("setup"))

@app.route("/login", methods=["POST"])
def do_login():
    u = request.form.get("username", "").strip()
    p = request.form.get("password", "")
    try:
        r = requests.post(
            f"{BACKEND}/api/v1/auth/login",
            json={"username": u, "password": p},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        data = r.json()
    except requests.exceptions.ConnectionError:
        return render_template("login.html", error="backend", backend_url=BACKEND)
    except Exception as e:
        return render_template("login.html", error="backend", backend_url=str(e))

    if r.status_code == 200:
        user = data.get("user", {})
        if user.get("role") != "admin":
            return render_template("login.html", error="noadmin")
        session.permanent    = True
        session["logged_in"] = True
        session["username"]  = user["username"]
        session["role"]      = user["role"]
        session["user_id"]   = user["id"]
        session["token"]     = data["token"]
        return redirect(url_for("portal"))
    return render_template("login.html", error="invalid")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/portal")
@login_required
def portal():
    return render_template("portal.html",
                           username=session.get("username", ""),
                           backend=BACKEND)

# ── API proxies ───────────────────────────────────────────────────────────────

@app.route("/api/setup-status")
def api_setup_status():
    setup_needed, err = _setup_status()
    if err:
        return jsonify({"error": err, "setup_needed": False}), 503
    return jsonify({"setup_needed": setup_needed})

@app.route("/api/users", methods=["GET"])
@login_required
def api_list_users():
    s, d = _backend("/api/v1/admin/users")
    return jsonify(d), s

@app.route("/api/users", methods=["POST"])
@login_required
def api_create_user():
    s, d = _backend("/api/v1/admin/users", "POST", request.get_json())
    return jsonify(d), s

@app.route("/api/users/<uid>", methods=["GET"])
@login_required
def api_get_user(uid):
    s, d = _backend(f"/api/v1/admin/users/{uid}")
    return jsonify(d), s

@app.route("/api/users/<uid>", methods=["PATCH"])
@login_required
def api_update_user(uid):
    s, d = _backend(f"/api/v1/admin/users/{uid}", "PATCH", request.get_json())
    return jsonify(d), s

@app.route("/api/users/<uid>", methods=["DELETE"])
@login_required
def api_delete_user(uid):
    s, d = _backend(f"/api/v1/admin/users/{uid}", "DELETE")
    return jsonify(d), s

@app.route("/api/users/<uid>/reset-password", methods=["POST"])
@login_required
def api_reset_password(uid):
    s, d = _backend(f"/api/v1/admin/users/{uid}/reset-password", "POST", request.get_json())
    return jsonify(d), s

@app.route("/api/keys", methods=["GET"])
@login_required
def api_list_keys():
    s, d = _backend("/api/v1/admin/keys")
    return jsonify(d), s

@app.route("/api/keys", methods=["POST"])
@login_required
def api_create_key():
    s, d = _backend("/api/v1/admin/keys", "POST", request.get_json())
    return jsonify(d), s

@app.route("/api/keys/<kid>/revoke", methods=["POST"])
@login_required
def api_revoke_key(kid):
    s, d = _backend(f"/api/v1/admin/keys/{kid}/revoke", "POST")
    return jsonify(d), s

@app.route("/api/keys/<kid>", methods=["DELETE"])
@login_required
def api_delete_key(kid):
    s, d = _backend(f"/api/v1/admin/keys/{kid}", "DELETE")
    return jsonify(d), s

@app.route("/api/audit")
@login_required
def api_audit():
    s, d = _backend("/api/v1/admin/audit")
    return jsonify(d), s

# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TraceGuard Admin Portal")
    parser.add_argument("--force-setup", action="store_true",
                        help="Delete all users via direct DB and force first-run setup")
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("TraceGuard_ADMIN_PORT", 5001)))
    args = parser.parse_args()

    _startup(force_setup=args.force_setup)

    print(f"Starting on http://0.0.0.0:{args.port}\n")
    app.run(host="0.0.0.0", port=args.port, debug=False)

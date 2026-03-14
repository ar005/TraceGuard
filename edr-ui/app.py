"""
TraceGuard Web UI
Run:  pip install flask requests && python app.py
Open: http://localhost:5000

Auth: Login via POST /api/v1/auth/login on the backend.
      All proxy requests forward the session JWT as Bearer token.
      If the backend returns 401 the session is cleared and the
      user is redirected to /login.

      Users are created in the Admin Portal (http://localhost:5001).
      Both admin and analyst roles can log in here.
"""
import os, requests, secrets
from flask import (Flask, render_template, jsonify, request,
                   session, redirect, url_for)
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("EDR_SECRET") or secrets.token_hex(32)

BACKEND = os.environ.get("EDR_BACKEND", "http://localhost:8080")

# ── auth helpers ──────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in") or not session.get("token"):
            # Clear any stale pre-JWT session
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthenticated"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper

def _headers():
    h = {"Content-Type": "application/json"}
    t = session.get("token", "")
    if t:
        h["Authorization"] = f"Bearer {t}"
    return h

# ── login / logout ────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET"])
def login_page():
    if session.get("logged_in") and session.get("token"):
        return redirect(url_for("index"))
    error = request.args.get("error")
    return render_template("login.html", error=error)

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
        if r.status_code == 200:
            data = r.json()
            session.clear()
            session.permanent   = True
            session["logged_in"] = True
            session["username"]  = data["user"]["username"]
            session["role"]      = data["user"]["role"]
            session["user_id"]   = data["user"]["id"]
            session["token"]     = data["token"]
            return redirect(url_for("index"))
        # Backend returned non-200 — wrong password
        return redirect(url_for("login_page", error="1"))
    except requests.exceptions.ConnectionError:
        return redirect(url_for("login_page", error="backend"))
    except Exception:
        return redirect(url_for("login_page", error="1"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# ── main UI ───────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html", backend=BACKEND,
                           username=session.get("username", ""),
                           role=session.get("role", ""))

# ── proxy helper ──────────────────────────────────────────────────────────────

def proxy(path, method="GET", body=None):
    url = BACKEND + path
    qs  = request.query_string.decode()
    if qs:
        url += "?" + qs
    try:
        r = requests.request(method, url, json=body, headers=_headers(), timeout=10)
        # If backend says unauthorized, clear session and tell the UI
        if r.status_code == 401:
            session.clear()
            return jsonify({"error": "session expired — please log in again"}), 401
        return jsonify(r.json()), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot reach backend at {BACKEND}"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── proxy routes ──────────────────────────────────────────────────────────────

@app.route("/api/health")
@login_required
def health(): return proxy("/health")

@app.route("/api/dashboard")
@login_required
def dashboard(): return proxy("/api/v1/dashboard")

@app.route("/api/agents")
@login_required
def agents(): return proxy("/api/v1/agents")

@app.route("/api/agents/<aid>")
@login_required
def agent(aid): return proxy(f"/api/v1/agents/{aid}")

@app.route("/api/events")
@login_required
def events(): return proxy("/api/v1/events")

@app.route("/api/events/<eid>")
@login_required
def event_detail(eid): return proxy(f"/api/v1/events/{eid}")

@app.route("/api/alerts")
@login_required
def alerts(): return proxy("/api/v1/alerts")

@app.route("/api/alerts/<aid>", methods=["GET", "PATCH"])
@login_required
def alert(aid):
    return proxy(f"/api/v1/alerts/{aid}", request.method,
                 request.get_json() if request.method == "PATCH" else None)

@app.route("/api/alerts/<aid>/events")
@login_required
def alert_events(aid): return proxy(f"/api/v1/alerts/{aid}/events")

@app.route("/api/rules", methods=["GET", "POST"])
@login_required
def rules():
    return proxy("/api/v1/rules", request.method,
                 request.get_json() if request.method == "POST" else None)

@app.route("/api/rules/reload", methods=["POST"])
@login_required
def rules_reload(): return proxy("/api/v1/rules/reload", "POST")

@app.route("/api/rules/<rid>", methods=["GET", "PUT", "DELETE"])
@login_required
def rule(rid):
    body = request.get_json() if request.method in ("PUT", "POST") else None
    return proxy(f"/api/v1/rules/{rid}", request.method, body)

@app.route("/api/events/inject", methods=["POST"])
@login_required
def inject(): return proxy("/api/v1/events/inject", "POST", request.get_json())

if __name__ == "__main__":
    port = int(os.environ.get("EDR_UI_PORT", 5000))
    print(f"  TraceGuard UI  \u2192  http://localhost:{port}")
    print(f"  Proxying to      \u2192  {BACKEND}")
    app.run(host="0.0.0.0", port=port, debug=True)

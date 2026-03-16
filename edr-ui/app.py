"""
TraceGuard Web UI
Run:  pip install flask requests && python app.py
Open: http://localhost:5000
"""
import os, requests, secrets
from flask import (Flask, render_template, jsonify, request,
                   Response, session, redirect, url_for)
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("EDR_SECRET") or secrets.token_hex(32)

BACKEND = os.environ.get("EDR_BACKEND", "http://localhost:8080")

# Persistent connection pool — reuses TCP connections to the backend
_session = requests.Session()
_adapter = requests.adapters.HTTPAdapter(
    pool_connections=8,
    pool_maxsize=32,
    max_retries=0,
)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)

# ── auth helpers ──────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in") or not session.get("token"):
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
    return render_template("login.html",
                           error=request.args.get("error"),
                           setup_done=request.args.get("setup"))

@app.route("/login", methods=["POST"])
def do_login():
    u = request.form.get("username", "").strip()
    p = request.form.get("password", "")
    try:
        r = _session.post(
            f"{BACKEND}/api/v1/auth/login",
            json={"username": u, "password": p},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json()
            session.clear()
            session.permanent    = True
            session["logged_in"] = True
            session["username"]  = data["user"]["username"]
            session["role"]      = data["user"]["role"]
            session["user_id"]   = data["user"]["id"]
            session["token"]     = data["token"]
            return redirect(url_for("index"))
        return redirect(url_for("login_page", error="1"))
    except requests.exceptions.ConnectionError:
        return redirect(url_for("login_page", error="backend"))
    except Exception:
        return redirect(url_for("login_page", error="1"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/api/auth/refresh", methods=["POST"])
@login_required
def refresh_token():
    try:
        r = _session.post(
            f"{BACKEND}/api/v1/auth/refresh",
            headers=_headers(),
            timeout=5,
        )
        if r.status_code == 200:
            session["token"] = r.json()["token"]
            return jsonify({"ok": True})
        session.clear()
        return jsonify({"ok": False}), 401
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── main UI ───────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html", backend=BACKEND,
                           username=session.get("username", ""),
                           role=session.get("role", ""))

# ── proxy helper ──────────────────────────────────────────────────────────────

def proxy(path, method="GET", body=None):
    """Forward a request to the backend and stream the response back.
    Uses the persistent connection pool. Skips double JSON parse by
    streaming the raw response body directly."""
    url = BACKEND + path
    qs  = request.query_string.decode()
    if qs:
        url += "?" + qs
    try:
        r = _session.request(
            method, url,
            json=body,
            headers=_headers(),
            timeout=10,
            stream=True,          # don't buffer entire response in memory
        )
        if r.status_code == 401:
            session.clear()
            return jsonify({"error": "session expired — please log in again"}), 401
        # Stream raw bytes straight back — no JSON parse/re-serialize overhead
        content_type = r.headers.get("Content-Type", "application/json")
        return Response(
            r.iter_content(chunk_size=None),
            status=r.status_code,
            content_type=content_type,
        )
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot reach backend at {BACKEND}"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── diagnostic ────────────────────────────────────────────────────────────────

@app.route("/api/diag")
def diag():
    results = {}
    tok = session.get("token", "")
    endpoints = [("/health", "GET", None, False)]
    if tok:
        endpoints += [("/api/v1/me", "GET", None, True),
                      ("/api/v1/dashboard", "GET", None, True)]
    for path, method, body, auth in endpoints:
        hdrs = {"Content-Type": "application/json"}
        if auth and tok:
            hdrs["Authorization"] = f"Bearer {tok}"
        try:
            r = _session.request(method, BACKEND + path, json=body,
                                 headers=hdrs, timeout=5)
            try: rb = r.json()
            except: rb = r.text[:200]
            results[path] = {"status": r.status_code, "body": rb}
        except Exception as e:
            results[path] = {"status": "ERROR", "body": str(e)}
    return jsonify({
        "backend": BACKEND,
        "session_logged_in": session.get("logged_in", False),
        "session_has_token": bool(tok),
        "results": results,
    })

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

@app.route("/api/agents/<aid>", methods=["GET", "PATCH"])
@login_required
def agent(aid):
    body = request.get_json() if request.method == "PATCH" else None
    return proxy(f"/api/v1/agents/{aid}", request.method, body)

@app.route("/api/alerts/<aid>/explain", methods=["POST"])
@login_required
def alert_explain(aid): return proxy(f"/api/v1/alerts/{aid}/explain", "POST")

@app.route("/api/settings/retention", methods=["GET", "POST"])
@login_required
def settings_retention():
    body = request.get_json() if request.method == "POST" else None
    return proxy("/api/v1/settings/retention", request.method, body)

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

@app.route("/api/alerts/<aid>/timeline")
@login_required
def alert_timeline(aid): return proxy(f"/api/v1/alerts/{aid}/timeline")

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

@app.route("/api/rules/<rid>/backtest", methods=["POST"])
@login_required
def rule_backtest(rid):
    return proxy(f"/api/v1/rules/{rid}/backtest", "POST", request.get_json())

@app.route("/api/events/inject", methods=["POST"])
@login_required
def inject(): return proxy("/api/v1/events/inject", "POST", request.get_json())

@app.route("/api/suppressions", methods=["GET"])
@login_required
def suppressions(): return proxy("/api/v1/suppressions")

@app.route("/api/suppressions", methods=["POST"])
@login_required
def create_suppression():
    return proxy("/api/v1/suppressions", "POST", request.get_json())

@app.route("/api/suppressions/<sid>", methods=["PUT", "DELETE"])
@login_required
def suppression(sid):
    body = request.get_json() if request.method == "PUT" else None
    return proxy(f"/api/v1/suppressions/{sid}", request.method, body)

if __name__ == "__main__":
    port = int(os.environ.get("EDR_UI_PORT", 5000))
    print(f"  TraceGuard UI  \u2192  http://localhost:{port}")
    print(f"  Proxying to      \u2192  {BACKEND}")
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)

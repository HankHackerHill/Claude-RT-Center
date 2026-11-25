#!/usr/bin/env bash
# Stage 1 bring-up: range + Suricata + Wazuh single-node (upstream repo, pinned tag, layered with our override).
# Idempotent: safe to re-run. Run from anywhere:  ./scripts/bootstrap.sh
#
# Optional hooks (generic; used e.g. by restricted CI/sandbox hosts, never needed on a normal Linux box):
#   CC_COMPOSE_EXTRA   colon-separated extra compose files layered over the Wazuh stack (e.g. lower ulimits)
#   CC_CERTGEN_ARGS    extra args for the one-shot cert generator `docker compose run` (e.g. a CA bundle mount)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
export CC_ROOT="$ROOT"

die() { echo "[bootstrap] ERROR: $*" >&2; exit 1; }
log() { echo "[bootstrap] $*"; }

# ---------- 0. config ----------
[[ -f .env ]] || die ".env missing: cp .env.example .env (secrets left empty are generated)"
set -a; source .env; set +a
for v in WAZUH_VERSION SURICATA_TAG JUICE_TAG; do [[ -n "${!v:-}" ]] || die "$v is empty in .env"; done
[[ "$WAZUH_VERSION" =~ ^v4\.[0-9]+\.[0-9]+$ ]] || die "WAZUH_VERSION must look like v4.x.y (got '$WAZUH_VERSION')"
[[ "$SURICATA_TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "SURICATA_TAG must be a full x.y.z tag (got '$SURICATA_TAG')"
[[ "$JUICE_TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "JUICE_TAG must be a numbered release (got '$JUICE_TAG')"

command -v docker >/dev/null || die "docker not installed"
cv=$(docker compose version --short 2>/dev/null) || die "docker compose v2 plugin not installed"
python3 - "$cv" <<'EOF' || die "docker compose >= 2.24.4 required for !override in wazuh/compose.override.yml (have $cv)"
import re, sys
v = tuple(int(x) for x in re.findall(r"\d+", sys.argv[1])[:3])
sys.exit(0 if v >= (2, 24, 4) else 1)
EOF

# ---------- 1. kernel setting required by the OpenSearch-based indexer ----------
cur=$(sysctl -n vm.max_map_count)
if (( cur < 262144 )); then
  log "raising vm.max_map_count $cur -> 262144 (needs sudo; persisted in /etc/sysctl.d/99-wazuh.conf)"
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null
fi

# ---------- 2. upstream wazuh-docker at the pinned tag ----------
if [[ ! -d wazuh-docker ]]; then
  git clone --depth 1 --branch "$WAZUH_VERSION" https://github.com/wazuh/wazuh-docker.git
else
  have=$(git -C wazuh-docker describe --tags --exact-match 2>/dev/null || echo unknown)
  [[ "$have" == "$WAZUH_VERSION" ]] || die "wazuh-docker/ is at '$have', .env wants '$WAZUH_VERSION': remove the dir or fix .env"
fi
SN="$ROOT/wazuh-docker/single-node"
WZ=(docker compose --env-file "$ROOT/.env" -f docker-compose.yml -f "$ROOT/wazuh/compose.override.yml")
if [[ -n "${CC_COMPOSE_EXTRA:-}" ]]; then
  IFS=: read -ra extra <<< "$CC_COMPOSE_EXTRA"
  for f in "${extra[@]}"; do [[ -f "$f" ]] || die "CC_COMPOSE_EXTRA file not found: $f"; WZ+=(-f "$f"); done
fi
mkdir -p data/suricata/log data/suricata/lib data/wazuh

# ---------- 3. credentials before first boot (never run with upstream defaults) ----------
docker pull -q "wazuh/wazuh-indexer:${WAZUH_VERSION#v}" >/dev/null
python3 scripts/gen_secrets.py
set -a; source .env; set +a   # pick up generated values

# ---------- 4. certificates (must be complete BEFORE any `up`) ----------
CERTS="$SN/config/wazuh_indexer_ssl_certs"
NEED=(root-ca.pem root-ca-manager.pem admin.pem admin-key.pem wazuh.indexer.pem wazuh.indexer-key.pem
      wazuh.manager.pem wazuh.manager-key.pem wazuh.dashboard.pem wazuh.dashboard-key.pem)
if [[ ! -f "$CERTS/root-ca.pem" ]]; then
  log "generating indexer certificates"
  certgen=()
  [[ -n "${CC_CERTGEN_ARGS:-}" ]] && read -ra certgen <<< "$CC_CERTGEN_ARGS"
  (cd "$SN" && docker compose -f generate-indexer-certs.yml run --rm "${certgen[@]}" generator)
fi
for f in "${NEED[@]}"; do
  # A missing bind-mount source makes Docker create a DIRECTORY at that path; certs are then permanently wrong.
  [[ -f "$CERTS/$f" ]] || die "certificate $CERTS/$f missing or not a regular file. Run: (cd $SN && ${WZ[*]} down) && rm -rf $CERTS && re-run bootstrap"
done

# ---------- 5. manager ossec.conf = upstream + CC rule dir + eve.json localfile ----------
python3 scripts/gen_manager_conf.py "$SN/config/wazuh_cluster/wazuh_manager.conf" data/wazuh/ossec.conf

# ---------- 6. range + Suricata ----------
docker compose --env-file .env -f range/compose.yml up -d --build
log "updating Suricata ET Open ruleset (best effort)"
if docker compose --env-file .env -f range/compose.yml exec -T suricata suricata-update -f; then
  docker compose --env-file .env -f range/compose.yml restart suricata
else
  log "WARN: suricata-update failed (no internet?): CC local rules still load"
fi

# ---------- 7. Wazuh ----------
(cd "$SN" && "${WZ[@]}" up -d)
MGR=$(cd "$SN" && "${WZ[@]}" ps -q wazuh.manager)
[[ -n "$MGR" ]] || die "wazuh.manager container not found"
wait_manager() {
  log "waiting for wazuh-analysisd"
  for _ in $(seq 1 60); do
    # capture first: `status` exits non-zero when optional daemons are off, and grep -q under pipefail SIGPIPEs it
    st=$(docker exec "$MGR" /var/ossec/bin/wazuh-control status 2>/dev/null || true)
    [[ "$st" == *"wazuh-analysisd is running"* ]] && return 0
    sleep 5
  done
  docker exec "$MGR" sh -c 'grep -E "CRITICAL|ERROR" /var/ossec/logs/ossec.log | tail -5' >&2 || true
  die "wazuh-analysisd did not start (see errors above)"
}
wait_manager
# ossec.conf is applied by upstream's copy-on-create only (a plain restart skips it: upstream init bug), so
# recreate the manager whenever the running copy differs from the generated one.
want=$(sha256sum data/wazuh/ossec.conf | cut -d' ' -f1)
have=$(docker exec "$MGR" sha256sum /var/ossec/etc/ossec.conf | cut -d' ' -f1)
if [[ "$want" != "$have" ]]; then
  log "manager ossec.conf is stale: recreating the manager container"
  (cd "$SN" && "${WZ[@]}" up -d --force-recreate --no-deps wazuh.manager)
  MGR=$(cd "$SN" && "${WZ[@]}" ps -q wazuh.manager)
  wait_manager
fi
# Migration from v3: rules used to be docker-cp'd into etc/rules. A leftover copy duplicates every rule ID
# ("Rules in an inconsistent state") now that wazuh/rules/ is mounted at etc/cc-rules.
if docker exec "$MGR" test -e /var/ossec/etc/rules/cc_rules.xml; then
  log "removing stale v3 copy /var/ossec/etc/rules/cc_rules.xml"
  docker exec "$MGR" rm -f /var/ossec/etc/rules/cc_rules.xml
  docker exec "$MGR" /var/ossec/bin/wazuh-control restart >/dev/null
  wait_manager
fi

# ---------- 8. least-privilege indexer role for the CC API / triage agent ----------
log "applying indexer role cc_read -> cc_reader (waits for the security index)"
for i in $(seq 1 60); do
  python3 scripts/indexer_roles.py && break
  (( i == 60 )) && die "could not apply indexer role (is WAZUH_ADMIN_PASS the password this indexer was initialised with?)"
  sleep 5
done

# ---------- 9. rule regression against the real engine ----------
python3 tests/rules_logtest.py --container "$MGR" || die "CC rules failed wazuh-logtest (output above)"

cat <<EOF

[bootstrap] Stack is up. Wazuh UI: https://${WAZUH_DASHBOARD_BIND:-127.0.0.1} (user admin, password WAZUH_ADMIN_PASS in .env).
Next:  ./scripts/range-drill.sh  &&  sleep 60  &&  ./scripts/verify.sh
EOF

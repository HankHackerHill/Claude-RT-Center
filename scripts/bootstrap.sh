#!/usr/bin/env bash
# Stage 1 bring-up: Wazuh single-node (upstream repo, pinned tag) + range + Suricata + CC rules.
# Idempotent: safe to re-run. Run from the project root:  ./scripts/bootstrap.sh
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

die() { echo "[bootstrap] ERROR: $*" >&2; exit 1; }
log() { echo "[bootstrap] $*"; }

[[ -f .env ]] || die ".env missing — cp .env.example .env and fill REQUIRED values"
set -a; source .env; set +a
for v in WAZUH_VERSION SURICATA_TAG JUICE_TAG; do
  [[ -n "${!v:-}" ]] || die "$v is empty in .env"
done
[[ "$WAZUH_VERSION" =~ ^v4\.[0-9]+\.[0-9]+$ ]] || die "WAZUH_VERSION must look like v4.x.y (got '$WAZUH_VERSION')"

command -v docker >/dev/null || die "docker not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin not installed"

# 1. Kernel setting required by the OpenSearch-based indexer.
cur=$(sysctl -n vm.max_map_count)
if (( cur < 262144 )); then
  log "raising vm.max_map_count $cur -> 262144 (needs sudo; persisted in /etc/sysctl.d/99-wazuh.conf)"
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null
fi

# 2. Upstream wazuh-docker at the pinned tag.
if [[ ! -d wazuh-docker ]]; then
  git clone --depth 1 --branch "$WAZUH_VERSION" https://github.com/wazuh/wazuh-docker.git
else
  have=$(git -C wazuh-docker describe --tags --exact-match 2>/dev/null || echo unknown)
  [[ "$have" == "$WAZUH_VERSION" ]] || die "wazuh-docker/ is at '$have', .env wants '$WAZUH_VERSION' — remove the dir or fix .env"
fi

SN="$ROOT/wazuh-docker/single-node"
if [[ ! -f "$SN/config/wazuh_indexer_ssl_certs/root-ca.pem" ]]; then
  log "generating indexer certificates"
  (cd "$SN" && docker compose -f generate-indexer-certs.yml run --rm generator)
fi
(cd "$SN" && docker compose up -d)

# 3. Range + Suricata.
mkdir -p data/suricata/log data/suricata/lib
docker compose --env-file .env -f range/compose.yml up -d --build
log "updating Suricata ET Open ruleset"
docker compose --env-file .env -f range/compose.yml exec -T suricata suricata-update -f || log "WARN: suricata-update failed (no internet?) — local rules still load"
docker compose --env-file .env -f range/compose.yml restart suricata

# 4. Install CC correlation rules into the Wazuh manager and restart it.
MGR=$(cd "$SN" && docker compose ps -q wazuh.manager)
[[ -n "$MGR" ]] || die "wazuh.manager container not found in $SN"
log "waiting for the manager to come up"
for _ in $(seq 1 60); do
  docker exec "$MGR" test -x /var/ossec/bin/wazuh-control && break; sleep 5
done
docker cp wazuh/cc_rules.xml "$MGR":/var/ossec/etc/rules/cc_rules.xml
docker exec "$MGR" chown wazuh:wazuh /var/ossec/etc/rules/cc_rules.xml
docker exec "$MGR" /var/ossec/bin/wazuh-control restart

cat <<EOF

[bootstrap] Stack is up. Remaining manual steps (README, Stage 1):
  1.4  change the default indexer/dashboard passwords and put the new one in .env INDEXER_PASS
  1.5  install the Wazuh agent on this host and add the Suricata localfile block:
         <localfile><log_format>json</log_format><location>$ROOT/data/suricata/log/eve.json</location></localfile>
  Dashboard (Wazuh): https://127.0.0.1   CA for the CC API: $SN/config/wazuh_indexer_ssl_certs/root-ca.pem
Then run: ./scripts/range-drill.sh && ./scripts/verify.sh
EOF

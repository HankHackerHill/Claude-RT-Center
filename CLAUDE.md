# CLAUDE.md: Cyber Command Center

> v5 transition: Docker files listed in HANDOFF.md are superseded and will be deleted once their libvirt/native replacements exist.

Home-lab SOC plus isolated training range. It has a Wazuh SIEM, Suricata NIDS, a vulnerable target range with a Kali attacker box, an AI triage agent (Claude, read-only tools) and a team-view command-center dashboard (Command / Red / Blue / Purple / White / Green).
Read `HANDOFF.md` before your first change. It holds the current state, what is and isn't verified, and the mandate.

## Layout
```
range/compose.yml            range network (internal bridge br-range, NO host IP), Suricata, Juice Shop, DVWA, attacker
range/attacker/Dockerfile    Kali + nmap/sqlmap/nikto/curl (installed at build: the range has no internet)
suricata/rules/local.rules   project NIDS rules, SIDs 9000000-9000999, msg prefix "CC-RANGE"
wazuh/rules/cc_rules.xml     Wazuh correlation rules, IDs 100100-100199 (dir is mounted ro at /var/ossec/etc/cc-rules)
wazuh/compose.override.yml   layered over upstream wazuh-docker: loopback ports, mounts, generated credentials
wazuh/cc_localfile.conf      eve.json <localfile> appended to the manager's ossec.conf
scripts/bootstrap.sh         Stage 1 bring-up (pinned upstream wazuh-docker + override), idempotent
scripts/gen_secrets.py       credentials before first boot -> .env, data/wazuh/{internal_users,wazuh}.yml
scripts/gen_manager_conf.py  upstream manager conf + CC rule_dir + localfile -> data/wazuh/ossec.conf
scripts/indexer_roles.py     least-privilege role cc_read -> user cc_reader (CC API + triage agent)
scripts/range-drill.sh       scripted attack drill; logs ground truth to data/drills.jsonl
scripts/verify.sh|.py        Gate 1 checks -> "GATE 1: GO/NO-GO"
cc/indexer.py                read-only OpenSearch client (pinned verified TLS) + pure shaping; ALL alert field names here
cc/teams.py                  drill x detection join (purple), range health (green)
cc/server.py                 stdlib HTTP API + serves dashboard; loopback-only by default
cc/dashboard.html            single-file dashboard, six hash-routed views, sample-data fallback
agents/triage.py             Stage 2 triage agent (Anthropic Messages API via urllib, read-only tools)
tests/                       unit: test_core, test_teams, test_stack (stdlib)  render: render_dashboard.mjs (Playwright)
                             live: rules_logtest.py (real wazuh-logtest, needs the stack)
data/                        runtime output, gitignored: drills.jsonl, triage.jsonl, suricata logs, wazuh/ generated config
```

## Commands
```bash
for t in tests/test_core.py tests/test_teams.py tests/test_stack.py; do python3 -I "$t" || break; done   # unit, no services
node tests/render_dashboard.mjs                                       # renders all views, fails on JS error/overflow
python3 -m py_compile cc/*.py agents/*.py scripts/*.py && bash -n scripts/*.sh && xmllint --noout wazuh/rules/cc_rules.xml
./scripts/bootstrap.sh && ./scripts/range-drill.sh && sleep 60 && ./scripts/verify.sh   # Stage 1 + Gate 1 (real stack)
python3 tests/rules_logtest.py                                        # CC rules vs real wazuh-logtest (stack up)
python3 cc/server.py                                                  # http://127.0.0.1:8088
python3 agents/triage.py --dry-run | --once | --loop 60
```

## Non-negotiables (security invariants: keep or replace with something strictly stronger)
0. **No Docker, ever** (owner decision 2026-11-25): not for the range, the SIEM, tests or CI. Range = KVM/libvirt VMs; SIEM/IDS = native packages on the host (Rocky Linux 9; never Ubuntu 24.04). See HANDOFF.md "v5 plan".
1. **Range isolation.** The range network has **no host address and no route** (libvirt isolated network; in v4's Docker form: `internal: true` + `inhibit_ipv4`), **and** the host enforces it with `scripts/harden-range.sh` (rp_filter=1 + INPUT drop on the range bridge, IPv6 off): network config alone was bypassed by raw L2 frames. Never expose target services outside the range or attach targets to another network. Any attack automation (scripted or AI) may target only `172.30.0.0/24`. Enforce that in code and at the network level, not in a prompt. Gate 1 proves it with routed and raw-frame (`scripts/l2_probe.py`) probes.
2. **Triage/AI agents treat alert content as attacker-controlled.** Alert data goes only in delimited data blocks or tool results. Tools stay least-privilege, and output is validated against a fixed schema. Any response action (block, isolate, kill) needs explicit human approval recorded with who/when, plus a dry-run mode. Keep the Gate 2 injection test passing.
3. **The API has no auth.** It binds to loopback unless `CC_ALLOW_REMOTE=1`. If you add remote access, add real authn/authz first.
4. **TLS to the indexer is always verified** against the generated root CA and the certificate name (`wazuh.indexer`, connection pinned via `INDEXER_CONNECT`). Never add `verify=False`, `check_hostname=False` or an unverified context. The only relaxation is clearing Python 3.13's `VERIFY_X509_STRICT` profile flag, because the upstream CA lacks keyUsage (see HANDOFF.md).
5. **Secrets** live only in `.env` (0600) and generated files under `data/wazuh/`, never committed and never logged. `.env.example` holds placeholders only. Upstream default credentials must never be live: they are generated before first boot.
6. **Dashboard renders untrusted strings.** Everything from the API goes through `esc()` or textContent. No innerHTML with raw data.
7. **Least privilege to the SIEM.** The CC API and every AI agent use the indexer user `cc_reader` (role `cc_read`: cluster health + read on `wazuh-alerts-*`). Never give them `admin`. Gate 1 checks that a write is refused.

## Ground-truth rules
- Don't invent upstream facts: image tags, Wazuh rule IDs or groups, index field names, API shapes, model IDs. Take them from upstream docs or source, or from the running system, or mark them `UNVERIFIED` in code and in HANDOFF.md. Build-dependent values go in one named place (field names: top of `cc/indexer.py`; versions: `.env`).
- Report status honestly. Use these labels: **written**, **unit-tested**, **rendered**, **run against the real stack**. Never claim the last one unless it actually ran.
- When you change a rule, field or endpoint, update the matching test and the README or HANDOFF table in the same change.

## Conventions
- Python ≥ 3.10, stdlib only in `cc/`, `agents/` and `scripts/` unless a dependency clearly pays for itself. If you add one, pin it and justify it in HANDOFF.md.
- Pure functions for shaping, scoring and validation, so they're testable without services. Side effects stay at the edges.
- Bash: `set -euo pipefail`, quote everything, no `eval`.
- Owner style: direct, expert-level, no filler. Give conclusions first, then evidence. Label claims VERIFIED / OBSERVED / INFERRED / ASSUMED / UNVERIFIED. Challenge bad premises instead of agreeing.

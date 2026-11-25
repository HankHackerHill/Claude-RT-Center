# CLAUDE.md: Cyber Command Center

Home-lab SOC plus isolated training range. It has a Wazuh SIEM, Suricata NIDS, a vulnerable target range with a Kali attacker box, an AI triage agent (Claude, read-only tools) and a team-view command-center dashboard (Command / Red / Blue / Purple / White / Green).
Read `HANDOFF.md` before your first change. It holds the current state, what is and isn't verified, and the mandate.

## Layout
```
range/compose.yml          range network (internal bridge br-range), Suricata, Juice Shop, DVWA, attacker
range/attacker/Dockerfile  Kali + nmap/sqlmap/nikto/curl (installed at build: the range has no internet)
suricata/rules/local.rules project NIDS rules, SIDs 9000000-9000999, msg prefix "CC-RANGE"
wazuh/cc_rules.xml         Wazuh correlation rules, IDs 100100-100199
scripts/bootstrap.sh       Stage 1 bring-up (clones upstream wazuh-docker at the pinned tag)
scripts/range-drill.sh     scripted attack drill; logs ground truth to data/drills.jsonl
scripts/verify.sh          Gate 1 checks -> "GATE 1: GO/NO-GO"
cc/indexer.py              read-only OpenSearch client + pure shaping helpers; ALL alert field names live here
cc/teams.py                drill x detection join (purple), range health (green)
cc/server.py               stdlib HTTP API + serves dashboard; loopback-only by default
cc/dashboard.html          single-file dashboard, six hash-routed views, sample-data fallback, RUBRIC for scoring
agents/triage.py           Stage 2 triage agent (Anthropic Messages API via urllib, read-only tools)
tests/                     test_core.py, test_teams.py (stdlib), render_dashboard.py (Playwright)
data/                      runtime output (gitignored in spirit): drills.jsonl, triage.jsonl, suricata logs
```

## Commands
```bash
python3 -I tests/test_core.py && python3 -I tests/test_teams.py      # unit tests, no services needed
python3 tests/render_dashboard.py                                     # renders all views, fails on JS error/overflow
python3 -m py_compile cc/*.py agents/*.py && bash -n scripts/*.sh && xmllint --noout wazuh/cc_rules.xml
docker compose --env-file .env -f range/compose.yml config -q         # compose lint (needs .env or exported tags)
python3 cc/server.py                                                  # http://127.0.0.1:8088
python3 agents/triage.py --dry-run | --once | --loop 60
```

## Non-negotiables (security invariants: keep or replace with something strictly stronger)
1. **Range isolation.** `range` network stays `internal: true`. Never publish ports from Juice Shop or DVWA, and never attach them to another network. Any attack automation (scripted or AI) may target only `172.30.0.0/24`. Enforce that in code and at the network level, not in a prompt.
2. **Triage/AI agents treat alert content as attacker-controlled.** Alert data goes only in delimited data blocks or tool results. Tools stay least-privilege, and output is validated against a fixed schema. Any response action (block, isolate, kill) needs explicit human approval recorded with who/when, plus a dry-run mode. Keep the Gate 2 injection test passing.
3. **The API has no auth.** It binds to loopback unless `CC_ALLOW_REMOTE=1`. If you add remote access, add real authn/authz first.
4. **TLS to the indexer is always verified** against the generated root CA. Never add `verify=False` or an unverified context.
5. **Secrets** live only in `.env`, which is never committed and never logged. `.env.example` holds placeholders only.
6. **Dashboard renders untrusted strings.** Everything from the API goes through `esc()` or textContent. No innerHTML with raw data.

## Ground-truth rules
- Don't invent upstream facts: image tags, Wazuh rule IDs or groups, index field names, API shapes, model IDs. Take them from upstream docs or source, or from the running system, or mark them `UNVERIFIED` in code and in HANDOFF.md. Build-dependent values go in one named place (field names: top of `cc/indexer.py`; versions: `.env`).
- Report status honestly. Use these labels: **written**, **unit-tested**, **rendered**, **run against the real stack**. Never claim the last one unless it actually ran.
- When you change a rule, field or endpoint, update the matching test and the README or HANDOFF table in the same change.

## Conventions
- Python ≥ 3.10, stdlib only in `cc/` and `agents/` unless a dependency clearly pays for itself. If you add one, pin it and justify it in HANDOFF.md.
- Pure functions for shaping, scoring and validation, so they're testable without services. Side effects stay at the edges.
- Bash: `set -euo pipefail`, quote everything, no `eval`.
- Owner style: direct, expert-level, no filler. Give conclusions first, then evidence. Label claims VERIFIED / OBSERVED / INFERRED / ASSUMED / UNVERIFIED. Challenge bad premises instead of agreeing.

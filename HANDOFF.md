# HANDOFF: Cyber Command Center (as of 2026-11-25)

## Mandate
You own this build now. You have full discretion over architecture, design, features, stack changes and refactors, including replacing components I chose, if you can justify it. The goal is a state-of-the-art home-lab **cyber command center + training range**. Stay within the non-negotiables in `CLAUDE.md`. Work in stages with explicit go/no-go gates. Prefer a smaller thing that provably works over a larger thing that plausibly works.

Owner context:
- Hardware: one Linux host, 16–32 GB RAM, Docker.
- Purpose: home lab plus red/blue training range, viewed on desktop and on the Claude mobile app.
- Long-term direction: the owner is also building **"Red Team Pentest"**, a range/hacker game with autonomous AI red-team and blue-team agents. This command center is a natural backend and scoring layer for it. Design with that in mind, but don't couple to it prematurely.

## Current state
| Component | Files | Status |
|---|---|---|
| Range + Suricata compose | `range/compose.yml`, `range/attacker/Dockerfile` | written; `docker compose config` passes. **Never run.** |
| Suricata rules (6) | `suricata/rules/local.rules` | written. **Never loaded** in Suricata (`suricata -T` not run). |
| Wazuh correlation rules (4) | `wazuh/cc_rules.xml` | written; XML well-formed. **Never run through wazuh-logtest.** |
| Bootstrap / verify | `scripts/bootstrap.sh`, `scripts/verify.sh` | written; `bash -n` passes. **Never run.** |
| Drill + ground-truth log | `scripts/range-drill.sh` | run against a stub `docker`: writes 5 valid JSONL steps. **Never run against containers.** |
| Indexer client + shaping | `cc/indexer.py` | unit-tested with fabricated responses. **Never queried a real indexer.** |
| Team backends | `cc/teams.py` | unit-tested (`read_drills`, `purple_query`, `shape_purple`, `parse_docker_ps`, `infra(None)`). |
| API server | `cc/server.py` | smoke-tested here without an indexer: health/summary/purple/infra, plus the loopback-bind refusal. |
| Dashboard (6 views) | `cc/dashboard.html` | rendered in headless Chrome at 1280 and 390 px with no JS errors and no overflow; sample score red 20 / blue 81 matches a hand calculation. Published as a private claude.ai artifact showing sample data. |
| Triage agent | `agents/triage.py` | unit-tested with a mocked model + indexer (tool loop, schema validation, IP validation). **Never called the real Anthropic API.** |

**Nothing has been run against a real Wazuh/Suricata stack.** Gate 1 has not passed. Treat everything downstream as unproven until it does.

## Data flow
```
attacker --(br-range)--> juice-shop / dvwa
Suricata (host netns, -i br-range) -> data/suricata/log/eve.json
host Wazuh agent <localfile json> -> manager (docker, upstream wazuh-docker single-node) -> indexer :9200
cc/server.py (read-only) -> /api/summary /api/triage /api/purple /api/infra -> dashboard.html
agents/triage.py (read-only tools) -> data/triage.jsonl -> /api/triage
range-drill.sh -> data/drills.jsonl -> /api/purple (each step = alerts from step src_ip in [start, end+120s])
```

## Assumptions to verify first (ranked by blast radius)
1. **ASSUMED:** Wazuh's built-in Suricata rules put alerts in group `ids`, and the EVE fields decode as `data.alert.signature` and `data.src_ip`. Every `cc_rules.xml` rule, and the purple join, depends on this. Check with `wazuh-logtest` and in Discover.
2. **ASSUMED:** the index field names at the top of `cc/indexer.py` (`timestamp`, `rule.level`, `rule.mitre.tactic`, `rule.mitre.id`, `agent.name`, `data.dest_ip`) are keyword or date typed in the `wazuh-alerts-*` template for the chosen tag. Terms aggregations break on `text` fields.
3. **ASSUMED:** `<same_field>src_ip</same_field>` works in a frequency rule on the pinned 4.x version.
4. **ASSUMED:** the `jasonish/suricata` entrypoint passes args through to suricata, so `-s` adds the local rules file and `-k none` takes effect; and the container can write its mounted log directory.
5. **ASSUMED:** Suricata sees container-to-container traffic on `br-range` (normal for a Linux bridge; verify there is no `br_netfilter` or ebtables surprise).
6. **ASSUMED:** the `http.request_body` buffer catches the DVWA command-injection POST. The unauthenticated request gets a redirect, but the body still crosses the wire. Sample data shows this step as the deliberate gap; the real result is unknown.
7. **UNVERIFIED:** model ID `claude-sonnet-5-5` and the Messages API tool-use shapes in `triage.py` are written from documentation memory. Run one `--once` with a real key.
8. **UNVERIFIED:** the wazuh-docker password-change procedure for the chosen tag. The README points to the upstream doc rather than restating it.
9. **Gap:** the `RUBRIC` scoring lives only in dashboard JS. It is covered by the render test's red 20 / blue 81 assertion, not by a unit test.

## Known weaknesses (fix or consciously accept)
- No auth anywhere; the API is loopback only. Needed before multi-user or remote use.
- No persistence beyond JSONL. Triage state is a JSON file capped at 5000 ids. No retention or rotation for `data/`.
- Detection = "an alert from the attacker IP in a time window." That's coarse: it doesn't prove the *right* alert fired for the *right* step when steps overlap. Consider per-step markers, such as a unique UA or URI token per step, and match on them.
- The dashboard is dark-only, uses a 15 s polling refresh and is one ~500-line file. Fine for now; split it if it grows.
- `vulnerables/web-dvwa` is unmaintained and `:latest`-only. Pin it by digest, or replace it.
- No Zeek, no endpoint telemetry from the targets, no case management, no CI.

## Non-binding roadmap ideas (your call)
- **Gate 1–3 bring-up first**, fixing whatever the assumptions above break.
- Per-step drill markers for exact purple attribution; ATT&CK Navigator layer export; Sigma rules compiled to Wazuh/Suricata.
- A scenario engine: named exercises with rounds, timers, objectives and a White-team control panel (start/pause/reset round).
- An autonomous red agent that plans and executes drills **inside the range only**. Use a network-level egress allowlist of `172.30.0.0/24`, a kill switch, a per-round action budget and full action logging into `drills.jsonl`, and keep it in a separate container from anything holding secrets.
- A blue response agent with human-approved actions (for example a Suricata drop rule or a container network disconnect) and dry-run by default.
- Zeek on `br-range`; Wazuh agents inside the targets; SQLite (or the indexer) for triage, cases and scoring history; authn (OIDC or local accounts) before remote access; CI running the tests.

## Definition of done, for any change
- Unit tests and the render test pass, and new logic has tests.
- Status is reported with the labels from `CLAUDE.md`.
- HANDOFF.md's state table and assumptions list are updated. Remove an assumption only when it has actually been verified, and say how.
- None of the non-negotiables is weakened.

## Session history
- **v1:** Stage 1 stack and range, Stage 2 triage agent, Stage 3 single-view dashboard.
- **v2:** team views (Red / Blue / Purple / White / Green), drill ground-truth logging, `/api/purple` and `/api/infra`, scoring rubric.
- **v3:** this handoff. Tests moved into `tests/`.

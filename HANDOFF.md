# HANDOFF: Cyber Command Center (as of 2026-11-25, v4)

## Mandate
Unchanged from v3: own the build, full discretion within `CLAUDE.md`'s non-negotiables, stages with explicit go/no-go
gates, prefer a smaller thing that provably works. Long-term: backend + scoring layer for the owner's "Red Team Pentest"
range game with autonomous red/blue AI agents. Design for it, don't couple to it prematurely.

## Where the evidence comes from (read this first)
v4 ran the stack for real **inside a Claude Code cloud session container** (Docker 29.9.3, compose 5.7.1, kernel 6.18,
cgroup v1, 4 CPU, 15 GB), not on the owner's host. Label used below: **run against the real stack (cloud container)**.
Sandbox-only deviations, none of them committed as defaults:
- `nofile` ulimit 20000 / `memlock` 8 MiB for manager+indexer (host hard limit; passed via the `CC_COMPOSE_EXTRA` hook).
  OpenSearch tolerated it because `discovery.type: single-node` skips bootstrap checks.
- The cert generator needed the sandbox proxy's CA (`CC_CERTGEN_ARGS` hook). Containers here cannot verify TLS to the
  internet, so **ET Open (`suricata-update`) and Wazuh's vulnerability feed never downloaded**: only CC rules were tested.
- Docker Hub rate-limited the sandbox IP; images came through `mirror.gcr.io` (same digests).
The owner's host still needs one `bootstrap.sh && range-drill.sh && verify.sh` run; nothing here proves host-specific
behaviour (LAN, br_netfilter, a different kernel, Docker 2x).

## Current state
| Component | Files | Status |
|---|---|---|
| Range + Suricata | `range/compose.yml`, `range/attacker/Dockerfile` | **run against the real stack (cloud container)** |
| Suricata rules (8) | `suricata/rules/local.rules` | `suricata -T` 8.0.8 OK; 7 of 8 fired live in drills (9000007 tripwire verified only by design, see A5) |
| Wazuh rules (5) | `wazuh/rules/cc_rules.xml` | **run against the real stack**: `tests/rules_logtest.py` 14/14 + live drill classification |
| Wazuh integration | `wazuh/compose.override.yml`, `wazuh/cc_localfile.conf`, `scripts/gen_manager_conf.py` | **run against the real stack** |
| Credentials | `scripts/gen_secrets.py`, `scripts/indexer_roles.py` | **run against the real stack** (fresh volume, twice) + unit-tested |
| Bootstrap / verify | `scripts/bootstrap.sh`, `scripts/verify.sh`/`.py` | **run against the real stack**: from-scratch bootstrap rc=0 twice; `GATE 1: GO` |
| Drill + ground truth | `scripts/range-drill.sh` | **run against the real stack** (unchanged from v3; per-step markers still TODO) |
| Indexer client | `cc/indexer.py` | **run against the real stack** (pinned verified TLS as `cc_reader`) + unit-tested (local TLS server) |
| Team backends | `cc/teams.py` | unit-tested only |
| API server | `cc/server.py` | smoke-tested in v3 without an indexer only |
| Dashboard | `cc/dashboard.html` | rendered (v3, sample data) |
| Triage agent | `agents/triage.py` | unit-tested with a mocked model; never called the real API |

**Gate 1: GO (cloud container).** Gate 2 and Gate 3: not run yet.

## Plan (v4) and gates
| Stage | Work | Gate | State |
|---|---|---|---|
| A | Real Gate 1 bring-up, verify assumptions, fix what breaks | `GATE 1: GO` | **done** |
| B | Gate 3 for real + correctness (sample fallback, server-side scoring, render test port, per-step markers) | badge LIVE, KPIs = direct indexer query | pending |
| C | Gate 2: `--dry-run` on real alerts; real `--once` + injection test need an API key (owner decision) | injection test not a confident FP | pending |
| D | CI, independent adversarial review of the invariants, docs, push | findings fixed or accepted | pending |

## Assumptions from v3: outcome
| # | v3 assumption | Outcome (how verified) |
|---|---|---|
| 1 | Suricata alerts in group `ids`, fields `data.alert.signature`/`data.src_ip` | **VERIFIED, but the rules built on it were wrong.** Source of `0475-suricata_rules.xml` 4.14.11: group `ids,suricata`; 86600 (level 0) matches EVERY EVE record, 86601 = alerts. Rules now parent on `if_sid 86601`. logtest + index confirm the field names. |
| 2 | Field names keyword/date typed | **VERIFIED** via `_mapping/field` on the live `wazuh-alerts-4.x-*` index; `verify.py` re-checks every run. `agent.name` is now `wazuh.manager` (manager reads EVE). Timestamps are `+0000`, not `Z`. |
| 3 | `same_field src_ip` in a frequency rule | **VERIFIED** in logtest and live. The rule's *parenting* needed three iterations (see rule comment): only "child of the CC rules" works live without misfiling. logtest does NOT apply `ignore=`. |
| 4 | jasonish entrypoint passes args; can write logs | **VERIFIED** (entrypoint source) **but the v3 compose could not start**: it `chown -R /etc/suricata` under `set -e`, and the rules were mounted read-only there. Rules moved to `/cc-rules`. |
| 5 | Suricata sees container traffic on `br-range` | **VERIFIED** (http/flow events attacker->juice in EVE), also with `inhibit_ipv4`. |
| 6 | `http.request_body` catches the DVWA POST | **VERIFIED live, after fixing the rule**: v3's SID 9000006 did not parse (unescaped `;` in pcre: 5/6 rules loaded). The sample data's "deliberate gap" was a broken rule. |
| 7 | Model ID and Messages API shapes | **UNVERIFIED**: no API key in this session. |
| 8 | wazuh-docker password procedure | **Replaced**: credentials are generated *before first boot* (bcrypt via the indexer's own `hash.sh -env`), so no change procedure is needed on a fresh volume. Changing them on an existing volume still needs securityadmin: **UNVERIFIED**, not scripted. |
| 9 | RUBRIC only in dashboard JS | still open (Stage B) |

## Defects found and fixed in v4 (all OBSERVED on the real stack unless marked)
1. **Range isolation hole.** `internal: true` blocks forwarding only; the host answered on `172.30.0.1` (TCP RST observed
   from the attacker). Anything the host binds to 0.0.0.0 (upstream publishes indexer 9200, API 55000, 1514/1515, 443 on
   0.0.0.0; `CC_ALLOW_REMOTE=1`) was reachable from the range: INFERRED, the full reproduction (opening 0.0.0.0 listeners)
   was refused by the session's permission policy. Fix: `inhibit_ipv4` on the bridge (no host IP; Suricata still captures
   at L2) + every Wazuh port on loopback. Verified: attacker probes get silence and no packet reaches the wire.
2. Suricata never started (read-only mount under `/etc/suricata` + entrypoint chown under `set -e`).
3. SID 9000006 failed to parse; Suricata loaded 5/6 rules.
4. **`cc_rules.xml` 100102 was a syntax error** under OS_Regex (`(a|b)`): analysisd logs CRITICAL and loads **no rules at
   all**, i.e. v3 would have stopped Wazuh analysing anything. Patterns now `type="pcre2"`.
5. Indexer cert has SAN `DNS:wazuh.indexer` only: v3's `https://127.0.0.1:9200` with verified TLS could never connect.
   Fix: URL uses the cert name; `INDEXER_CONNECT=127.0.0.1` pins the TCP target (like `curl --resolve`). The client also
   uses `http.client` directly, so `HTTPS_PROXY` is never applied to the indexer (urllib would have).
6. Python 3.13 `VERIFY_X509_STRICT` rejects the upstream CA (no keyUsage). Decision: clear only that flag (chain, hostname,
   CERT_REQUIRED stay on; = Python <=3.12 behaviour). Unit tests prove wrong-name and foreign-CA certs fail.
   Alternative not taken: regenerate the CA ourselves (forks upstream cert tooling).
7. Campaign rule: v3 shape (`if_matched_group ids`) counted non-alert EVE records; `if_matched_sid 86601` never fired on
   drills; multi-parent shape misfiled ~1 in 10 CC alerts to 86601 during the ignore window. Final shape documented
   in the rule. Trade-off: ET-only campaigns are not correlated.
8. v3's Wazuh defaults: well-known passwords (admin/SecretPassword, API, kibanaserver) and four extra demo users with
   published hashes. Now generated before first boot; demo users dropped; verify checks the default is refused.
9. **The CC API and the AI triage agent authenticated as indexer `admin`.** Now `cc_reader` with role `cc_read`
   (cluster health + read on `wazuh-alerts-*`); built-in `readall` was rejected (no health permission, reads all indices).
10. Nikto 2.6.1 sends a stock Chrome UA (7940/8003 requests): the UA rule is blind to it. Added behavioural rule 9000008
    (30+ 404s to one client in 10 s). Verified live.
11. Suricata `stats` records (512 fields) exceed the Wazuh JSON decoder ("Too many fields"): now ignored at logcollector.

## Upstream behaviour to know (wazuh-docker v4.14.11)
- A plain `docker restart` of the manager skips `/wazuh-config-mount` (its init exits at a multigroups re-install step).
  Only container (re)creation applies `ossec.conf`; `bootstrap.sh` force-recreates when the running copy differs.
- A second `<ruleset>` block in `ossec.conf` **replaces** the default rule/decoder dirs ("Total rules enabled: 0").
- Single-file bind mounts pin the inode: an editor that saves by rename leaves the container on the old file. The CC
  rules are mounted as a directory for this reason; `rules_logtest.py` checks the active file hash.
- A failed `up` with missing cert files makes Docker create *directories* at those paths; bootstrap refuses to continue.
- Bootstrap removes a stale v3 `/var/ossec/etc/rules/cc_rules.xml` (it duplicates every rule ID).

## Known weaknesses (fix or consciously accept)
- No auth on the CC API (loopback only). Needed before multi-user/remote use.
- No persistence beyond JSONL; no retention/rotation for `data/` (eve.json grows unbounded: add logrotate or Suricata rotation).
- Purple attribution is time window + source IP. Observed: Nikto's probes fire SQLi and traversal rules, so a scan step
  "detects" as T1190 and overlapping steps cannot be told apart. Per-step markers: Stage B.
- ARP-level probing from the range is invisible to Suricata (no IP packet leaves). Tripwire 9000007/100104 only covers
  IP traffic, i.e. it fires if isolation regresses.
- `vulnerables/web-dvwa` is unmaintained and `:latest`-only. Pin by digest or replace.
- Filebeat inside the manager uses the indexer admin credential (upstream design).
- No Zeek, no endpoint telemetry from targets, no case management, no CI yet.

## Definition of done, for any change
- Unit tests + render test pass, new logic has tests; rule changes pass `tests/rules_logtest.py` on a running stack.
- Status reported with the labels from `CLAUDE.md`.
- This file's state table and assumptions updated; an assumption is removed only when verified, saying how.
- No non-negotiable weakened.

## Session history
- **v1:** Stage 1 stack and range, Stage 2 triage agent, Stage 3 single-view dashboard.
- **v2:** team views, drill ground truth, `/api/purple`, `/api/infra`, scoring rubric.
- **v3:** handoff; tests moved into `tests/`.
- **v4:** first run against a real stack (cloud container). Gate 1 GO after 11 defect fixes (above).

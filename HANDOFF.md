# HANDOFF: Cyber Command Center (as of 2026-11-25, v4 -> v5 pivot)

## Mandate
Own the build, full discretion within `CLAUDE.md`'s non-negotiables, stages with explicit go/no-go gates, prefer a smaller
thing that provably works. Long-term: backend + scoring layer for the owner's "Red Team Pentest" range game with
autonomous red/blue AI agents. Design for it, don't couple to it prematurely.

## Owner decisions (2026-11-25)
- **No Docker, ever** (and no other path that reintroduces it: no Docker for tests or CI either).
- **Range: KVM/libvirt VMs** (attacker + targets; hypervisor boundary for code that is attacked and, later, an AI agent).
- **SIEM/IDS: native packages on the host** (Wazuh manager + indexer + dashboard, Suricata) as systemd services.
- **Host OS: Parrot OS or Rocky Linux, never Ubuntu 24.04.** Chosen: **Rocky Linux 9 primary** (Wazuh officially
  supports EL9; KVM/libvirt first-class; SELinux + nftables). Parrot = best-effort later. Owner may overrule.

## Where the v4 evidence comes from (read this first)
v4 ran the v3 design for real in a Claude Code cloud container on **Docker** (Wazuh 4.14.11 single-node, Suricata 8.0.8,
Juice Shop v20.4.0, DVWA). That stack is now superseded, but most of what it proved is runtime-independent: rule logic,
field names, the alert pipeline shape, attribution, API, dashboard, scoring, agent behaviour. Labels used:
**run against the real stack (cloud container, Docker)** = proven there; **written** = not run; **unit-tested**; **rendered**.
The cloud container has no /dev/kvm, no systemd and is Ubuntu 24.04: **nothing of v5's Rocky/libvirt stack can be
run there.** v5 provisioning is proven only by running it on the owner's Rocky host.

## What carries over to v5 unchanged (runtime-independent)
| Component | Status |
|---|---|
| `suricata/rules/local.rules` (9 rules) | 7 fired live in v4; 9000004/9000006 rewritten after review -> **unit-tested** (regex semantics, `tests/test_rules_regex.py`); `suricata -T` on Rocky still to run |
| `wazuh/rules/cc_rules.xml` (5 rules) | **run against the real stack (Docker)**: logtest 15/15 + live drill classification; engine-agnostic |
| `wazuh/cc_localfile.conf`, `scripts/gen_manager_conf.py` | proven (Docker); v5 applies them to the native `/var/ossec/etc/ossec.conf` |
| `cc/indexer.py` (pinned verified TLS, initiator/victim fields) | proven against the real indexer (Docker) + unit-tested |
| `cc/teams.py` attribution (markers, packet windows) | proven (Docker: per-step counts exact) + unit-tested; `infra()` is Docker-specific -> v5 |
| `cc/server.py`, `cc/scoring.py`, `cc/dashboard.html` | proven live (Docker) + **rendered**; review fixes unit/render-tested |
| `agents/triage.py` | **unit-tested**; tools + dry-run proven against the real indexer; **real API call never made** (no key) |
| `scripts/gen_secrets.py`, `scripts/indexer_roles.py` | proven (Docker volume init); now hash with the native indexer's `hash.sh` -> **written** for v5 |
| `scripts/harden-range.sh`, `scripts/l2_probe.py` | proven on the Docker bridge (see A1); bridge-generic -> retarget to the libvirt bridge |
| `tests/` | unit + render suites pass in the cloud container; `rules_logtest.py` now targets native `/var/ossec` |

## To be replaced in v5 (Docker-specific; kept only until replacements exist, then deleted)
`range/compose.yml`, `range/attacker/Dockerfile`, `wazuh/compose.override.yml`, `scripts/bootstrap.sh` (Docker flow),
`scripts/range-drill.sh` (uses `docker compose exec`), `scripts/verify.py` (container/network checks), `cc/teams.py infra()`
(`docker ps`). The CI workflow is already Docker-free.

## v5 plan, stages and gates
| Stage | Work | Gate (go/no-go) |
|---|---|---|
| **E1 SIEM/IDS native** | `scripts/install-siem.sh` (Rocky 9): Wazuh 4.14.x all-in-one from packages.wazuh.com (certs tool, indexer, manager, dashboard), credentials generated before the security index initialises, `cc_read` role, loopback binds; Suricata 8.0.x (OISF COPR or EPEL, pinned) on the range bridge, project rules, alerts-only localfile | `suricata -T` 0 failed; `tests/rules_logtest.py` all pass; indexer green over verified TLS as `cc_reader` with roles = `[cc_read]` |
| **E2 Range on libvirt** | isolated libvirt network (no `<ip>`, no `<forward>` => no host IP, no route); VMs attacker / juice / dvwa built offline from cloud images (cloud-init on a separate build network, then moved); control plane via **qemu-guest-agent** (no network path from the range to the host); clean snapshots for round resets; `harden-range.sh` on the libvirt bridge (nftables on Rocky) | `l2_probe.py` from the attacker: 0 host echoes, tripwires 9000007/9000009 fire; routed probe silent |
| **E3 Port drill + Gate 1** | `range-drill.sh` via `virsh qemu-agent-command guest-exec`; `verify.py` on libvirt/systemd (VM states, network XML, bridge has no IP, host isolation, EVE vs indexed alert counts) ; `teams.infra()` via `virsh`/`systemctl` | `GATE 1: GO` on the Rocky host |
| **E4 Gates 2/3 on the host** | `triage.py --once` + injection test with the owner's key; dashboard `--live` render | Gate 2 + Gate 3 GO |
| **E5 Scenario engine** (roadmap) | rounds/timers/White-team control, AI red agent inside the attacker VM with guest-agent-only control, action budget, kill switch | defined when E4 is GO |

## Assumptions: outcome
| # | Assumption | Outcome |
|---|---|---|
| 1 | Suricata alerts group/fields | **VERIFIED** (Wazuh 4.14.11 source + logtest); rules parent on `if_sid 86601`. |
| 2 | Field types keyword/date | **VERIFIED** via `_mapping` (Docker run). Re-check on the native install (same template expected: INFERRED). |
| 3 | `same_field` frequency | **VERIFIED**; campaign uses `flow.src_ip`, children of CC rules only (live-misfile evidence in the rule comment). |
| 4/5/6 | Suricata entrypoint / bridge capture / request_body | Verified on Docker; 4 is moot in v5 (no container). Bridge capture on a libvirt bridge: **UNVERIFIED** (expected same Linux bridge semantics). |
| 7 | Model ID + API shapes | Checked against Anthropic's API reference (claude-api skill): `claude-sonnet-5-5`, version `2026-10-21`, structured outputs + strict tools, refusal + `fallbacks: "default"`. **Live call UNVERIFIED** (no key). |
| 8 | Wazuh password procedure | Replaced: generate before the security index initialises. Native flow: **written**, not run. |
| 9 | Rubric only in JS | **Resolved**: `cc/scoring.py` authoritative (`/api/score`), JS copy parity-tested. |
| 10 (new) | Wazuh native packages on Rocky 9 at 4.14.x, Suricata 8.0.x for EL9 | **UNVERIFIED** until E1 runs. |
| 11 (new) | libvirt isolated network yields a bridge with no host address and no route | **UNVERIFIED** (documented libvirt behaviour); E2 gate proves it. |

## Independent review (5 reviewers + 1 skeptic per finding; 17 confirmed, 0 refuted, 8 low unverified)
| Finding | Status |
|---|---|
| CRITICAL: range container with CAP_NET_RAW reached the host IP stack via raw L2 frames to the bridge MAC | **Fixed + verified on Docker bridge**: baseline 3/3 echoes processed; after `harden-range.sh` (rp_filter=1, INPUT drop, IPv6 off) 0/9; targets drop NET_RAW. A raw-PREROUTING drop was tried and removed (with bridge-nf-call-iptables it blinded Suricata). Re-verify on libvirt (E2). |
| HIGH: spoofed-source frames evade tripwires | **Fixed + verified**: SID 9000009 fired on a TEST-NET source |
| HIGH: logcollector queue overflow lost 29% of drill alerts | **Fixed + verified**: alerts-only localfile -> 271/271 indexed |
| HIGH: `cc_reader` inherits `own_index` (write to its own index) | Fixed (written + unit-tested): mapping emptied; verify asserts roles == [cc_read] |
| HIGH: triage paging starved older alerts; state cap evicted wrong ids | Fixed, unit-tested (ids excluded in query; age-based state) |
| HIGH: Blue "critical+high open" from the 50-row feed | Fixed: server-side count over all level>=12; unit-tested |
| HIGH/MED: cmd-injection + traversal PCREs missed encoded forms | Fixed; regex semantics unit-tested; `suricata -T` pending (E1) |
| MED: DNS rebinding on the unauthenticated API | Fixed: Host allowlist (421); unit-tested |
| MED: dest_ip was the attacker on to_client alerts | Fixed: flow destination; unit-tested |
| MED: score counted verdicts outside the window | Fixed; unit-tested |
| MED: dashboard switched to SAMPLE for good after one failed load | Fixed: SAMPLE only for file://, "API UNREACHABLE" + retry; render-tested |
| MED: Gate 1 blind to the raw-frame path; no IPv6 coverage; dashboard isolation check ignored inhibit_ipv4 | Open -> E3 (new verify.py for libvirt, includes l2_probe + IPv6) |
| LOW: marker s1 matched s10; non-adjacent window overlap; `::1` bind crash; `.env.tmp` world-readable; admin secrets in agent env; triage loop died on JSON errors | Fixed, unit-tested |
| LOW: drill scope accepts .0/.1/.255; relative CC_COMPOSE_EXTRA; SYN-sweep rule counts any 60 SYNs | Open (drill/bootstrap are rewritten in E2/E3; SYN rule accepted as coarse) |

## Known weaknesses (fix or consciously accept)
- No auth on the CC API (loopback only, Host-checked). Needed before multi-user/remote use.
- No persistence beyond JSONL; no retention/rotation for `data/` or eve.json.
- ARP-level probing from the range is invisible to Suricata; tripwires cover IP only.
- Filebeat uses the indexer admin credential (Wazuh's own design).
- DVWA is unmaintained (v5: build the DVWA VM from source at a pinned commit).
- No Zeek, no endpoint telemetry from targets (v5: Wazuh agents inside the target VMs become easy), no case management.

## Definition of done, for any change
Unit + render tests pass and new logic has tests; rule changes pass `tests/rules_logtest.py` on the host; status labels
from `CLAUDE.md`; this file updated (assumptions removed only when verified, saying how); no non-negotiable weakened.

## Session history
- **v1-v3:** stack + range, triage agent, dashboard, team views, drills, rubric; handoff.
- **v4:** first real run (Docker, cloud container). 11 defects fixed to reach Gate 1; exact purple attribution;
  server-side scoring; agent hardened against the current API; independent review: 17 confirmed findings, the critical
  one (L2 isolation bypass) fixed and verified. **Owner then ruled out Docker -> v5 on Rocky 9 + KVM/libvirt + native.**

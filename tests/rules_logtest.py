#!/usr/bin/env python3
"""Regression tests for wazuh/rules/cc_rules.xml against the REAL Wazuh engine: the host's native wazuh-logtest.

Needs the wazuh-manager package installed and running on this host (Stage E1), and root (uses sudo -n otherwise).
Not a unit test: it proves rule parsing, parenting, field names and frequency/same_field behaviour on the pinned build.

  python3 tests/rules_logtest.py [--ossec /var/ossec]

Each case is one logtest session (state such as frequency counters persists inside a session only).
It also checks that the rules file the manager has loaded is byte-identical to the repo copy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "wazuh" / "rules" / "cc_rules.xml"
ACTIVE_REL = "etc/cc-rules/cc_rules.xml"     # scripts install wazuh/rules/ here and add it as a <rule_dir>


def eve(sig: str, n: int, src: str = "172.30.0.10", dst: str = "172.30.0.20", etype: str = "alert",
        to_client: bool = False) -> str:
    """Shape copied from Suricata 8.0.8 alerts: packet src/dest flip on to_client, flow.src_ip is the initiator."""
    ps, pd = (dst, src) if to_client else (src, dst)
    d = {"timestamp": f"2026-11-25T18:00:{n % 60:02d}.000000+0000", "flow_id": n, "in_iface": "br-range",
         "event_type": etype, "src_ip": ps, "src_port": 40000 + n, "dest_ip": pd, "dest_port": 3000, "proto": "TCP"}
    if etype == "alert":
        d["alert"] = {"action": "allowed", "gid": 1, "signature_id": 9000000, "rev": 1, "signature": sig,
                      "category": "test", "severity": 1}
        d["direction"] = "to_client" if to_client else "to_server"
        d["flow"] = {"src_ip": src, "dest_ip": dst, "pkts_toserver": 3, "pkts_toclient": 3}
    else:
        d["flow"] = {"pkts_toserver": 3, "pkts_toclient": 3, "state": "closed"}
    return json.dumps(d)


ET = "ET SCAN generic test signature"
CASES = [
    # (name, [eve lines], expected rule id per line)
    ("sqli -> 100101", [eve("CC-RANGE SQLi probe in URI", 1)], ["100101"]),
    ("union -> 100101", [eve("CC-RANGE SQLi UNION SELECT", 1)], ["100101"]),
    ("traversal -> 100102", [eve("CC-RANGE Path traversal", 1)], ["100102"]),
    ("cmdi -> 100102", [eve("CC-RANGE Command injection in body", 1)], ["100102"]),
    ("syn sweep -> 100103", [eve("CC-RANGE Recon SYN sweep", 1)], ["100103"]),
    ("scanner ua -> 100103", [eve("CC-RANGE Scanner user-agent", 1)], ["100103"]),
    ("isolation -> 100104", [eve("CC-RANGE Isolation probe - range host contacted gateway or off-range address", 1,
                                 dst="172.30.0.1")], ["100104"]),
    ("non-CC ET alert stays 86601", [eve(ET, 1)], ["86601"]),
    ("lookalike prefix not CC", [eve("XCC-RANGE SQLi", 1)], ["86601"]),
    # campaign counts CC alerts only (see the comment on rule 100110 for why)
    ("campaign: ET-only alerts not correlated", [eve(ET, i) for i in range(1, 13)], ["86601"] * 12),
    ("campaign: 10 CC alerts same src",
     [eve("CC-RANGE SQLi probe in URI" if i % 2 else "CC-RANGE Scanner user-agent", i) for i in range(1, 13)],
     [("100101" if i % 2 else "100103") for i in range(1, 10)] + ["100110"]
     + [("100101" if i % 2 else "100103") for i in range(11, 13)]),
    ("campaign: to_client alerts count for the initiator, not the victim",
     [eve("CC-RANGE Path traversal" if i % 2 else "CC-RANGE Scanner behaviour - burst of HTTP 404s to one client", i,
          to_client=not i % 2) for i in range(1, 11)],
     [("100102" if i % 2 else "100103") for i in range(1, 10)] + ["100110"]),
    ("campaign: distinct sources never",
     [eve("CC-RANGE Path traversal", i, src=f"172.30.0.{100 + i}") for i in range(1, 13)], ["100102"] * 12),
    ("campaign: flow records do not count",
     [eve("", i, etype="flow") for i in range(1, 10)] + [eve("CC-RANGE Path traversal", 10)], ["86600"] * 9 + ["100102"]),
]

ID_RE = re.compile(r"^\s+id: '(\d+)'", re.M)


def _root(cmd: list[str]) -> list[str]:
    import os
    return cmd if os.geteuid() == 0 else ["sudo", "-n", *cmd]


def logtest(ossec: str, lines: list[str]) -> list[str]:
    """One session: feed all lines on stdin, return the matched rule id per event ('' when no rule matched)."""
    p = subprocess.run(_root([f"{ossec}/bin/wazuh-logtest"]),
                       input="\n".join(lines) + "\n", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=120, check=False)  # logtest prints its phases on stderr
    blocks = re.split(r"\*\*Phase 1: Completed pre-decoding\.", p.stdout)[1:]
    if len(blocks) != len(lines):
        raise RuntimeError(f"expected {len(lines)} events, logtest returned {len(blocks)}:\n{p.stdout[-2000:]}")
    out = []
    for b in blocks:
        m = ID_RE.search(b.split("**Phase 3", 1)[1]) if "**Phase 3" in b else None
        out.append(m.group(1) if m else "")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ossec", default="/var/ossec")
    a = ap.parse_args()
    fails = 0
    active_path = f"{a.ossec}/{ACTIVE_REL}"
    active = subprocess.run(_root(["sha256sum", active_path]), capture_output=True, text=True, check=False)
    want = hashlib.sha256(RULES.read_bytes()).hexdigest()
    if active.returncode != 0 or active.stdout.split()[:1] != [want]:
        print(f"FAIL  manager's {active_path} differs from repo copy (or is missing): {active.stdout.strip() or active.stderr.strip()}")
        fails += 1
    else:
        print("PASS  active rules file matches repo")
    for name, lines, expected in CASES:
        got = logtest(a.ossec, lines)
        ok = got == expected
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n      expected {expected}\n      got      {got}"))
    print("RULES: ALL PASS" if not fails else f"RULES: {fails} FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

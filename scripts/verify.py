#!/usr/bin/env python3
"""Gate 1 checks against the running stack. Prints PASS/FAIL/SKIP per check, then "GATE 1: GO" or "GATE 1: NO-GO".

  ./scripts/verify.sh            (wrapper)     python3 scripts/verify.py [--no-probe]

Run ./scripts/range-drill.sh within the last 30 min first (checks 9-10 need drill alerts).
--no-probe skips the active isolation probe (attacker tries host ports + an internet IP; all must stay silent and
no IP packet may reach the wire).
Uses the CC's own indexer client and credentials (cc_reader), so it also proves what the API/agent will see.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cc"))
import indexer as I  # noqa: E402

RANGE = ["docker", "compose", "--env-file", str(ROOT / ".env"), "-f", str(ROOT / "range" / "compose.yml")]
SN = ROOT / "wazuh-docker" / "single-node"
EVE = ROOT / "data" / "suricata" / "log" / "eve.json"
EXPECT_TYPES = {I.F_TIME: "date", I.F_LEVEL: "long", I.F_RULE_ID: "keyword", I.F_RULE_DESC: "keyword",
                I.F_GROUPS: "keyword", I.F_TACTIC: "keyword", I.F_TECHNIQUE: "keyword", I.F_AGENT: "keyword",
                "data.src_ip": "keyword", "data.dest_ip": "keyword", "data.alert.signature": "keyword"}
CC_RULES = ["100101", "100102", "100103", "100104", "100110"]
results: list[tuple[str, str]] = []


def rec(status: str, msg: str) -> None:
    results.append((status, msg))
    print(f"{status:5} {msg}", flush=True)


def run(cmd: list[str], timeout: float = 30, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, **kw)


def containers() -> str | None:
    ps = run(RANGE + ["ps", "--format", "json"])
    states = {}
    for ln in ps.stdout.splitlines():
        try:
            d = json.loads(ln)
        except json.JSONDecodeError:
            continue
        states[d.get("Service")] = d.get("State")
    for svc in ("suricata", "juice-shop", "dvwa", "attacker"):
        st = states.get(svc, "missing")
        rec("PASS" if st == "running" else "FAIL", f"range/{svc} {st}")
    ids = run(["docker", "ps", "--filter", "label=com.docker.compose.project=single-node", "--format", "{{.Names}} {{.State}}"])
    seen = dict(ln.split(" ", 1) for ln in ids.stdout.splitlines() if " " in ln)
    for svc in ("wazuh.manager", "wazuh.indexer", "wazuh.dashboard"):
        name = next((n for n in seen if svc in n), None)
        rec("PASS" if name and seen[name] == "running" else "FAIL", f"wazuh/{svc} {seen.get(name, 'missing') if name else 'missing'}")
    return next((n for n in seen if "wazuh.manager" in n), None)


def bridge_ipv4(dev: str = "br-range") -> str | None:
    import fcntl
    import socket
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", dev.encode()))[20:24])  # SIOCGIFADDR
    except OSError:
        return None
    finally:
        s.close()


def isolation(probe: bool) -> float | None:
    net = run(["docker", "network", "inspect", "cc-range_range", "--format", "{{json .Internal}} {{json .Options}}"])
    internal, _, opts = net.stdout.strip().partition(" ")
    rec("PASS" if internal == "true" else "FAIL", f"range network internal={internal or '?'}")
    try:
        inhibit = json.loads(opts or "{}").get("com.docker.network.bridge.inhibit_ipv4") == "true"
    except json.JSONDecodeError:
        inhibit = False
    ip = bridge_ipv4()
    rec("PASS" if inhibit and ip is None else "FAIL",
        f"br-range has no host IPv4 (inhibit_ipv4={inhibit}, address={ip or 'none'})")
    if not probe:
        rec("SKIP", "active isolation probe (--no-probe)")
        return None
    t0 = time.time()
    # A connect that is REFUSED means the host's IP stack answered: that is a failure, not a pass.
    script = ("for t in 172.30.0.1:9200 172.30.0.1:55000 172.30.0.1:8088 1.1.1.1:443; do "
              "h=${t%:*}; p=${t#*:}; if timeout 3 bash -c \"</dev/tcp/$h/$p\" 2>/tmp/e; then echo \"$t OPEN\"; "
              "elif grep -q refused /tmp/e; then echo \"$t REFUSED\"; else echo \"$t silent\"; fi; done")
    out = run(RANGE + ["exec", "-T", "attacker", "bash", "-c", script], timeout=40).stdout.split("\n")
    bad = [ln for ln in out if ln.strip() and not ln.endswith("silent")]
    rec("PASS" if not bad and len([x for x in out if x.strip()]) == 4 else "FAIL",
        "attacker gets no answer from host/off-range targets" + (f": {bad}" if bad else ""))
    time.sleep(3)
    leaked = off_range_packets(t0)
    rec("PASS" if not leaked else "FAIL",
        "no IP packet from the range toward host/off-range reached the wire during the probe (EVE)"
        + (f": {leaked[:5]}" if leaked else ""))
    return t0


RANGE_HOSTS = {f"172.30.0.{i}" for i in range(2, 255)}


def off_range_packets(since: float) -> list[str]:
    """EVE records (any type) from a range host to a non-range-host IP since `since` (epoch s). Pure scan of eve.json."""
    import datetime
    out = []
    if not EVE.exists():
        return out
    with EVE.open(errors="replace") as f:
        f.seek(max(0, EVE.stat().st_size - 20_000_000))
        for ln in f:
            if "172.30.0." not in ln:          # cheap prefilter; must not depend on JSON whitespace
                continue
            try:
                d = json.loads(ln)
                ts = datetime.datetime.strptime(d["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
            dst = d.get("dest_ip", "")
            if ts >= since and d.get("src_ip") in RANGE_HOSTS and dst not in RANGE_HOSTS \
                    and dst != "172.30.0.255" and not dst.startswith(("224.", "239.", "ff")):
                out.append(f"{d.get('event_type')} {d.get('src_ip')}->{dst}:{d.get('dest_port')}")
    return out


def suricata() -> None:
    if not EVE.exists() or EVE.stat().st_size == 0:
        rec("FAIL", "eve.json missing/empty: Suricata not capturing on br-range")
        return
    age = time.time() - EVE.stat().st_mtime
    rec("PASS" if age < 120 else "FAIL", f"eve.json last write {age:.0f}s ago")
    sigs: dict[str, int] = {}
    with EVE.open(errors="replace") as f:
        f.seek(max(0, EVE.stat().st_size - 50_000_000))
        for ln in f:
            if '"event_type":"alert"' in ln and "CC-RANGE" in ln:
                try:
                    s = json.loads(ln)["alert"]["signature"]
                except (json.JSONDecodeError, KeyError):
                    continue
                sigs[s] = sigs.get(s, 0) + 1
    rec("PASS" if sigs else "FAIL", f"eve.json CC-RANGE alerts by signature: {sigs or 'none: run range-drill.sh'}")


def rules(mgr: str | None) -> None:
    if not mgr:
        rec("FAIL", "CC rules logtest: no manager container")
        return
    p = run([sys.executable, str(ROOT / "tests" / "rules_logtest.py"), "--container", mgr], timeout=600)
    last = (p.stdout.strip().splitlines() or ["no output"])[-1]
    rec("PASS" if p.returncode == 0 else "FAIL", f"CC rules vs wazuh-logtest: {last}")
    if p.returncode:
        print(p.stdout[-3000:])


def indexer_checks() -> None:
    try:
        ix = I.Indexer()
    except I.IndexerError as e:
        rec("FAIL", f"indexer client config: {e}")
        return
    h = ix.health()
    rec("PASS" if h in ("green", "yellow") else "FAIL", f"indexer health={h} (verified TLS, user {os.environ.get('INDEXER_USER')})")
    if h.startswith("error"):
        return
    # least privilege: the CC credential must not be able to write
    try:
        ix._request("PUT", "/cc-write-probe/_doc/1", {"probe": True}, 10)
        rec("FAIL", "CC indexer user can WRITE: it must be read-only (cc_reader / readall)")
    except I.IndexerError as e:
        rec("PASS" if "HTTP 403" in str(e) else "FAIL", f"CC indexer user is read-only ({str(e)[:60]})")
    # upstream default admin password must not work
    saved = dict(os.environ)
    try:
        os.environ["INDEXER_USER"], os.environ["INDEXER_PASS"] = "admin", "SecretPassword"
        dflt = I.Indexer().health()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    rec("PASS" if "HTTP 401" in dflt else "FAIL", f"upstream default admin password rejected ({dflt[:50]})")
    # field types the API aggregates on
    try:
        m = ix._request("GET", f"/{I.INDEX}/_mapping/field/{','.join(EXPECT_TYPES)}", None, 10)
        got = {}
        for idx in m.values():
            for f, v in (idx.get("mappings") or {}).items():
                got[f] = next(iter(v["mapping"].values())).get("type")
        wrong = {f: (got.get(f), t) for f, t in EXPECT_TYPES.items() if got.get(f) != t}
        rec("PASS" if not wrong else "FAIL", "alert field types match cc/indexer.py" + (f": {wrong} (got, want)" if wrong else ""))
    except I.IndexerError as e:
        rec("FAIL", f"field mapping: {e}")
    win = {"range": {I.F_TIME: {"gte": "now-30m"}}}
    r = ix.search({"size": 0, "query": {"bool": {"filter": [win, {"terms": {I.F_RULE_ID: CC_RULES}}]}},
                   "aggs": {"ids": {"terms": {"field": I.F_RULE_ID, "size": 20}}}})
    ids = {b["key"]: b["doc_count"] for b in r["aggregations"]["ids"]["buckets"]}
    rec("PASS" if ids else "FAIL", f"CC rules indexed in last 30m: {ids or 'none: run range-drill.sh, wait ~60s'}")
    # regression guard: a CC signature must never finish at the generic Suricata rule (lost level + ATT&CK tag)
    r = ix.search({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
        win, {"term": {I.F_RULE_ID: "86601"}}, {"prefix": {"data.alert.signature": "CC-RANGE"}}]}}})
    n = r["hits"]["total"]["value"]
    rec("PASS" if n == 0 else "FAIL", f"CC signatures misfiled at 86601 in last 30m: {n}")
    # Tripwire 9000007 -> 100104 fires only if IP traffic from the range reaches the wire toward the host/off-range.
    # With inhibit_ipv4 nothing does (ARP for .1 never resolves, there is no default route), so ANY 100104 alert in
    # the window means isolation is broken somewhere.
    r = ix.search({"size": 0, "track_total_hits": True,
                   "query": {"bool": {"filter": [win, {"term": {I.F_RULE_ID: "100104"}}]}}})
    n = r["hits"]["total"]["value"]
    rec("PASS" if n == 0 else "FAIL", f"isolation tripwire 100104 alerts in last 30m: {n}")


def api() -> None:
    import urllib.request
    url = f"http://{os.environ.get('CC_BIND', '127.0.0.1')}:{os.environ.get('CC_PORT', '8088')}/api/health"
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=3) as r:
            rec("PASS" if r.status == 200 else "FAIL", f"CC API {url} -> {r.status}")
    except OSError:
        rec("SKIP", "CC API not running (start: python3 cc/server.py)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-probe", action="store_true")
    a = ap.parse_args()
    I.load_env()
    mgr = containers()
    isolation(not a.no_probe)
    suricata()
    rules(mgr)
    indexer_checks()
    api()
    fails = [m for s, m in results if s == "FAIL"]
    print("\nGATE 1: GO" if not fails else f"\nGATE 1: NO-GO ({len(fails)} failed)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

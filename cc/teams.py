"""Team-view backends: drill ground truth x detections (Red/Purple/White) and range health (Green). Stdlib only."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from indexer import (F_AGENT, F_EVENT_TIME, F_HTTP_UA, F_RULE_DESC, F_RULE_ID, F_TECHNIQUE, F_TIME, ROOT,
                     initiator_filter)

DRILL_LOG = ROOT / "data" / "drills.jsonl"
EVE = ROOT / "data" / "suricata" / "log" / "eve.json"
PIPELINE_GRACE_MS = 120_000   # EVE -> manager -> indexer; outer bound on SIEM time (observed latency: 0.5-2 s)
PACKET_SLACK_MS = 500         # packet-time slack around a step; windows are also clipped so they never overlap
MARKER_RE = re.compile(r"^cc-step/[A-Za-z0-9_.:-]{1,100}$")   # written by range-drill.sh; anything else is ignored
MARKER_PREFIX = "cc-step/"
MAX_STEPS = 100
RANGE_NETWORK = "cc-range_range"   # compose project "cc-range" + network "range"


# ---------------- drills ----------------

def read_drills(since_ms: int, path: Path = DRILL_LOG) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for ln in path.read_text().splitlines():
        try:
            d = json.loads(ln)
            s, e = int(d["start_ms"]), int(d["end_ms"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        if e < s or s < since_ms:
            continue
        out.append({**d, "start_ms": s, "end_ms": e})
    return out[-MAX_STEPS:]


def _rng(gte: int, lte: int, field: str = F_TIME) -> dict:
    return {"range": {field: {"gte": gte, "lte": lte, "format": "epoch_millis"}}}


def valid_marker(m) -> str | None:
    return m if isinstance(m, str) and MARKER_RE.match(m) else None


def _has_marker(m: str) -> dict:
    """The drill appends the marker as the LAST token of the UA, so anchor at the end: an unanchored "*cc-step/..-s1*"
    also matched steps s10..s19 (review finding)."""
    return {"wildcard": {F_HTTP_UA: {"value": f"*{m}"}}}


def packet_windows(steps: list[dict]) -> list[tuple[int, int, bool]]:
    """Pure: per step, the Suricata packet-time window used for alerts that carry no marker, as (lo, hi, ambiguous).
    Windows of consecutive steps from the same source are clipped at the midpoint of the gap between them, so an
    unmarked alert is attributed to at most one step (drill steps are ~50 ms apart; a fixed slack double-counted).
    Steps that genuinely overlap in time cannot be told apart this way: they are flagged ambiguous."""
    out = [(s["start_ms"] - PACKET_SLACK_MS, s["end_ms"] + PACKET_SLACK_MS, False) for s in steps]
    by_src: dict[str, list[int]] = {}
    for i, s in enumerate(steps):
        by_src.setdefault(s.get("src_ip"), []).append(i)
    for idx in by_src.values():
        idx.sort(key=lambda i: steps[i]["start_ms"])
        # compare each step with the step that ends LATEST so far, not only its neighbour: a long step that spans
        # several shorter ones overlaps all of them (review finding: only adjacent pairs were checked)
        reach = idx[0]
        for b in idx[1:]:
            a = reach
            ea, sb = steps[a]["end_ms"], steps[b]["start_ms"]
            if sb <= ea:                                   # concurrent steps from one source
                out[a], out[b] = (out[a][0], out[a][1], True), (out[b][0], out[b][1], True)
            else:
                mid = (ea + sb) // 2
                out[a] = (out[a][0], min(out[a][1], mid), out[a][2])
                out[b] = (max(out[b][0], mid + 1), out[b][1], out[b][2])
            if steps[b]["end_ms"] >= steps[reach]["end_ms"]:
                reach = b
    return out


def _any_marker() -> dict:
    return {"wildcard": {F_HTTP_UA: {"value": f"*{MARKER_PREFIX}*"}}}


def step_filter(s: dict, window: tuple[int, int, bool] | None = None) -> dict:
    """Pure: which alerts belong to drill step `s`.
    initiator == step source AND SIEM time in [start, end+grace] AND
      (alert UA carries THIS step's marker
       OR (Suricata packet time in [start-1s, end+1s] AND the alert carries NO step marker)).
    The second branch covers non-HTTP steps (nmap) and HTTP requests whose UA the tool rewrote (Nikto's shellshock
    probes). v3 used only source + a 120 s window, which attributed every later step's alerts to every earlier step."""
    m = valid_marker(s.get("marker"))
    lo, hi, _ = window or (s["start_ms"] - PACKET_SLACK_MS, s["end_ms"] + PACKET_SLACK_MS, False)
    unmarked = {"bool": {"filter": [_rng(lo, hi, F_EVENT_TIME)], "must_not": [_any_marker()]}}
    how = [_has_marker(m), unmarked] if m else [unmarked]
    return {"bool": {"filter": [_rng(s["start_ms"], s["end_ms"] + PIPELINE_GRACE_MS), initiator_filter(s["src_ip"])],
                     "should": how, "minimum_should_match": 1}}


def purple_query(steps: list[dict]) -> dict:
    """One request: a filters-agg bucket per drill step."""
    lo = min(s["start_ms"] for s in steps)
    hi = max(s["end_ms"] for s in steps) + PIPELINE_GRACE_MS
    return {
        "size": 0,
        "query": {"bool": {"filter": [_rng(lo, hi)]}},
        "aggs": {"steps": {
            "filters": {"filters": {str(i): step_filter(s, w) for i, (s, w) in enumerate(zip(steps, packet_windows(steps)))}},
            "aggs": {"first": {"min": {"field": F_TIME}},
                     "by_marker": {"filter": {"wildcard": {F_HTTP_UA: {"value": f"*{MARKER_PREFIX}*"}}}},
                     "techniques": {"terms": {"field": F_TECHNIQUE, "size": 20}},
                     "rules": {"terms": {"field": F_RULE_DESC, "size": 10}},
                     "rule_ids": {"terms": {"field": F_RULE_ID, "size": 20}}}}},
    }


def parent_technique(t: str) -> str:
    return str(t).split(".")[0].upper()


def shape_purple(resp: dict, steps: list[dict]) -> list[dict]:
    """Pure: join drill ground truth with per-step detection buckets."""
    buckets = resp.get("aggregations", {}).get("steps", {}).get("buckets", {}) or {}
    ambiguous = [w[2] for w in packet_windows(steps)]
    out = []
    for i, s in enumerate(steps):
        b = buckets.get(str(i), {}) or {}
        n = int(b.get("doc_count", 0))
        first = (b.get("first") or {}).get("value")
        techs = [x["key"] for x in b.get("techniques", {}).get("buckets", [])]
        latency = (first - s["start_ms"]) / 1000 if (n and isinstance(first, (int, float))) else None
        out.append({
            **{k: s.get(k) for k in ("drill_id", "step_id", "step", "technique", "tactic", "src_ip", "target", "tool",
                                     "start_ms", "end_ms")},
            "marker": valid_marker(s.get("marker")),
            "attribution_ambiguous": ambiguous[i],
            "alerts": n,
            "alerts_by_marker": int((b.get("by_marker") or {}).get("doc_count", 0)),
            "detected": n > 0,
            "first_alert_ms": first if n else None,
            "latency_s": round(max(latency, 0.0), 1) if latency is not None else None,
            "techniques_detected": techs,
            "technique_match": parent_technique(s.get("technique", "")) in {parent_technique(t) for t in techs},
            "rules": [{"key": x["key"], "count": x["doc_count"]} for x in b.get("rules", {}).get("buckets", [])],
            "rule_ids": [x["key"] for x in b.get("rule_ids", {}).get("buckets", [])],
        })
    return out


# ---------------- green: range health ----------------

def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout if p.returncode == 0 else p.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def parse_docker_ps(text: str) -> list[dict]:
    out = []
    for ln in text.splitlines():
        try:
            d = json.loads(ln)
        except json.JSONDecodeError:
            continue
        name = d.get("Names", "")
        if not (name.startswith("cc-range") or name.startswith("single-node")):
            continue
        out.append({"name": name, "image": d.get("Image", ""), "state": d.get("State", ""), "status": d.get("Status", "")})
    return sorted(out, key=lambda x: x["name"])


def infra(indexer) -> dict:
    now = time.time()
    rc, txt = _run(["docker", "ps", "-a", "--format", "{{json .}}"])
    containers = parse_docker_ps(txt) if rc == 0 else []
    rc2, net = _run(["docker", "network", "inspect", RANGE_NETWORK, "--format", "{{json .Internal}}"])
    eve = {"exists": EVE.exists()}
    if eve["exists"]:
        st = EVE.stat()
        eve.update(size_mb=round(st.st_size / 1e6, 2), age_s=round(now - st.st_mtime, 1))
    du = shutil.disk_usage(ROOT)
    agents, ingest = [], None
    if indexer is not None:
        try:
            r = indexer.search({"size": 0, "query": {"range": {F_TIME: {"gte": "now-24h"}}},
                                "aggs": {"agents": {"terms": {"field": F_AGENT, "size": 50},
                                                    "aggs": {"last": {"max": {"field": F_TIME}}}},
                                         "last5": {"filter": {"range": {F_TIME: {"gte": "now-5m"}}}}}})
            agents = [{"name": b["key"], "alerts_24h": b["doc_count"],
                       "last_seen_s": round(now - b["last"]["value"] / 1000, 1) if b.get("last", {}).get("value") else None}
                      for b in r.get("aggregations", {}).get("agents", {}).get("buckets", [])]
            ingest = round(r.get("aggregations", {}).get("last5", {}).get("doc_count", 0) / 5, 1)
        except Exception as e:  # health view must render even when the indexer is down
            agents = [{"name": f"error: {e}", "alerts_24h": 0, "last_seen_s": None}]
    return {
        "docker": "ok" if rc == 0 else f"error: {txt.strip()[:200]}",
        "containers": containers,
        "range_internal": (net.strip() == "true") if rc2 == 0 else None,
        "indexer": indexer.health() if indexer is not None else "not configured",
        "eve": eve,
        "disk": {"total_gb": round(du.total / 1e9, 1), "free_gb": round(du.free / 1e9, 1),
                 "used_pct": round(100 * (du.total - du.free) / du.total, 1)},
        "agents": agents,
        "ingest_per_min": ingest,
        "generated_at": now,
    }

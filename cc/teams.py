"""Team-view backends: drill ground truth x detections (Red/Purple/White) and range health (Green). Stdlib only."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from indexer import F_AGENT, F_RULE_DESC, F_RULE_ID, F_SRC, F_TECHNIQUE, F_TIME, ROOT

DRILL_LOG = ROOT / "data" / "drills.jsonl"
EVE = ROOT / "data" / "suricata" / "log" / "eve.json"
PIPELINE_GRACE_MS = 120_000   # EVE -> agent -> manager -> indexer; an alert this long after a step still counts
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


def _src_filter(ip: str) -> dict:
    return {"bool": {"should": [{"term": {f: ip}} for f in F_SRC], "minimum_should_match": 1}}


def _rng(gte: int, lte: int) -> dict:
    return {"range": {F_TIME: {"gte": gte, "lte": lte, "format": "epoch_millis"}}}


def purple_query(steps: list[dict]) -> dict:
    """One request: a filters-agg bucket per drill step (time window + attacker source)."""
    lo = min(s["start_ms"] for s in steps)
    hi = max(s["end_ms"] for s in steps) + PIPELINE_GRACE_MS
    return {
        "size": 0,
        "query": {"bool": {"filter": [_rng(lo, hi)]}},
        "aggs": {"steps": {
            "filters": {"filters": {str(i): {"bool": {"filter": [
                _rng(s["start_ms"], s["end_ms"] + PIPELINE_GRACE_MS), _src_filter(s["src_ip"])]}}
                for i, s in enumerate(steps)}},
            "aggs": {"first": {"min": {"field": F_TIME}},
                     "techniques": {"terms": {"field": F_TECHNIQUE, "size": 20}},
                     "rules": {"terms": {"field": F_RULE_DESC, "size": 10}},
                     "rule_ids": {"terms": {"field": F_RULE_ID, "size": 20}}}}},
    }


def parent_technique(t: str) -> str:
    return str(t).split(".")[0].upper()


def shape_purple(resp: dict, steps: list[dict]) -> list[dict]:
    """Pure: join drill ground truth with per-step detection buckets."""
    buckets = resp.get("aggregations", {}).get("steps", {}).get("buckets", {}) or {}
    out = []
    for i, s in enumerate(steps):
        b = buckets.get(str(i), {}) or {}
        n = int(b.get("doc_count", 0))
        first = (b.get("first") or {}).get("value")
        techs = [x["key"] for x in b.get("techniques", {}).get("buckets", [])]
        latency = (first - s["start_ms"]) / 1000 if (n and isinstance(first, (int, float))) else None
        out.append({
            **{k: s.get(k) for k in ("drill_id", "step", "technique", "tactic", "src_ip", "target", "tool", "start_ms", "end_ms")},
            "alerts": n,
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

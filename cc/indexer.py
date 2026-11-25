"""Read-only Wazuh indexer (OpenSearch) client shared by the CC API and the triage agent. Stdlib only."""
from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Field names in the wazuh-alerts-* template. Centralised so a template change is a one-line fix.
# Verify once in Wazuh Dashboard > Discover on your build (README, Gate 1).
F_TIME = "timestamp"
F_LEVEL = "rule.level"
F_RULE_ID = "rule.id"
F_RULE_DESC = "rule.description"
F_GROUPS = "rule.groups"
F_TACTIC = "rule.mitre.tactic"
F_TECHNIQUE = "rule.mitre.id"
F_AGENT = "agent.name"
F_SRC = ("data.src_ip", "data.srcip")   # Suricata EVE uses src_ip; syslog-style decoders use srcip
INDEX = "wazuh-alerts-*"

SEVERITY_BANDS = (("critical", 15, 99), ("high", 12, 14), ("medium", 7, 11), ("low", 0, 6))


def load_env(path: Path = ROOT / ".env") -> None:
    """Minimal KEY=VALUE loader; real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


class IndexerError(RuntimeError):
    pass


class Indexer:
    def __init__(self) -> None:
        load_env()
        self.url = os.environ.get("INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")
        user, pw = os.environ.get("INDEXER_USER", ""), os.environ.get("INDEXER_PASS", "")
        if not user or not pw:
            raise IndexerError("INDEXER_USER / INDEXER_PASS not set")
        ca = os.environ.get("INDEXER_CA", "")
        ca_path = (ROOT / ca).resolve() if ca and not os.path.isabs(ca) else Path(ca)
        if not ca or not ca_path.is_file():
            raise IndexerError(f"INDEXER_CA not found: {ca_path} — TLS verification is not optional")
        self.ctx = ssl.create_default_context(cafile=str(ca_path))
        self.auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    def search(self, body: dict, timeout: float = 10.0) -> dict:
        req = urllib.request.Request(
            f"{self.url}/{INDEX}/_search",
            data=json.dumps(body).encode(),
            headers={"Authorization": self.auth, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise IndexerError(f"indexer HTTP {e.code}: {e.read(300).decode(errors='replace')}") from e
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as e:
            raise IndexerError(f"indexer unreachable: {e}") from e

    def health(self) -> str:
        req = urllib.request.Request(f"{self.url}/_cluster/health", headers={"Authorization": self.auth})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=5) as r:
                return json.load(r).get("status", "unknown")
        except Exception as e:  # health endpoint: report, don't raise
            return f"error: {e}"


# ---------- pure helpers (testable without the indexer) ----------

def _get(doc: dict, dotted: str):
    cur = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def severity(level) -> str:
    try:
        lv = int(level)
    except (TypeError, ValueError):
        return "unknown"
    for name, lo, hi in SEVERITY_BANDS:
        if lo <= lv <= hi:
            return name
    return "unknown"


def normalize_hit(hit: dict) -> dict:
    """Flatten one indexer hit into the shape the dashboard and agent use. Truncates attacker-controlled text."""
    s = hit.get("_source", {}) or {}
    src = next((v for f in F_SRC if (v := _get(s, f))), None)
    level = _get(s, F_LEVEL)
    tactic = _get(s, F_TACTIC) or []
    tech = _get(s, F_TECHNIQUE) or []
    return {
        "id": hit.get("_id"),
        "index": hit.get("_index"),
        "time": _get(s, F_TIME),
        "level": level,
        "severity": severity(level),
        "rule_id": _get(s, F_RULE_ID),
        "description": str(_get(s, F_RULE_DESC) or "")[:300],
        "groups": _get(s, F_GROUPS) or [],
        "tactics": tactic if isinstance(tactic, list) else [tactic],
        "techniques": tech if isinstance(tech, list) else [tech],
        "agent": _get(s, F_AGENT),
        "src_ip": src,
        "dest_ip": _get(s, "data.dest_ip") or _get(s, "data.dstip"),
        "signature": str(_get(s, "data.alert.signature") or "")[:300],
        "http_url": str(_get(s, "data.http.url") or "")[:500],
        "http_ua": str(_get(s, "data.http.http_user_agent") or "")[:300],
    }


def summary_query(minutes: int, bucket_s: int) -> dict:
    window = {"range": {F_TIME: {"gte": f"now-{minutes}m"}}}
    return {
        "size": 50,
        "track_total_hits": True,
        "sort": [{F_TIME: "desc"}],
        "query": {"bool": {"filter": [window]}},
        "aggs": {
            "by_level": {"range": {"field": F_LEVEL, "ranges": [{"key": n, "from": lo, "to": hi + 1} for n, lo, hi in SEVERITY_BANDS]}},
            "timeline": {"date_histogram": {"field": F_TIME, "fixed_interval": f"{bucket_s}s", "min_doc_count": 0,
                                             "extended_bounds": {"min": f"now-{minutes}m", "max": "now"}}},
            "top_rules": {"terms": {"field": F_RULE_DESC, "size": 10}},
            "tactics": {"terms": {"field": F_TACTIC, "size": 14}},
            "agents": {"terms": {"field": F_AGENT, "size": 10}},
            **{f"src_{i}": {"terms": {"field": f, "size": 10}} for i, f in enumerate(F_SRC)},
            **{f"src_card_{i}": {"cardinality": {"field": f}} for i, f in enumerate(F_SRC)},
        },
    }


def shape_summary(resp: dict, minutes: int) -> dict:
    aggs = resp.get("aggregations", {}) or {}
    total = resp.get("hits", {}).get("total", {})
    total = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    terms = lambda k: [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get(k, {}).get("buckets", [])]
    srcs: dict[str, int] = {}
    for i in range(len(F_SRC)):
        for b in terms(f"src_{i}"):
            srcs[b["key"]] = srcs.get(b["key"], 0) + b["count"]
    return {
        "window_min": minutes,
        "total": total,
        "by_severity": {b["key"]: b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])},
        "timeline": [{"t": b["key"], "count": b["doc_count"]} for b in aggs.get("timeline", {}).get("buckets", [])],
        "top_rules": terms("top_rules"),
        "tactics": terms("tactics"),
        "agents": terms("agents"),
        "top_sources": sorted(({"key": k, "count": v} for k, v in srcs.items()), key=lambda x: -x["count"])[:10],
        "unique_sources": max((aggs.get(f"src_card_{i}", {}).get("value", 0) for i in range(len(F_SRC))), default=0),
        "latest": [normalize_hit(h) for h in resp.get("hits", {}).get("hits", [])],
    }

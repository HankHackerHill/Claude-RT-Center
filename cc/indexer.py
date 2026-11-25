"""Read-only Wazuh indexer (OpenSearch) client shared by the CC API and the triage agent. Stdlib only."""
from __future__ import annotations

import base64
import datetime
import http.client
import json
import os
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent

# Field names in the wazuh-alerts-* template. Centralised so a template change is a one-line fix.
# VERIFIED on 4.14.11 (2026-11-25, GET wazuh-alerts-*/_mapping/field/...): all keyword, rule.level long,
# timestamp date. scripts/verify.sh re-checks the types on every Gate 1 run.
F_TIME = "timestamp"
F_LEVEL = "rule.level"
F_RULE_ID = "rule.id"
F_RULE_DESC = "rule.description"
F_GROUPS = "rule.groups"
F_TACTIC = "rule.mitre.tactic"
F_TECHNIQUE = "rule.mitre.id"
F_AGENT = "agent.name"
# Who STARTED the activity. Suricata's src_ip is the *packet* source: for to_client alerts (e.g. a burst of 404s) it is
# the victim (observed). flow.src_ip is the flow initiator and is present on every Suricata 8 alert (observed 271/271).
F_FLOW_SRC = "data.flow.src_ip"
F_SRC = (F_FLOW_SRC, "data.src_ip", "data.srcip")   # first present wins; srcip = syslog-style decoders
# Who was TARGETED: flow destination (data.dest_ip is the packet destination = the attacker on to_client alerts).
F_DST = ("data.flow.dest_ip", "data.dest_ip", "data.dstip")
F_EVENT_TIME = "data.timestamp"   # Suricata's own packet time (date-typed); F_TIME is when Wazuh raised the alert
F_HTTP_UA = "data.http.http_user_agent"
INDEX = "wazuh-alerts-*"
MAX_RESPONSE_BYTES = 20_000_000   # a summary/purple response is ~100 KB; anything near this is a bug or an attack

SEVERITY_BANDS = (("critical", 15, 99), ("high", 12, 14), ("medium", 7, 11), ("low", 0, 6))


# Keys the CC API and the triage agent may read from .env. The Wazuh admin/API/dashboard passwords are deliberately
# excluded: these two processes handle attacker-controlled text and must not hold credentials they do not use.
ENV_ALLOW = ("INDEXER_", "CC_", "TRIAGE_", "ANTHROPIC_API_KEY")


def load_env(path: Path = ROOT / ".env", allow: tuple[str, ...] | None = ENV_ALLOW) -> None:
    """Minimal KEY=VALUE loader; real environment variables win. `allow`: key prefixes to load (None = every key,
    for admin tooling such as scripts/indexer_roles.py)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if allow is None or k.startswith(allow):
            os.environ.setdefault(k, v.strip())


class IndexerError(RuntimeError):
    pass


def tls_context(ca_path: Path) -> ssl.SSLContext:
    """Verified TLS only: CA from the generated root, hostname checked, TLS >= 1.2. Never relaxed (CLAUDE.md #4)."""
    ctx = ssl.create_default_context(cafile=str(ca_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Python >= 3.13 adds VERIFY_X509_STRICT (RFC 5280 profile checks). wazuh-docker's generated root CA has
    # basicConstraints CA:TRUE but no keyUsage, which strict mode rejects. Clearing ONLY that flag keeps chain
    # verification against the pinned CA, hostname checking and CERT_REQUIRED (= Python <= 3.12 behaviour).
    # Decision recorded in HANDOFF.md; tests/test_stack.py proves wrong-name and foreign-CA certs still fail.
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    if not (ctx.check_hostname and ctx.verify_mode == ssl.CERT_REQUIRED):   # not an assert: -O must not strip it
        raise IndexerError("TLS context is not verifying; refusing to continue")
    return ctx


class _PinnedHTTPS(http.client.HTTPSConnection):
    """TCP-connects to `connect_host`, but does SNI + certificate-name verification against the URL host.
    Same idea as `curl --resolve`: the wazuh-docker cert is issued for "wazuh.indexer", not for 127.0.0.1.
    Uses http.client directly, so HTTPS_PROXY is never applied to the indexer connection."""

    def __init__(self, tls_host: str, port: int, connect_host: str, context: ssl.SSLContext, timeout: float):
        super().__init__(tls_host, port, context=context, timeout=timeout)
        # http.client sets _create_connection as an INSTANCE attribute in __init__, so a method override would be
        # shadowed (observed: it then resolved "wazuh.indexer" via DNS). Re-bind it here instead.
        self._create_connection = lambda address, timeout=None, source_address=None: socket.create_connection(
            (connect_host, address[1]), timeout, source_address)


class Indexer:
    def __init__(self) -> None:
        load_env()
        u = urlsplit(os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200"))
        if u.scheme != "https" or not u.hostname:
            raise IndexerError(f"INDEXER_URL must be https://<cert-name>:<port> (got {u.geturl()!r})")
        self.tls_host, self.port = u.hostname, u.port or 9200
        self.connect_host = os.environ.get("INDEXER_CONNECT", "").strip() or self.tls_host
        user, pw = os.environ.get("INDEXER_USER", ""), os.environ.get("INDEXER_PASS", "")
        if not user or not pw:
            raise IndexerError("INDEXER_USER / INDEXER_PASS not set")
        ca = os.environ.get("INDEXER_CA", "")
        ca_path = (ROOT / ca).resolve() if ca and not os.path.isabs(ca) else Path(ca)
        if not ca or not ca_path.is_file():
            raise IndexerError(f"INDEXER_CA not found: {ca_path} - TLS verification is not optional")
        self.ctx = tls_context(ca_path)
        self.auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    def _request(self, method: str, path: str, body: dict | None, timeout: float) -> dict:
        conn = _PinnedHTTPS(self.tls_host, self.port, self.connect_host, self.ctx, timeout)
        headers = {"Authorization": self.auth, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=data, headers=headers)
            r = conn.getresponse()
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise IndexerError(f"indexer response over {MAX_RESPONSE_BYTES} bytes")
            if r.status >= 400:
                raise IndexerError(f"indexer HTTP {r.status}: {raw[:300].decode(errors='replace')}")
            return json.loads(raw)
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:   # socket.timeout/TimeoutError are OSError
            raise IndexerError(f"indexer unreachable: {e}") from e
        except json.JSONDecodeError as e:
            raise IndexerError(f"indexer returned non-JSON: {e}") from e
        finally:
            conn.close()

    def search(self, body: dict, timeout: float = 10.0) -> dict:
        return self._request("POST", f"/{INDEX}/_search", body, timeout)

    def health(self) -> str:
        try:
            return str(self._request("GET", "/_cluster/health", None, 5.0).get("status", "unknown"))
        except IndexerError as e:  # health endpoint: report, don't raise
            return f"error: {e}"


# ---------- pure helpers (testable without the indexer) ----------

def _get(doc: dict, dotted: str):
    cur = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def initiator_filter(ip: str) -> dict:
    """Alerts whose activity was started by `ip`: flow.src_ip when Suricata provides it, else src_ip/srcip.
    (A plain OR over all three would also match to_client alerts where `ip` is only the responder.)"""
    legacy = [{"term": {f: ip}} for f in F_SRC[1:]]
    return {"bool": {"should": [
        {"term": {F_FLOW_SRC: ip}},
        {"bool": {"must_not": [{"exists": {"field": F_FLOW_SRC}}],
                  "should": legacy, "minimum_should_match": 1}}], "minimum_should_match": 1}}


def severity(level) -> str:
    try:
        lv = int(level)
    except (TypeError, ValueError):
        return "unknown"
    for name, lo, hi in SEVERITY_BANDS:
        if lo <= lv <= hi:
            return name
    return "unknown"


def iso_utc(v) -> str | None:
    """Wazuh writes "2026-11-25T18:24:55.445+0000" (no colon in the offset). V8 parses that; WebKit (the Claude mobile
    app) is not guaranteed to, so the API always emits ISO-8601 UTC with a Z. Unparseable input passes through."""
    if not isinstance(v, str) or not v:
        return v
    try:
        d = datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        try:
            d = datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return v
    if d.tzinfo is None:
        return v
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


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
        "time": iso_utc(_get(s, F_TIME)),
        "level": level,
        "severity": severity(level),
        "rule_id": _get(s, F_RULE_ID),
        "description": str(_get(s, F_RULE_DESC) or "")[:300],
        "groups": _get(s, F_GROUPS) or [],
        "tactics": tactic if isinstance(tactic, list) else [tactic],
        "techniques": tech if isinstance(tech, list) else [tech],
        "agent": _get(s, F_AGENT),
        "src_ip": src,
        "dest_ip": next((v for f in F_DST if (v := _get(s, f))), None),
        "signature": str(_get(s, "data.alert.signature") or "")[:300],
        "http_url": str(_get(s, "data.http.url") or "")[:500],
        "http_ua": str(_get(s, F_HTTP_UA) or "")[:300],
    }


def _only_field(i: int) -> dict:
    """Docs whose initiator is F_SRC[i]: that field exists and no earlier F_SRC field does."""
    return {"bool": {"filter": [{"exists": {"field": F_SRC[i]}}],
                     "must_not": [{"exists": {"field": f}} for f in F_SRC[:i]]}}


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
            # sources by initiator: each doc is counted under exactly one field (no double counting)
            **{f"src_{i}": {"filter": _only_field(i), "aggs": {
                "t": {"terms": {"field": f, "size": 10}}, "card": {"cardinality": {"field": f}}}}
               for i, f in enumerate(F_SRC)},
        },
    }


def shape_summary(resp: dict, minutes: int) -> dict:
    aggs = resp.get("aggregations", {}) or {}
    total = resp.get("hits", {}).get("total", {})
    total = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    terms = lambda k: [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get(k, {}).get("buckets", [])]
    srcs: dict[str, int] = {}
    exact, card_sum = True, 0
    for i in range(len(F_SRC)):
        a = aggs.get(f"src_{i}", {}) or {}
        t = a.get("t", {}) or {}
        for b in t.get("buckets", []):
            srcs[b["key"]] = srcs.get(b["key"], 0) + b["doc_count"]
        exact = exact and not t.get("sum_other_doc_count")
        card_sum += int((a.get("card") or {}).get("value", 0) or 0)
    return {
        "window_min": minutes,
        "total": total,
        "by_severity": {b["key"]: b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])},
        "timeline": [{"t": b["key"], "count": b["doc_count"]} for b in aggs.get("timeline", {}).get("buckets", [])],
        "top_rules": terms("top_rules"),
        "tactics": terms("tactics"),
        "agents": terms("agents"),
        "top_sources": sorted(({"key": k, "count": v} for k, v in srcs.items()), key=lambda x: -x["count"])[:10],
        # exact when every partition fit in its top-10; otherwise an upper bound (an IP can appear in 2 partitions)
        "unique_sources": len(srcs) if exact else card_sum,
        "unique_sources_exact": exact,
        "latest": [normalize_hit(h) for h in resp.get("hits", {}).get("hits", [])],
    }

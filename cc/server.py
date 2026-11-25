#!/usr/bin/env python3
"""Command-center API + dashboard host. Stdlib only. Read-only against the indexer.

  python3 cc/server.py            # serves http://127.0.0.1:8088
Endpoints: /  /api/health  /api/summary?minutes=60  /api/triage?limit=50  /api/purple?minutes=240  /api/score?minutes=240
           /api/infra
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from indexer import F_LEVEL, F_TIME, ROOT, Indexer, IndexerError, load_env, shape_summary, summary_query  # noqa: E402
import scoring  # noqa: E402
import teams  # noqa: E402

DASHBOARD = Path(__file__).resolve().parent / "dashboard.html"
TRIAGE_LOG = ROOT / "data" / "triage.jsonl"
CACHE_TTL = 5.0

_cache: dict[tuple, tuple[float, dict]] = {}
_lock = threading.Lock()
_indexer: Indexer | None = None


def clamp_int(raw, lo: int, hi: int, default: int) -> int:
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def bucket_for(minutes: int) -> int:
    """~60 timeline buckets, never below 10 s."""
    return max(10, minutes)  # window_seconds / 60 buckets == minutes


_allowed_hosts: set[str] = set()
OPEN_MAX = 1000


def allowed_hosts(port: int, extra: str = "") -> set[str]:
    """Pure: Host header values the API answers. Anything else is refused, which defeats DNS rebinding (a web page
    whose name re-resolves to 127.0.0.1 would otherwise read this unauthenticated API from the user's browser)."""
    hs = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    hs |= {h.strip().lower() for h in extra.split(",") if h.strip()}
    return hs


def open_query(minutes: int) -> dict:
    """Pure: level >= 12 alerts in the window (ids only), for the Blue 'critical + high open' KPI. v3 derived it in
    the browser from the 50 newest alerts of ANY level, so it read 0 while high alerts sat untriaged."""
    return {"size": OPEN_MAX, "_source": False, "track_total_hits": True, "sort": [{F_TIME: "desc"}],
            "query": {"bool": {"filter": [{"range": {F_TIME: {"gte": f"now-{minutes}m"}}},
                                          {"range": {F_LEVEL: {"gte": 12}}}]}}}


def count_open(resp: dict, triaged_ids: set) -> dict:
    hits = resp.get("hits", {})
    ids = [h.get("_id") for h in hits.get("hits", [])]
    total = hits.get("total", {})
    total = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    return {"open_crit_high": sum(1 for i in ids if i not in triaged_ids) + max(0, total - len(ids)),
            "open_crit_high_approx": total > len(ids)}


def triage_in_window(recs: list[dict], minutes: int, now: float) -> list[dict]:
    """Pure: verdicts made inside the score window (v3 scored the last 500 verdicts whatever the window)."""
    lo = now - minutes * 60
    return [r for r in recs if isinstance(r.get("triaged_at"), (int, float)) and r["triaged_at"] >= lo]


def read_triage(limit: int) -> list[dict]:
    if not TRIAGE_LOG.exists():
        return []
    out = []
    with TRIAGE_LOG.open() as f:
        lines = f.readlines()[-limit:]
    for ln in reversed(lines):
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


def purple_data(minutes: int) -> dict:
    """Drill ground truth joined with detections; cached like the summary."""
    key = ("purple", minutes)
    with _lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < CACHE_TTL:
            return hit[1]
    steps = teams.read_drills(int((time.time() - minutes * 60) * 1000))
    data = {"steps": [], "window_min": minutes, "grace_s": teams.PIPELINE_GRACE_MS // 1000}
    if steps:
        if _indexer is None:
            raise IndexerError("indexer not configured")
        data["steps"] = teams.shape_purple(_indexer.search(teams.purple_query(steps)), steps)
    with _lock:
        _cache[key] = (time.monotonic(), data)
    return data


class Handler(BaseHTTPRequestHandler):
    server_version = "cc/1"

    def log_message(self, fmt, *args):  # quieter access log
        sys.stderr.write("[cc] %s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json")

    def do_GET(self):  # noqa: N802
        if (self.headers.get("Host") or "").lower() not in _allowed_hosts:
            return self._json(421, {"error": "unexpected Host header"})
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            return self._send(200, DASHBOARD.read_bytes(), "text/html; charset=utf-8")
        if u.path == "/api/health":
            return self._json(200, {"ok": True, "indexer": _indexer.health() if _indexer else "not configured"})
        if u.path == "/api/summary":
            if _indexer is None:
                return self._json(503, {"error": "indexer not configured"})
            minutes = clamp_int(q.get("minutes", [60])[0], 5, 1440, 60)
            key = ("summary", minutes)
            with _lock:
                hit = _cache.get(key)
                if hit and time.monotonic() - hit[0] < CACHE_TTL:
                    return self._json(200, hit[1])
            try:
                data = shape_summary(_indexer.search(summary_query(minutes, bucket_for(minutes))), minutes)
                triaged = {r.get("alert_id") for r in read_triage(5000)}
                data.update(count_open(_indexer.search(open_query(minutes)), triaged))
            except IndexerError as e:
                return self._json(502, {"error": str(e)})
            data["generated_at"] = time.time()
            with _lock:
                _cache[key] = (time.monotonic(), data)
            return self._json(200, data)
        if u.path in ("/api/purple", "/api/score"):
            minutes = clamp_int(q.get("minutes", [240])[0], 5, 10080, 240)
            try:
                data = purple_data(minutes)
            except IndexerError as e:
                return self._json(502 if _indexer is not None else 503, {"error": str(e)})
            if u.path == "/api/purple":
                return self._json(200, data)
            # authoritative score (the dashboard's JS copy is only for offline sample data)
            tri = triage_in_window(read_triage(5000), minutes, time.time())
            return self._json(200, {**scoring.score(data["steps"], tri), "window_min": minutes})
        if u.path == "/api/infra":
            with _lock:
                hit = _cache.get(("infra",))
                if hit and time.monotonic() - hit[0] < CACHE_TTL:
                    return self._json(200, hit[1])
            data = teams.infra(_indexer)
            with _lock:
                _cache[("infra",)] = (time.monotonic(), data)
            return self._json(200, data)
        if u.path == "/api/triage":
            return self._json(200, read_triage(clamp_int(q.get("limit", [50])[0], 1, 500, 50)))
        return self._json(404, {"error": "not found"})


def main() -> None:
    global _indexer
    load_env()
    bind = os.environ.get("CC_BIND", "127.0.0.1")
    port = clamp_int(os.environ.get("CC_PORT"), 1, 65535, 8088)
    if bind not in ("127.0.0.1", "::1", "localhost") and os.environ.get("CC_ALLOW_REMOTE") != "1":
        sys.exit(f"refusing to bind {bind}: the API has no auth. Put it behind an authenticating proxy and set CC_ALLOW_REMOTE=1.")
    try:
        _indexer = Indexer()
    except IndexerError as e:
        print(f"[cc] WARNING: {e} - the dashboard will show LIVE · DEGRADED with this error", file=sys.stderr)
    global _allowed_hosts
    _allowed_hosts = allowed_hosts(port, os.environ.get("CC_ALLOWED_HOSTS", ""))
    _allowed_hosts.add(f"{bind}:{port}" if ":" not in bind else f"[{bind}]:{port}")
    srv_cls = ThreadingHTTPServer
    if ":" in bind:                                   # "::1": ThreadingHTTPServer is AF_INET only (crashed in v3)
        srv_cls = type("V6Server", (ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
    srv = srv_cls((bind, port), Handler)
    print(f"[cc] serving http://{bind}:{port}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()

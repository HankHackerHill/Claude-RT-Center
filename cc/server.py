#!/usr/bin/env python3
"""Command-center API + dashboard host. Stdlib only. Read-only against the indexer.

  python3 cc/server.py            # serves http://127.0.0.1:8088
Endpoints: /  /api/health  /api/summary?minutes=60  /api/triage?limit=50  /api/purple?minutes=240  /api/infra
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from indexer import ROOT, Indexer, IndexerError, load_env, shape_summary, summary_query  # noqa: E402
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
            except IndexerError as e:
                return self._json(502, {"error": str(e)})
            data["generated_at"] = time.time()
            with _lock:
                _cache[key] = (time.monotonic(), data)
            return self._json(200, data)
        if u.path == "/api/purple":
            minutes = clamp_int(q.get("minutes", [240])[0], 5, 10080, 240)
            steps = teams.read_drills(int((time.time() - minutes * 60) * 1000))
            if not steps:
                return self._json(200, {"steps": [], "window_min": minutes})
            if _indexer is None:
                return self._json(503, {"error": "indexer not configured"})
            try:
                resp = _indexer.search(teams.purple_query(steps))
            except IndexerError as e:
                return self._json(502, {"error": str(e)})
            return self._json(200, {"steps": teams.shape_purple(resp, steps), "window_min": minutes,
                                    "grace_s": teams.PIPELINE_GRACE_MS // 1000})
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
        print(f"[cc] WARNING: {e} — dashboard will fall back to sample data", file=sys.stderr)
    srv = ThreadingHTTPServer((bind, port), Handler)
    print(f"[cc] serving http://{bind}:{port}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()

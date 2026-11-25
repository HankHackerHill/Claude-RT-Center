#!/usr/bin/env bash
# Gate 1 checks -> "GATE 1: GO" / "GATE 1: NO-GO". Logic lives in scripts/verify.py (reuses the CC indexer client).
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/verify.py "$@"

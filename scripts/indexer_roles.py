#!/usr/bin/env python3
"""Create/refresh the least-privilege indexer role for the CC API and triage agent. Stdlib only. Idempotent.

  python3 scripts/indexer_roles.py           # run by scripts/bootstrap.sh after the indexer is up

Uses the admin credential (WAZUH_ADMIN_PASS) once, over the same verified-TLS client as the CC, to PUT:
  role cc_read: cluster:monitor/health + read-only on wazuh-alerts-* (nothing else)
  role mapping cc_read -> user cc_reader; default own_index mapping (users "*") emptied
Built-in "readall" was tried first and rejected: it lacks cluster:monitor/health and grants read on ALL indices.
"""
from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cc"))
import indexer as I  # noqa: E402

ROLE = "cc_read"
USER = "cc_reader"


def role_body() -> dict:
    """Pure: the exact privileges the CC needs (search + aggregations + field-mapping check + cluster health)."""
    return {
        "description": "Command center API + triage agent: read-only on Wazuh alerts",
        "cluster_permissions": ["cluster:monitor/health"],
        "index_permissions": [{"index_patterns": [I.INDEX], "allowed_actions": ["read"]}],
    }


def mapping_body() -> dict:
    return {"users": [USER], "backend_roles": [], "hosts": []}


def own_index_unmapped() -> dict:
    """OpenSearch's default roles_mapping maps role own_index to users ["*"]: every user, cc_reader included, gets
    write access to an index named after itself (review finding; the Gate 1 write probe used another index name).
    admin (all_access) and kibanaserver (kibana_server) do not need it."""
    return {"users": [], "backend_roles": [], "hosts": []}


def main() -> None:
    I.load_env(allow=None)   # admin tooling: needs WAZUH_ADMIN_PASS
    pw = os.environ.get("WAZUH_ADMIN_PASS", "")
    if not pw:
        sys.exit("[indexer_roles] WAZUH_ADMIN_PASS not set (run scripts/gen_secrets.py)")
    os.environ["INDEXER_USER"], os.environ["INDEXER_PASS"] = "admin", pw
    ix = I.Indexer()
    ix._request("PUT", f"/_plugins/_security/api/roles/{ROLE}", role_body(), 15)
    ix._request("PUT", f"/_plugins/_security/api/rolesmapping/{ROLE}", mapping_body(), 15)
    ix._request("PUT", "/_plugins/_security/api/rolesmapping/own_index", own_index_unmapped(), 15)
    print(f"[indexer_roles] role {ROLE} -> user {USER} applied")


if __name__ == "__main__":
    try:
        main()
    except I.IndexerError as e:
        sys.exit(f"[indexer_roles] {e}")

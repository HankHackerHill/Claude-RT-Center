#!/usr/bin/env python3
"""Build the manager's ossec.conf = upstream wazuh_manager.conf + CC rule dir + CC localfile block. Stdlib only.

  python3 scripts/gen_manager_conf.py <upstream wazuh_manager.conf> <out ossec.conf>

Pure core (build_manager_conf) is unit-tested in tests/test_stack.py.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CC_RULE_DIR = "etc/cc-rules"          # compose.override.yml mounts wazuh/rules/ here (read-only)
SNIPPET = ROOT / "wazuh" / "cc_localfile.conf"


def build_manager_conf(upstream: str, snippet: str) -> str:
    """Insert <rule_dir>etc/cc-rules</rule_dir> into upstream's single <ruleset>, then append the snippet.
    Idempotent: running it on its own output returns the same text."""
    line = f"    <rule_dir>{CC_RULE_DIR}</rule_dir>\n"
    if line in upstream:
        return upstream if snippet.strip() in upstream else upstream.rstrip("\n") + "\n\n" + snippet.strip() + "\n"
    n = upstream.count("</ruleset>")
    if n != 1:
        raise ValueError(f"expected exactly one </ruleset> in upstream manager conf, found {n}")
    i = upstream.index("</ruleset>")
    i = upstream.rindex("\n", 0, i) + 1          # start of the </ruleset> line
    out = upstream[:i] + line + upstream[i:]
    return out.rstrip("\n") + "\n\n" + snippet.strip() + "\n"


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(".tmp")
    tmp.write_text(build_manager_conf(src.read_text(), SNIPPET.read_text()))
    tmp.replace(dst)
    print(f"[gen_manager_conf] wrote {dst}")


if __name__ == "__main__":
    main()

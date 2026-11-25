"""Semantics of the project's Suricata PCREs, extracted verbatim from suricata/rules/local.rules. Stdlib only.

Python's `re` is PCRE-compatible for these patterns (classes, alternation, \\x escapes, /i). This proves WHAT the patterns
match; it does not prove Suricata parses the rule (that is `suricata -T`, run on the Rocky host / self-hosted CI).

  python3 -I tests/test_rules_regex.py
"""
import pathlib
import re

RULES = (pathlib.Path(__file__).resolve().parent.parent / "suricata" / "rules" / "local.rules").read_text()


def pcre(sid: int) -> re.Pattern:
    line = next(ln for ln in RULES.splitlines() if f"sid:{sid};" in ln and not ln.startswith("#"))
    body, flags = re.search(r'pcre:"/(.*)/([a-z]*)"', line).groups()
    body = body.replace(r"\;", ";")             # Suricata rule-option escape, not a regex escape
    return re.compile(body, re.I if "i" in flags else 0)


TRAV = pcre(9000004)
for hit in ["/ftp/../../etc/passwd", "/a/..%2fetc", "/a/%2e%2e/etc", "/a/%2e%2e%2fetc", "/a/.%2e/x", "/a/..\\windows",
            "/a/..%5cwin", "/a/%252e%252e%252fetc", "/A/%2E%2E%2F"]:
    assert TRAV.search(hit), f"traversal miss: {hit}"
for clean in ["/index.html", "/a.b/c.d", "/v1.2/x", "/..."[:3] + "x", "/files/report..pdf"]:
    assert not TRAV.search(clean), f"traversal false positive: {clean}"

CMDI = pcre(9000006)
for hit in ["ip=127.0.0.1;id&Submit=Submit", "ip=127.0.0.1%3B+whoami&Submit=Submit", "ip=1|uname -a", "ip=1%7Cid",
            "ip=1%0Aid", "ip=1&&whoami", "ip=1%26%26whoami", "ip=1`id`", "ip=1$(id)", "ip=1%24%28whoami%29",
            "ip=1;cat /etc/passwd", "ip=1%3Bcat+%2Fetc%2Fpasswd"]:
    assert CMDI.search(hit), f"cmdi miss: {hit}"
for clean in ["ip=127.0.0.1&Submit=Submit", "user=idris&x=1", "q=category;identity", "name=cathy", "a=1;b=2"]:
    assert not CMDI.search(clean), f"cmdi false positive: {clean}"
print("RULE REGEX TESTS PASS")

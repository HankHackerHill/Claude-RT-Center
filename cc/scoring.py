"""Exercise scoring: the authoritative Red vs Blue score, server-side. Pure, stdlib only.

The White team owns RUBRIC. The dashboard keeps a JS copy only to score its offline sample data; tests/render_dashboard.mjs
asserts the two implementations agree (same RUBRIC, same rows) on shared fixtures. A future game backend must use this
module, never a client-side score.
"""
from __future__ import annotations

RUBRIC = {"detect": 10, "fastBonus": 5, "fastS": 60, "tagMatch": 5, "triageRight": 3, "triageMissed": -5,
          "redEvade": 15, "redSlow": 5, "slowS": 300, "redFooled": 5}


def score(steps: list[dict], triage: list[dict], rubric: dict = RUBRIC) -> dict:
    """steps: shape_purple() output. triage: triage.jsonl records. Returns {rows, red, blue, rubric}."""
    r = rubric
    rows: list[dict] = []

    def add(label: str, count: int, red: int, blue: int) -> None:
        if count:
            rows.append({"label": label, "count": count, "red": red * count, "blue": blue * count})

    attackers = {s.get("src_ip") for s in steps}
    det = [s for s in steps if s.get("detected")]
    lat = lambda s: s.get("latency_s")  # noqa: E731
    add("Step detected", len(det), 0, r["detect"])
    add(f"Detected within {r['fastS']} s", sum(1 for s in det if lat(s) is not None and lat(s) <= r["fastS"]), 0, r["fastBonus"])
    add("Correct ATT&CK tag", sum(1 for s in det if s.get("technique_match")), 0, r["tagMatch"])
    add("Step evaded detection", len(steps) - len(det), r["redEvade"], 0)
    add(f"Detected after {r['slowS']} s", sum(1 for s in det if lat(s) is not None and lat(s) > r["slowS"]), r["redSlow"], 0)
    on_attack = [t for t in triage if t.get("src_ip") in attackers]
    add("Attack triaged correctly", sum(1 for t in on_attack if t.get("verdict") in ("true_positive", "benign_true_positive")),
        0, r["triageRight"])
    add("Attack dismissed as false positive", sum(1 for t in on_attack if t.get("verdict") == "false_positive"),
        r["redFooled"], r["triageMissed"])
    return {"rows": rows, "red": sum(x["red"] for x in rows), "blue": sum(x["blue"] for x in rows), "rubric": dict(r)}

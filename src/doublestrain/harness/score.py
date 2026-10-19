"""doublestrain score — metrics for a harness run (results.jsonl).

Headline metric is FALSE NOT-REACHABLE (label reachable, judge said not_reachable and it
was accepted): that is the error that silently demotes a live risk. Everything else
(accuracy, coverage, escalation, cost) is traded against keeping that at zero.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

_GOT = {"reachable": "reachable", "unreachable": "not_reachable"}


def summarise(rows: list[dict]) -> dict:
    confusion = Counter()        # (expected, got) with got in reachable|not_reachable|unresolved
    raw = Counter()              # (expected, judge's raw verdict incl. rejected/unsure)
    sources = Counter()
    n_dec_ok = n_lab = 0
    escalated = 0
    latency = 0.0
    cost = 0.0
    cached = 0
    calls = 0
    for r in rows:
        exp = (r.get("expect") or {}).get("reachability")
        got = _GOT.get(r["got"]["reachability"], "unresolved")
        j = r.get("judge")
        if j:
            calls += 1
            latency += j.get("latency_s") or 0.0
            cost += j.get("cost_usd") or 0.0
            cached += bool(j.get("cached"))
            escalated += bool(j.get("trail"))
            for t in j.get("trail") or []:
                cost += t.get("cost_usd") or 0.0
                latency += t.get("latency_s") or 0.0
        if got != "unresolved":
            sources[r["got"]["reach_source"]] += 1
        if exp:
            n_lab += 1
            confusion[(exp, got)] += 1
            raw[(exp, j["verdict"] if j else "none")] += 1
            n_dec_ok += r["got"]["decision"] == r["oracle_decision"]

    # EPSS sensitivity: Acts at each threshold, split by what the reachability fact was.
    sens = {}
    for r in rows:
        for t, d in (r.get("epss_sensitivity") or {}).items():
            s = sens.setdefault(t, {"act": 0, "act_reachable": 0, "act_unresolved": 0,
                                    "oracle_act": 0, "agree": 0})
            got = r["got"]["reachability"]
            if d["decision"] == "Act":
                s["act"] += 1
                s["act_reachable" if got == "reachable" else "act_unresolved"] += 1
            s["oracle_act"] += d["oracle"] == "Act"
            s["agree"] += d["decision"] == d["oracle"]

    resolved = sum(v for (e, g), v in confusion.items() if g != "unresolved")
    correct = sum(v for (e, g), v in confusion.items() if e == g)
    return {
        "n": len(rows), "labelled": n_lab,
        "false_not_reachable": confusion[("reachable", "not_reachable")],
        "false_reachable": confusion[("not_reachable", "reachable")],
        "resolved": resolved,
        "coverage": round(resolved / n_lab, 3) if n_lab else None,
        "accuracy_resolved": round(correct / resolved, 3) if resolved else None,
        "decision_agreement": round(n_dec_ok / n_lab, 3) if n_lab else None,
        "decisions_correct": n_dec_ok,
        "judge_calls": calls, "escalated": escalated, "cached": cached,
        "resolved_by": dict(sources),
        "judge_latency_s": round(latency, 2), "cost_usd": round(cost, 4),
        "confusion": {f"{e}->{g}": v for (e, g), v in sorted(confusion.items())},
        "raw_verdicts": {f"{e}->{g}": v for (e, g), v in sorted(raw.items())},
        "epss_sensitivity": dict(sorted(sens.items())),
    }


def render(s: dict) -> str:
    lines = [
        f"labelled {s['labelled']}  resolved {s['resolved']} (coverage {s['coverage']})  "
        f"accuracy(resolved) {s['accuracy_resolved']}",
        f"FALSE NOT-REACHABLE {s['false_not_reachable']}   false reachable {s['false_reachable']}",
        f"decision agreement vs oracle {s['decisions_correct']}/{s['labelled']} ({s['decision_agreement']})",
        f"judge calls {s['judge_calls']}  escalated {s['escalated']}  cached {s['cached']}  "
        f"resolved_by {s['resolved_by']}  latency {s['judge_latency_s']}s  cost ${s['cost_usd']}",
        "confusion (expected->accepted): " + ", ".join(f"{k} {v}" for k, v in s["confusion"].items()),
        "raw judge verdicts (expected->final verdict): " + ", ".join(f"{k} {v}" for k, v in s["raw_verdicts"].items()),
    ]
    if s.get("epss_sensitivity"):
        lines.append("EPSS Act threshold sensitivity (Act = reachable + unresolved | oracle Act | agree):")
        lines += [f"  >= {t}: Act {v['act']} = {v['act_reachable']} + {v['act_unresolved']} | "
                  f"oracle {v['oracle_act']} | agree {v['agree']}/{s['labelled']}"
                  for t, v in s["epss_sensitivity"].items()]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run_dir")
    args = ap.parse_args(argv)
    rows = [json.loads(ln) for ln in (Path(args.run_dir) / "results.jsonl").read_text().splitlines() if ln]
    print(render(summarise(rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

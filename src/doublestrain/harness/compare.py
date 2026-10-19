"""doublestrain compare — diff two harness runs: headline metric deltas + per-candidate changes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

_KEYS = ("false_not_reachable", "false_reachable", "coverage", "accuracy_resolved",
         "decision_agreement", "escalated", "judge_latency_s", "cost_usd")


def _load(d: str):
    p = Path(d)
    summary = json.loads((p / "summary.json").read_text())
    rows = {(r["case"], r["pr"]): r for r in
            (json.loads(ln) for ln in (p / "results.jsonl").read_text().splitlines() if ln)}
    return summary, rows


def _jv(r):
    j = r.get("judge")
    return f"{j['source']}:{j['verdict']}@{j['confidence']:.2f}" if j else "-"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("a")
    ap.add_argument("b")
    args = ap.parse_args(argv)
    sa, ra = _load(args.a)
    sb, rb = _load(args.b)
    print(f"A = {sa['run']['judge']} ({args.a})\nB = {sb['run']['judge']} ({args.b})\n")
    for k in _KEYS:
        print(f"  {k:<22} {str(sa.get(k)):>8} -> {str(sb.get(k)):<8}")
    print()
    changed = 0
    for key in sorted(set(ra) | set(rb)):
        a, b = ra.get(key), rb.get(key)
        if not a or not b:
            print(f"  {key}: only in {'A' if a else 'B'}")
            continue
        if (a["got"]["decision"], a["got"]["reachability"]) != (b["got"]["decision"], b["got"]["reachability"]):
            changed += 1
            ok = lambda r: "ok" if r["got"]["decision"] == r["oracle_decision"] else "WRONG"
            print(f"  {key[0]} {b['package']}: expect {b['expect'].get('reachability')} / oracle {b['oracle_decision']}\n"
                  f"      A {_jv(a):<26} {a['got']['reachability']:<12} {a['got']['decision']:<6} {ok(a)}\n"
                  f"      B {_jv(b):<26} {b['got']['reachability']:<12} {b['got']['decision']:<6} {ok(b)}")
    print(f"\n{changed} candidate(s) changed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

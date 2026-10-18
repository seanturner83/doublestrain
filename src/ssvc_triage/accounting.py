"""Usage ledger: one JSON line per model call, tagged with what asked for it.

Every claude-code call (`judges.claude_code._invoke`) and every OpenAI-compatible
endpoint call (`judges.local.OpenAIJudge.complete`) is appended to
SSVC_ACCOUNTING_LOG (default ~/.cache/ssvc-triage/accounting.jsonl; "off" disables),
mode 0600. A line carries:

- tags: `tool` (ssvc-run, ssvc-scan, ...), `run` (the run id), `case`, `cve`,
  `package` (whatever is in scope when the call is made: see `tag`);
- the call: `kind` (claude | endpoint), `purpose` (spec, shape, judge, match, defeat,
  triage), `model` asked for, `models` that answered, `outcome` (ok, refused, error,
  limit, timeout), `cost_usd`, token counts, `latency_s`, and claude's `session_id` so a
  line can be matched against the account's own usage view.

Nothing about the code under review is written: no prompts, no answers. `ssvc-usage`
summarises the ledger; the harness also prints this process's totals at the end of a
run and keeps them in summary.json.
"""
from __future__ import annotations

import argparse
import contextlib
import contextvars
import json
import os
import sys
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

_TAGS: contextvars.ContextVar[dict] = contextvars.ContextVar("ssvc_accounting_tags", default={})
_BASE: dict = {}
# this process's totals: (kind, purpose, model) -> counters
TOTALS: dict[tuple[str, str, str], dict] = defaultdict(lambda: defaultdict(float))
_LOCK = threading.Lock()      # `ssvc-run --workers`: records come from several threads


def ledger_path() -> Path | None:
    p = os.environ.get("SSVC_ACCOUNTING_LOG", "~/.cache/ssvc-triage/accounting.jsonl").strip()
    return None if p.lower() in ("", "off", "0", "none") else Path(p).expanduser()


def start(tool: str, run: str = "") -> str:
    """Process-wide tags for a command; returns the run id (generated if not given)."""
    run = run or f"{tool}-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
    _BASE.update(tool=tool, run=run)
    return run


@contextlib.contextmanager
def tag(**kw):
    """Tags for the calls made inside the block (nested blocks add to the outer ones)."""
    tok = _TAGS.set({**_TAGS.get(), **{k: v for k, v in kw.items() if v not in (None, "")}})
    try:
        yield
    finally:
        _TAGS.reset(tok)


def record(kind: str, purpose: str, **fields) -> None:
    """Append one call to the ledger and the process totals. Never raises."""
    line = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kind": kind,
            "purpose": purpose or "", **_BASE, **_TAGS.get(), **fields}
    with _LOCK:
        t = TOTALS[(kind, line["purpose"], str(fields.get("model") or ""))]
        t["calls"] += 1
        t[f"outcome_{fields.get('outcome', 'ok')}"] += 1
        for k in ("cost_usd", "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "latency_s"):
            t[k] += float(fields.get(k) or 0)
        p = ledger_path()
        if p is None:
            return
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as fh:
                fh.write(json.dumps(line, default=str) + "\n")
        except OSError:
            pass


def claude_fields(out: dict) -> dict:
    """Token/cost fields from a `claude -p --output-format json` envelope."""
    u = out.get("usage") or {}
    return {"cost_usd": float(out.get("total_cost_usd") or 0.0),
            "input_tokens": int(u.get("input_tokens") or 0),
            "output_tokens": int(u.get("output_tokens") or 0),
            "cache_read_tokens": int(u.get("cache_read_input_tokens") or 0),
            "cache_write_tokens": int(u.get("cache_creation_input_tokens") or 0),
            "turns": out.get("num_turns"), "session_id": out.get("session_id")}


def endpoint_fields(out: dict) -> dict:
    u = out.get("usage") or {}
    return {"input_tokens": int(u.get("prompt_tokens") or 0),
            "output_tokens": int(u.get("completion_tokens") or 0)}


def totals() -> list[dict]:
    return [{"kind": k, "purpose": p, "model": m, **{a: round(b, 4) for a, b in v.items()}}
            for (k, p, m), v in sorted(TOTALS.items())]


def render(rows: list[dict]) -> str:
    if not rows:
        return "usage: no model calls"
    out = [f"{'kind':<9} {'purpose':<8} {'model':<28} {'calls':>6} {'usd':>8} {'in_tok':>10} {'out_tok':>9} "
           f"{'cache_rd':>10} {'not_ok':>6}"]
    for r in rows:
        bad = sum(v for k, v in r.items() if k.startswith("outcome_") and k != "outcome_ok")
        out.append(f"{r['kind']:<9} {r['purpose']:<8} {str(r['model'])[:28]:<28} {int(r['calls']):>6} "
                   f"{r.get('cost_usd', 0):>8.2f} {int(r.get('input_tokens', 0)):>10} {int(r.get('output_tokens', 0)):>9} "
                   f"{int(r.get('cache_read_tokens', 0)):>10} {int(bad):>6}")
    return "\n".join(out)


# --- ssvc-usage ---------------------------------------------------------------

def _since(s: str) -> datetime:
    n, unit = float(s[:-1]), s[-1]
    return datetime.now(timezone.utc) - timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[unit]: n})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ssvc-usage", description="Summarise the model-call ledger.")
    ap.add_argument("--since", default="24h", help="window: 90m, 24h, 7d (default 24h)")
    ap.add_argument("--run", help="only this run id")
    ap.add_argument("--by", default="tool,run,kind,purpose,model",
                    help="comma-separated grouping fields (default tool,run,kind,purpose,model)")
    args = ap.parse_args(argv)
    p = ledger_path()
    if p is None or not p.exists():
        print("no ledger", file=sys.stderr)
        return 1
    try:
        since = _since(args.since)
    except (ValueError, KeyError, IndexError):
        print("--since: use e.g. 90m, 24h, 7d", file=sys.stderr)
        return 2
    by = [b.strip() for b in args.by.split(",") if b.strip()]
    groups: dict[tuple, dict] = defaultdict(lambda: defaultdict(float))
    first = last = None
    for raw in p.read_text().splitlines():
        try:
            d = json.loads(raw)
            ts = datetime.fromisoformat(d["ts"])
        except (ValueError, KeyError):
            continue
        if ts < since or (args.run and d.get("run") != args.run):
            continue
        first, last = first or ts, ts
        g = groups[tuple(str(d.get(b, "")) for b in by)]
        g["calls"] += 1
        g["not_ok"] += d.get("outcome", "ok") != "ok"
        for k in ("cost_usd", "input_tokens", "output_tokens", "cache_read_tokens"):
            g[k] += float(d.get(k) or 0)
    if not groups:
        print("no calls in the window")
        return 0
    print(f"{first:%Y-%m-%d %H:%M} .. {last:%Y-%m-%d %H:%M} UTC")
    w = [max(len(b), *(len(k[i]) for k in groups)) for i, b in enumerate(by)]
    print("  ".join(f"{b:<{w[i]}}" for i, b in enumerate(by))
          + f"  {'calls':>6} {'usd':>8} {'in_tok':>11} {'out_tok':>9} {'cache_rd':>11} {'not_ok':>6}")
    for k, g in sorted(groups.items(), key=lambda kv: -kv[1]["cost_usd"]):
        print("  ".join(f"{v:<{w[i]}}" for i, v in enumerate(k))
              + f"  {int(g['calls']):>6} {g['cost_usd']:>8.2f} {int(g['input_tokens']):>11} "
              f"{int(g['output_tokens']):>9} {int(g['cache_read_tokens']):>11} {int(g['not_ok']):>6}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["start", "tag", "record", "claude_fields", "endpoint_fields", "totals", "render", "ledger_path"]

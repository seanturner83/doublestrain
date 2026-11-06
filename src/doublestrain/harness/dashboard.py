"""doublestrain dashboard: a local, live view of the funnel's configuration and progress.

    doublestrain dashboard [--port 8765] [--runs runs] [--cases cases]

Serves one page on 127.0.0.1 (never another interface) with:

- Pipeline: every case (and every `doublestrain scan`) and how far it has come:
  checked out -> inventoried (advisory rows) -> dependency source fetched -> labelled ->
  judged -> settled, with the wrong settles against the labels.
- Runs: each harness run (live while it runs: rows done of its plan.json), and its
  funnel: per cascade tier, the rows that reached it and what that tier did with them
  (settled reachable / not_reachable, held, escalated).
- Inference: the model calls from the usage ledger (`accounting`), streamed as they
  happen: destination, model, purpose, case / advisory / package, bytes and tokens each
  way, latency, cost, outcome; totals per destination over 1h / 24h / 7d. The ledger
  holds no prompt or answer text, so neither does this page.
- Config: acceptance floors per role and model, which ecosystems are held, measured or
  corroborated, the per-ecosystem claude model, and the SSVC_* settings in effect
  (secrets shown only as set / unset).

Updates arrive over Server-Sent Events (/api/events): the server watches the ledger and
the run directories and tells the page what changed. Everything is read from local files;
the page loads nothing from the network. Requests must name this host (Host header), so
another site can't read it through DNS rebinding.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ECOSYSTEMS = ("npm", "go", "pypi", "cargo", "maven", "composer")
_SECRET = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|HEADERS|AUTH", re.I)
_LEDGER_FIELDS = ("ts", "kind", "purpose", "tool", "run", "case", "cve", "package", "outcome", "model", "models",
                  "endpoint", "dest", "latency_s", "cost_usd", "input_tokens", "output_tokens", "cache_read_tokens",
                  "cache_write_tokens", "sent_bytes", "recv_bytes")
_SET = re.compile(r"\(([a-z]+\d+)\)")          # "(php1)", "(rs2)" in a case description


class Store:
    """Reads the runs, cases, ledger and config, with mtime-keyed caches (runs can hold
    hundreds of directories; a finished run never changes)."""

    def __init__(self, runs: Path, cases: Path):
        self.runs, self.cases = runs, cases
        self._run_cache: dict[str, tuple[tuple, dict]] = {}
        self._lock = threading.Lock()

    # --- runs ---------------------------------------------------------------------
    def run_dirs(self) -> list[Path]:
        if not self.runs.is_dir():
            return []
        return sorted((d for d in self.runs.iterdir() if d.is_dir() and (d / "results.jsonl").is_file()),
                      key=lambda d: d.name, reverse=True)

    def _rows(self, d: Path) -> list[dict]:
        out = []
        try:
            with open(d / "results.jsonl") as fh:
                for ln in fh:
                    try:
                        out.append(json.loads(ln))
                    except ValueError:
                        break                      # a row being written
        except OSError:
            pass
        return out

    def labels(self) -> tuple[tuple, dict]:
        """The current labels, (case, pr) -> (reachability, ecosystem), from every case.json, and a
        version key: runs are scored against these, not the labels copied into results.jsonl when
        they ran (re-reviews change labels after the runs)."""
        files = sorted(self.cases.glob("*/case.json"))
        ver = tuple((str(f), f.stat().st_mtime) for f in files)
        with self._lock:
            if getattr(self, "_labels", None) and self._labels[0] == ver:
                return self._labels
        out = {}
        for f in files:
            c = _json(f) or {}
            cid = c.get("id") or f.parent.name
            for cand in c.get("candidates") or []:
                out[(cid, cand.get("pr", ""))] = ((cand.get("expect") or {}).get("reachability") or "",
                                                  (cand.get("facts") or {}).get("ecosystem", ""))
        with self._lock:
            self._labels = (ver, out)
        return self._labels

    def run(self, d: Path) -> dict:
        res = d / "results.jsonl"
        key = tuple((p.stat().st_mtime, p.stat().st_size) if p.exists() else None
                    for p in (res, d / "summary.json", d / "plan.json")) + (hash(self.labels()[0]),)
        with self._lock:
            hit = self._run_cache.get(d.name)
            if hit and hit[0] == key:
                return hit[1]
        info = self._run_info(d)
        with self._lock:
            self._run_cache[d.name] = (key, info)
        return info

    def _run_info(self, d: Path) -> dict:
        rows = self._rows(d)
        labels = self.labels()[1]
        for r in rows:                 # score against today's labels; a case's rows keep theirs if it's gone
            lab, eco = labels.get((r.get("case", ""), r.get("pr", "")), (None, ""))
            if lab is not None:
                r["expect"] = {"reachability": lab} if lab else {}
            r["_eco"] = eco
        summ = _json(d / "summary.json") or {}
        plan = _json(d / "plan.json") or {}
        scan = d.name.startswith("scan-")
        judge = (summ.get("run") or {}).get("judge") or summ.get("judge") or plan.get("judge") or ""
        cases = (summ.get("run") or {}).get("cases") or plan.get("cases") or (
            [summ["name"]] if scan and summ.get("name") else sorted({r.get("case", "") for r in rows} - {""}))
        planned = plan.get("rows") or summ.get("n") or len(rows)
        mtime = (d / "results.jsonl").stat().st_mtime
        running = not (d / "summary.json").exists() and time.time() - mtime < 900
        info = {"name": d.name, "kind": "scan" if scan else "run", "judge": judge, "cases": cases,
                "rows": len(rows), "planned": planned, "running": running,
                "finished": not running and (d / "summary.json").exists(),
                "updated": datetime.fromtimestamp(mtime).isoformat(timespec="seconds"),
                "cost_usd": round(float(summ.get("cost_usd") or sum(float((r.get("judge") or {}).get("cost_usd") or 0)
                                                                   for r in rows)), 2)}
        info.update(_score(rows))
        info["funnel"] = _funnel(rows, judge)
        info["by_case"] = _by_case(rows)
        info["_rows"] = {(r.get("case", ""), r.get("pr", "")): _row_view(r) for r in rows}
        return info

    def runs_list(self) -> list[dict]:
        out = []
        for d in self.run_dirs():
            r = self.run(d)
            out.append({k: v for k, v in r.items() if k not in ("funnel", "by_case", "_rows")})
        return out

    def _run_full(self, name: str) -> dict | None:
        d = next((d for d in self.run_dirs() if d.name == name), None)     # only listed names, never a path
        return self.run(d) if d else None

    def run_detail(self, name: str) -> dict | None:
        r = self._run_full(name)
        return {k: v for k, v in r.items() if k != "_rows"} if r else None

    # --- cases ----------------------------------------------------------------------
    def pipeline(self) -> list[dict]:
        latest: dict[str, list[dict]] = defaultdict(list)
        for r in self.runs_list():
            for c in r["cases"]:
                latest[c].append(r)
        out = []
        for cj in sorted(self.cases.glob("*/case.json")):
            case = _json(cj)
            if not case:
                continue
            cid, cands = case.get("id") or cj.parent.name, case.get("candidates") or []
            repo = cj.parent / (case.get("repo") or "repo")
            ecos = Counter((c.get("facts") or {}).get("ecosystem", "") for c in cands)
            labelled = sum(bool((c.get("expect") or {}).get("reachability")) for c in cands)
            pkgs = {((c.get("facts") or {}).get("ecosystem", ""), (c.get("facts") or {}).get("package", ""),
                     (c.get("facts") or {}).get("version", "")) for c in cands}
            fetched = sum(_source_cached(*p) for p in pkgs)
            runs = [r for r in latest.get(cid, []) if r["kind"] == "run"]
            labels = {c.get("pr", ""): (c.get("expect") or {}).get("reachability") or "" for c in cands}
            nr_labels = sum(v == "not_reachable" for v in labels.values())
            best = self._best_result(cid, cands, labels, runs)
            row = {"rows_judged": best["rows_judged"], "nr_labels": nr_labels, "nr_right": best["right"],
                   "nr_wrong": best["wrong"], "coverage": round(best["right"] / nr_labels, 3) if nr_labels else None}
            judged = {"name": best["run"], "judge": best["how"]} if best["run"] else None
            m = _SET.search(case.get("description") or "")
            out.append({"id": cid, "set": m.group(1) if m else cid.rsplit("-", 1)[0],
                        "description": case.get("description") or "",
                        "ecosystems": dict(ecos), "checked_out": repo.is_dir() and any(repo.iterdir()),
                        "rows": len(cands), "packages": len(pkgs), "sources": fetched, "labelled": labelled,
                        "runs": len(runs), "last_run": judged["name"] if judged else "", "settled_by": best["how"],
                        "last_judge": judged["judge"] if judged else "", **{f"last_{k}": v for k, v in row.items()}})
        return out

    def _best_result(self, cid: str, cands: list[dict], labels: dict, runs: list[dict]) -> dict:
        """Where this case stands: the newest full cascade run's own settles, or the split +
        claude pair, whichever settles more (a wrong settle counts as five right ones lost). The pair: the newest
        split run's not_reachable at split's floor (per ecosystem) where the newest claude run
        also says not_reachable at claude's floor; on maven never a deserialization gadget.
        Scored against the case's current labels."""
        best = {"run": "", "how": "", "right": 0, "wrong": 0, "rows_judged": 0}
        n = len(cands)

        def better(c):
            return (c["right"] - 5 * c["wrong"], c["rows_judged"]) > (best["right"] - 5 * best["wrong"], best["rows_judged"])
        # the newest full cascade (or govulncheck) run only: older single-tier runs settled under
        # rules that no longer apply (Jev alone, an endpoint without a second read)
        for r in runs:
            if not r["judge"].startswith(("cascade", "govulncheck")):
                continue
            full = self._run_full(r["name"]) or {}
            mine = {k: v for k, v in full.get("_rows", {}).items() if k[0] == cid}
            if len(mine) < 0.9 * n:
                continue
            right = sum(v["settled"] == "not_reachable" and labels.get(pr) == "not_reachable" for (_, pr), v in mine.items())
            wrong = sum(v["settled"] == "not_reachable" and labels.get(pr) not in ("not_reachable", "") for (_, pr), v in mine.items())
            best = {"run": r["name"], "how": r["judge"], "right": right, "wrong": wrong, "rows_judged": len(mine)}
            break
        split = next((r for r in runs if r["judge"].startswith("split")), None)
        claude = next((r for r in runs if r["judge"] == "claude"), None)
        if split and claude:
            from ..judges import base
            from ..reach import _GADGET
            roles, _ = base._table(os.environ.get("SSVC_FLOORS_FILE") or str(base._FLOORS_FILE))
            sp = {k: v for k, v in (self._run_full(split["name"]) or {}).get("_rows", {}).items() if k[0] == cid}
            cl = {k: v for k, v in (self._run_full(claude["name"]) or {}).get("_rows", {}).items() if k[0] == cid}
            c_floor = float((roles.get("claude") or {}).get("not_reachable", 0.7))
            right = wrong = 0
            for cand in cands:
                f = cand.get("facts") or {}
                eco, k = f.get("ecosystem", ""), (cid, cand.get("pr", ""))
                srole = roles.get("split") or {}
                s_floor = float((srole.get("not_reachable_by_ecosystem") or {}).get(eco, srole.get("not_reachable", 0.95)))
                a, b = (sp.get(k) or {}).get("nr_raw"), (cl.get(k) or {}).get("nr_raw")
                if a is None or b is None or a < s_floor or b < c_floor:
                    continue
                if eco == "maven" and _GADGET.search(f"{f.get('advisory_summary') or ''} {' '.join(f.get('vuln_symbols') or [])}"):
                    continue
                lab = labels.get(cand.get("pr", ""))
                right += lab == "not_reachable"
                wrong += lab not in ("not_reachable", "")
            c = {"run": split["name"], "how": f"pair: {split['judge']} + claude", "right": right, "wrong": wrong,
                 "rows_judged": len(sp)}
            if better(c):
                best = c
        return best

    def scans(self) -> list[dict]:
        return [r for r in self.runs_list() if r["kind"] == "scan"]


def _json(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


_PKGSRC_PREFIX = {"npm": "", "go": "go+", "pypi": "pypi+", "cargo": "crates+", "maven": "maven+",
                  "composer": "composer+"}


_SRC_INDEX: tuple[float, set[str]] = (0.0, set())


def _source_index() -> set[str]:
    """`<prefix><name>@<version>` for every fetched source in the pkgsrc cache (its
    manifests are `<that>-<tag>.json`), re-read when the cache directory changes."""
    global _SRC_INDEX
    from .. import pkgsrc
    root = pkgsrc.cache_root()
    try:
        m = root.stat().st_mtime
    except OSError:
        return set()
    if m != _SRC_INDEX[0]:
        _SRC_INDEX = (m, {f.name[:-5].rsplit("-", 1)[0] for f in os.scandir(root) if f.name.endswith(".json")})
    return _SRC_INDEX[1]


def _source_cached(eco: str, name: str, version: str) -> bool:
    if eco not in _PKGSRC_PREFIX:
        return False
    from ..pkgsrc import _go_escape
    stem = {"maven": name.replace(":", "+"), "pypi": re.sub(r"[-_.]+", "-", name).lower(),
            "go": _go_escape(name).replace("/", "+")}.get(eco, name.replace("/", "+"))
    return f"{_PKGSRC_PREFIX[eco]}{stem}@{version}" in _source_index()


# --- scoring and the funnel -----------------------------------------------------------

def _label(r: dict) -> str:
    return (r.get("expect") or {}).get("reachability") or ""


def _settled(r: dict) -> tuple[str, str]:
    """(verdict the row settled as: reachable | not_reachable | "", the tier that settled it)."""
    got = r.get("got") or {}
    reach, src = got.get("reachability") or "", got.get("reach_source") or ""
    if not src:
        return "", ""
    return ("not_reachable" if reach in ("unreachable", "not_reachable") else "reachable"
            if reach == "reachable" else ""), src


_FLOORS: tuple[float, dict] = (0.0, {})


def _nr_floor(source: str, eco: str) -> float:
    """The not_reachable floor for the role behind `source` on this ecosystem (floors.toml)."""
    global _FLOORS
    from ..judges import base
    path = Path(os.environ.get("SSVC_FLOORS_FILE") or str(base._FLOORS_FILE))
    m = path.stat().st_mtime
    if m != _FLOORS[0]:
        _FLOORS = (m, base._table(str(path))[0])
    roles = _FLOORS[1]
    p = roles.get(base.role(source)) or roles.get("endpoint") or {}
    return float((p.get("not_reachable_by_ecosystem") or {}).get(eco, p.get("not_reachable", 0.9)))


def _score(rows: list[dict]) -> dict:
    """`nr_*`: rows the run settled not_reachable. `said_*`: rows whose final judge answered
    not_reachable at its role's floor (held or open-world-downgraded answers included), which is
    what a stage run (one tier, before the pair is formed) measures."""
    nr_labels = sum(_label(r) == "not_reachable" for r in rows)
    s = Counter()
    for r in rows:
        j = r.get("judge") or {}
        raw = _row_view(r)["nr_raw"]
        if raw is not None and raw >= _nr_floor(j.get("source") or "", r.get("_eco", "")) and _label(r):
            s["said_right" if _label(r) == "not_reachable" else "said_wrong"] += 1
        v, _ = _settled(r)
        lab = _label(r)
        if v and lab:
            s[f"{v}_{'right' if v == lab else 'wrong'}"] += 1
        elif v:
            s[f"{v}_unlabelled"] += 1
        s[(r.get("got") or {}).get("decision") or "?"] += 1
    return {"labelled": sum(bool(_label(r)) for r in rows), "nr_labels": nr_labels,
            "nr_right": s["not_reachable_right"], "nr_wrong": s["not_reachable_wrong"],
            "r_right": s["reachable_right"], "r_wrong": s["reachable_wrong"],
            "settled_unlabelled": s["not_reachable_unlabelled"] + s["reachable_unlabelled"],
            "coverage": round(s["not_reachable_right"] / nr_labels, 3) if nr_labels else None,
            "said_right": s["said_right"], "said_wrong": s["said_wrong"],
            "said_coverage": round(s["said_right"] / nr_labels, 3) if nr_labels else None,
            "decisions": {k: s[k] for k in ("Act", "Attend", "Track") if s[k]}}


def _tiers(judge: str) -> list[str]:
    if judge.startswith("cascade:"):
        return [t for t in judge[len("cascade:"):].split(",") if t]
    return [judge] if judge else []


def _same_tier(source: str, tier: str) -> bool:
    if source == tier:
        return True
    # a tier's verdicts can name the model behind it (shape:claude-opus-5-5 for `shape`)
    return source.partition(":")[0] == tier.partition(":")[0] and ":" not in tier


def _funnel(rows: list[dict], judge: str) -> list[dict]:
    """Per tier, in cascade order: the rows that reached it and what it did with them."""
    tiers = _tiers(judge)
    stats = [{"tier": t, "entered": 0, "reachable": 0, "not_reachable": 0, "unsure": 0, "unavailable": 0,
              "settled_reachable": 0, "settled_not_reachable": 0, "held": 0, "wrong": 0, "wrong_nr": 0, "wrong_r": 0,
              "cost_usd": 0.0}
             for t in tiers]
    for r in rows:
        j = r.get("judge") or {}
        # a hold or open-world downgrade on the final answer is in its rationale, not the trail
        why = j.get("rationale") or ""
        final = {**{k: j.get(k) for k in ("source", "verdict", "confidence", "cost_usd")},
                 "note": why[:120] if why.startswith(("not_reachable held", "not_reachable downgraded")) else ""}
        trail = list(j.get("trail") or []) + [final]
        v_set, by = _settled(r)
        seen = set()
        for e in trail:
            src = e.get("source") or ""
            i = next((i for i, t in enumerate(tiers) if _same_tier(src, t)), None)
            if i is None or i in seen:
                continue
            seen.add(i)
            st = stats[i]
            st["entered"] += 1
            st[e.get("verdict") or "unavailable"] = st.get(e.get("verdict") or "unavailable", 0) + 1
            st["cost_usd"] += float(e.get("cost_usd") or 0)
            if (e.get("note") or "").startswith(("not_reachable held", "not_reachable downgraded")):
                st["held"] += 1
        if by:
            i = next((i for i, t in enumerate(tiers) if _same_tier(by, t)), None)
            if i is not None:
                stats[i][f"settled_{v_set}"] += 1
                if _label(r) and v_set != _label(r):
                    stats[i]["wrong"] += 1
                    stats[i]["wrong_nr" if v_set == "not_reachable" else "wrong_r"] += 1
    for st in stats:
        st["cost_usd"] = round(st["cost_usd"], 2)
        st["escalated"] = st["entered"] - st["settled_reachable"] - st["settled_not_reachable"]
    return stats


def _row_view(r: dict) -> dict:
    """What the pipeline needs of one row: how it settled, and the judge's own not_reachable
    confidence even where a hold or an open-world downgrade turned it to unsure."""
    j = r.get("judge") or {}
    v, why = j.get("verdict"), j.get("rationale") or ""
    raw = (float(j.get("confidence") or 0) if v == "not_reachable" or (
        v == "unsure" and ("not_reachable held" in why or "dynamic access (open world)" in why)) else None)
    return {"settled": _settled(r)[0], "nr_raw": raw}


def _by_case(rows: list[dict]) -> dict:
    g: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        g[r.get("case", "")].append(r)
    return {c: {"rows_judged": len(rs), **_score(rs)} for c, rs in g.items()}


# --- inference ledger -------------------------------------------------------------------

def ledger_lines(since: datetime, limit: int = 400) -> list[dict]:
    from .. import accounting
    p = accounting.ledger_path()
    if p is None or not p.exists():
        return []
    out = []
    with open(p, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - 64 * 2**20))         # the last 64 MB is weeks of calls
        for raw in fh.read().splitlines():
            try:
                d = json.loads(raw)
                if datetime.fromisoformat(d["ts"]) >= since:
                    out.append(_ledger_row(d))
            except (ValueError, KeyError):
                continue
    return out[-limit:] if limit else out


def _ledger_row(d: dict) -> dict:
    row = {k: d[k] for k in _LEDGER_FIELDS if k in d}
    if "dest" not in row:          # calls logged before the ledger recorded a destination
        row["dest"] = "anthropic (claude CLI)" if d.get("kind") == "claude" else f"endpoint {d.get('endpoint', '?')}"
    return row


def ledger_totals() -> dict:
    now = datetime.now(timezone.utc)
    rows = ledger_lines(now - timedelta(days=7), limit=0)
    out = {}
    for label, delta in (("1h", timedelta(hours=1)), ("24h", timedelta(days=1)), ("7d", timedelta(days=7))):
        cut = now - delta
        g: dict[tuple, Counter] = defaultdict(Counter)
        for r in rows:
            if datetime.fromisoformat(r["ts"]) < cut:
                continue
            c = g[(r.get("dest", ""), str(r.get("model") or ""), r.get("purpose", ""))]
            c["calls"] += 1
            c["not_ok"] += r.get("outcome", "ok") != "ok"
            for k in ("cost_usd", "input_tokens", "output_tokens", "cache_read_tokens", "sent_bytes", "recv_bytes"):
                c[k] += float(r.get(k) or 0)
        out[label] = sorted(({"dest": k[0], "model": k[1], "purpose": k[2],
                              **{f: round(v, 4) if f == "cost_usd" else int(v) for f, v in c.items()}}
                             for k, c in g.items()), key=lambda x: -x.get("cost_usd", 0))
    return out


# --- config ---------------------------------------------------------------------------

def config(store: Store) -> dict:
    from ..judges import base
    from ..judges.claude_code import MODEL_BY_ECOSYSTEM
    from ..judges.usage import corroborated_for, measured_for, unmeasured_ecosystems
    from .. import pkgsrc
    path = os.environ.get("SSVC_FLOORS_FILE") or str(base._FLOORS_FILE)
    roles, models = base._table(path)
    held = unmeasured_ecosystems()
    labels = Counter()
    rows = Counter()
    for cj in store.cases.glob("*/case.json"):
        for c in (_json(cj) or {}).get("candidates") or []:
            e = (c.get("facts") or {}).get("ecosystem", "")
            rows[e] += 1
            labels[e] += bool((c.get("expect") or {}).get("reachability"))
    ecos = []
    for e in ECOSYSTEMS:
        ecos.append({"ecosystem": e, "held": e in held,
                     "measured_by": sorted(r for r in roles if e in measured_for(r)),
                     "corroborated": sorted(r for r in roles if e in corroborated_for(r)),
                     "nr_floor_override": {r: v["not_reachable_by_ecosystem"][e] for r, v in roles.items()
                                           if e in (v.get("not_reachable_by_ecosystem") or {})},
                     "claude_model": os.environ.get(f"SSVC_CLAUDE_MODEL_{e.upper()}") or MODEL_BY_ECOSYSTEM.get(e)
                     or os.environ.get("SSVC_CLAUDE_MODEL") or "sonnet",
                     "case_rows": rows[e], "labelled_rows": labels[e]})
    env = {k: ("(set)" if _SECRET.search(k) else v) for k, v in sorted(os.environ.items()) if k.startswith("SSVC_")}
    return {"floors_file": path,
            "roles": {r: {k: (str(v) if isinstance(v, float) and v == float("inf") else v) for k, v in p.items()}
                      for r, p in roles.items()},
            "models": [{"role": r, "model": m, **{k: (str(v) if v == float("inf") else v) for k, v in e.items()
                                                  if k not in ("role", "model")}} for (r, m), e in models.items()],
            "ecosystems": ecos, "env": env, "pkgsrc_cache": str(pkgsrc.cache_root()),
            "composer_git_hosts": sorted(pkgsrc.composer_git_hosts())}


# --- server ---------------------------------------------------------------------------

def _watch_state(store: Store) -> tuple:
    from .. import accounting
    p = accounting.ledger_path()
    led = p.stat().st_size if p is not None and p.exists() else 0
    runs = []
    for d in store.run_dirs()[:20]:          # recent runs: where anything is still changing
        try:
            runs.append((d.name, (d / "results.jsonl").stat().st_size, (d / "summary.json").exists()))
        except OSError:
            pass
    n = len(store.run_dirs())
    return led, tuple(runs), n


class Handler(BaseHTTPRequestHandler):
    store: Store
    port: int
    server_version = "doublestrain-dashboard"

    def log_message(self, fmt, *args):      # quiet
        pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        return host in {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj):
        self._send(200, json.dumps(obj, default=str).encode(), "application/json")

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._send(403, b"forbidden host", "text/plain")
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        if u.path == "/api/config":
            return self._json(config(self.store))
        if u.path == "/api/pipeline":
            return self._json({"cases": self.store.pipeline(), "scans": self.store.scans()})
        if u.path == "/api/runs":
            return self._json(self.store.runs_list())
        if u.path == "/api/run":
            r = self.store.run_detail((q.get("name") or [""])[0])
            return self._json(r) if r else self._send(404, b"no such run", "text/plain")
        if u.path == "/api/inference":
            hours = min(float((q.get("hours") or ["168"])[0] or 168), 24 * 7)
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            return self._json({"calls": ledger_lines(since, 400), "totals": ledger_totals()})
        if u.path == "/api/events":
            return self._events()
        return self._send(404, b"not found", "text/plain")

    def _events(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        from .. import accounting
        last = _watch_state(self.store)
        p = accounting.ledger_path()
        pos = last[0]
        try:
            while True:
                time.sleep(1.5)
                cur = _watch_state(self.store)
                msgs = []
                if cur[0] != last[0] and p is not None and p.exists():
                    with open(p, "rb") as fh:
                        fh.seek(pos if cur[0] >= pos else 0)
                        chunk = fh.read()
                    complete, _, _ = chunk.rpartition(b"\n")
                    pos = (pos if cur[0] >= pos else 0) + len(complete) + (1 if complete else 0)
                    calls = []
                    for raw in complete.splitlines():
                        try:
                            calls.append(_ledger_row(json.loads(raw)))
                        except ValueError:
                            continue
                    if calls:
                        msgs.append(("calls", calls))
                if cur[1:] != last[1:]:
                    msgs.append(("runs", sorted({t[0] for t in set(cur[1]) ^ set(last[1])})))
                last = cur
                if not msgs:
                    self.wfile.write(b": ping\n\n")
                for ev, data in msgs:
                    self.wfile.write(f"event: {ev}\ndata: {json.dumps(data, default=str)}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Serve a live dashboard of the funnel on 127.0.0.1.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--runs", default="runs", help="run directories (default runs)")
    ap.add_argument("--cases", default="cases", help="case directories (default cases)")
    args = ap.parse_args(argv)
    store = Store(Path(args.runs).expanduser().resolve(), Path(args.cases).expanduser().resolve())
    handler = type("H", (Handler,), {"store": store, "port": args.port})
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    srv.daemon_threads = True
    print(f"dashboard: http://127.0.0.1:{args.port}/  (runs {store.runs}, cases {store.cases}; Ctrl-C stops)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


PAGE = (Path(__file__).with_name("dashboard.html")).read_text() if Path(__file__).with_name("dashboard.html").exists() else ""

if __name__ == "__main__":
    raise SystemExit(main())

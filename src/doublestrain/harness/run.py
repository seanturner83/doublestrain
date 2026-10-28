"""doublestrain run — run labelled SSVC cases through a reachability judge and grade them.

A case is a directory `cases/<id>/` holding `case.json` and the app checkout:

  {"id": "...", "description": "...",
   "repo": "repo",                       # checkout dir, relative to the case dir (or absolute / ~)
   "exposure": "public-internet",        # exposure class of this app
   "enrichment": {"CVE-...": {"kev": false, "epss": 0.2}},   # FIXTURE exploit signals
                                         # (--enrich live|cache-only swaps in real KEV/EPSS)
   "candidates": [ {<sweep record: "pr", "facts">,
                    "expect": {"reachability": "reachable|not_reachable", "note": "..."}} ]}

For each candidate the runner asks the judge (only where reachability is still open),
grades with the deterministic SSVC tree, and also grades an ORACLE copy whose
reachability is the label — so decision agreement is measured against what the tree
would decide with perfect reachability, not against hand-written decisions.

Output: runs/<timestamp>-<judge>/{results.jsonl, summary.json, digest.txt}.
"""
from __future__ import annotations

import argparse
import contextvars
import copy
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from ..feeds import MODES as ENRICH_MODES, build_enrichment
from ..judges import get_judge, preflight
from .. import accounting
from ..reach import resolve_reachability
from ..ssvc import Reachability, _coherent_cves, grade

# EPSS Act thresholds the summary reports a sensitivity line for.
SENSITIVITY = (0.01, 0.05, 0.10, 0.20)
from ..sweep import ExposureMap, candidate_from_record
from . import score

_LABEL_REACH = {"reachable": Reachability.REACHABLE, "not_reachable": Reachability.UNREACHABLE}


def load_cases(root: Path, only: list[str] | None = None) -> list[tuple[Path, dict]]:
    out = []
    for cj in sorted(root.glob("*/case.json")):
        case = json.loads(cj.read_text())
        case.setdefault("id", cj.parent.name)
        if only and case["id"] not in only:
            continue
        out.append((cj.parent, case))
    return out


def _repo_path(case_dir: Path, case: dict) -> str:
    p = Path(case.get("repo", "repo")).expanduser()
    return str(p if p.is_absolute() else case_dir / p)


def case_cves(case: dict) -> set[str]:
    return {a.upper() for rec in case["candidates"]
            for a in ((rec.get("facts") or {}).get("advisories") or [[]])[0]
            if a.upper().startswith("CVE-")}


def run_case(case_dir: Path, case: dict, judge, enrich: dict | None = None):
    """Yield one result row per candidate as soon as it's judged and graded (a big
    real-* case takes many minutes; progress shouldn't wait for the whole case)."""
    for rec in case["candidates"]:
        yield judge_row(case_dir, case, rec, judge, enrich)


def judge_row(case_dir: Path, case: dict, rec: dict, judge, enrich: dict | None = None) -> dict:
    """Judge and grade one candidate (and its oracle copy). Safe to run on a thread."""
    repo_path = _repo_path(case_dir, case)
    if art := case.get("artifact"):
        # a JVM case: the release artifact is the deployed classpath judges read (jvmjars)
        from .. import jvmjars
        jvmjars.register(repo_path, {**art, "paths": [str(p if (p := Path(x).expanduser()).is_absolute() else case_dir / p)
                                                      for x in art["paths"]]})
    enrich = case.get("enrichment", {}) if enrich is None else enrich
    repo_short = rec["pr"].split("#")[0].split("/")[-1]
    em = ExposureMap({repo_short: case["exposure"]}) if case.get("exposure") else None
    # the harness measures the JUDGE, so the sweep's own reachability claim is ignored
    c = candidate_from_record(rec, em, use_sweep_reachability=False)
    cves = _coherent_cves(c)
    expect = rec.get("expect", {})

    oracle = copy.deepcopy(c)
    if expect.get("reachability") in _LABEL_REACH:
        oracle.reachability = _LABEL_REACH[expect["reachability"]]
        oracle.reach_source = "label"
    g_oracle = grade(oracle, enrichment_map=enrich)

    t0 = time.monotonic()
    r = resolve_reachability(c, judge, repo_path, cves[0] if cves else "")
    wall = round(time.monotonic() - t0, 3)
    g = grade(c, enrichment_map=enrich)
    sens = {f"{t:.2f}": {"decision": grade(c, enrichment_map=enrich, epss_act=t).decision.value,
                         "oracle": grade(oracle, enrichment_map=enrich, epss_act=t).decision.value}
            for t in SENSITIVITY}

    return {
        "case": case["id"], "pr": rec["pr"], "package": c.bumped_package,
        "cve": cves[0] if cves else None,
        "expect": expect,
        "enrichment": {cv: enrich.get(cv) for cv in cves},
        "oracle_decision": g_oracle.decision.value,
        "judge": r.to_dict() if r else None,
        "got": {"reachability": c.reachability.value, "reach_source": c.reach_source,
                "reach_confidence": c.reach_confidence,
                "decision": g.decision.value, "reason": g.reason},
        "epss_sensitivity": sens,
        "wall_s": wall,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", default="cases", help="cases root dir (default: cases)")
    ap.add_argument("--case", action="append", help="only this case id (repeatable)")
    ap.add_argument("--judge", default="null", help="null|jev|local|claude|cascade[:a,b] (default null)")
    ap.add_argument("--no-cache", action="store_true", help="bypass the judge answer cache")
    ap.add_argument("--out", default="runs", help="runs root dir (default: runs)")
    ap.add_argument("--label", default="", help="suffix for the run dir name")
    ap.add_argument("--enrich", default="fixture", choices=ENRICH_MODES,
                    help="exploit signals: the cases' fixture values (default), live KEV/EPSS, "
                         "or the feed cache only")
    ap.add_argument("--claude-budget", type=float, metavar="USD", help="stop calling claude after this spend")
    ap.add_argument("--require-tiers", action="store_true", help="refuse to run if any judge tier is down")
    ap.add_argument("--pkgsrc", action="store_true", help="give the claude judge verified dependency source")
    ap.add_argument("--egress", choices=("any", "shape", "network", "machine"), default="any",
                    help="where app source may be sent: any (default), shape (abstracted call shapes may leave; source stays on your network), network (this machine + "
                         "private network), machine (this machine only); off-machine models then "
                         "see third-party code only (use local/LAN endpoints and `split`)")
    ap.add_argument("--no-registry-integrity", action="store_true",
                    help="refuse dependency source whose lockfile entry has no integrity hash, instead of "
                         "verifying it against the registry's sha512 for that version "
                         "(SSVC_PKGSRC_REGISTRY_INTEGRITY=0)")
    ap.add_argument("--workers", type=int, default=1, metavar="N",
                    help="judge N rows at once (default 1). Each row's cascade stays in order; useful "
                         "when an endpoint serves parallel requests (LM Studio: parallel slots)")
    ap.add_argument("--claude-workers", type=int, metavar="N",
                    help="at most N claude calls at once (default: no cap beyond --workers; the session "
                         "limit is shared across the account; SSVC_CLAUDE_CONCURRENCY)")
    ap.add_argument("--no-wait-on-limit", action="store_true",
                    help="on a claude usage limit, leave the row unresolved instead of waiting for the reset")
    ap.add_argument("--no-escalate-disagreement", action="store_true",
                    help="let a tier's not_reachable settle even when an earlier tier said reachable "
                         "(default: it goes on to the next tier; SSVC_ESCALATE_DISAGREEMENT=0)")
    ap.add_argument("--no-corroborate", action="store_true",
                    help="let a not_reachable from a model floors.toml marks `corroborate` settle alone "
                         "(default: a later split/shape/claude tier must agree; SSVC_CORROBORATE=0)")
    ap.add_argument("--escalate-disagreement", "--corroborate", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    os.environ["SSVC_APP_CODE_EGRESS"] = args.egress
    if args.no_escalate_disagreement:
        os.environ["SSVC_ESCALATE_DISAGREEMENT"] = "0"
    if args.no_corroborate:
        os.environ["SSVC_CORROBORATE"] = "0"
    if not args.no_wait_on_limit:
        os.environ.setdefault("SSVC_CLAUDE_WAIT_ON_LIMIT", "1")
    if args.claude_budget is not None:
        os.environ["SSVC_CLAUDE_BUDGET_USD"] = str(args.claude_budget)
    if args.pkgsrc:
        os.environ["SSVC_PKGSRC"] = "1"
    if args.no_registry_integrity:
        os.environ["SSVC_PKGSRC_REGISTRY_INTEGRITY"] = "0"
    if args.claude_workers:
        os.environ["SSVC_CLAUDE_CONCURRENCY"] = str(args.claude_workers)
    args.workers = max(1, args.workers)

    cases = load_cases(Path(args.cases), args.case)
    if not cases:
        print(f"no cases found under {args.cases}", file=sys.stderr)
        return 2
    try:
        judge = get_judge(args.judge, cache=not args.no_cache)
    except ValueError as exc:
        print(f"judge: {exc}", file=sys.stderr)
        return 2
    lines, down = preflight(judge)
    print("judge tiers:\n" + "\n".join(lines), flush=True)
    if down and args.require_tiers:
        print(f"tiers down: {', '.join(down)} (--require-tiers)", file=sys.stderr)
        return 2

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"{stamp}-{args.judge.replace(':', '_').replace(',', '+')}"
    run_dir = Path(args.out) / (f"{name}-{args.label}" if args.label else name)
    run_dir.mkdir(parents=True)
    accounting.start("ssvc-run", run_dir.name)

    live_map, enrich_prov = None, {"mode": "fixture"}
    if args.enrich != "fixture":
        live_map, enrich_prov = build_enrichment(set().union(*(case_cves(c) for _, c in cases)),
                                                 mode=args.enrich)
        print(f"enrichment: {json.dumps(enrich_prov)}", flush=True)

    tasks = [(case_dir, case, rec) for case_dir, case in cases for rec in case["candidates"]]

    def one(task):
        case_dir, case, rec = task
        with accounting.tag(case=case["id"]):      # every model call this row makes
            return judge_row(case_dir, case, rec, judge, live_map)

    rows = []
    pool = ThreadPoolExecutor(args.workers, thread_name_prefix="ssvc-row") if args.workers > 1 else None
    if pool:
        # each row on its own thread with a copy of the tags; its cascade stays in order.
        # Rows are written in input order, so runs stay comparable line by line.
        futures = [pool.submit(contextvars.copy_context().run, one, t) for t in tasks]
        results = (f.result() for f in futures)
    else:
        results = map(one, tasks)
    with open(run_dir / "results.jsonl", "w") as fh:
        try:
            for row in results:
                fh.write(json.dumps(row) + "\n")
                fh.flush()
                rows.append(row)
                j = row["judge"]
                jv = f"{j['source']}:{j['verdict']}@{j['confidence']:.2f}" if j else "-"
                print(f"  {row['case']:<28} {row['package'] + ' ' + (row['cve'] or ''):<31} expect={row['expect'].get('reachability', '?'):<13} "
                      f"judge={jv:<26} -> {row['got']['decision']:<6} (oracle {row['oracle_decision']})",
                      flush=True)
        finally:
            if pool:
                pool.shutdown(wait=False, cancel_futures=True)

    summary = score.summarise(rows)
    summary["run"] = {"judge": args.judge, "cases": [c["id"] for _, c in cases],
                      "cache": not args.no_cache, "dir": str(run_dir),
                      "enrichment": enrich_prov}
    summary["usage"] = accounting.totals()
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    report = score.render(summary)
    (run_dir / "digest.txt").write_text(report + "\n")
    print()
    print(report)
    print("\n" + accounting.render(summary["usage"]))
    print(f"\nrun dir: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

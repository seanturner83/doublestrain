"""doublestrain scan — grade a repo's dependency advisories end to end.

  lockfile -> OSV advisories -> candidates -> reachability judge -> KEV/EPSS -> SSVC tree

Writes runs/scan-<ts>-<name>/{results.jsonl, digest.txt, summary.json}. With
--emit-case DIR it also writes a harness case skeleton (case.json with every candidate
and an empty `expect`) to label by hand and add to the harness.

Network: OSV gets package names + versions; KEV/EPSS get CVE ids; the judge backend
gets what that judge always gets. --offline uses only the caches.
"""
from __future__ import annotations

import argparse
import contextvars
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import accounting
from .feeds import build_enrichment
from .judges import get_judge, preflight
from .judges.claude_code import SPEND
from .osv import candidates as osv_candidates
from .reach import resolve_reachability
from .ssvc import Decision, _coherent_cves, grade_all
from .sweep import ExposureMap, candidate_from_record


def _row(g, c, rec, j) -> dict:
    f = rec["facts"]
    return {"pr": rec["pr"], "package": c.bumped_package, "version": f.get("version"),
            "ids": f["advisories"][0], "dev": f.get("dev"), "direct": f.get("direct"),
            "fixed": f.get("fixed"), "severity": f.get("severity"),
            "decision": g.decision.value, "reason": g.reason, "malicious": g.malicious, "suspected_malicious": g.suspected_malicious,
            "reachability": g.reachability, "reach_source": g.reach_source,
            "reach_confidence": g.reach_confidence, "kev": g.kev, "epss": g.max_epss,
            "epss_percentile": g.max_epss_percentile, "judge": j.to_dict() if j else None}


def digest(rows: list[dict], name: str, prov: dict) -> str:
    by = Counter(r["decision"] for r in rows)
    lines = [f"SSVC scan {name}: {prov['osv']['deps']} deps, {prov['osv']['advisories']} advisories "
             f"on {prov['osv']['vulnerable_packages']} package versions — "
             f"Act {by.get('Act', 0)} · Attend {by.get('Attend', 0)} · Track {by.get('Track', 0)}"]
    for tier in ("Act", "Attend", "Track"):
        rs = [r for r in rows if r["decision"] == tier]
        if not rs:
            continue
        lines.append(f"\n{tier} ({len(rs)})")
        for r in rs:
            reach = r["reachability"] + (f" ({r['reach_source']}@{r['reach_confidence']:.2f})"
                                         if r["reach_source"] and r["reach_confidence"] is not None else "")
            ep = (f"epss {r['epss']:.3f} p{100 * r['epss_percentile']:.0f}"
                  if r["epss"] is not None and r["epss_percentile"] is not None else "epss ?")
            flags = "".join([" MALWARE" if r.get("malicious") else "", " SUSPECTED-MALWARE" if r.get("suspected_malicious") else "", " KEV" if r["kev"] else "", " dev" if r["dev"] else "",
                             "" if r["direct"] else " transitive"])
            fix = f" fix {','.join(r['fixed'][:2])}" if r["fixed"] else " no fix"
            pv = f"{r['package']}@{r['version']}"
            lines.append(f"  {pv:<28} {r['ids'][0]:<20} {ep:<17} {reach:<34}{flags}{fix}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", help="checkout with package-lock.json and/or requirements*.txt")
    ap.add_argument("--name", help="repo name for the report (default: directory name)")
    ap.add_argument("--judge", default="cascade", help="null|jev|local|claude|cascade[:a,b] (default cascade)")
    ap.add_argument("--enrich", default="live", choices=("live", "cache-only"))
    ap.add_argument("--exposure", default="unknown",
                    help="exposure class of this app (public-internet, sase-reachable, mesh-only, ...)")
    ap.add_argument("--prod-only", action="store_true", help="skip dev-only dependencies")
    ap.add_argument("--offline", action="store_true", help="OSV + feeds from cache only")
    ap.add_argument("--out", default="runs")
    ap.add_argument("--emit-case", metavar="DIR", help="also write a harness case skeleton here")
    ap.add_argument("--claude-budget", type=float, default=5.0, metavar="USD",
                    help="stop calling claude after this much spend (default 5; unresolved grades like reachable)")
    ap.add_argument("--require-tiers", action="store_true", help="refuse to run if any judge tier is down")
    ap.add_argument("--pkgsrc", action="store_true",
                    help="give the claude judge integrity-verified dependency source (contacts the npm registry)")
    ap.add_argument("--workers", type=int, default=1, metavar="N",
                    help="judge N advisories at once (default 1); each one's cascade stays in order")
    ap.add_argument("--claude-workers", type=int, metavar="N",
                    help="at most N claude calls at once (SSVC_CLAUDE_CONCURRENCY)")
    ap.add_argument("--no-registry-integrity", action="store_true",
                    help="refuse dependency source whose lockfile entry has no integrity hash, instead of "
                         "verifying it against the registry's sha512 for that version "
                         "(SSVC_PKGSRC_REGISTRY_INTEGRITY=0)")
    ap.add_argument("--egress", choices=("any", "shape", "network", "machine"), default="any",
                    help="where app source may be sent: any (default), shape (abstracted call shapes may leave; source stays on your network), network (this machine + "
                         "private network), machine (this machine only); off-machine models then "
                         "see third-party code only (use local/LAN endpoints and `split`)")
    ap.add_argument("--no-escalate-disagreement", action="store_true",
                    help="let a tier's not_reachable settle even when an earlier tier said reachable "
                         "(default: it goes on to the next tier; SSVC_ESCALATE_DISAGREEMENT=0)")
    ap.add_argument("--no-corroborate", action="store_true",
                    help="let a not_reachable from a model floors.toml marks `corroborate` settle alone "
                         "(default: a later split/shape/claude tier must agree; SSVC_CORROBORATE=0)")
    ap.add_argument("--escalate-disagreement", "--corroborate", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    accounting.start("ssvc-scan")
    os.environ["SSVC_APP_CODE_EGRESS"] = args.egress
    if args.no_escalate_disagreement:
        os.environ["SSVC_ESCALATE_DISAGREEMENT"] = "0"
    if args.no_corroborate:
        os.environ["SSVC_CORROBORATE"] = "0"
    os.environ["SSVC_CLAUDE_BUDGET_USD"] = str(args.claude_budget)
    if args.pkgsrc and not args.offline:
        os.environ["SSVC_PKGSRC"] = "1"
    if args.no_registry_integrity:
        os.environ["SSVC_PKGSRC_REGISTRY_INTEGRITY"] = "0"
    if args.claude_workers:
        os.environ["SSVC_CLAUDE_CONCURRENCY"] = str(args.claude_workers)
    args.workers = max(1, args.workers)

    repo = Path(args.repo).expanduser().resolve()
    name = args.name or repo.name
    records, osv_prov = osv_candidates(repo, name, include_dev=not args.prod_only, offline=args.offline)
    print(f"osv: {json.dumps(osv_prov)}", flush=True)
    if not records:
        print("no advisories for the locked dependency versions")
        return 0

    em = ExposureMap({name.split("/")[-1]: args.exposure}) if args.exposure != "unknown" else None
    try:
        judge = get_judge(args.judge)
    except ValueError as exc:
        print(f"judge: {exc}", file=sys.stderr)
        return 2
    lines, down = preflight(judge)
    print("judge tiers:\n" + "\n".join(lines), flush=True)
    if down and args.require_tiers:
        print(f"tiers down: {', '.join(down)} (--require-tiers)", file=sys.stderr)
        return 2
    cands, judged = [], {}
    t0 = time.monotonic()

    def one(rec):
        c = candidate_from_record(rec, em, use_sweep_reachability=False)
        cves = _coherent_cves(c)
        return c, cves, resolve_reachability(c, judge, str(repo), cves[0] if cves else "")

    pool = ThreadPoolExecutor(args.workers, thread_name_prefix="ssvc-adv") if args.workers > 1 else None
    done = ((f.result() for f in [pool.submit(contextvars.copy_context().run, one, r) for r in records])
            if pool else map(one, records))
    for i, (rec, (c, cves, j)) in enumerate(zip(records, done), 1):
        judged[rec["pr"]] = j
        print(f"  [{i}/{len(records)}] {c.bumped_package}@{rec['facts']['version']} {cves[0] if cves else '-'}: "
              f"{(j.source + ':' + j.verdict.value + '@' + format(j.confidence, '.2f')) if j else '-'} "
              f"-> {c.reachability.value}", flush=True)
        cands.append((c, rec))
    if pool:
        pool.shutdown()

    mode = "cache-only" if args.offline else args.enrich
    enrich, feed_prov = build_enrichment({cv for c, _ in cands for cv in _coherent_cves(c)}, mode=mode)
    grades = grade_all([c for c, _ in cands], enrichment_map=enrich)
    by_pr = {f"{c.repo}#{c.pr_number}": (c, rec) for c, rec in cands}
    rows = [_row(g, *by_pr[f"{g.repo}#{g.pr_number}"], judged[by_pr[f"{g.repo}#{g.pr_number}"][1]["pr"]])
            for g in grades]

    prov = {"repo": str(repo), "name": name, "judge": args.judge, "exposure": args.exposure,
            "osv": osv_prov, "feeds": feed_prov, "judge_wall_s": round(time.monotonic() - t0, 1),
            "tiers_down": down, "claude_spend": dict(SPEND),
            "usage": accounting.totals()}
    run_dir = Path(args.out) / f"scan-{datetime.now():%Y%m%d-%H%M%S}-{name.replace('/', '_')}"
    run_dir.mkdir(parents=True)
    with open(run_dir / "results.jsonl", "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    (run_dir / "summary.json").write_text(json.dumps(prov, indent=2))
    text = digest(rows, name, prov)
    (run_dir / "digest.txt").write_text(text + "\n")
    print("\n" + text + f"\n\nrun dir: {run_dir}")

    if args.emit_case:
        d = Path(args.emit_case)
        d.mkdir(parents=True, exist_ok=True)
        case = {"id": d.name, "description": f"{name} (OSV-generated; label each `expect`)",
                "repo": str(repo), "exposure": args.exposure,
                "_note": "enrichment empty: run the harness with --enrich live",
                "enrichment": {},
                "candidates": [{**rec, "pr": f"local/{d.name}#{rec['pr'].rsplit('#', 1)[1]}",
                                "expect": {}} for rec in records]}
        (d / "case.json").write_text(json.dumps(case, indent=2) + "\n")
        print(f"case skeleton: {d / 'case.json'} ({len(records)} candidates to label)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Fill a Candidate's reachability axis from a judge — facts in, never the decision.

Precedence: a deterministic signal (govulncheck, or the sweep's own verdict) is never
overridden by a model. A judge only fills UNAVAILABLE / UNSCANNED, and only with a
verdict that clears its asymmetric acceptance floor (`judges.accept`).
"""
from __future__ import annotations

from . import accounting
from .judges import JudgeResult, ReachQuery, Verdict, accept
from .judges.base import role
from .judges.usage import nr_held
from .ssvc import Candidate, Reachability

_FILLABLE = (Reachability.UNAVAILABLE, Reachability.UNSCANNED)


def query_for(c: Candidate, repo_path: str, cve: str) -> ReachQuery:
    return ReachQuery(repo_path=repo_path, ecosystem=c.ecosystem or ("go" if c.is_go else ""),
                      dependency=c.bumped_package, cve=cve,
                      vuln_symbols=tuple(c.vuln_symbols), advisory=c.advisory_summary,
                      import_name=c.import_name, version=c.version)


def resolve_reachability(c: Candidate, judge, repo_path: str | None,
                         cve: str = "") -> JudgeResult | None:
    """Ask `judge` about `c` (if its reachability is still open) and apply an accepted
    verdict in place. Returns the judge's raw result (accepted or not) for the audit
    log, or None if the judge wasn't consulted / had no answer."""
    if c.malicious or c.suspected_malicious or c.reachability not in _FILLABLE or not repo_path:
        return None     # malware isn't a reachability question (see ssvc.Candidate.malicious)
    with accounting.tag(cve=cve, package=c.bumped_package):
        r = judge.judge(query_for(c, repo_path, cve))
    if (accept(r) and r.verdict == Verdict.NOT_REACHABLE and r.source != "govulncheck"
            and nr_held(c.ecosystem, role(r.source))):
        return r        # no measured floor for this ecosystem: a tier that skips the guard can't settle it
    if accept(r):
        c.reachability = (Reachability.REACHABLE if r.verdict == Verdict.REACHABLE
                          else Reachability.UNREACHABLE)
        c.reach_source = r.source
        c.reach_confidence = r.confidence
    return r

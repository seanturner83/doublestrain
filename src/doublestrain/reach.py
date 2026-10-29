"""Fill a Candidate's reachability axis from a judge — facts in, never the decision.

Precedence: a deterministic signal (govulncheck, or the sweep's own verdict) is never
overridden by a model. A judge only fills UNAVAILABLE / UNSCANNED, and only with a
verdict that clears its asymmetric acceptance floor (`judges.accept`).
"""
from __future__ import annotations

import re

from . import accounting, advisory_notes
from .judges import JudgeResult, ReachQuery, Verdict, accept
from .judges.base import needs_corroboration, policy, role
from .judges.usage import nr_held
from .ssvc import Candidate, Reachability

_FILLABLE = (Reachability.UNAVAILABLE, Reachability.UNSCANNED)


def query_for(c: Candidate, repo_path: str, cve: str) -> ReachQuery:
    """The judges' question for a candidate. Known gaps in the advisory's own text
    (`advisory_notes`, widening only) are added to its summary, so every tier reads
    them; only rows with a note get a new cache key."""
    eco = c.ecosystem or ("go" if c.is_go else "")
    ids = [i for aliases, _affected in c.advisories for i in aliases] + [cve]
    notes = advisory_notes.notes_for(ids, c.bumped_package, eco, c.version)
    return ReachQuery(repo_path=repo_path, ecosystem=eco,
                      dependency=c.bumped_package, cve=cve,
                      vuln_symbols=tuple(c.vuln_symbols),
                      advisory=advisory_notes.annotate(c.advisory_summary, notes),
                      import_name=c.import_name, version=c.version)


# A Java deserialization gadget: the advisory's code is a library class's own readObject /
# readResolve / readExternal, which the JDK's deserializer calls by class name from whatever
# stream it is reading (jv3: guava's CompactHashMap behind kafka-ui's JMX-over-RMI client).
# No call graph sees that dispatch, so on maven a not_reachable for one never settles.
_GADGET = re.compile(r"readObject\s*\(|\breadResolve\b|\breadExternal\b|native deserializ"
                     r"|java (?:native |object )?deserializ|\bObjectInputStream\b", re.I)


def deserialization_gadget(c: Candidate) -> bool:
    return bool(_GADGET.search(f"{c.advisory_summary} {' '.join(c.vuln_symbols)}"))


def resolve_reachability(c: Candidate, judge, repo_path: str | None,
                         cve: str = "") -> JudgeResult | None:
    """Ask `judge` about `c` (if its reachability is still open) and apply an accepted
    verdict in place. Returns the judge's raw result (accepted or not) for the audit
    log, or None if the judge wasn't consulted / had no answer."""
    if c.malicious or c.suspected_malicious or c.reachability not in _FILLABLE or not repo_path:
        return None     # malware isn't a reachability question (see ssvc.Candidate.malicious)
    with accounting.tag(cve=cve, package=c.bumped_package):
        r = judge.judge(query_for(c, repo_path, cve))
    eco = c.ecosystem
    if (accept(r, eco) and r.verdict == Verdict.NOT_REACHABLE and r.source != "govulncheck"
            and nr_held(eco, role(r.source))
            and all(nr_held(eco, role(s)) for s in r.corroborates.split(",") if s)):
        return r        # no measured floor for this ecosystem: a tier that skips the guard can't settle it
    if (accept(r, eco) and needs_corroboration(r, eco) and not r.corroborates
            and not policy(r).get("corroborate")):
        return r        # measured on this ecosystem only as a pair (pypi: split, then claude): alone it settles nothing
    if accept(r, eco) and r.verdict == Verdict.NOT_REACHABLE and eco == "maven" and deserialization_gadget(c):
        return r        # a deserialization gadget: dispatched by class name, invisible to the call graph
    if accept(r, eco):
        c.reachability = (Reachability.REACHABLE if r.verdict == Verdict.REACHABLE
                          else Reachability.UNREACHABLE)
        c.reach_source = r.source
        c.reach_confidence = r.confidence
    return r

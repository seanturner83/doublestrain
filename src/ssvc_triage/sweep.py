"""Sweep audit records -> SSVC Candidates.

One record per line, sweep JSONL shape:
  {"kind": "keep", "pr": "org/repo#N", "facts": {
      "package": ..., "is_go": bool, "created_at": ISO8601,
      "advisories": [[cve_aliases...], [affected_pkgs...]],
      "reachability": "reachable|unreachable|unscanned"   # optional, sweep's own verdict
      # optional judge context:
      "ecosystem": "npm|pypi|go", "import_name": ..., "vuln_symbols": [...],
      "advisory_summary": ...}}
"""
from __future__ import annotations

from .ssvc import Candidate, Reachability

_SWEEP_REACH = {"reachable": Reachability.REACHABLE,
                "unreachable": Reachability.UNREACHABLE,
                "unscanned": Reachability.UNSCANNED}


class ExposureMap:
    """Repo short name -> exposure class. A miss is 'unknown', never 'mesh-only'."""

    def __init__(self, entries):
        self.entries = {k.lower(): v for k, v in (entries or {}).items()}

    def classify(self, short) -> dict | None:
        e = self.entries.get(short.lower())
        return {"class": e} if e else None


def exposure_for(em, repo) -> str:
    short = repo.split("/")[-1]
    c = em.classify(short) if em else None
    return c["class"] if c else "unknown"


def parse_pr(pr: str) -> tuple[str, int]:
    repo = pr.split("#")[0]
    try:
        return repo, int(pr.split("#")[1])
    except (IndexError, ValueError):
        return repo, 0


def candidate_from_record(r: dict, em=None, *, use_sweep_reachability=True) -> Candidate:
    facts = r.get("facts") or {}
    repo, num = parse_pr(r["pr"])
    pkg = facts.get("package", "")
    # the record's own reachability claim, if asked for; the judges (govulncheck included)
    # fill it otherwise (reach.resolve_reachability)
    reach = (_SWEEP_REACH.get(facts.get("reachability", ""), Reachability.UNAVAILABLE)
             if use_sweep_reachability else Reachability.UNAVAILABLE)
    source = "sweep" if reach != Reachability.UNAVAILABLE else ""
    # One advisory per record: [aliases, affected_pkgs] -> one (aliases, affected) tuple.
    advs = facts.get("advisories", [])
    return Candidate(repo=repo, pr_number=num, bumped_package=pkg,
                     is_go=bool(facts.get("is_go")),
                     advisories=[tuple(advs)] if advs else [],
                     reachability=reach, exposure_class=exposure_for(em, repo),
                     reach_source=source,
                     ecosystem=facts.get("ecosystem", ""),
                     import_name=facts.get("import_name", ""),
                     version=facts.get("version", ""),
                     malicious=bool(facts.get("malicious")),
                     suspected_malicious=bool(facts.get("suspected_malicious")),
                     malware_hints=list(facts.get("malware_hints") or []),
                     vuln_symbols=list(facts.get("vuln_symbols") or []),
                     advisory_summary=facts.get("advisory_summary", ""))

"""SSVC grading for dependency advisories: Act, Attend or Track.

The grade is a pure function of facts about one advisory on one installed package,
in the spirit of CISA's SSVC deployer tree:

- exploitation: is it known exploited (CISA KEV), or likely to be (EPSS at or above
  `EPSS_ACT`)? A CVE with no EPSS score is unknown, not zero.
- reachability: can the vulnerable code run on attacker data in this app? It comes
  from a deterministic tool (govulncheck) or from a model judge whose verdict cleared
  its acceptance floor (`judges/`), and records where it came from (`reach_source`).
  No accepted verdict leaves it unavailable, and unavailable grades like reachable:
  the absence of a signal is never treated as safety.
- exposure: how reachable the service is from untrusted networks (`EXPOSED_CLASSES`).
  An app with no exposure entry is `unknown`, which surfaces instead of hiding.

Models never make the decision; they only supply the reachability fact.

    malicious package version                         -> Act (install-time compromise)
    suspected malicious (advisory text)               -> graded without reachability,
                                                         never below Attend
    no advisory that names this package               -> Track
    proven unreachable                                -> Attend if exploited and exposed,
                                                         else Track
    exposed and exploited                             -> Act
    exposed                                           -> Attend
    exploited, exposure unknown                       -> Attend
    anything else                                     -> Track
"""
from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

EPSS_ACT = float(os.environ.get("SSVC_EPSS_ACT", "0.10"))

EXPOSED_CLASSES = frozenset({"public-internet", "public-internet-transitive", "sase-reachable",
                             "sase-reachable-transitive", "control-plane"})
UNKNOWN_EXPOSURE = "unknown"


class Decision(str, Enum):
    ACT = "Act"          # SLA-bearing: fix now
    ATTEND = "Attend"    # a human looks at it
    TRACK = "Track"      # no urgency


class Reachability(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNSCANNED = "unscanned"        # a tool could have answered but didn't scan this module
    UNAVAILABLE = "unavailable"    # no accepted reachability fact


@dataclass
class Candidate:
    """One advisory on one installed package. `advisories` holds (ids, affected packages)
    pairs as the advisory source reported them."""
    repo: str
    pr_number: int
    bumped_package: str
    is_go: bool = False
    advisories: list[tuple[list[str], list[str]]] = field(default_factory=list)
    reachability: Reachability = Reachability.UNAVAILABLE
    exposure_class: str = UNKNOWN_EXPOSURE
    reach_source: str = ""                  # "govulncheck", a judge id, "label", ...
    reach_confidence: float | None = None
    malicious: bool = False                 # a malicious package version (OSV MAL-*, CWE-506)
    suspected_malicious: bool = False       # advisory text reads like one (judges/malware.py)
    malware_hints: list[str] = field(default_factory=list)
    # read by the reachability judges only
    ecosystem: str = ""
    import_name: str = ""
    version: str = ""
    vuln_symbols: list[str] = field(default_factory=list)
    advisory_summary: str = ""


@dataclass
class Grade:
    repo: str
    pr_number: int
    decision: Decision
    reason: str
    bumped_package: str = ""
    kev: bool = False
    max_epss: float | None = None
    max_epss_percentile: float | None = None
    exposure_class: str = UNKNOWN_EXPOSURE
    reachability: str = Reachability.UNAVAILABLE.value
    coherent_cves: list[str] = field(default_factory=list)
    reach_source: str = ""
    reach_confidence: float | None = None
    malicious: bool = False
    suspected_malicious: bool = False


def _names_package(affected: list[str], package: str) -> bool:
    want = (package or "").strip().lower()
    return bool(want) and any((a or "").strip().lower() == want for a in affected)


def _coherent_cves(c: Candidate) -> list[str]:
    """The advisory ids that apply to this package: each matching advisory's CVE aliases
    (upper-cased, the KEV/EPSS key), or its first id when it has no CVE (a GHSA-only
    advisory still counts; it just has no exploitation signal). Advisories that don't
    name the package are dropped before they can drive a decision."""
    ids: list[str] = []
    seen: set[str] = set()
    for aliases, affected in c.advisories:
        if not _names_package(affected, c.bumped_package):
            continue
        cves = [a.upper() for a in aliases if a.upper().startswith("CVE-")]
        for a in cves or [a for a in aliases[:1] if a]:
            if a.upper() not in seen:
                seen.add(a.upper())
                ids.append(a)
    return ids


@dataclass
class _Exploitation:
    kev: bool
    max_epss: float | None
    max_percentile: float | None

    def signal(self, threshold: float) -> bool:
        return self.kev or (self.max_epss is not None and self.max_epss >= threshold)

    def why(self, threshold: float) -> str:
        return "KEV known-exploited" if self.kev else f"EPSS {self.max_epss:.3f} >= {threshold}"


def _exploitation(ids: list[str], feed: dict | None) -> _Exploitation:
    rows = [r for r in ((feed or {}).get(i.upper()) or (feed or {}).get(i) for i in ids) if r]
    epss = [r["epss"] for r in rows if r.get("epss") is not None]
    pct = [r["epss_percentile"] for r in rows if r.get("epss_percentile") is not None]
    return _Exploitation(any(bool(r.get("kev")) for r in rows), max(epss, default=None), max(pct, default=None))


def grade(c: Candidate, *, enrichment_map: dict | None = None, epss_act: float | None = None,
          use_vulncheck: bool = True) -> Grade:
    """Grade one candidate. `enrichment_map` maps advisory id -> {"kev", "epss",
    "epss_percentile"} (feeds.build_enrichment, or a case's fixture values)."""
    threshold = EPSS_ACT if epss_act is None else epss_act
    ids = _coherent_cves(c)

    def out(decision: Decision, reason: str, ex: _Exploitation | None = None, **kw) -> Grade:
        return Grade(c.repo, c.pr_number, decision, reason, bumped_package=c.bumped_package,
                     kev=bool(ex and ex.kev), max_epss=ex.max_epss if ex else None,
                     max_epss_percentile=ex.max_percentile if ex else None,
                     exposure_class=c.exposure_class, reachability=c.reachability.value,
                     coherent_cves=ids, reach_source=c.reach_source,
                     reach_confidence=c.reach_confidence, **kw)

    if not ids:
        return out(Decision.TRACK, "no coherent advisory cited (routine/mis-attributed bump)")
    if c.malicious:
        return out(Decision.ACT, "MALICIOUS package version: it compromises every machine that installs "
                                 "it (dev, CI, prod), so reachability, exposure and EPSS don't apply → SLA-bearing",
                   malicious=True)
    if c.suspected_malicious:
        # reachability is the wrong question for an install-time payload: set it aside,
        # grade the rest, and never let a possible compromise sink to Track
        plain = copy.copy(c)
        plain.suspected_malicious = False
        plain.reachability, plain.reach_source, plain.reach_confidence = Reachability.UNAVAILABLE, "", None
        g = grade(plain, enrichment_map=enrichment_map, epss_act=epss_act)
        g.suspected_malicious = True
        why = ("SUSPECTED malicious/compromised package version (advisory text: "
               + ", ".join(c.malware_hints[:3]) + ") — confirm; reachability not applied")
        g.decision, g.reason = ((Decision.ATTEND, why) if g.decision == Decision.TRACK
                                else (g.decision, f"{why}; {g.reason}"))
        return g

    ex = _exploitation(ids, enrichment_map)
    exploited = ex.signal(threshold)
    exposed = c.exposure_class in EXPOSED_CLASSES
    source = c.reach_source or ("govulncheck" if c.is_go else "") or "reachability"

    if c.reachability == Reachability.UNREACHABLE:
        if exploited and exposed:
            return out(Decision.ATTEND, f"KEV/high-EPSS + exposed, BUT {source} says the vulnerable code "
                                        "is unreachable — review, don't auto-file", ex)
        return out(Decision.TRACK, f"{source} says the vulnerable code is unreachable — not needed", ex)

    # reachable, or no accepted fact either way: exposure and exploitation decide
    if exposed and exploited:
        reach = (f"reachable ({source})" if c.reachability == Reachability.REACHABLE
                 else f"reachability {c.reachability.value}")
        return out(Decision.ACT, f"{ex.why(threshold)}; {c.exposure_class}; {reach} → SLA-bearing", ex)
    if exposed:
        return out(Decision.ATTEND, f"coherent advisory on an exposed ({c.exposure_class}) service, "
                                    "no exploitation signal yet — human triage", ex)
    if exploited and c.exposure_class == UNKNOWN_EXPOSURE:
        return out(Decision.ATTEND, "KEV/high-EPSS and not proven unreachable, but exposure is unknown "
                                    "(the app has no exposure entry) — confirm, don't assume internal", ex)
    return out(Decision.TRACK, f"coherent advisory, but not exposed ({c.exposure_class})", ex)


_ORDER = {Decision.ACT: 0, Decision.ATTEND: 1, Decision.TRACK: 2}


def grade_all(candidates: Iterable[Candidate], *, enrichment_map: dict | None = None,
              use_vulncheck: bool = True) -> list[Grade]:
    """Grades in digest order: Act first, then Attend, then Track; highest EPSS first within each."""
    return sorted((grade(c, enrichment_map=enrichment_map) for c in candidates),
                  key=lambda g: (_ORDER[g.decision], -(g.max_epss or 0.0)))

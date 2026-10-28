"""SSVC decision function for kept Dependabot PRs — deterministic inputs only.

Clean-room reimplementation from spec + reasoning (no copied source).

Grades a KEPT advisory-bearing Dependabot bump into Act / Attend / Track by composing three DETERMINISTIC axes. Judgement/confidence is NOT an input: calibration showed ~half of keeps are "unable-to-determine" and a graded-model-confidence band just manufactures "maybe", which is not a valid SLA gate — so the grader gates only on facts (exploitability, reachability, exposure).

Axes
----
1. exploitability   — KEV (known-exploited) + EPSS (predicted). "No EPSS" is UNKNOWN, never treated as 0. In this clean-room build the signal comes from an injected `enrichment_map` (deterministic, no external call), so a mock run grades Act/Attend/Track offline.
2. reachability     — Go: govulncheck call-graph verdict (reachable / unreachable / unscanned). Non-Go: a reachability JUDGE (Jev / claude-code, see `judges/`) may supply a verdict; the judge's verdict is a FACT input with recorded provenance (`reach_source`), never the decision. No accepted verdict -> UNAVAILABLE; absence of a signal is NOT safety.
3. exposure         — ExposureMap class: public-internet / sase-reachable / mesh-only. The reachability PROXY for repos where code-reachability is unavailable.

Decision (two-factor Act, per the locked policy)
ACT    = MALICIOUS package version (bypasses every other axis: install-time compromise), OR
         coherent advisory AND reachable-or-nonGo AND (KEV OR EPSS>=EPSS_ACT) AND exposure in {public-internet, sase}
ATTEND = coherent advisory AND exposed AND NOT proven-unreachable
TRACK  = everything else (kept, no urgency signal)

Advisory coherence is applied FIRST — a mis-attributed advisory is dropped before it can drive any decision.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

EPSS_ACT = float(os.environ.get("SSVC_EPSS_ACT", "0.10"))

_EXPOSED = {"public-internet", "public-internet-transitive",
            "sase-reachable", "sase-reachable-transitive", "control-plane"}
_UNKNOWN_EXPOSURE = "unknown"


class Decision(str, Enum):
    ACT = "Act"          # file an SLA-bearing ticket / drive the merge
    ATTEND = "Attend"    # surface in the digest for human triage
    TRACK = "Track"      # kept, no urgency — digest tail only


class Reachability(str, Enum):
    REACHABLE = "reachable"            # Go: govulncheck traced the vuln symbol
    UNREACHABLE = "unreachable"        # Go: proven not on any call path
    UNSCANNED = "unscanned"            # Go module but govulncheck didn't scan it
    UNAVAILABLE = "unavailable"        # no code-level reachability signal (non-Go, judge unsure/off)


@dataclass
class Signal:
    """One CVE's deterministic exploit signal (injected in the clean-room build)."""
    kev: bool = False
    epss: float | None = None
    percentile: float | None = None   # context for the digest; decisions use the probability


@dataclass
class Enrichment:
    signals: dict[str, "Signal"]

    def worst(self) -> "Signal | None":
        best = None
        bestrank = None
        for s in self.signals.values():
            r = (int(bool(s.kev)), float(s.epss) if s.epss is not None else 0.0)
            if bestrank is None or r > bestrank:
                best, bestrank = s, r
        return best


def _enrich(cves, *, enrichment_map=None) -> Enrichment:
    """Deterministic exploit signals from the injected map (no external calls)."""
    sigs = {}
    if enrichment_map:
        for cve in cves:
            m = (enrichment_map.get(cve.upper()) or enrichment_map.get(cve))
            if not m:
                continue
            sigs[cve] = Signal(kev=bool(m.get("kev")), epss=m.get("epss"),
                               percentile=m.get("epss_percentile"))
    return Enrichment(sigs)


@dataclass
class Candidate:
    """One kept PR to grade. `advisories` is a list of (cve_aliases, affected_pkgs)."""
    repo: str
    pr_number: int
    bumped_package: str
    is_go: bool = False
    advisories: list[tuple[list[str], list[str]]] = field(default_factory=list)
    reachability: Reachability = Reachability.UNAVAILABLE
    # UNKNOWN, not "mesh-only": a map miss must SURFACE (Attend), never silently Track.
    exposure_class: str = _UNKNOWN_EXPOSURE
    # Where the reachability fact came from: "" (none), "govulncheck", "sweep", or a judge
    # id ("jev", "claude", ...). Recorded so every Act/Track traces back to its evidence.
    reach_source: str = ""
    reach_confidence: float | None = None
    # Malicious package version (OSV MAL-* / CWE-506): not a vulnerability to reach — the
    # code runs at install time on every machine that installs it. Bypasses the
    # reachability gate and grades Act.
    malicious: bool = False
    # Advisory TEXT reads like malware but carries no structured marker (judges/malware.py).
    # Also skips the reachability gate; graded on its other axes but never below Attend.
    suspected_malicious: bool = False
    malware_hints: list[str] = field(default_factory=list)
    # Judge context (optional; only the reachability judges read these).
    ecosystem: str = ""                                    # npm | pypi | go | ...
    import_name: str = ""                                  # module name when != package (PyYAML -> yaml)
    version: str = ""                                      # installed version (lockfile)
    vuln_symbols: list[str] = field(default_factory=list)  # e.g. ["template"] for lodash
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
    exposure_class: str = _UNKNOWN_EXPOSURE
    reachability: str = "unavailable"
    coherent_cves: list[str] = field(default_factory=list)
    reach_source: str = ""
    reach_confidence: float | None = None
    malicious: bool = False
    suspected_malicious: bool = False


def advisory_matches_bump(bumped_package, affected_pkgs) -> bool:
    """An advisory is coherent with a bump when one of its affected packages matches."""
    b = (bumped_package or "").strip()
    if not b:
        return False
    return any(a and a.strip().lower() == b.lower() for a in affected_pkgs)


def _coherent_cves(c) -> list[str]:
    """CVE aliases from advisories that actually apply to the bumped package. An advisory
    with NO CVE alias (GHSA/PYSEC-only) is kept under its first id rather than dropped:
    it carries no KEV/EPSS signal, but it is still a coherent advisory (Attend if exposed)."""
    out = []
    for aliases, affected in c.advisories:
        if advisory_matches_bump(c.bumped_package, affected):
            cves = [a for a in aliases if a.upper().startswith("CVE-")]
            out.extend(cves or [a for a in aliases[:1] if a])
    seen, uniq = set(), []
    for a in out:
        au = a.upper()
        if au not in seen:
            # CVE ids are normalised to upper case (KEV/EPSS keys); GHSA/PYSEC ids keep
            # their canonical spelling (GHSA-xxxx-xxxx-xxxx is lower case after the prefix)
            seen.add(au); uniq.append(au if au.startswith("CVE-") else a)
    return uniq


def _parse_gvc_cache(text) -> dict:
    """Parse the govulncheck fleet cache JSON (clean-room schema)."""
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001 — unparseable cache = no claim
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def gvc_reachability(repo, package, *, cache_dir=None):
    """Read the govulncheck fleet cache for `repo` and return (Reachability, osv_ids)."""
    cdir = os.environ.get("CACHE_DIR", os.path.expanduser("~/.cache/gvc_fleet"))
    name = repo.split("/")[-1]
    p = f"{cdir}/{name}.json"
    if not os.path.exists(p):
        return Reachability.UNAVAILABLE, []
    try:
        data = _parse_gvc_cache(open(p).read())
    except Exception:  # noqa: BLE001
        return Reachability.UNAVAILABLE, []
    matched = [m for m in data if m == package or m.startswith(package + "/")
               or package.startswith(m + "/")]
    if not matched:
        return Reachability.UNSCANNED, []
    osvs = sorted({o for m in matched for o in (data[m] or {}).get("osvs", [])})
    reachable = any((data[m] or {}).get("reachable") for m in matched)
    return (Reachability.REACHABLE if reachable else Reachability.UNREACHABLE), osvs


def grade(c, *, use_vulncheck=True, enrichment_map=None, epss_act: float | None = None) -> Grade:
    """Grade one candidate. Pure function of the deterministic axes."""
    cves = _coherent_cves(c)
    exposed = c.exposure_class in _EXPOSED
    src = c.reach_source or ("govulncheck" if c.is_go else "")

    # No coherent advisory -> nothing to be urgent about. Track.
    if not cves:
        return Grade(c.repo, c.pr_number, Decision.TRACK,
                     "no coherent advisory cited (routine/mis-attributed bump)",
                     bumped_package=c.bumped_package,
                     exposure_class=c.exposure_class,
                     reachability=c.reachability.value,
                     reach_source=c.reach_source, reach_confidence=c.reach_confidence)

    if c.malicious:
        return Grade(c.repo, c.pr_number, Decision.ACT,
                     "MALICIOUS package version — install-time compromise on every machine that "
                     "installs it (dev, CI, prod); reachability/exposure/EPSS don't apply → SLA-bearing",
                     bumped_package=c.bumped_package, exposure_class=c.exposure_class,
                     reachability=c.reachability.value, coherent_cves=cves, malicious=True)

    if c.suspected_malicious:
        # grade the other axes with reachability set aside (it's the wrong question for an
        # install-time payload), then floor at Attend: a missed compromise must not Track
        import copy
        c2 = copy.copy(c)
        c2.suspected_malicious = False
        c2.reachability, c2.reach_source = Reachability.UNAVAILABLE, ""
        g = grade(c2, use_vulncheck=use_vulncheck, enrichment_map=enrichment_map, epss_act=epss_act)
        g.suspected_malicious = True
        why = "SUSPECTED malicious/compromised package version (advisory text: " + \
              ", ".join(c.malware_hints[:3]) + ") — confirm; reachability not applied"
        if g.decision == Decision.TRACK:
            g.decision, g.reason = Decision.ATTEND, why
        else:
            g.reason = f"{why}; {g.reason}"
        return g

    e = _enrich(cves, enrichment_map=enrichment_map)
    worst = e.worst()
    kev = bool(worst and worst.kev)
    max_epss = max((s.epss for s in e.signals.values() if s.epss is not None), default=None)
    epss_act = EPSS_ACT if epss_act is None else epss_act
    exploit_signal = kev or (max_epss is not None and max_epss >= epss_act)
    pcts = [s.percentile for s in e.signals.values() if s.percentile is not None]

    g = Grade(c.repo, c.pr_number, Decision.TRACK, "",
              bumped_package=c.bumped_package,
              kev=kev, max_epss=max_epss, max_epss_percentile=max(pcts, default=None),
              exposure_class=c.exposure_class,
              reachability=c.reachability.value, coherent_cves=cves,
              reach_source=c.reach_source, reach_confidence=c.reach_confidence)

    # Proven-unreachable (govulncheck, or an ACCEPTED judge verdict — the judge layer only
    # emits UNREACHABLE above its high not-reachable floor): positive evidence the vuln
    # can't be hit. Never Act; Attend only if there IS an exploit signal (worth a human
    # glance), else Track.
    if c.reachability == Reachability.UNREACHABLE:
        if exploit_signal and exposed:
            g.decision, g.reason = Decision.ATTEND, (f"KEV/high-EPSS + exposed, BUT {src or 'reachability'} says the vuln symbol is unreachable — review, don't auto-file")
            return g
        else:
            g.decision, g.reason = Decision.TRACK, f"{src or 'reachability'} says vuln symbol unreachable — not needed"
            return g

    # Reachable, or no proof either way (unscanned / unavailable): exposure decides.
    reachable_or_nongo = True

    if reachable_or_nongo and exposed and exploit_signal:
        why = ("KEV known-exploited" if kev else f"EPSS {max_epss:.3f} >= {epss_act}")
        reach = (f"reachable ({src})" if c.reachability == Reachability.REACHABLE
                 else "no code-reachability signal (non-Go)" if not c.is_go
                 else c.reachability.value)
        g.decision, g.reason = Decision.ACT, f"{why}; {c.exposure_class}; {reach} → SLA-bearing"
        return g

    if reachable_or_nongo and exposed:
        g.decision, g.reason = Decision.ATTEND, (f"coherent advisory on an exposed ({c.exposure_class}) service, no live-exploit signal yet — human triage")
        return g

    # UNKNOWN exposure + exploit signal + reachable: absence of an exposure signal is NOT evidence of safety; do NOT silently Track — surface for confirmation.
    if (reachable_or_nongo and exploit_signal and c.exposure_class == _UNKNOWN_EXPOSURE):
        g.decision, g.reason = Decision.ATTEND, "KEV/high-EPSS + reachable but exposure UNKNOWN (repo not in the exposure map) — confirm exposure, don't assume internal"
        return g

    g.decision, g.reason = Decision.TRACK, f"coherent advisory but not exposed ({c.exposure_class}) / not reachable"
    return g


def grade_all(candidates: Iterable[Candidate], *, use_vulncheck=True,
              enrichment_map=None) -> list[Grade]:
    """Grade a batch, returned Act-first then by EPSS desc (digest order)."""
    graded = [grade(c, use_vulncheck=use_vulncheck, enrichment_map=enrichment_map) for c in candidates]
    order = {Decision.ACT: 0, Decision.ATTEND: 1, Decision.TRACK: 2}
    graded.sort(key=lambda g: (order[g.decision], -(g.max_epss or 0.0)))
    return graded

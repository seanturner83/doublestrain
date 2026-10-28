"""Unit tests for the clean-room SSVC grader (offline, injected enrichment map).

The grader is a pure function of three deterministic axes: exploitability x
reachability x exposure. These tests exercise Act / Attend / Track across every
branch with an INJECTED enrichment map — no network, no LLM judgement.
"""
from doublestrain.ssvc import (
    Candidate, Reachability, Decision, grade, grade_all)


def _cand(repo="org/api-gateway", pr=1, pkg="github.com/acme/api-gateway",
          is_go=False, advisories=None, reach=Reachability.UNAVAILABLE,
          exposure="unknown"):
    # `advisories` = [aliases_list, affected_pkgs_list] for one advisory (the
    # JSONL shape); wrap into a list of (aliases, affected) tuples.
    advs = [tuple(advisories)] if advisories else []
    return Candidate(repo=repo, pr_number=pr, bumped_package=pkg,
                     is_go=is_go, advisories=advs,
                     reachability=reach, exposure_class=exposure)


def test_act_kev_reachable_go_exposed():
    """KEV + Go reachable + exposed (public-internet) -> Act."""
    c = _cand(is_go=True, advisories=[["CVE-2024-1234"], ["github.com/acme/api-gateway"]],
              reach=Reachability.REACHABLE, exposure="public-internet")
    g = grade(c, enrichment_map={"CVE-2024-1234": {"kev": True, "epss": 0.5}})
    assert g.decision == Decision.ACT


def test_act_epss_nongo_sase():
    """EPSS>=EPSS_ACT + non-Go (reachability unavailable) + sase-reachable -> Act."""
    c = _cand(pkg="github.com/acme/portal", is_go=False,
             advisories=[["CVE-2024-5678"], ["github.com/acme/portal"]],
             reach=Reachability.UNAVAILABLE, exposure="sase-reachable")
    g = grade(c, enrichment_map={"CVE-2024-5678": {"kev": False, "epss": 0.30}})
    assert g.decision == Decision.ACT


def test_attend_coherent_exposed_no_exploit_signal():
    """Coherent advisory on an exposed service, but no live exploit signal -> Attend."""
    c = _cand(pkg="github.com/acme/portal", is_go=False,
             advisories=[["CVE-2024-9999"], ["github.com/acme/portal"]],
             exposure="sase-reachable")
    g = grade(c, enrichment_map={"CVE-2024-9999": {"kev": False, "epss": 0.01}})
    assert g.decision == Decision.ATTEND


def test_attend_unknown_exposure_with_exploit_signal():
    """UNKNOWN exposure + exploit signal + reachable -> Attend (surface), never Track."""
    c = _cand(pkg="github.com/acme/edge", is_go=False,
             advisories=[["CVE-2024-1234"], ["github.com/acme/edge"]],
             reach=Reachability.UNAVAILABLE, exposure="unknown")
    g = grade(c, enrichment_map={"CVE-2024-1234": {"kev": True, "epss": None}})
    assert g.decision == Decision.ATTEND


def test_track_no_coherent_advisory():
    """No coherent advisory cited -> Track (mis-attributed bump dropped first)."""
    c = _cand(pkg="github.com/acme/other",
             advisories=[["CVE-2024-1234"], ["something-else"]], exposure="public-internet")
    g = grade(c, enrichment_map={"CVE-2024-1234": {"kev": True}})
    assert g.decision == Decision.TRACK


def test_track_go_proven_unreachable_no_exploit():
    """Go proven-unreachable + no exploit signal -> Track (not needed)."""
    c = _cand(is_go=True, advisories=[["CVE-2024-1234"], ["github.com/acme/api-gateway"]],
              reach=Reachability.UNREACHABLE, exposure="public-internet")
    g = grade(c, enrichment_map={})   # no signal at all -> Track
    assert g.decision == Decision.TRACK


def test_attend_go_proven_unreachable_but_exploit():
    """Go proven-unreachable + KEV/high-EPSS + exposed -> Attend (review, don't auto-file)."""
    c = _cand(is_go=True, advisories=[["CVE-2024-1234"], ["github.com/acme/api-gateway"]],
              reach=Reachability.UNREACHABLE, exposure="public-internet")
    g = grade(c, enrichment_map={"CVE-2024-1234": {"kev": True}})
    assert g.decision == Decision.ATTEND


def test_track_not_exposed():
    """Coherent advisory + reachable but not exposed (mesh-only) -> Track."""
    c = _cand(is_go=True, advisories=[["CVE-2024-1234"], ["github.com/acme/api-gateway"]],
              reach=Reachability.REACHABLE, exposure="mesh-only")
    g = grade(c, enrichment_map={"CVE-2024-1234": {"kev": True}})
    assert g.decision == Decision.TRACK


def test_grade_all_orders_act_first():
    """grade_all returns Act first (then Attend/Track), by EPSS desc within tier."""
    cs = [
        _cand(repo="org/a", pr=1, advisories=[["CVE-2024-1"], ["github.com/acme/api-gateway"]],
              is_go=False, exposure="public-internet"),
        _cand(repo="org/b", pr=2, pkg="github.com/acme/portal",
             advisories=[["CVE-2024-2"], ["github.com/acme/portal"]],
              is_go=False, exposure="sase-reachable"),
    ]
    em = {"CVE-2024-1": {"kev": True}, "CVE-2024-2": {"epss": 0.5}}
    graded = grade_all(cs, enrichment_map=em)
    assert [g.decision for g in graded] == [Decision.ACT, Decision.ACT]


def test_enrichment_is_case_insensitive_for_known_cves():
    """The injected map matches both raw and upper-cased CVE aliases."""
    c = _cand(advisories=[["cve-2024-1234"], ["github.com/acme/api-gateway"]], exposure="public-internet")
    g = grade(c, enrichment_map={"CVE-2024-1234": {"kev": True}})
    assert g.decision == Decision.ACT

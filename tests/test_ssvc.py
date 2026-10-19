"""The SSVC decision table (ssvc.grade): one test per row, plus advisory coherence and
digest order. Offline: exploitation signals are passed in as a map."""
import pytest

from doublestrain.ssvc import Candidate, Decision, Reachability, _coherent_cves, grade, grade_all

PKG = "left-pad"
CVE = "CVE-2030-0001"


def cand(*, reach=Reachability.UNAVAILABLE, exposure="public-internet", ids=(CVE,), affected=(PKG,), **kw):
    return Candidate(repo="acme/web", pr_number=1, bumped_package=PKG,
                     advisories=[(list(ids), list(affected))] if ids else [],
                     reachability=reach, exposure_class=exposure, **kw)


KEV = {CVE: {"kev": True, "epss": 0.01}}
HIGH = {CVE: {"kev": False, "epss": 0.40, "epss_percentile": 0.97}}
LOW = {CVE: {"kev": False, "epss": 0.02}}


@pytest.mark.parametrize("reach,exposure,feed,want", [
    # exposed and exploited -> Act, unless proven unreachable
    (Reachability.REACHABLE, "public-internet", KEV, Decision.ACT),
    (Reachability.UNAVAILABLE, "sase-reachable", HIGH, Decision.ACT),     # no fact grades like reachable
    (Reachability.UNSCANNED, "control-plane", KEV, Decision.ACT),
    (Reachability.UNREACHABLE, "public-internet", KEV, Decision.ATTEND),
    # exposed, no exploitation signal -> Attend; unreachable -> Track
    (Reachability.REACHABLE, "public-internet", LOW, Decision.ATTEND),
    (Reachability.UNAVAILABLE, "public-internet", None, Decision.ATTEND),
    (Reachability.UNREACHABLE, "public-internet", LOW, Decision.TRACK),
    # exposure unknown: an exploitation signal surfaces, nothing else does
    (Reachability.UNAVAILABLE, "unknown", KEV, Decision.ATTEND),
    (Reachability.UNAVAILABLE, "unknown", LOW, Decision.TRACK),
    (Reachability.UNREACHABLE, "unknown", KEV, Decision.TRACK),
    # internal only
    (Reachability.REACHABLE, "mesh-only", KEV, Decision.TRACK),
])
def test_decision_table(reach, exposure, feed, want):
    assert grade(cand(reach=reach, exposure=exposure), enrichment_map=feed).decision == want


def test_epss_threshold_and_unknown_epss():
    g = grade(cand(), enrichment_map=HIGH, epss_act=0.5)
    assert g.decision == Decision.ATTEND and g.max_epss == 0.40 and g.max_epss_percentile == 0.97
    assert grade(cand(), enrichment_map=HIGH, epss_act=0.4).decision == Decision.ACT
    g = grade(cand(), enrichment_map={CVE: {"kev": False, "epss": None}})
    assert g.max_epss is None and g.decision == Decision.ATTEND          # unscored: unknown, so no signal


def test_unreachable_reason_names_its_source():
    g = grade(cand(reach=Reachability.UNREACHABLE, reach_source="split:workstation"), enrichment_map=LOW)
    assert g.decision == Decision.TRACK and "split:workstation" in g.reason and g.reach_source == "split:workstation"


def test_malicious_beats_everything():
    g = grade(cand(reach=Reachability.UNREACHABLE, exposure="mesh-only", malicious=True))
    assert g.decision == Decision.ACT and g.malicious and "MALICIOUS" in g.reason


def test_suspected_malicious_ignores_reachability_and_floors_at_attend():
    g = grade(cand(reach=Reachability.UNREACHABLE, exposure="mesh-only", suspected_malicious=True,
                   malware_hints=["exfiltrates env"]), enrichment_map=LOW)
    assert g.decision == Decision.ATTEND and g.suspected_malicious and g.reason.startswith("SUSPECTED")
    g = grade(cand(reach=Reachability.UNREACHABLE, suspected_malicious=True), enrichment_map=KEV)
    assert g.decision == Decision.ACT and g.reason.startswith("SUSPECTED")   # unreachable set aside


def test_coherence_drops_advisories_for_other_packages():
    c = cand(affected=("right-pad",))
    assert _coherent_cves(c) == [] and grade(c, enrichment_map=KEV).decision == Decision.TRACK
    c = Candidate(repo="r", pr_number=1, bumped_package="Left-Pad",
                  advisories=[(["GHSA-aaaa-bbbb-cccc", "cve-2030-0002"], ["left-pad"]),
                              (["GHSA-dddd-eeee-ffff"], ["LEFT-PAD"]),
                              (["CVE-2030-0002"], ["left-pad"]),
                              (["CVE-2030-0003"], ["other"])])
    assert _coherent_cves(c) == ["CVE-2030-0002", "GHSA-dddd-eeee-ffff"]


def test_digest_order():
    feeds = {"CVE-2030-0010": {"epss": 0.2}, "CVE-2030-0011": {"epss": 0.9}, "CVE-2030-0012": {"kev": True}}
    cs = [cand(ids=(i,), exposure=e) for i, e in (("CVE-2030-0010", "public-internet"),
                                                   ("CVE-2030-0011", "public-internet"),
                                                   ("CVE-2030-0012", "mesh-only"),
                                                   ("CVE-2030-0013", "public-internet"))]
    out = grade_all(cs, enrichment_map=feeds)
    assert [(g.decision, g.coherent_cves[0]) for g in out] == [
        (Decision.ACT, "CVE-2030-0011"), (Decision.ACT, "CVE-2030-0010"),
        (Decision.ATTEND, "CVE-2030-0013"), (Decision.TRACK, "CVE-2030-0012")]

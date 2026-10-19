"""Feed tests — offline: a fake HTTP server stands in for CISA KEV and FIRST EPSS."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from doublestrain.feeds import build_enrichment, epss, kev
from doublestrain.ssvc import Candidate, Decision, grade

KEV_DOC = {"catalogVersion": "2026.10.04", "dateReleased": "2026-10-04T00:00:00Z",
           "vulnerabilities": [{"cveID": "CVE-2024-0001", "dateAdded": "2026-01-02",
                                "knownRansomwareCampaignUse": "Known", "dueDate": "2026-01-23",
                                "shortDescription": "dropped from the cache"}]}
EPSS = {"CVE-2024-0001": "0.91", "CVE-2024-0002": "0.03"}   # CVE-2024-0003: no score


@pytest.fixture
def feeds(tmp_path, monkeypatch):
    hits = {"kev": 0, "epss": []}
    state = {"down": False}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if state["down"]:
                self.send_response(503)
                self.end_headers()
                return
            u = urlparse(self.path)
            if u.path == "/kev.json":
                hits["kev"] += 1
                body = KEV_DOC
            else:
                asked = parse_qs(u.query)["cve"][0].split(",")
                hits["epss"].append(asked)
                body = {"data": [{"cve": c, "epss": EPSS[c], "percentile": "0.5", "date": "2026-10-06"}
                                 for c in asked if c in EPSS]}
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    monkeypatch.setattr(kev, "URL", f"{base}/kev.json")
    monkeypatch.setattr(epss, "URL", f"{base}/epss")
    monkeypatch.setenv("SSVC_FEED_CACHE", str(tmp_path / "feeds"))
    yield hits, state
    srv.shutdown()


CVES = ["CVE-2024-0001", "cve-2024-0002", "CVE-2024-0003"]


def test_live_merges_kev_and_epss_and_keeps_unknown_unknown(feeds):
    m, prov = build_enrichment(CVES, mode="live")
    assert m["CVE-2024-0001"]["kev"] is True and m["CVE-2024-0001"]["epss"] == 0.91
    assert m["CVE-2024-0001"]["kev_ransomware"] == "Known"
    assert m["CVE-2024-0002"] == {**m["CVE-2024-0002"], "kev": False, "epss": 0.03}
    assert m["CVE-2024-0003"]["epss"] is None          # unscored -> UNKNOWN, never 0
    assert prov["kev"]["catalogVersion"] == "2026.10.04"
    assert prov["epss"]["unknown"] == ["CVE-2024-0003"]


def test_second_live_run_is_served_from_cache(feeds):
    hits, _ = feeds
    build_enrichment(CVES, mode="live")
    build_enrichment(CVES, mode="live")
    assert hits["kev"] == 1 and len(hits["epss"]) == 1   # unknown CVE negatively cached too


def test_cache_only_never_touches_network(feeds):
    hits, _ = feeds
    m, prov = build_enrichment(CVES, mode="cache-only")
    assert hits == {"kev": 0, "epss": []}
    assert all(v["epss"] is None and v["kev"] is False for v in m.values())
    assert "unavailable" in prov["kev"]["status"]


def test_failed_refresh_falls_back_to_stale_cache(feeds, monkeypatch):
    _, state = feeds
    build_enrichment(CVES, mode="live")
    monkeypatch.setenv("SSVC_FEED_MAX_AGE_H", "0")        # everything is now stale
    state["down"] = True
    m, prov = build_enrichment(CVES, mode="live")
    assert m["CVE-2024-0001"]["kev"] is True and m["CVE-2024-0001"]["epss"] == 0.91
    assert prov["kev"]["status"].startswith("stale") and prov["epss"]["status"].startswith("stale")


def test_epss_batches(feeds, monkeypatch):
    hits, _ = feeds
    monkeypatch.setattr(epss, "BATCH", 2)
    build_enrichment(CVES, mode="live")
    assert [len(b) for b in hits["epss"]] == [2, 1]


def test_fixture_mode_passes_through():
    m, prov = build_enrichment(CVES, mode="fixture", fixture={"CVE-1": {"kev": True}})
    assert m == {"CVE-1": {"kev": True}} and prov == {"mode": "fixture"}


def test_live_kev_drives_act(feeds):
    m, _ = build_enrichment(["CVE-2024-0001"], mode="live")
    c = Candidate(repo="o/app", pr_number=1, bumped_package="p", advisories=[(["CVE-2024-0001"], ["p"])],
                  exposure_class="public-internet")
    g = grade(c, enrichment_map=m)
    assert g.decision == Decision.ACT and g.kev

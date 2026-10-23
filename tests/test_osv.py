"""OSV / lockfile tests — offline: a fake OSV server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from doublestrain import osv
from doublestrain.ssvc import Candidate, Decision, _coherent_cves, grade

LOCK_V2 = {
    "lockfileVersion": 2,
    "packages": {
        "": {"dependencies": {"express": "^4"}, "devDependencies": {"mocha": "^9"}},
        "node_modules/express": {"version": "4.17.1"},
        "node_modules/qs": {"version": "6.7.0"},
        "node_modules/mocha": {"version": "9.0.0", "dev": True},
        "node_modules/minimist": {"version": "1.2.0", "dev": True},
        "node_modules/mocha/node_modules/qs": {"version": "6.5.0", "dev": True},
        "node_modules/@scope/pkg": {"version": "1.0.0"},
        "node_modules/linked": {"link": True},
    },
}

VULNS = {
    "GHSA-aaaa": {"id": "GHSA-aaaa", "summary": "Prototype pollution in `qs.parse`",
                  "details": "Calling `parse()` with `__proto__` keys...", "aliases": ["CVE-2022-24999"],
                  "database_specific": {"severity": "HIGH"},
                  "affected": [{"package": {"name": "qs", "ecosystem": "npm"},
                                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "6.7.3"}]}]}]},
    # same CVE filed again under a second GHSA id -> must merge with GHSA-aaaa
    "GHSA-bbbb": {"id": "GHSA-bbbb", "aliases": ["CVE-2022-24999"], "summary": "dup",
                  "affected": [{"package": {"name": "qs", "ecosystem": "npm"},
                                "ranges": [{"events": [{"fixed": "6.7.3"}]}]}]},
    "GHSA-cccc": {"id": "GHSA-cccc", "summary": "No CVE assigned", "aliases": [],
                  "affected": [{"package": {"name": "express", "ecosystem": "npm"},
                                "ranges": [{"events": [{"fixed": "4.20.0"}]}]}]},
    "GHSA-wwww": {"id": "GHSA-wwww", "withdrawn": "2024-01-01", "aliases": []},
}
BY_PKG = {("qs", "6.7.0"): ["GHSA-aaaa", "GHSA-bbbb"], ("express", "4.17.1"): ["GHSA-cccc", "GHSA-wwww"]}


@pytest.fixture
def fake_osv(tmp_path, monkeypatch):
    seen = {"batch": 0, "vulns": 0}

    class H(BaseHTTPRequestHandler):
        def _send(self, obj, code=200):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            seen["batch"] += 1
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self._send({"results": [
                {"vulns": [{"id": i} for i in BY_PKG.get((q["package"]["name"], q["version"]), [])]}
                for q in body["queries"]]})

        def do_GET(self):
            seen["vulns"] += 1
            vid = self.path.rsplit("/", 1)[-1]
            self._send(VULNS[vid]) if vid in VULNS else self._send({}, 404)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(osv, "API", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("SSVC_FEED_CACHE", str(tmp_path / "cache"))
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps(LOCK_V2))
    yield repo, seen
    srv.shutdown()


def test_parse_npm_lock_v2_direct_dev_and_nested(fake_osv):
    repo, _ = fake_osv
    deps = {(d.name, d.version): d for d in osv.parse_npm_lock(repo / "package-lock.json")}
    assert deps[("express", "4.17.1")].direct and not deps[("express", "4.17.1")].dev
    assert not deps[("qs", "6.7.0")].direct and not deps[("qs", "6.7.0")].dev    # prod transitive
    assert deps[("mocha", "9.0.0")].dev and deps[("qs", "6.5.0")].dev            # nested dev copy
    assert ("@scope/pkg", "1.0.0") in deps and not any(n == "linked" for n, _ in deps)


def test_parse_npm_lock_v1(tmp_path):
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": True}}}}}))
    deps = {d.name: d for d in osv.parse_npm_lock(p)}
    assert deps["a"].direct and not deps["a"].dev and deps["b"].dev and not deps["b"].direct


def test_parse_requirements(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text("flask==3.0.3\nPyYAML[ext]==5.3.1 ; python_version>'3'\nrequests>=2\n# x==1\n")
    assert [(d.name, d.version) for d in osv.parse_requirements(p)] == [("flask", "3.0.3"), ("PyYAML", "5.3.1")]


def test_candidates_merge_aliases_drop_withdrawn_keep_cveless(fake_osv):
    repo, _ = fake_osv
    recs, prov = osv.candidates(repo, "org/app", include_dev=False)
    by_pkg = {r["facts"]["package"]: r for r in recs}
    assert set(by_pkg) == {"qs", "express"} and prov["advisories"] == 2
    q = by_pkg["qs"]["facts"]
    assert q["advisories"][0][0] == "CVE-2022-24999"                     # CVE first
    assert set(q["advisories"][0]) == {"CVE-2022-24999", "GHSA-aaaa", "GHSA-bbbb"}
    assert q["fixed"] == ["6.7.3"] and q["severity"] == "HIGH" and not q["direct"]
    assert "qs.parse" in q["vuln_symbols"] and "parse" in q["vuln_symbols"]
    assert by_pkg["express"]["facts"]["advisories"][0] == ["GHSA-cccc"]


def test_cveless_advisory_is_still_coherent():
    c = Candidate(repo="o/app", pr_number=1, bumped_package="express",
                  advisories=[(["GHSA-cccc"], ["express"])], exposure_class="public-internet")
    assert _coherent_cves(c) == ["GHSA-cccc"]
    assert grade(c, enrichment_map={}).decision == Decision.ATTEND     # was silently Track


def test_queries_and_records_are_cached(fake_osv):
    repo, seen = fake_osv
    osv.candidates(repo, "org/app")
    first = dict(seen)
    osv.candidates(repo, "org/app")
    assert seen == first                                                 # second run: all cache
    recs, _ = osv.candidates(repo, "org/app", offline=True)
    assert len(recs) == 2 and seen == first


def test_guess_symbols_skips_noise():
    a = osv.Advisory(ids=["X"], package="lodash", version="1", ecosystem="npm",
                     summary="Command injection in `template`",
                     details="`options.variable` and `lodash` and `true` and `_.template()`")
    assert osv.guess_symbols(a) == ["template", "options.variable", "_.template"]


# --- malware advisories bypass the reachability gate ------------------------------

@pytest.mark.parametrize("rec,expected", [
    ({"id": "MAL-2023-462", "aliases": ["GHSA-xv2f-5jw4-v95m"]}, True),
    ({"id": "GHSA-xv2f-5jw4-v95m", "aliases": ["MAL-2023-462"]}, True),
    ({"id": "GHSA-x", "database_specific": {"malicious-packages-origins": [{}]}}, True),
    ({"id": "GHSA-y", "database_specific": {"cwe_ids": ["CWE-506"]}}, True),
    ({"id": "GHSA-z", "database_specific": {"cwe_ids": ["CWE-1333"]}, "aliases": ["CVE-2024-1"]}, False),
])
def test_is_malicious(rec, expected):
    assert osv.is_malicious(rec) is expected


def test_malicious_candidate_grades_act_regardless_of_other_axes():
    from doublestrain.ssvc import Reachability
    for reach, exposure in [(Reachability.UNREACHABLE, "mesh-only"), (Reachability.UNAVAILABLE, "unknown")]:
        c = Candidate(repo="o/app", pr_number=1, bumped_package="fsevents",
                      advisories=[(["GHSA-xv2f-5jw4-v95m", "MAL-2023-462"], ["fsevents"])],
                      reachability=reach, exposure_class=exposure, malicious=True)
        g = grade(c, enrichment_map={})
        assert g.decision == Decision.ACT and g.malicious and "MALICIOUS" in g.reason


def test_malicious_candidate_skips_the_judges(tmp_path):
    from doublestrain.reach import resolve_reachability

    class Boom:
        name = "boom"

        def judge(self, q):
            raise AssertionError("a judge was consulted for a malware advisory")
    c = Candidate(repo="o/app", pr_number=1, bumped_package="fsevents",
                  advisories=[(["MAL-2023-462"], ["fsevents"])], malicious=True)
    assert resolve_reachability(c, Boom(), str(tmp_path), "MAL-2023-462") is None


def test_candidates_flag_malware(fake_osv, monkeypatch):
    repo, _ = fake_osv
    VULNS["MAL-2099-1"] = {"id": "MAL-2099-1", "summary": "Malicious code in qs (npm)",
                           "aliases": [], "affected": [{"package": {"name": "qs", "ecosystem": "npm"},
                                                        "ranges": [{"events": [{"introduced": "0"}]}]}]}
    monkeypatch.setitem(BY_PKG, ("qs", "6.7.0"), ["GHSA-aaaa", "MAL-2099-1"])
    recs, _ = osv.candidates(repo, "org/app", include_dev=False)
    flags = {r["facts"]["advisories"][0][0]: r["facts"]["malicious"] for r in recs}
    assert flags == {"CVE-2022-24999": False, "MAL-2099-1": True, "GHSA-cccc": False}


# --- suspected malware (no structured marker) ------------------------------------

from doublestrain.judges import malware as _mw


@pytest.mark.parametrize("text,hit", [
    ("Embedded malware in ua-parser-js", True),
    ("versions 3.3.6 were a malicious version published after the maintainer account was compromised", True),
    ("postinstall script that downloads a cryptominer", True),
    ("the payload exfiltrates environment variables to a remote host", True),
    ("A malicious user could craft a query string that causes a ReDoS", False),
    ("Prototype pollution via crafted input", False),
])
def test_malware_hints(text, hit):
    assert bool(_mw.hints(text)) is hit


def test_malware_hint_cwe_912():
    assert _mw.hints("hidden functionality", ["CWE-912"]) == ["CWE-912"]


@pytest.mark.parametrize("check,suspected", [
    ({"verdict": "vulnerability", "confidence": 0.95}, False),       # confidently cleared
    ({"verdict": "vulnerability", "confidence": 0.5}, True),         # not confident -> keep
    ({"verdict": "unsure", "confidence": 0.9}, True),
    ({"verdict": "malicious_package", "confidence": 1.0}, True),
    (None, True),                                                    # Jev unavailable -> keep
])
def test_assess_only_clears_on_confident_vulnerability(monkeypatch, check, suspected):
    monkeypatch.setattr(_mw, "classify", lambda pkg, text: check)
    a = _mw.assess("pkg", "Embedded malware in pkg", "")
    assert a["suspected"] is suspected and a["hints"]


@pytest.mark.parametrize("check,suspected", [
    ({"verdict": "malicious_package", "confidence": 0.9}, True),     # no phrase, Jev confident: flag
    ({"verdict": "malicious_package", "confidence": 0.5}, False),    # no phrase, Jev not confident
    ({"verdict": "unsure", "confidence": 0.9}, False),
    (None, False),                                                   # Jev down, no phrase: as before
])
def test_assess_without_hints_still_asks_jev(monkeypatch, check, suspected):
    calls = []
    monkeypatch.setattr(_mw, "classify", lambda pkg, text: calls.append(text) or check)
    a = _mw.assess("qs", "Version 2.1.4 sends the host's npm token to a remote server on install", "")
    assert calls and a["hints"] == [] and a["suspected"] is suspected


def _sus(**kw):
    from doublestrain.ssvc import Reachability
    base = dict(repo="o/app", pr_number=1, bumped_package="evil", advisories=[(["GHSA-evil-0000-0000"], ["evil"])],
                exposure_class="mesh-only", reachability=Reachability.UNREACHABLE, reach_source="claude",
                suspected_malicious=True, malware_hints=["malicious version"])
    base.update(kw)
    return Candidate(**base)


def test_suspected_malware_never_tracks():
    g = grade(_sus(), enrichment_map={})          # unreachable + not exposed: would be Track
    assert g.decision == Decision.ATTEND and g.suspected_malicious and "SUSPECTED" in g.reason


def test_suspected_malware_keeps_act_from_other_axes():
    g = grade(_sus(advisories=[(["CVE-2099-1"], ["evil"])], exposure_class="public-internet"),
              enrichment_map={"CVE-2099-1": {"kev": True}})
    assert g.decision == Decision.ACT and g.reason.startswith("SUSPECTED")


def test_suspected_malware_skips_the_judges(tmp_path):
    from doublestrain.reach import resolve_reachability
    from doublestrain.ssvc import Reachability

    class Boom:
        name = "boom"

        def judge(self, q):
            raise AssertionError("judge consulted")
    assert resolve_reachability(_sus(reachability=Reachability.UNAVAILABLE), Boom(), str(tmp_path)) is None


def test_candidates_carry_suspicion(fake_osv, monkeypatch):
    repo, _ = fake_osv
    VULNS["GHSA-evil"] = {"id": "GHSA-evil", "summary": "Compromised version of qs", "aliases": [],
                          "details": "The maintainer account was compromised and a malicious version published.",
                          "affected": [{"package": {"name": "qs", "ecosystem": "npm"}, "ranges": [{"events": [{"introduced": "0"}]}]}]}
    monkeypatch.setitem(BY_PKG, ("qs", "6.7.0"), ["GHSA-evil"])
    monkeypatch.setattr(_mw, "classify", lambda pkg, text: {"verdict": "malicious_package", "confidence": 1.0})
    recs, _ = osv.candidates(repo, "org/app", include_dev=False)
    f = {r["facts"]["advisories"][0][0]: r["facts"] for r in recs}["GHSA-evil"]
    assert f["suspected_malicious"] and not f["malicious"] and "malicious version" in f["malware_hints"]


def test_malware_cache_is_per_endpoint(monkeypatch, tmp_path):
    import hashlib
    monkeypatch.setenv("SSVC_FEED_CACHE", str(tmp_path))
    monkeypatch.delenv("TYPESAFE_BASE_URL", raising=False)
    hosted = _mw._cache_path("pkg\nadvisory text")
    legacy = hashlib.sha256(f"{_mw._PROMPT_ID}\npkg\nadvisory text".encode()).hexdigest()[:24]
    assert hosted.name == f"{legacy}.json"                # hosted Jev keeps its existing cache
    monkeypatch.setenv("TYPESAFE_BASE_URL", "http://127.0.0.1:8091")
    other = _mw._cache_path("pkg\nadvisory text")
    assert other != hosted and other.parent == hosted.parent

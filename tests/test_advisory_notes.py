"""The register of known gaps in advisory text: widening only, version ranges, and how a
note reaches the judges' question."""
import pytest

from doublestrain import advisory_notes as an
from doublestrain.reach import query_for
from doublestrain.ssvc import Candidate


def _write(tmp_path, note, kind="widens", evidence='[{ path = "x@1.0.0/a.js", line = 1, quote = "abc" }]'):
    p = tmp_path / "notes.toml"
    p.write_text(f'''
[[advisory]]
id = "CVE-2030-0001"
package = "x"
ecosystem = "npm"
versions = "<2.0.0"
kind = "{kind}"
note = """{note}"""
evidence = {evidence}
verified = "test"
''')
    an.load.cache_clear()
    return str(p)


@pytest.mark.parametrize("text", [
    "The app is not affected unless it calls parse().",
    "This only applies when the server role is used.",
    "It does not apply to the client.",
    "Usually a false positive.",
    "Cannot be reached from request handlers.",
])
def test_a_note_that_narrows_is_refused(tmp_path, text):
    with pytest.raises(ValueError, match="narrowing"):
        an.load(_write(tmp_path, text))


def test_the_register_shape_is_enforced(tmp_path):
    with pytest.raises(ValueError, match="widens"):
        an.load(_write(tmp_path, "Also reached through the client.", kind="narrows"))
    with pytest.raises(ValueError, match="path, line and quote"):
        an.load(_write(tmp_path, "Also reached through the client.", evidence='[{ path = "x@1/a.js" }]'))
    notes = an.load(_write(tmp_path, "Also reached through the client parser."))
    assert notes[0].note == "Also reached through the client parser."


def test_shipped_register_loads_and_widens_only():
    an.load.cache_clear()
    notes = an.load()
    assert {n.id for n in notes} >= {"CVE-2025-69223", "CVE-2024-43800"}
    assert all(n.evidence and not an._NARROWING.search(n.note) for n in notes)


@pytest.mark.parametrize("version,spec,want", [
    ("3.9.5", "<3.13.3", True), ("3.13.3", "<3.13.3", False), ("3.13.3rc1", "<3.13.3", True),
    ("1.15.0", "<1.16.0 || >=2.0.0-0,<2.1.0", True), ("2.0.0", "<1.16.0 || >=2.0.0-0,<2.1.0", True),
    ("2.1.0", "<1.16.0 || >=2.0.0-0,<2.1.0", False), ("1.16.0", "<1.16.0 || >=2.0.0-0,<2.1.0", False),
    ("2.9.0.post0", ">2.9.0", True), ("v1.2.3", ">=1.2.3", True),
])
def test_version_ranges(version, spec, want):
    assert an.in_range(version, spec) is want


def test_a_matching_note_reaches_every_tier_through_the_query(monkeypatch):
    an.load.cache_clear()
    c = Candidate(repo="r", pr_number=1, bumped_package="aiohttp", ecosystem="pypi", version="3.9.5",
                  advisories=[(["CVE-2025-69223", "GHSA-xxxx"], ["aiohttp"])], advisory_summary="zip bomb in the server")
    q = query_for(c, "/app", "CVE-2025-69223")
    assert q.advisory.startswith("zip bomb in the server") and "client's response parser" in q.advisory
    fixed = Candidate(repo="r", pr_number=1, bumped_package="aiohttp", ecosystem="pypi", version="3.13.3",
                      advisories=[(["CVE-2025-69223"], ["aiohttp"])], advisory_summary="zip bomb in the server")
    assert query_for(fixed, "/app", "CVE-2025-69223").advisory == "zip bomb in the server"     # out of range
    other = Candidate(repo="r", pr_number=1, bumped_package="aiohttp", ecosystem="pypi", version="3.9.5",
                      advisories=[(["CVE-2024-0001"], ["aiohttp"])], advisory_summary="s")
    assert query_for(other, "/app", "CVE-2024-0001").advisory == "s"                         # no note: same key
    monkeypatch.setenv("SSVC_ADVISORY_NOTES", "none")
    an.load.cache_clear()
    assert query_for(c, "/app", "CVE-2025-69223").advisory == "zip bomb in the server"
    an.load.cache_clear()


def test_check_verifies_each_step_against_the_source(tmp_path, monkeypatch):
    from doublestrain import pkgsrc
    src = tmp_path / "x@1.0.0"
    src.mkdir()
    (src / "a.js").write_text("const abc = require('y')\n")
    monkeypatch.setattr(pkgsrc, "fetch", lambda name, version, integrity: src)
    good = an.load(_write(tmp_path, "Also reached through y.",
                          evidence='[{ path = "x@1.0.0/a.js", line = 1, quote = "const abc = require(\'y\')" }]'))
    assert an.check(good) == []
    bad = an.load(_write(tmp_path, "Also reached through y.",
                         evidence='[{ path = "x@1.0.0/a.js", line = 1, quote = "something else entirely" }]'))
    assert an.check(bad) and "not on that line" in an.check(bad)[0]
    an.load.cache_clear()

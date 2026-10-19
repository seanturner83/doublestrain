"""Cargo workspaces: lockfile + manifests -> deps, kinds, chains; the Rust pre-pass; the
not_reachable hold for ecosystems without a measured floor. Offline."""
import pytest

from doublestrain import cargo, osv
from doublestrain.judges import depgraph
from doublestrain.judges.base import Verdict
from doublestrain.judges.usage import guard_not_reachable, usage_summary

REG = '"registry+https://github.com/rust-lang/crates.io-index"'


@pytest.fixture
def ws(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["api", "core"]\n[workspace.dependencies]\njson = { package = "serde_json", version = "1" }\n')
    (tmp_path / "api").mkdir()
    (tmp_path / "api/Cargo.toml").write_text(
        '[package]\nname = "api"\nversion = "0.1.0"\n'
        '[dependencies]\ncore = { path = "../core" }\nhyper = "1"\njson = { workspace = true }\n'
        '[dev-dependencies]\ntokio-test = "0.4"\n'
        '[build-dependencies]\ncc = "1"\n'
        '[target.\'cfg(unix)\'.dependencies]\nlibc = "0.2"\n')
    (tmp_path / "core").mkdir()
    (tmp_path / "core/Cargo.toml").write_text('[package]\nname = "core"\nversion = "0.1.0"\n[dependencies]\nring = "0.17"\n')
    pk = lambda n, v, deps=(), src=REG: (f'[[package]]\nname = "{n}"\nversion = "{v}"\n'  # noqa: E731
                                         + (f'source = {src}\nchecksum = "ab{n}"\n' if src else "")
                                         + (f"dependencies = [{', '.join(repr(d).replace(chr(39), chr(34)) for d in deps)}]\n" if deps else "") + "\n")
    (tmp_path / "Cargo.lock").write_text(
        "version = 4\n\n"
        + pk("api", "0.1.0", ["cc", "core", "hyper", "libc", "serde_json", "tokio-test"], src=None)
        + pk("core", "0.1.0", ["ring"], src=None)
        + pk("hyper", "1.4.0", ["h2"]) + pk("h2", "0.4.5")
        + pk("serde_json", "1.0.120") + pk("tokio-test", "0.4.4", ["h2"])
        + pk("cc", "1.1.0", ["jobserver"]) + pk("jobserver", "0.1.32")
        + pk("libc", "0.2.155") + pk("ring", "0.17.8"))
    (tmp_path / "api/src").mkdir()
    (tmp_path / "api/src/main.rs").write_text(
        "use hyper::server::conn::http1;\nuse json::Value;\nfn main() { let v: Value = json::from_str(s); }\n"
        "/// see `json::to_string`\n")
    return tmp_path


def test_kinds_follow_member_manifests_not_the_lockfile(ws):
    w = cargo.load(ws)
    k = w.kind_of()
    assert k["hyper@1.4.0"] == k["h2@0.4.5"] == "runtime"     # h2 is also a dev path: runtime wins
    assert k["tokio-test@0.4.4"] == "dev"
    assert k["cc@1.1.0"] == k["jobserver@0.1.32"] == "build"
    assert k["ring@0.17.8"] == "runtime"                      # via the path dependency on `core`
    assert k["libc@0.2.155"] == "runtime"                     # [target.'cfg'.dependencies]
    assert cargo.ident("serde_json", w) == "json"             # workspace rename


def test_parse_cargo_lock_deps(ws):
    deps = {d.name: d for d in osv.parse_cargo_lock(ws)}
    assert set(deps) == {"hyper", "h2", "serde_json", "tokio-test", "cc", "jobserver", "libc", "ring"}
    assert deps["hyper"].direct and not deps["hyper"].dev and deps["hyper"].ecosystem == "crates.io"
    assert deps["tokio-test"].dev and deps["jobserver"].dev and not deps["h2"].direct


def test_cargo_chain_and_import_sites(ws):
    g = depgraph.load(ws, "cargo")
    assert ["hyper@1.4.0", "h2@0.4.5"] in depgraph.chains(g, "h2", "0.4.5")
    u = usage_summary(str(ws), "cargo", "h2", version="0.4.5")
    assert "app -> hyper@1.4.0 -> h2@0.4.5" in u.text and "api/src/main.rs:1" in u.text
    u = usage_summary(str(ws), "cargo", "serde_json", ["serde_json::from_str"], import_name="json")
    assert [s.split(":")[1] for s in u.import_sites] == ["2", "3"] and u.closed_world


def test_cargo_not_reachable_is_held_until_measured(ws, monkeypatch):
    u = usage_summary(str(ws), "cargo", "h2", version="0.4.5")
    v, note = guard_not_reachable(Verdict.NOT_REACHABLE, u)
    assert v == Verdict.UNSURE and "no measured floor for cargo" in note
    monkeypatch.setenv("SSVC_NR_UNMEASURED", "")
    assert guard_not_reachable(Verdict.NOT_REACHABLE, u)[0] == Verdict.NOT_REACHABLE


def test_rustsec_functions_platforms_and_informational():
    rec = {"id": "RUSTSEC-1", "affected": [{
        "package": {"name": "smallvec", "ecosystem": "crates.io"},
        "database_specific": {"informational": "unsound"},
        "ecosystem_specific": {"affects": {"os": ["windows"], "arch": [], "functions": ["smallvec::SmallVec::insert_many"]}}}]}
    assert osv._rustsec([rec], "smallvec") == (["smallvec::SmallVec::insert_many"], ["os=windows"], "unsound")
    assert "unsound" not in osv._NOT_VULNS and "unmaintained" in osv._NOT_VULNS


def test_inline_cfg_test_modules_are_test_code(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/issuer.rs").write_text(
        "pub fn issue() { let s = \"{\"; }\n"                     # a brace in a string
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn verifies() {\n"
        "        let v = jsonwebtoken::Validation::new(alg);\n    }\n}\n"
        "pub fn after() { jsonwebtoken::decode(t, k, v); }\n")
    u = usage_summary(str(tmp_path), "cargo", "jsonwebtoken")
    assert [s.endswith("(test code)") for s in u.import_sites] == [True, False]

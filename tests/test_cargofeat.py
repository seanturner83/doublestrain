"""cargofeat: Cargo feature resolution over manifests, read as data (rs1)."""
from pathlib import Path

import pytest

from doublestrain import cargofeat
from doublestrain.judges import get_judge
from doublestrain.judges.base import ReachQuery, Verdict

SUM = "0" * 64
LOCK = """version = 3
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["http", "macros", "cc", "winapi", "serde"]
[[package]]
name = "cli"
version = "0.1.0"
dependencies = ["clap"]
[[package]]
name = "http"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
dependencies = ["quinn", "hyper", "rustls", "openssl"]
[[package]]
name = "quinn"
version = "0.11.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
[[package]]
name = "hyper"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
dependencies = ["h2"]
[[package]]
name = "h2"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
[[package]]
name = "rustls"
version = "0.23.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
[[package]]
name = "openssl"
version = "0.10.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
[[package]]
name = "macros"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
dependencies = ["zip"]
[[package]]
name = "zip"
version = "0.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
[[package]]
name = "cc"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
[[package]]
name = "winapi"
version = "0.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
[[package]]
name = "clap"
version = "4.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
[[package]]
name = "serde"
version = "1.0.0"
source = "git+https://github.com/someone/serde-fork#abc"
dependencies = ["itoa"]
[[package]]
name = "itoa"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%(s)s"
""" % {"s": SUM}

CRATES = {
    # quinn only through a weak feature: `http3` is off, so `quinn?/ring` doesn't turn it on
    "http": """[package]\nname = "http"\nversion = "1.0.0"\n
[dependencies.quinn]\nversion = "0.11"\noptional = true\n
[dependencies.hyper]\nversion = "1"\ndefault-features = false\n
[dependencies.rustls]\nversion = "0.23"\noptional = true\n
[target.'cfg(windows)'.dependencies.openssl]\nversion = "0.10"\n
[features]\ndefault = ["tls"]\ntls = ["dep:rustls", "quinn?/ring"]\nhttp3 = ["dep:quinn"]\nh2 = ["hyper/http2"]\n""",
    "hyper": """[package]\nname = "hyper"\nversion = "1.0.0"\n
[dependencies.h2]\nversion = "0.4"\noptional = true\n
[features]\nhttp2 = ["dep:h2"]\n""",
    "quinn": '[package]\nname = "quinn"\nversion = "0.11.0"\n[features]\nring = []\n',
    "rustls": '[package]\nname = "rustls"\nversion = "0.23.0"\n',
    "openssl": '[package]\nname = "openssl"\nversion = "0.10.0"\n',
    "macros": '[package]\nname = "macros"\nversion = "1.0.0"\n[lib]\nproc-macro = true\n[dependencies]\nzip = "0.6"\n',
    "zip": '[package]\nname = "zip"\nversion = "0.6.0"\n',
    "cc": '[package]\nname = "cc"\nversion = "1.0.0"\n',
    "winapi": '[package]\nname = "winapi"\nversion = "0.3.0"\n',
    "clap": '[package]\nname = "clap"\nversion = "4.0.0"\n',
    "itoa": '[package]\nname = "itoa"\nversion = "1.0.0"\n',
}


@pytest.fixture
def ws(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "cli").mkdir()
    (repo / "Cargo.toml").write_text('[workspace]\nmembers = ["app", "cli"]\nresolver = "2"\n'
                                     '[workspace.dependencies]\nhttp = { version = "1", default-features = false }\n')
    (repo / "app/Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n'
        '[dependencies]\nhttp = { workspace = true, features = ["tls"] }\nmacros = "1"\nserde = { git = "x" }\n'
        '[build-dependencies]\ncc = "1"\n'
        '[target.\'cfg(windows)\'.dependencies]\nwinapi = "0.3"\n'
        '[features]\nfast = ["http/h2"]\n')
    (repo / "cli/Cargo.toml").write_text('[package]\nname = "cli"\nversion = "0.1.0"\n[dependencies]\nclap = "4"\n')
    (repo / "Cargo.lock").write_text(LOCK)
    src = tmp_path / "crates"
    for name, toml in CRATES.items():
        (src / name).mkdir(parents=True)
        (src / name / "Cargo.toml").write_text(toml)
    monkeypatch.setattr(cargofeat.pkgsrc, "fetch_crate", lambda n, v, s: src / n)
    monkeypatch.setenv("SSVC_JUDGE_CACHE", str(tmp_path / "cache"))
    cargofeat._analyse.cache_clear()
    cargofeat._key.cache_clear()
    cargofeat.imagedeps._cargo_builds.cache_clear()
    return repo


def _compiled(repo: Path) -> set[str]:
    return {c.split("@")[0] for c in cargofeat.analyse(repo)["compiled"]}


def test_only_what_the_image_builds_is_compiled(ws):
    (ws / "Dockerfile").write_text("FROM rust AS build\nARG FEATS\nRUN cargo build --release -p app --features \"$FEATS\"\n"
                                   "FROM debian\nCOPY --from=build /src/target/release/app /usr/bin/app\n")
    a = cargofeat.analyse(ws)
    got = _compiled(ws)
    assert got >= {"http", "hyper", "rustls", "itoa"}
    assert not got & {"quinn", "h2", "openssl", "zip", "cc", "winapi", "clap"}
    assert "optional dependency no enabled feature" in a["why"]["quinn@0.11.0"] and "http@1.0.0" in a["why"]["quinn@0.11.0"]
    assert "build-time crate macros" in a["why"]["zip@0.6.0"]
    assert "build-dependency" in a["why"]["cc@1.0.0"]
    assert "isn't built for" in a["why"]["openssl@0.10.0"]
    assert "workspace package cli" in a["why"]["clap@4.0.0"]
    assert "serde@1.0.0" in a["opaque"]          # a git fork: no manifest, its locked deps all count


def test_features_and_unknowns_widen(ws):
    (ws / "Dockerfile").write_text("FROM rust\nRUN cargo build -p app --features fast\n")
    assert {"h2", "hyper"} <= _compiled(ws)          # app/fast -> http/h2 -> hyper/http2 -> dep:h2
    cargofeat._analyse.cache_clear(); cargofeat._key.cache_clear(); cargofeat.imagedeps._cargo_builds.cache_clear()
    (ws / "Dockerfile").write_text("FROM rust\nRUN echo no cargo here\n")
    got = _compiled(ws)                              # no build line: every package, all ITS features
    assert {"clap", "h2"} <= got and not got & {"quinn", "openssl", "winapi", "zip"}   # no package feature asks for http3


def test_cfg_expressions():
    assert cargofeat.target_ok('cfg(unix)') and not cargofeat.target_ok('cfg(windows)')
    assert cargofeat.target_ok('cfg(all(unix, not(target_os = "macos")))')
    assert not cargofeat.target_ok('cfg(any(target_os = "macos", target_os = "ios"))')
    assert cargofeat.target_ok('cfg(target_arch = "aarch64")') and not cargofeat.target_ok('cfg(target_arch = "wasm32")')
    assert cargofeat.target_ok('cfg(target_env = "musl")') and cargofeat.target_ok('cfg(feature = "x")')   # unknown holds
    assert cargofeat.target_ok("x86_64-unknown-linux-gnu") and not cargofeat.target_ok("x86_64-pc-windows-msvc")


def test_the_tier(ws, monkeypatch):
    monkeypatch.setenv("SSVC_PKGSRC", "1")
    (ws / "Dockerfile").write_text("FROM rust\nRUN cargo build -p app\n")
    j = get_judge("cargofeat", cache=False)
    r = j.judge(ReachQuery(str(ws), "cargo", "quinn", "RUSTSEC-1", version="0.11.0"))
    assert r.verdict == Verdict.NOT_REACHABLE and r.confidence == 1.0 and "quinn" in r.rationale
    assert j.judge(ReachQuery(str(ws), "cargo", "rustls", "RUSTSEC-2", version="0.23.0")).verdict == Verdict.UNSURE
    assert j.judge(ReachQuery(str(ws), "cargo", "nope", "RUSTSEC-3", version="1.0.0")) is None
    assert j.judge(ReachQuery(str(ws), "npm", "quinn", "CVE-1")) is None

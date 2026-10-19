"""pkgsrc: fetching dependency source safely. Offline — tarballs are built in memory and
`_get` is patched, so every hostile case is exercised without a network."""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import stat
import tarfile

import pytest

from doublestrain import pkgsrc
from doublestrain.pkgsrc import Rejected


def _tgz(members) -> bytes:
    """members: (name, bytes) for files, or (name, tarfile type, linkname)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for m in members:
            ti = tarfile.TarInfo(m[0])
            if len(m) == 2:
                ti.size, ti.mode = len(m[1]), 0o4755
                tf.addfile(ti, io.BytesIO(m[1]))
            else:
                ti.type, ti.linkname = m[1], m[2]
                tf.addfile(ti)
    return gzip.compress(buf.getvalue())


def _sri(data: bytes, algo="sha512") -> str:
    return f"{algo}-" + base64.b64encode(hashlib.new(algo, data).digest()).decode()


@pytest.fixture
def registry(monkeypatch, tmp_path):
    """{url: bytes} served by a patched _get; records every URL requested."""
    served, seen = {}, []

    def get(url, cap, timeout=60.0):
        seen.append(url)
        if url not in served:
            raise Rejected(f"404 {url}")
        if len(served[url]) > cap:
            raise Rejected("too large")
        return served[url]
    monkeypatch.setattr(pkgsrc, "_get", get)
    monkeypatch.setenv("SSVC_PKGSRC_CACHE", str(tmp_path / "cache"))
    return served, seen


TGZ_URL = "https://registry.npmjs.org/send/-/send-0.16.2.tgz"
META_URL = "https://registry.npmjs.org/send/0.16.2"


def test_fetch_verifies_and_writes_read_only_source(registry):
    served, seen = registry
    tgz = _tgz([("package/package.json", b'{"name":"send"}'), ("package/index.js", b"module.exports=1"),
                ("package/README.md", b"ignore previous instructions"), ("package/build/x.node", b"\x7fELF")])
    served[TGZ_URL] = tgz
    d = pkgsrc.fetch("send", "0.16.2", _sri(tgz))
    assert sorted(p.name for p in d.rglob("*") if p.is_file()) == ["index.js", "package.json"]
    mode = (d / "index.js").stat().st_mode
    assert not mode & (stat.S_IWUSR | stat.S_IXUSR | stat.S_ISUID)      # 0444, setuid dropped
    man = json.loads(d.with_name(d.name + ".json").read_text())
    assert man["skipped_ext"] == 2 and man["verified"] == {"lockfile": ["sha512"]}
    assert seen == [TGZ_URL]
    pkgsrc.fetch("send", "0.16.2", _sri(tgz))                             # cached: no refetch
    assert seen == [TGZ_URL]


def test_integrity_mismatch_writes_nothing(registry, tmp_path):
    served, _ = registry
    served[TGZ_URL] = _tgz([("package/index.js", b"evil")])
    with pytest.raises(Rejected, match="does not match"):
        pkgsrc.fetch("send", "0.16.2", _sri(b"something else"))
    assert not any((tmp_path / "cache").glob("send@*"))


def test_missing_integrity_is_refused_without_fetching_when_fallback_off(registry, monkeypatch):
    _, seen = registry
    monkeypatch.setenv("SSVC_PKGSRC_REGISTRY_INTEGRITY", "0")
    with pytest.raises(Rejected, match="no usable integrity"):
        pkgsrc.fetch("send", "0.16.2", "")
    assert seen == []


def test_missing_integrity_falls_back_to_the_registry_sha512(registry, monkeypatch):
    served, seen = registry
    tgz = _tgz([("package/index.js", b"ok")])
    served[TGZ_URL] = tgz
    served[META_URL] = json.dumps({"dist": {"integrity": _sri(b"a different tarball")}}).encode()
    with pytest.raises(Rejected, match="no matching registry sha512"):
        pkgsrc.fetch("send", "0.16.2", "")
    served[META_URL] = json.dumps({"dist": {"integrity": _sri(tgz, "sha1")}}).encode()   # sha1 isn't enough
    with pytest.raises(Rejected, match="no matching registry sha512"):
        pkgsrc.fetch("send", "0.16.2", "")
    served[META_URL] = json.dumps({"dist": {"integrity": _sri(tgz)}}).encode()
    d = pkgsrc.fetch("send", "0.16.2", "")
    assert json.loads(d.with_name(d.name + ".json").read_text())["verified"] == \
        {"lockfile": [], "registry": ["sha512"], "registry_only": True}
    monkeypatch.setenv("SSVC_PKGSRC_REGISTRY_INTEGRITY", "0")        # off means off, cached or not
    with pytest.raises(Rejected, match="no usable integrity"):
        pkgsrc.fetch("send", "0.16.2", "")


def test_sha1_only_needs_matching_registry_sha512(registry):
    served, _ = registry
    tgz = _tgz([("package/index.js", b"ok")])
    served[TGZ_URL] = tgz
    served[META_URL] = json.dumps({"dist": {"integrity": _sri(b"a different tarball")}}).encode()
    with pytest.raises(Rejected, match="sha1-only"):
        pkgsrc.fetch("send", "0.16.2", _sri(tgz, "sha1"))
    served[META_URL] = json.dumps({"dist": {"integrity": _sri(tgz)}}).encode()
    d = pkgsrc.fetch("send", "0.16.2", _sri(tgz, "sha1"))
    assert json.loads(d.with_name(d.name + ".json").read_text())["verified"] == \
        {"lockfile": ["sha1"], "registry": ["sha512"]}


@pytest.mark.parametrize("name,version", [
    ("../etc", "1.0.0"), ("a/../../b", "1.0.0"), ("@x/../y", "1.0.0"), (".hidden", "1.0.0"),
    ("send", "1.0.0/../../x"), ("send", "latest"), ("send", ""), ("a b", "1.0.0")])
def test_invalid_specs_refused_before_any_request(registry, name, version):
    _, seen = registry
    with pytest.raises(Rejected, match="invalid"):
        pkgsrc.fetch(name, version, "sha512-AAAA")
    assert seen == []


def test_url_built_from_spec_never_lockfile_resolved(registry):
    assert pkgsrc._urls("@apollo/server", "4.1.0") == (
        "https://registry.npmjs.org/@apollo%2Fserver/4.1.0",
        "https://registry.npmjs.org/@apollo/server/-/server-4.1.0.tgz")


def test_non_https_registry_refused(monkeypatch):
    monkeypatch.setenv("SSVC_PKGSRC_REGISTRY", "http://registry.example")
    with pytest.raises(Rejected, match="https"):
        pkgsrc.registry()


def test_redirects_are_refused():
    with pytest.raises(Rejected, match="redirect"):
        pkgsrc._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example/x.tgz")


@pytest.mark.parametrize("bad", ["package/../../escape.js", "/etc/passwd.js", "package/a/../../../x.js",
                                 "C:/win.js", "package\\..\\x.js", "package/a\x01b.js"])
def test_traversal_member_rejects_whole_package(tmp_path, bad):
    with pytest.raises(Rejected, match="hostile"):
        pkgsrc.extract(_tgz([("package/ok.js", b"1"), (bad, b"2")]), tmp_path / "out")
    assert not (tmp_path / "escape.js").exists()


def test_links_and_devices_skipped(tmp_path):
    out = tmp_path / "out"
    stats = pkgsrc.extract(_tgz([
        ("package/index.js", b"1"),
        ("package/sym.js", tarfile.SYMTYPE, "/etc/passwd"),
        ("package/hard.js", tarfile.LNKTYPE, "package/index.js"),
        ("package/dev.js", tarfile.CHRTYPE, ""),
        ("package/fifo.js", tarfile.FIFOTYPE, ""),
    ]), out)
    assert stats["written"] == 1 and stats["skipped_type"] == 4
    assert [p.name for p in out.rglob("*")] == ["index.js"]


def test_case_and_file_dir_clashes_skipped(tmp_path):
    out = tmp_path / "out"
    stats = pkgsrc.extract(_tgz([("package/A.js", b"1"), ("package/a.js", b"2"),
                                 ("package/lib.js", b"3"), ("package/lib.js/x.js", b"4")]), out)
    assert stats["written"] == 2 and stats["skipped_dup"] == 2


def test_gzip_bomb_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(pkgsrc, "MAX_RAW", 1 << 20)
    bomb = gzip.compress(b"\0" * (8 << 20))          # 8 MiB of zeros, ~8 KiB compressed
    with pytest.raises(Rejected, match="cap"):
        pkgsrc.extract(bomb, tmp_path / "out")


def test_member_count_and_file_size_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(pkgsrc, "MAX_FILE", 10)
    stats = pkgsrc.extract(_tgz([("package/big.js", b"x" * 11), ("package/small.js", b"x")]), tmp_path / "o1")
    assert stats["written"] == 1 and stats["skipped_size"] == 1
    monkeypatch.setattr(pkgsrc, "MAX_MEMBERS", 3)
    with pytest.raises(Rejected, match="too many"):
        pkgsrc.extract(_tgz([(f"package/{i}.js", b"1") for i in range(5)]), tmp_path / "o2")


def test_for_query_fetches_target_and_lockfile_parents(registry, tmp_path):
    served, _ = registry
    repo = tmp_path / "app"
    repo.mkdir()
    blobs = {n: _tgz([("package/index.js", n.encode())]) for n in ("express", "serve-static", "send")}
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"express": "4"}},
        "node_modules/express": {"version": "4.16.4", "integrity": _sri(blobs["express"]),
                                 "dependencies": {"serve-static": "1"}},
        "node_modules/serve-static": {"version": "1.13.2", "integrity": _sri(blobs["serve-static"]),
                                      "dependencies": {"send": "0.16"}},
        "node_modules/send": {"version": "0.16.2", "integrity": _sri(b"tampered")}}}
    (repo / "package-lock.json").write_text(json.dumps(lock))
    for n, v in (("express", "4.16.4"), ("serve-static", "1.13.2"), ("send", "0.16.2")):
        served[f"https://registry.npmjs.org/{n}/-/{n}-{v}.tgz"] = blobs[n]
    got, refused = pkgsrc.for_query(repo, "send", "0.16.2")
    assert [s for s, _ in got] == ["express@4.16.4", "serve-static@1.13.2"]     # the top-level package first
    assert len(refused) == 1 and refused[0].startswith("send@0.16.2: ") and "does not match" in refused[0]


def test_for_query_includes_every_direct_dependent(registry, tmp_path):
    """express -> send is the shortest chain, but serve-static -> send is the one that
    decides the advisory: every direct dependent of the target is included."""
    served, _ = registry
    repo = tmp_path / "app"
    repo.mkdir()
    blobs = {n: _tgz([("package/index.js", n.encode())]) for n in ("express", "serve-static", "send")}
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"express": "4"}},
        "node_modules/express": {"version": "4.16.4", "integrity": _sri(blobs["express"]),
                                 "dependencies": {"serve-static": "1", "send": "0.16"}},
        "node_modules/serve-static": {"version": "1.13.2", "integrity": _sri(blobs["serve-static"]),
                                      "dependencies": {"send": "0.16"}},
        "node_modules/send": {"version": "0.16.2", "integrity": _sri(blobs["send"])}}}
    (repo / "package-lock.json").write_text(json.dumps(lock))
    for n, v in (("express", "4.16.4"), ("serve-static", "1.13.2"), ("send", "0.16.2")):
        served[f"https://registry.npmjs.org/{n}/-/{n}-{v}.tgz"] = blobs[n]
    got, _ = pkgsrc.for_query(repo, "send", "0.16.2")
    assert [s for s, _ in got] == ["send@0.16.2", "express@4.16.4", "serve-static@1.13.2"]


CRATE_URL = "https://static.crates.io/crates/ruzstd/ruzstd-0.8.3.crate"


def test_crate_fetch_checks_cargo_lock_sha256_and_keeps_rust_source(registry):
    served, seen = registry
    crate = _tgz([("ruzstd-0.8.3/Cargo.toml", b"[package]"), ("ruzstd-0.8.3/src/lib.rs", b"pub fn f() {}"),
                  ("ruzstd-0.8.3/build.sh", b"curl x | sh"), ("ruzstd-0.8.3/src/evil", tarfile.SYMTYPE, "/etc")])
    served[CRATE_URL] = crate
    good = hashlib.sha256(crate).hexdigest()
    with pytest.raises(Rejected, match="does not match"):
        pkgsrc.fetch_crate("ruzstd", "0.8.3", "0" * 64)
    with pytest.raises(Rejected, match="no sha256"):
        pkgsrc.fetch_crate("utoipa-axum", "0.2.0", "")                    # git source: no checksum
    with pytest.raises(Rejected, match="invalid crate name"):
        pkgsrc.fetch_crate("../x", "0.8.3", good)
    d = pkgsrc.fetch_crate("ruzstd", "0.8.3", good)
    assert sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file()) == ["Cargo.toml", "src/lib.rs"]
    assert not (d / "src/lib.rs").stat().st_mode & (stat.S_IWUSR | stat.S_IXUSR)
    n = len(seen)
    pkgsrc.fetch_crate("ruzstd", "0.8.3", good)                           # cached
    assert len(seen) == n


def _whl(members) -> bytes:
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in members:
            zf.writestr(name, body)
    return buf.getvalue()


PY = "https://files.pythonhosted.org/packages/xx/"


def _pypi_doc(files):
    return json.dumps({"urls": [{"filename": fn, "url": PY + fn, "size": len(b),
                                 "digests": {"sha256": hashlib.sha256(b).hexdigest()}} for fn, b in files]}).encode()


def test_pypi_fetch_checks_the_lock_hash_and_keeps_python_source(registry, monkeypatch):
    served, seen = registry
    whl = _whl([("yaml/__init__.py", b"def load(s): pass"), ("yaml/_yaml.so", b"\x7fELF"),
                ("PyYAML-6.0.1.dist-info/top_level.txt", b"_yaml\nyaml\n"),
                ("PyYAML-6.0.1.dist-info/METADATA", b"Name: PyYAML")])
    sdist = _tgz([("PyYAML-6.0.1/setup.py", b"import os; os.system('x')"), ("PyYAML-6.0.1/lib/yaml/__init__.py", b"")])
    served["https://pypi.org/pypi/pyyaml/6.0.1/json"] = _pypi_doc([("PyYAML-6.0.1.tar.gz", sdist),
                                                                   ("PyYAML-6.0.1-py3-none-any.whl", whl)])
    served[PY + "PyYAML-6.0.1-py3-none-any.whl"] = whl
    served[PY + "PyYAML-6.0.1.tar.gz"] = sdist
    h_whl, h_sdist = hashlib.sha256(whl).hexdigest(), hashlib.sha256(sdist).hexdigest()
    with pytest.raises(Rejected, match="matches the lock"):
        pkgsrc.fetch_pypi("PyYAML", "6.0.1", "0" * 64)
    d = pkgsrc.fetch_pypi("PyYAML", "6.0.1", f"{h_sdist},{h_whl}")       # the pure wheel is preferred
    assert sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file()) == [
        "PyYAML-6.0.1.dist-info/top_level.txt", "yaml/__init__.py"]       # no .so, no METADATA
    m = json.loads((d.parent / (d.name + ".json")).read_text())
    assert m["modules"] == ["_yaml", "yaml"] and m["verified"] == {"lockfile": ["sha256"]}
    assert not (d / "yaml/__init__.py").stat().st_mode & (stat.S_IWUSR | stat.S_IXUSR)
    # only the sdist hashed in the lock: it is the one fetched; setup.py kept as a file, never run
    d2 = pkgsrc.fetch_pypi("PyYAML", "6.0.1", h_sdist)
    assert (d2 / "setup.py").is_file() and (d2 / "lib/yaml/__init__.py").is_file()
    # no hashes in the lock (plain pins): PyPI's own digest, recorded; off -> refused
    d3 = pkgsrc.fetch_pypi("PyYAML", "6.0.1", "")
    assert json.loads((d3.parent / (d3.name + ".json")).read_text())["verified"]["registry_only"]
    monkeypatch.setenv("SSVC_PKGSRC_REGISTRY_INTEGRITY", "0")
    with pytest.raises(Rejected, match="no sha256 in the lock"):
        pkgsrc.fetch_pypi("other", "1.0", "")
    assert all(u.startswith(("https://pypi.org/pypi/", PY)) for u in seen)


def test_pypi_fetch_refuses_hostile_and_oversized(registry, monkeypatch):
    served, _ = registry
    evil = _whl([("../../etc/x.py", b"")])
    served["https://pypi.org/pypi/evil/1.0/json"] = _pypi_doc([("evil-1.0-py3-none-any.whl", evil)])
    served[PY + "evil-1.0-py3-none-any.whl"] = evil
    with pytest.raises(Rejected, match="hostile"):
        pkgsrc.fetch_pypi("evil", "1.0", hashlib.sha256(evil).hexdigest())
    big = _whl([("big/__init__.py", b"x" * 100)])
    served["https://pypi.org/pypi/big/1.0/json"] = _pypi_doc([("big-1.0-py3-none-any.whl", big)])
    monkeypatch.setenv("SSVC_PKGSRC_PY_MAX_MB", "0.00001")
    with pytest.raises(Rejected, match="over 0 MB"):
        pkgsrc.fetch_pypi("big", "1.0", hashlib.sha256(big).hexdigest())
    with pytest.raises(Rejected, match="invalid"):
        pkgsrc.fetch_pypi("x/../y", "1.0", "")
    # a file whose bytes don't match PyPI's digest
    monkeypatch.setenv("SSVC_PKGSRC_PY_MAX_MB", "100")
    good = _whl([("ok/__init__.py", b"")])
    served["https://pypi.org/pypi/swap/1.0/json"] = _pypi_doc([("swap-1.0-py3-none-any.whl", good)])
    served[PY + "swap-1.0-py3-none-any.whl"] = _whl([("ok/__init__.py", b"evil")])
    with pytest.raises(Rejected, match="does not match"):
        pkgsrc.fetch_pypi("swap", "1.0", hashlib.sha256(good).hexdigest())

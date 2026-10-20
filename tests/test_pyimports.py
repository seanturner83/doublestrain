"""pyimports: the Python import-graph tier on a tiny app, with pkgsrc faked by local dirs."""
import json
from pathlib import Path

import pytest

from doublestrain import pkgsrc
from doublestrain.judges import JudgeResult, ReachQuery, Verdict, accept
from doublestrain.judges.base import needs_corroboration
from doublestrain.judges.pyimports import PyImportsJudge, _absolute


def _dist(src: Path, name: str, version: str, files: dict, manifest: dict | None = None):
    d = src / f"{name}@{version}"
    for rel, text in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(text)
    d.mkdir(parents=True, exist_ok=True)
    Path(str(d) + ".json").write_text(json.dumps({"name": name, "file": f"{name}-{version}-py3-none-any.whl",
                                                  **(manifest or {})}))
    return d


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SSVC_PKGSRC", "1")
    monkeypatch.setenv("SSVC_JUDGE_CACHE", str(tmp_path / "cache"))
    repo = tmp_path / "app"
    (repo / "web").mkdir(parents=True)
    (repo / "web/__init__.py").write_text("")
    (repo / "web/views.py").write_text("import alpha\nfrom . import helpers\nfrom typing import TYPE_CHECKING\n"
                                       "if TYPE_CHECKING:\n    import gamma\n")
    (repo / "web/helpers.py").write_text("def f():\n    from delta.core import run\n    return run\n")
    (repo / "tests").mkdir()
    (repo / "tests/test_x.py").write_text("import epsilon\n")
    pins = ["alpha==1.0", "beta==1.0", "gamma==1.0", "delta==1.0", "epsilon==1.0", "zeta==1.0", "pyyaml==5.1"]
    (repo / "requirements.txt").write_text("\n".join(pins) + "\n")
    src = tmp_path / "pkgsrc"
    dists = {
        "alpha": {"alpha/__init__.py": "import importlib\ndef load(n):\n    return importlib.import_module(n)\n"},
        "beta": {"beta/__init__.py": ""},
        "gamma": {"gamma/__init__.py": ""},
        "delta": {"delta/__init__.py": "", "delta/core.py": "def run(): pass\n"},
        "epsilon": {"epsilon/__init__.py": ""},
        "zeta": {"zeta/__init__.py": ""},
        "pyyaml": {"lib/yaml/__init__.py": "print 'py2'\n", "lib3/yaml/__init__.py": "x = 1\n", "setup.py": ""},
    }
    for n, files in dists.items():
        man = {"file": "PyYAML-5.1.tar.gz", "modules": ["lib", "lib3"]} if n == "pyyaml" else None
        _dist(src, n, "1.0" if n != "pyyaml" else "5.1", files, man)
    monkeypatch.setattr(pkgsrc, "fetch_pypi", lambda name, version, hashes="": src / f"{name}@{version}")
    return repo


def _ask(repo, dep, version="1.0", judge=None):
    return (judge or PyImportsJudge()).judge(ReachQuery(str(repo), "pypi", dep, "CVE-2030-0001", version=version))


def test_imported_and_never_imported(app):
    j = PyImportsJudge()
    r = _ask(app, "alpha", judge=j)
    assert r.verdict == Verdict.UNSURE and "is imported" in r.rationale
    assert _ask(app, "delta", judge=j).verdict == Verdict.UNSURE        # imported inside a function, via a relative import
    for dep in ("gamma", "epsilon", "zeta"):        # TYPE_CHECKING only; tests only; nothing
        r = _ask(app, dep, judge=j)
        assert r.verdict == Verdict.NOT_REACHABLE and r.confidence == 1.0, (dep, r.rationale)
        assert accept(r) and needs_corroboration(r)
    assert _ask(app, "pyyaml", "5.1", judge=j).verdict == Verdict.NOT_REACHABLE   # lib3/ layout mapped, not imported


def test_guards(app):
    (app / "web/settings.py").write_text("INSTALLED_APPS = ['zeta.contrib']\n")
    r = _ask(app, "zeta")
    assert r.verdict == Verdict.UNSURE and "the app names zeta" in r.rationale
    # an import nothing provides could be the unmapped distribution: never a not_reachable
    (app / "web/views.py").write_text("import alpha\nimport yaml\n")
    (app / "web/settings.py").unlink()
    r = _ask(app, "pyyaml", "5.1")
    assert r.verdict == Verdict.UNSURE, r.rationale            # imported now: lib3/yaml resolves
    (app / "web/views.py").write_text("import alpha\nimport mystery\n")
    r = _ask(app, "beta")
    assert r.verdict == Verdict.NOT_REACHABLE                  # `mystery` can't be beta's


def test_unresolved_import_holds_a_possible_provider(app, tmp_path, monkeypatch):
    (app / "web/views.py").write_text("import alpha\nimport zeta_mod\n")
    src = tmp_path / "pkgsrc"
    _dist(src, "zeta-mod", "1.0", {"README": ""}, {"file": "zeta-mod-1.0.tar.gz"})       # no modules found
    (app / "requirements.txt").write_text("alpha==1.0\nzeta-mod==1.0\n")
    r = _ask(app, "zeta-mod")
    assert r.verdict == Verdict.UNSURE and ("couldn't map" in r.rationale or "no analysed distribution" in r.rationale)


def test_computed_import_in_an_imported_distribution(app):
    # alpha (imported) loads modules by computed name and declares beta: beta can't be cleared
    (app / "uv.lock").write_text('''
[[package]]
name = "app"
version = "0"
source = { virtual = "." }
dependencies = [{ name = "alpha" }, { name = "zeta" }]
[[package]]
name = "alpha"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "beta" }]
[[package]]
name = "beta"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "zeta"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
''')
    r = _ask(app, "beta")
    assert r.verdict == Verdict.UNSURE and "computed import" in r.rationale and "alpha@1.0 -> beta@1.0" in r.rationale
    assert _ask(app, "zeta").verdict == Verdict.NOT_REACHABLE


def test_relative_imports():
    assert _absolute("pkg.sub.mod", Path("mod.py"), "x", 1) == "pkg.sub.x"
    assert _absolute("pkg.sub", Path("__init__.py"), "x", 1) == "pkg.sub.x"
    assert _absolute("pkg.sub.mod", Path("mod.py"), "y", 2) == "pkg.y"
    assert _absolute("top", Path("top.py"), "x", 3) == ""


def test_held_on_pip_and_paired_with_an_endpoint(tmp_path):
    from doublestrain.judges import CascadeJudge
    from doublestrain.judges.usage import nr_held

    class Fixed:
        def __init__(self, r):
            self.r, self.name = r, r.source

        def judge(self, q):
            return self.r
    q = ReachQuery(str(tmp_path), "pypi", "x", "CVE-1")
    py = Fixed(JudgeResult(Verdict.NOT_REACHABLE, 1.0, "pyimports"))
    ws = Fixed(JudgeResult(Verdict.NOT_REACHABLE, 0.9, "workstation", model="qwen/qwen3.8-27b"))
    r = CascadeJudge([py, ws]).judge(q)
    assert accept(r) and r.rationale.startswith("corroborates")
    assert nr_held("pypi", "endpoint") and nr_held("pypi", "pyimports")      # still held until measured


def test_split_speaks_python():
    from doublestrain.judges import CachedJudge
    from doublestrain.judges.split import SplitJudge, spec_system
    system, sid = spec_system("pypi")
    assert "third-party Python distribution's" in system and "weights_only" in system and sid != spec_system("npm")[1]
    j = CachedJudge(SplitJudge("local"), cache_dir="/nonexistent")
    q = ReachQuery("/a", "pypi", "pyyaml", "CVE-1")
    assert j._path(q).name.startswith(q.key() + "-")               # Python answers keyed on their prompts


def test_claude_reads_python_source(app, monkeypatch):
    from doublestrain.judges import CachedJudge
    from doublestrain.judges import claude_code as cc
    j = cc.ClaudeCodeJudge(pkgsrc=True)
    q = ReachQuery(str(app), "pypi", "PyYAML", "CVE-1", version="5.1")
    specs = [s for s, _ in j._sources(q)[0]]
    assert specs and specs[0] == "pyyaml@5.1"
    assert j.query_salt(q).startswith("-py") and j.query_salt(ReachQuery("/a", "npm", "x", "CVE-1")) == ""
    assert "sha256-verified" in cc.PKGSRC_PROMPT_PY and "JS/TS/JSON only" in cc.PKGSRC_PROMPT
    assert cc._in_target(["pyyaml@5.1/lib3/yaml/loader.py:3"], "PyYAML", "pypi")
    assert cc._in_target(["@scope/pkg@1.0/index.js:1"], "@scope/pkg")
    assert CachedJudge(j, cache_dir="/nonexistent")._path(q).name.endswith(j.query_salt(q) + ".json")

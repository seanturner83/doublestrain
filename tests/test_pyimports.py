"""pyimports: the Python import-graph tier on a tiny app, with pkgsrc faked by local dirs."""
import json
import shutil
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
        "alpha": {"alpha/__init__.py": "def load(n):\n    return n\n"},
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
    monkeypatch.setattr(pkgsrc, "pypi_requires", lambda name, version: REQUIRES.get(name))
    REQUIRES.clear()
    return repo


REQUIRES: dict[str, list[str]] = {}        # fake PyPI requires_dist by name; missing = unknown


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


LOADER = "import importlib\ndef load(n):\n    return importlib.import_module(n)\n"


def test_computed_import_in_an_imported_distribution(app):
    # alpha (imported) loads modules by computed name and declares beta: beta can't be cleared
    (app.parent / "pkgsrc/alpha@1.0/alpha/__init__.py").write_text(LOADER)
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


def test_optional_importer_note_and_string_named_modules(app):
    from doublestrain.judges.pyimports import importers_note
    # the app loads `md.ext` by name (a markdown-style extension string); md's ext.py names
    # `md.hl`, which imports pygments: a route the lock doesn't show (md doesn't require it)
    src = app.parent / "pkgsrc"
    _dist(src, "md", "1.0", {"md/__init__.py": "", "md/ext.py": "EXTS = ['md.hl']\n",
                             "md/hl.py": "try:\n    import pygments\nexcept ImportError:\n    pygments = None\n"})
    _dist(src, "pygments", "1.0", {"pygments/__init__.py": ""})
    (app / "web/views.py").write_text("import alpha\nimport md\nHTML = md.render(x, extensions=['md.ext'])\n")
    (app / "requirements.txt").write_text("alpha==1.0\nmd==1.0\npygments==1.0\n")
    assert _ask(app, "pygments").verdict == Verdict.UNSURE          # reached through the string-named modules
    note = importers_note(str(app), "pypi", "pygments", "1.0")
    assert "md@1.0 md/hl.py:2" in note and "the app names it in web/views.py" in note
    assert importers_note(str(app), "pypi", "alpha", "1.0") == ""   # only the app imports it
    from doublestrain.judges import CachedJudge
    from doublestrain.judges.split import SplitJudge
    from doublestrain.judges.usage import usage_summary
    assert "WHO IMPORTS pygments@1.0" in usage_summary(str(app), "pypi", "pygments", version="1.0").text
    j = CachedJudge(SplitJudge("local"), cache_dir="/nonexistent")
    q = lambda d: ReachQuery(str(app), "pypi", d, "CVE-1", version="1.0")     # noqa: E731
    assert "-i" in j._path(q("pygments")).name and "-i" not in j._path(q("alpha")).name   # only that row re-keys
    from doublestrain.judges import claude_code as cc
    specs = [s for s, _ in cc.ClaudeCodeJudge(pkgsrc=True)._sources(q("pygments"))[0]]
    assert specs[:2] == ["pygments@1.0", "md@1.0"]                  # claude reads the importer's source too


def test_stale_lock_pins_are_installed(tmp_path):
    from doublestrain import pylock
    (tmp_path / "uv.lock").write_text('''
[[package]]
name = "app"
version = "0"
source = { virtual = "." }
dependencies = [{ name = "a" }]
[[package]]
name = "a"
version = "1"
source = { registry = "https://pypi.org/simple" }
''')
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["a==2", "md-ext==10.1", "loose>=1"]\n')
    (tmp_path / "requirements-dev.txt").write_text("devonly==1.0\n")
    lock = pylock.load(tmp_path)
    assert lock.stale == ("md-ext@10.1",) and "md-ext@10.1" in lock.runtime()   # widening only
    assert "a@1" in lock.pkgs and "a@2" not in lock.pkgs and "devonly@1.0" not in lock.pkgs


def test_edgeless_lock_holds_behind_a_hidden_loader(app):
    # plain pins record no edges: zeta could be one alpha requires and loads by name
    # (py4: paperless's allauth loads providers named in PAPERLESS_APPS, and requires pyjwt)
    assert _ask(app, "zeta").verdict == Verdict.NOT_REACHABLE          # no imported loader: cleared
    (app.parent / "pkgsrc/alpha@1.0/alpha/__init__.py").write_text(LOADER)
    shutil.rmtree(app.parent / "cache/pyimports-scans")                 # scans are cached per app
    r = _ask(app, "zeta")                                               # alpha's requirements unknown
    assert r.verdict == Verdict.UNSURE and "is unknown" in r.rationale and "alpha@1.0" in r.rationale
    # PyPI metadata gives the edges: alpha requires zeta only through an extra -> held as a route
    REQUIRES.update({n: [] for n in ("beta", "gamma", "delta", "epsilon", "zeta", "pyyaml")})
    REQUIRES["alpha"] = ['zeta>=1; extra == "all"']
    r = _ask(app, "zeta")
    assert r.verdict == Verdict.UNSURE and "alpha@1.0 -> zeta@1.0 (computed import" in r.rationale
    REQUIRES["alpha"] = ["beta"]                                        # alpha can't reach zeta
    assert _ask(app, "zeta").verdict == Verdict.NOT_REACHABLE
    r = _ask(app, "beta")
    assert r.verdict == Verdict.UNSURE and "alpha@1.0 -> beta@1.0" in r.rationale


def test_callers_note_follows_one_hop_through_installed_code(app):
    # py4: django-auditlog (imported) stores X-Forwarded-For in a GenericIPAddressField, whose
    # get_prep_value calls clean_ipv6_address; the app itself never names either
    from doublestrain.judges import CachedJudge
    from doublestrain.judges import claude_code as cc
    from doublestrain.judges.pycallers import callers_note
    from doublestrain.judges.split import SplitJudge
    src = app.parent / "pkgsrc"
    _dist(src, "ipt", "1.0", {"ipt/__init__.py": "", "ipt/utils.py": "def clean_addr(v):\n    return v\n",
                              "ipt/fields.py": "from .utils import clean_addr\nclass AddrField:\n"
                                               "    def prep(self, v):\n        return clean_addr(v)\n"})
    _dist(src, "audit", "1.0", {"audit/__init__.py": "", "audit/models.py": "from ipt.fields import AddrField\n"
                                                                         "remote = AddrField()\n",
                                "audit/migrations/0001.py": "from ipt.fields import AddrField\n"})
    (app / "web/views.py").write_text("import alpha\nimport audit.models\n")
    (app / "requirements.txt").write_text("alpha==1.0\nipt==1.0\naudit==1.0\n")
    sym = ("ipt.utils.clean_addr",)
    note = callers_note(str(app), "pypi", "ipt", "1.0", sym)
    assert "WHO CALLS clean_addr" in note and "audit@1.0 audit/models.py:1 uses AddrField" in note
    assert "via ipt: ipt/fields.py:4 AddrField.prep calls clean_addr" in note and "migrations" not in note
    assert callers_note(str(app), "pypi", "ipt", "1.0", ("load",)) == ""          # generic names aren't searched
    q = lambda s: ReachQuery(str(app), "pypi", "ipt", "CVE-1", version="1.0", vuln_symbols=s)   # noqa: E731
    j = CachedJudge(SplitJudge("local"), cache_dir="/nonexistent")
    assert "-k" in j._path(q(sym)).name and "-k" not in j._path(q(())).name
    specs = [s for s, _ in cc.ClaudeCodeJudge(pkgsrc=True)._sources(q(sym))[0]]
    assert specs[:2] == ["ipt@1.0", "audit@1.0"]                       # claude reads the caller's source too


def test_callers_note_names_the_route_when_the_app_uses_the_wrapping_class(app):
    # py5 healthchecks: the app's own model has a GenericIPAddressField (a name the advisory lists,
    # for the forms field), and django's model field calls clean_ipv6_address; app-only uses
    # used to suppress the note, so the judges never saw the route
    from doublestrain.judges.pycallers import callers_note
    src = app.parent / "pkgsrc"
    _dist(src, "ipt", "1.0", {"ipt/__init__.py": "", "ipt/utils.py": "def clean_addr(v):\n    return v\n",
                              "ipt/fields.py": "from .utils import clean_addr\nclass AddrField:\n"
                                               "    def prep(self, v):\n        return clean_addr(v)\n"})
    (app / "web/views.py").write_text("import alpha\nfrom ipt.fields import AddrField\nremote = AddrField()\n")
    (app / "requirements.txt").write_text("alpha==1.0\nipt==1.0\n")
    note = callers_note(str(app), "pypi", "ipt", "1.0", ("ipt.utils.clean_addr", "ipt.forms.AddrField"))
    assert "app web/views.py:2 uses AddrField  (via ipt: ipt/fields.py:4 AddrField.prep calls clean_addr)" in note
    assert "A 'via' line" in note and "A distribution here" not in note
    assert callers_note(str(app), "pypi", "ipt", "1.0", ("ipt.utils.clean_addr",)) != ""


def test_dependents_note_lists_a_library_the_app_hands_data_to(app):
    # py6 InvenTree: part images are django-stdimage fields; stdimage opens and re-saves them through
    # PIL.Image, so a TGA upload reaches Pillow's encoder although the app never saves a TGA
    from doublestrain.judges import CachedJudge
    from doublestrain.judges import claude_code as cc
    from doublestrain.judges.pyimports import dependents_note
    from doublestrain.judges.split import SplitJudge
    src = app.parent / "pkgsrc"
    _dist(src, "pil", "1.0", {"PIL/__init__.py": "", "PIL/Image.py": "def open(f):\n    return f\n"})
    _dist(src, "stdimg", "1.0", {"stdimg/__init__.py": "", "stdimg/models.py":
                                 "from PIL import Image\nclass Field:\n    def render(self, f):\n"
                                 "        with Image.open(f) as img:\n            img.save(f)\n",
                                 "stdimg/tests/test_m.py": "from PIL import Image\nImage.open('x')\n"})
    (app / "web/models.py").write_text("from stdimg.models import Field\npic = Field()\n")
    (app / "web/views.py").write_text("import alpha\nfrom . import models\n")
    (app / "requirements.txt").write_text("alpha==1.0\npil==1.0\nstdimg==1.0\n")
    note = dependents_note(str(app), "pypi", "pil", "1.0", ("ImagingTgaRleEncode",))
    assert "LIBRARIES THE APP USES THAT CALL pil" in note
    assert "stdimg@1.0 <- the app imports it (web/models.py:1)" in note
    assert "stdimg/models.py:4  with Image.open(f) as img:" in note and "tests" not in note
    assert "stdimg/models.py:5  img.save(f)" in note                   # the object Image.open returned
    assert dependents_note(str(app), "pypi", "alpha", "1.0") == ""          # nothing the app uses imports alpha
    q = lambda d: ReachQuery(str(app), "pypi", d, "CVE-1", version="1.0")   # noqa: E731
    j = CachedJudge(SplitJudge("local"), cache_dir="/nonexistent")
    assert "-d" in j._path(q("pil")).name and "-d" not in j._path(q("alpha")).name
    specs = [s for s, _ in cc.ClaudeCodeJudge(pkgsrc=True)._sources(q("pil"))[0]]
    assert specs[:2] == ["pil@1.0", "stdimg@1.0"]                       # claude reads the library's source too

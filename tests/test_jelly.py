"""The jelly tier: its guard rules on a fake scan, the app-file signals, the cascade's
mutual second read, and (when Jelly is installed) one real run on a tiny app."""
import json
import shutil
from pathlib import Path

import pytest

from ssvc_triage import pkgsrc
from ssvc_triage.judges import CascadeJudge, JellyJudge, JudgeResult, ReachQuery, Verdict, accept
from ssvc_triage.judges import jelly
from ssvc_triage.judges.base import needs_corroboration

QWEN = "qwen/qwen3.8-27b"


def _lock(repo: Path, pkgs: dict, deps: dict):
    """package-lock v2: pkgs = {path: (version, {dep: range}, dev)}."""
    packages = {"": {"name": "app", "version": "1.0.0", "dependencies": deps}}
    for path, (ver, d, dev) in pkgs.items():
        packages[path] = {"version": ver, "dependencies": d, "integrity": "sha512-x", **({"dev": True} if dev else {})}
    (repo / "package-lock.json").write_text(json.dumps({"lockfileVersion": 2, "packages": packages}))
    (repo / "package.json").write_text(json.dumps({"name": "app", "version": "1.0.0", "dependencies": deps}))


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SSVC_PKGSRC", "1")
    monkeypatch.setattr(jelly, "_main", lambda: Path(__file__))          # "installed"
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "server.js").write_text("require('express')\n")
    _lock(repo, {
        "node_modules/express": ("4.0.0", {"qs": "^6"}, False),
        "node_modules/qs": ("6.0.0", {}, False),
        "node_modules/sequelize": ("6.0.0", {"sqlite3": "^5"}, False),
        "node_modules/sqlite3": ("5.0.0", {"tar": "^6"}, False),
        "node_modules/tar": ("6.0.0", {}, False),
        "node_modules/cli": ("1.0.0", {"minimist": "^1"}, False),
        "node_modules/minimist": ("1.2.0", {}, False),
        "node_modules/cli/node_modules/lodash": ("4.0.0", {}, False),
        "node_modules/lodash": ("4.17.21", {}, False),
        "node_modules/jest": ("29.0.0", {}, True),
    }, {"express": "^4", "sequelize": "^6", "cli": "^1", "lodash": "^4", "jest": "^29"})
    return repo


def _scan(**kw):
    base = {"reached": [["app", "1.0.0"], ["express", "4.0.0"], ["qs", "6.0.0"], ["sequelize", "6.0.0"]],
            "entries": 1, "missing": [], "opaque": [], "parse_errors": [], "dynamic_packages": {},
            "bins": {}, "mentions": {}, "dynamic": [], "commands": {}}
    return {**base, **kw}


def _ask(app, monkeypatch, dep, version="", **scan):
    j = JellyJudge()
    monkeypatch.setattr(j, "_scan", lambda repo: _scan(**scan))
    monkeypatch.setattr(j, "version", lambda: "jelly@0.13.0")
    return j.judge(ReachQuery(str(app), "npm", dep, "CVE-2030-0001", version=version))


def test_loaded_is_unsure_and_never_loaded_is_not_reachable(app, monkeypatch):
    r = _ask(app, monkeypatch, "qs", "6.0.0")
    assert r.verdict == Verdict.UNSURE and "is loaded" in r.rationale and not accept(r)
    r = _ask(app, monkeypatch, "minimist", "1.2.0")
    assert r.verdict == Verdict.NOT_REACHABLE and r.confidence == 1.0 and r.source == "jelly"
    assert accept(r) and needs_corroboration(r)                 # held for a second read
    assert any("cli@1.0.0 -> minimist@1.2.0" in e for e in r.evidence)
    assert _ask(app, monkeypatch, "jest") is None               # dev-only: not this tier's question
    assert _ask(app, monkeypatch, "nope") is None
    monkeypatch.setenv("SSVC_PKGSRC", "0")
    assert _ask(app, monkeypatch, "minimist") is None


def test_guards(app, monkeypatch):
    def why(dep, **scan):
        r = _ask(app, monkeypatch, dep, **scan)
        assert r.verdict == Verdict.UNSURE and not accept(r), r.rationale
        return r.rationale
    # sequelize loads its dialect driver by a computed name: sqlite3 and what it pulls in
    dyn = {"node_modules/sequelize": "lib/dialects/abstract/connection-manager.js:44: require(moduleName"}
    assert "computed require" in why("sqlite3", dynamic_packages=dyn)
    assert "sequelize@6.0.0 -> sqlite3@5.0.0" in why("tar", dynamic_packages=dyn)
    # ... but a loaded package with no computed require doesn't hide one
    assert _ask(app, monkeypatch, "tar").verdict == Verdict.NOT_REACHABLE
    assert "the app names cli" in why("minimist", mentions={"cli": "config/default.json"})
    assert "scripts run or preload" in why("minimist", bins={"cli": ["node_modules/cli"]}, commands={"cli": "start"})
    assert "scripts run or preload" in why("minimist", commands={"minimist": "start"})
    assert "couldn't be fetched" in why("minimist", missing=["node_modules/cli"])
    assert "size caps" in why("minimist", opaque=["node_modules/minimist"])
    assert "computed require/import in the app" in why("minimist", dynamic=["server.js:3: require(name"])
    assert "couldn't parse" in why("minimist", parse_errors=["broken.js"])


def test_a_name_implicates_the_copy_it_loads(app, monkeypatch):
    # the app's `require('lodash')` loads node_modules/lodash, not the copy under cli
    r = _ask(app, monkeypatch, "lodash", "4.0.0", mentions={"lodash": "server.js"})
    assert r.verdict == Verdict.NOT_REACHABLE
    r = _ask(app, monkeypatch, "lodash", "4.17.21", mentions={"lodash": "server.js"})
    assert r.verdict == Verdict.UNSURE


def test_computed_requires():
    hits = lambda t: jelly.computed_requires(t, "f")      # noqa: E731
    for plain in ['require("x")', "require('a/b')", "require(`lodash`)", "require(path.join(__dirname, f))",
                  "require(join(models, f))", "import(`./a/${x}`)", "require.resolve(x)",
                  "__webpack_require__(3)", r"s = 'require(\"jq\")'", "// require(foo)"]:
        assert hits(plain) == [], plain
    for computed in ["require(name)", "import(`${p}`)", 'require("a" + b)', "await import(spec)"]:
        assert hits(computed), computed


def test_names_in_strings():
    names = {"pug", "lodash", "@babel/preset-env", "jquery", "pg"}
    assert jelly._names_in("pug", names) == {"pug"}
    assert jelly._names_in("lodash/fp", names) == {"lodash"}
    assert jelly._names_in("@babel/preset-env/lib", names) == {"@babel/preset-env"}
    assert jelly._names_in("index.pug", names) == {"pug"}
    assert jelly._names_in("/js/node_modules/jquery/dist/jquery.js", names) == {"jquery"}
    assert jelly._names_in("a sentence with pg in it", names) == set()


def test_app_signals(tmp_path):
    root = tmp_path / "app"
    for rel, text in {
        "server.js": "app.set('view engine', 'pug');\nconst d = require(cfg.driver);\n",
        "views/index.ejs": "<script src='/node_modules/jquery/dist/jquery.js'></script>",
        "config/default.json": '{"db": {"client": "pg"}}',
        "reports/example.json": '{"rules": [{"id": "lodash"}]}',          # data, not configuration
        "test/a.test.js": "require('mocha-only')",
        "package.json": json.dumps({"name": "app", "dependencies": {"left-pad": "1"},
                                    "babel": {"presets": ["@babel/preset-env"]},
                                    "scripts": {"start": "pm2 start server.js", "dev": "node -r dotenv/config ."}}),
    }.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    names = {"pug", "jquery", "pg", "lodash", "mocha-only", "@babel/preset-env", "left-pad", "dotenv", "ejs"}
    sig = jelly.app_signals(root, names, ["server.js"])
    assert set(sig["mentions"]) == {"pug", "jquery", "pg", "@babel/preset-env", "ejs"}
    assert sig["mentions"]["ejs"] == "views/index.ejs"                 # a view file named for its engine
    assert sig["dynamic"] == ["server.js:2: require(cfg.driver"]
    assert sig["commands"]["pm2"] == "start" and sig["commands"]["dotenv"] == "dev"


def test_jelly_and_an_endpoint_model_are_each_others_second_read(tmp_path):
    q = ReachQuery(str(tmp_path), "npm", "minimist", "CVE-2030-0001")

    class Fixed:
        def __init__(self, r):
            self.r, self.name = r, r.source

        def fingerprint(self):
            return self.name

        def judge(self, q):
            return self.r
    jl = Fixed(JudgeResult(Verdict.NOT_REACHABLE, 1.0, "jelly", model="jelly@0.13.0"))
    ws = Fixed(JudgeResult(Verdict.NOT_REACHABLE, 0.9, "workstation", model=QWEN))
    for order in ([jl, ws], [ws, jl]):
        r = CascadeJudge(order).judge(q)
        assert accept(r) and r.rationale.startswith("corroborates")
    unsure = Fixed(JudgeResult(Verdict.UNSURE, 0.0, "workstation", model=QWEN))
    split = Fixed(JudgeResult(Verdict.NOT_REACHABLE, 0.95, "split:workstation", model=QWEN))
    r = CascadeJudge([jl, unsure, split]).judge(q)
    assert accept(r) and r.source == "split:workstation"
    assert not accept(CascadeJudge([jl, unsure]).judge(q))              # alone, it settles nothing


@pytest.mark.skipif(not jelly._main().is_file() or not shutil.which("node"), reason="Jelly not installed")
def test_real_jelly_run(tmp_path, monkeypatch):
    monkeypatch.setenv("SSVC_PKGSRC", "1")
    monkeypatch.setenv("SSVC_JUDGE_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("SSVC_JELLY_WORK", str(tmp_path / "work"))
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "server.js").write_text("const a = require('a');\n")
    (repo / "broken.js").write_text("const c = require('c');\nlet x = = 3;\n")    # Jelly drops it silently
    _lock(repo, {"node_modules/a": ("1.0.0", {}, False), "node_modules/b": ("1.0.0", {}, False),
                 "node_modules/c": ("1.0.0", {}, False)}, {"a": "1", "b": "1", "c": "1"})
    src = tmp_path / "pkgsrc"

    def fake_fetch(name, version, integrity):          # stands in for the verified tarball
        d = src / f"{name}@{version}"
        if not d.is_dir():
            d.mkdir(parents=True)
            (d / "package.json").write_text(json.dumps({"name": name, "version": version}))
            (d / "index.js").write_text("module.exports = 1;\n")
            Path(str(d) + ".json").write_text(json.dumps({"skipped_size": 0, "skipped_dup": 0}))
        return d
    monkeypatch.setattr(pkgsrc, "fetch", fake_fetch)
    j = JellyJudge()
    ask = lambda dep: j.judge(ReachQuery(str(repo), "npm", dep, "CVE-2030-0001", version="1.0.0"))  # noqa: E731
    assert ask("a").verdict == Verdict.UNSURE and "is loaded" in ask("a").rationale
    r = ask("c")                       # only required from the file Jelly couldn't parse
    assert r.verdict == Verdict.UNSURE and "the app names c" in r.rationale and "couldn't parse" in r.rationale
    assert "couldn't parse" in ask("b").rationale           # it could have required anything
    assert not list((tmp_path / "work").iterdir())          # the analysis copy is removed
    (repo / "broken.js").unlink()                           # a changed app is scanned again
    j = JellyJudge()
    assert ask("b").verdict == Verdict.NOT_REACHABLE and ask("c").verdict == Verdict.NOT_REACHABLE

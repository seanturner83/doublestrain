"""bun.lock -> package-lock.json data (`npmlock`), and the npm readers on a Bun app."""
import json

from doublestrain import inventory, npmlock, osv
from doublestrain.judges import depgraph

# A Bun workspace: the root holds dev tools, `web` holds the app. `web/qs` is web's own
# copy of qs (a different version from the hoisted one); `mocha/qs` is nested under mocha.
BUN_LOCK = """{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "devDependencies": {
        "mocha": "9.0.0",
      },
    },
    "web": {
      "name": "@app/web",
      "dependencies": {
        "express": "4.17.1",
        "qs": "6.5.0",
        "fake-alias": "npm:real-pkg@1.0.0",
        "from-git": "github:owner/repo#abc123",
      },
    },
  },
  "packages": {
    "@app/web": ["@app/web@workspace:web"],
    "express": ["express@4.17.1", "", { "dependencies": { "qs": "6.7.0" } }, "sha512-ex"],
    "qs": ["qs@6.7.0", "", {}, "sha512-qs67"],
    "@app/web/qs": ["qs@6.5.0", "", {}, "sha512-qs65"],
    "mocha": ["mocha@9.0.0", "", { "dependencies": { "qs": "6.2.0", "@scope/util": "1.0.0" } }, "sha512-mo"],
    "mocha/qs": ["qs@6.2.0", "", {}, "sha512-qs62"],
    "@scope/util": ["@scope/util@1.0.0", "https://npm.example.com/@scope/util/-/util-1.0.0.tgz", {}, "sha512-su"],
    "fake-alias": ["real-pkg@1.0.0", "", {}, "sha512-rp"],
    "from-git": ["from-git@github:owner/repo#abc123", {}, "owner-repo-abc123"],
    "fsevents": ["fsevents@2.3.3", "", { "os": "darwin" }, "sha512-fs"],
  },
}
"""


def _app(tmp_path):
    (tmp_path / "bun.lock").write_text(BUN_LOCK)
    return tmp_path


def test_loads_allows_trailing_commas_but_not_inside_strings():
    assert npmlock.loads('{"a": [1, 2,], "b": "x,}",}') == {"a": [1, 2], "b": "x,}"}
    assert npmlock.loads('{"a": "q\\\\",}') == {"a": "q\\"}


def test_segments_keep_scoped_names_whole():
    assert npmlock._segments("@s/a/b/@t/c") == ["@s/a", "b", "@t/c"]
    assert npmlock._split_spec("@s/a@1.0.0") == ("@s/a", "1.0.0")
    assert npmlock._split_spec("x@github:o/r#sha") == ("x", "github:o/r#sha")


def test_from_bun_paths_versions_and_sources(tmp_path):
    pkgs = npmlock.load(_app(tmp_path))["packages"]
    assert pkgs[""]["devDependencies"] == {"mocha": "9.0.0"}
    assert pkgs["web"]["name"] == "@app/web" and "express" in pkgs["web"]["dependencies"]
    assert pkgs["node_modules/@app/web"] == {"resolved": "web", "link": True}
    assert pkgs["web/node_modules/qs"]["version"] == "6.5.0"                  # workspace-nested
    assert pkgs["node_modules/mocha/node_modules/qs"]["version"] == "6.2.0"  # package-nested
    assert pkgs["node_modules/qs"]["resolved"] == "https://registry.npmjs.org/qs/-/qs-6.7.0.tgz"
    assert pkgs["node_modules/qs"]["integrity"] == "sha512-qs67"
    assert pkgs["node_modules/@scope/util"]["resolved"].startswith("https://npm.example.com/")
    assert pkgs["node_modules/fake-alias"]["name"] == "real-pkg"
    assert "version" not in pkgs["node_modules/from-git"]                   # never sent to OSV
    assert pkgs["node_modules/from-git"]["source"] == "github:owner/repo#abc123"


def test_from_bun_dev_is_set_like_npm(tmp_path):
    pkgs = npmlock.load(_app(tmp_path))["packages"]
    assert not pkgs["node_modules/express"].get("dev")
    assert not pkgs["node_modules/qs"].get("dev")                  # through express
    assert not pkgs["web/node_modules/qs"].get("dev")
    assert pkgs["node_modules/mocha"]["dev"] and pkgs["node_modules/mocha/node_modules/qs"]["dev"]
    assert pkgs["node_modules/@scope/util"]["dev"]
    assert not pkgs["node_modules/fsevents"].get("dev")            # reached by nothing: kept, not dev


def test_find_prefers_package_lock(tmp_path):
    _app(tmp_path)
    assert npmlock.find(tmp_path).name == "bun.lock"
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}}}))
    assert npmlock.find(tmp_path).name == "package-lock.json"
    assert npmlock.find(tmp_path / "missing") is None


def test_osv_reads_bun_lock_with_workspace_direct_deps(tmp_path):
    deps, used = osv.find_deps(_app(tmp_path))
    assert used == ["bun.lock"]
    by = {(d.name, d.version): d for d in deps}
    assert by[("express", "4.17.1")].direct and not by[("express", "4.17.1")].dev
    assert by[("qs", "6.5.0")].direct and not by[("qs", "6.7.0")].direct    # web's own copy is direct
    assert by[("mocha", "9.0.0")].direct and by[("mocha", "9.0.0")].dev
    assert by[("qs", "6.2.0")].dev and not by[("qs", "6.2.0")].direct
    assert ("real-pkg", "1.0.0") in by and not any(n == "from-git" for n, _ in by)


def test_depgraph_chains_run_through_workspaces(tmp_path):
    g = depgraph.load(_app(tmp_path), "npm")
    assert "express" in g.direct and "mocha" in g.dev_direct
    assert ["web", "node_modules/express", "node_modules/qs"] in [c[-3:] for c in depgraph.chains(g, "qs", "6.7.0")]
    assert g.nodes["node_modules/qs"]["integrity"] == "sha512-qs67"


def test_inventory_from_bun_lock(tmp_path):
    inv = inventory.load(_app(tmp_path))
    names = {(c.name, c.version) for c in inv.components.values()} if isinstance(inv.components, dict) \
        else {(c.name, c.version) for c in inv.components}
    assert ("express", "4.17.1") in names and ("qs", "6.2.0") in names
    assert inv.source.endswith("bun.lock")

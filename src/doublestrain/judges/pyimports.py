"""pyimports: which Python distributions an app can import at all.

The Python counterpart of the `jelly` tier, built on the standard library's `ast`: it
parses (never imports or runs) the app's non-test source and the verified source of
every installed runtime distribution (`pkgsrc.fetch_pypi`), and follows `import`
statements from the app through the packages. Imports inside functions and `try`
blocks count (a superset of what runs); imports under `if TYPE_CHECKING:` don't (they
never run). It answers at DISTRIBUTION level only:

- the advisory's distribution (that installed version) is imported -> `unsure`, with
  the finding in the rationale: being imported says nothing about the vulnerable
  function;
- it is never imported, and nothing below explains a load the analysis can't see ->
  not_reachable 1.0, which needs a second read (floors.toml) and, while pip is held
  (SSVC_NR_UNMEASURED), settles nothing.

Python loads code in ways an import graph doesn't show. Each of these makes the answer
`unsure`, for the distribution and every distribution on its route from the app:

- a computed import in an imported distribution (`importlib.import_module(name)`,
  `__import__`, Django's `import_string`), an entry-point plugin loader, compiled
  extension modules (`.so`: their imports are invisible), or a file that doesn't parse,
  in a distribution that declares one on the route. When the lock records no edges
  (Pipfile.lock, plain pins) the edges come from each release's PyPI `requires_dist`,
  every extra counted; a distribution whose requirements stay unknown counts as
  declaring anything. paperless's allauth loads providers named in an environment
  variable, and pyjwt (which allauth requires) was a false not_reachable on py4's labels
  before this rule;
- lazy package loaders (transformers' `_LazyModule`, a module-level `__getattr__`): the
  whole distribution is analysed instead of what is imported from it;
- the app names a route distribution or one of its modules in a string or a config file
  (`INSTALLED_APPS`, `MIDDLEWARE`, `"app.main:app"`, a `postgresql+psycopg2://` URL);
- the app names a module of an installed distribution exactly in a string or a config
  file (`markdown(extensions=["pymdownx.extra"])`): something loads it by name, so the
  module is analysed as an entry (imports followed from it);
- a command the app is run with (Dockerfile, Procfile, compose, scripts, pyproject
  scripts) is a route distribution's console script: its module is analysed as an entry;
- `.pth` files run at interpreter start: the distributions shipping them are entries;
- the app itself has a computed import or a file that doesn't parse, and the route starts
  at one of its direct dependencies;
- a route distribution's source couldn't be fetched and verified, lost files to
  pkgsrc's size caps, or its modules couldn't be mapped (an unusual sdist layout);
- the app or an imported distribution imports a top-level module that no analysed
  distribution provides (and isn't the standard library or the app's own), and a route
  distribution could be the one providing it (its declared or likely module names).
  An unresolved import is never evidence of absence: pygoat's `import yaml` against
  PyYAML 5.1's sdist (lib/ and lib3/) was a false not_reachable before this rule.

Not covered: code paths inside compiled extensions beyond the guard above, plugins
named only in environment variables or databases, and Python 2-only syntax in packages
(such files count as unparsed).
"""
from __future__ import annotations

import ast
import functools
import hashlib
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

from .. import approots, pkgsrc, pylock
from .._locks import keylock
from . import depgraph
from .base import JudgeResult, ReachQuery, Verdict
from .usage import is_test_path

logger = logging.getLogger(__name__)

GUARD = "py5"      # py5: edgeless locks get edges from PyPI metadata (py4: unknown requires hold)
SCAN_V = 5         # bump when the scan result gains fields (it is cached on disk); 5: app_imports
_SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__", ".tox", "build", "dist",
              ".mypy_cache", ".pytest_cache"}
_CONFIG_EXT = (".yaml", ".yml", ".toml", ".ini", ".cfg", ".json", ".env", ".conf")
_CMD_FILES = re.compile(r"^(Dockerfile.*|.*\.Dockerfile|Procfile|docker-compose.*\.ya?ml|compose.*\.ya?ml|Makefile|"
                        r".*\.sh|gunicorn.*\.py|supervisord.*\.conf|entrypoint.*)$", re.I)
_IMPORT_CALLS = {"import_module", "__import__", "import_string", "import_by_path", "load_object", "locate",
                 "instantiate", "get_class", "load_entry_point", "_import"}
_PLUGIN_CALLS = {"entry_points", "iter_entry_points", "get_entry_map", "load_entry_point"}
_LAZY = re.compile(rb"_LazyModule\(|LazyModule\(|lazy_loader\.attach|\blazy_import\(|^def __getattr__\(", re.M)
_DOTTED = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")
_SA_URL = re.compile(r"\b[a-z0-9_]+\+([a-z0-9_]+)://")
_MAX_FILE = 4 * 2**20


def _walk(root: Path, skip=_SKIP_DIRS):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")
                       and not Path(dirpath, d).is_symlink()]
        for fn in filenames:
            p = Path(dirpath) / fn
            if not p.is_symlink() and p.is_file():
                yield p, p.relative_to(root)


def _app_walk(root: Path):
    """The app's files: the root, then the local projects its Dockerfile installs alongside
    it (approots: Baserow's premium/ and enterprise/), with ../ paths for those."""
    return approots.walk(root, _walk)


def _modpath(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or \
        (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


class _Visitor(ast.NodeVisitor):
    """Imports (module names, relative levels), computed loads and plugin loading in one file."""

    def __init__(self):
        self.imports: list[tuple[str, int, list[str], int]] = []      # (module, level, from-names, line)
        self.computed: list[int] = []
        self.plugins = False
        self.strings: list[tuple[str, int]] = []       # dotted string constants: modules loaded by name?

    def visit_If(self, node: ast.If):
        if _is_type_checking(node.test):
            for n in node.orelse:          # the else branch does run
                self.visit(n)
            return
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for a in node.names:
            self.imports.append((a.name, 0, [], node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self.imports.append((node.module or "", node.level or 0, [a.name for a in node.names if a.name != "*"],
                             node.lineno))

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str) and len(node.value) < 200 and _DOTTED.fullmatch(node.value):
            self.strings.append((node.value, node.lineno))

    def visit_Call(self, node: ast.Call):
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        if name in _PLUGIN_CALLS:
            self.plugins = True
        if name in _IMPORT_CALLS and node.args:
            a = node.args[0]
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                mod = a.value.split(":", 1)[0]
                level = len(mod) - len(mod.lstrip("."))
                self.imports.append((mod.lstrip("."), level, [], node.lineno))
            else:
                self.computed.append(node.lineno)
        self.generic_visit(node)


def _parse(path: Path) -> _Visitor | None:
    try:
        data = path.read_bytes()
        if len(data) > _MAX_FILE:
            return None
        tree = ast.parse(data, filename=str(path))
    except (SyntaxError, ValueError, OSError, RecursionError, MemoryError):
        return None
    v = _Visitor()
    try:
        v.visit(tree)
    except RecursionError:
        return None          # deeply nested (generated) code: counted as unparsed, the safe side
    return v


class PyImportsJudge:
    name = "pyimports"

    def __init__(self):
        self._scans: dict[str, dict | None] = {}

    def fingerprint(self) -> str:
        return f"pyimports@{GUARD}@src{pkgsrc.PYSRC_V}"

    def app_code_destination(self) -> str:
        return "machine"

    def probe(self) -> tuple[bool, str]:
        if not pkgsrc.enabled():
            return False, "needs dependency source (SSVC_PKGSRC=1 / --pkgsrc)"
        return True, "Python import graph (ast; nothing imported or run)"

    # --- one scan per checkout ---------------------------------------------------
    def _scan(self, repo: str) -> dict | None:
        with keylock(("pyimports", repo)):
            if repo not in self._scans:
                self._scans[repo] = self._scan_locked(Path(repo))
            return self._scans[repo]

    def _key(self, root: Path) -> str:
        h = hashlib.sha256((self.fingerprint() + f"@scan{SCAN_V}" + str(root.resolve())).encode())
        for p, rel in sorted(_app_walk(root), key=lambda f: f[1].as_posix()):
            if p.suffix == ".py" or p.suffix in _CONFIG_EXT or _CMD_FILES.match(p.name) or p.name.endswith(".lock") \
                    or p.name.startswith("requirements") or "Dockerfile" in p.name:   # imagedeps: the groups it installs
                h.update(rel.as_posix().encode() + b"\0")
                try:
                    h.update(hashlib.sha256(p.read_bytes()).digest())
                except OSError:
                    pass
        return h.hexdigest()[:24]

    def _scan_locked(self, root: Path) -> dict | None:
        lock = pylock.load(root)
        if lock is None:
            return None
        cf = Path(os.environ.get("SSVC_JUDGE_CACHE", "~/.cache/ssvc-triage/judge")).expanduser() \
            / "pyimports-scans" / f"{self._key(root)}.json"
        if cf.is_file():
            return json.loads(cf.read_text())
        t0 = time.monotonic()
        runtime = lock.runtime()
        # module index: dotted path -> [(owner, file)]; owner = dist id or "app"
        index: dict[str, list[tuple[str, Path]]] = {}
        missing, opaque, native, pth_entries, plugins_declared, scripts = [], [], [], [], [], {}
        for pid in sorted(runtime):
            p = lock.pkgs[pid]
            try:
                src = pkgsrc.fetch_pypi(p.name, p.version, ",".join(p.hashes))
            except (pkgsrc.Rejected, OSError) as exc:
                missing.append(pid)
                logger.info("pyimports: %s not analysed: %s", pid, exc)
                continue
            try:
                man = json.loads(Path(str(src) + ".json").read_text())
            except (OSError, ValueError):
                man = {}
            if man.get("skipped_size") or man.get("skipped_dup"):
                opaque.append(pid)
            if man.get("native"):
                native.append(pid)
            base = _source_base(src, man)
            for f, rel in _walk(base, {"__pycache__"}):
                if f.suffix == ".py" and not any(part.endswith((".dist-info", ".egg-info")) for part in rel.parts):
                    index.setdefault(_modpath(rel), []).append((pid, f))
            for pth in man.get("pth") or []:
                for ln in (src / pth).read_text(errors="replace").splitlines():
                    if ln.startswith("import "):
                        pth_entries += [m.strip() for m in ln[7:].split(";")[0].split(",")]
            for ep in src.glob("*.dist-info/entry_points.txt"):
                group = ""
                for ln in ep.read_text(errors="replace").splitlines():
                    ln = ln.strip()
                    if ln.startswith("[") and ln.endswith("]"):
                        group = ln[1:-1]
                    elif "=" in ln and group == "console_scripts":
                        k, v = (x.strip() for x in ln.split("=", 1))
                        scripts[k] = v.split(":", 1)[0]
                    elif "=" in ln and group:
                        plugins_declared.append(pid)
        app_files = [(f, rel) for f, rel in _app_walk(root) if f.suffix == ".py" and not is_test_path(rel)]
        roots = [r for top in (root, *approots.extra_roots(root)) for r in (top, top / "src") if r.is_dir()]
        roots += sorted({f.parent for f, rel in app_files if f.name == "manage.py"} - set(roots))
        for f, _rel in app_files:
            for r in roots:
                if f.is_relative_to(r):
                    index.setdefault(_modpath(f.relative_to(r)), []).append(("app", f))
        modpath_of = {g: mod for mod, files in index.items() for _o, g in files}   # last root wins (src/)
        names = {lock.pkgs[i].name for i in runtime}
        sig = app_signals(root, names, index)
        entries = [("app", f) for f, _ in app_files]
        for mod in pth_entries + [scripts[c] for c in sig["commands"] if c in scripts] + sig["modules_run"] \
                + sorted(sig["string_modules"]):
            entries += _resolve(index, mod)
        reached, files_done, computed, plugin_users, unparsed, lazy = set(), set(), {}, set(), {}, set()
        unresolved: dict[str, str] = {}
        importers: dict[str, list[list]] = {}     # dist -> [[importing dist, module file, line]]
        app_imports: dict[str, list] = {}         # dist -> [app file, line]: the app's own code imports it
        todo = list(entries)
        while todo:
            owner, f = todo.pop()
            if f in files_done:
                continue
            files_done.add(f)
            if owner != "app":
                reached.add(owner)
            v = _parse(f)
            if v is None:
                unparsed.setdefault(owner, str(f))
                continue
            if v.computed:
                computed.setdefault(owner, f"{f.name}:{v.computed[0]}")
            if v.plugins:
                plugin_users.add(owner)
            if owner != "app" and owner not in lazy and f.name == "__init__.py":
                try:
                    if _LAZY.search(f.read_bytes()):
                        lazy.add(owner)           # analyse the whole distribution
                        todo += [(o, g) for files in index.values() for o, g in files if o == owner]
                except OSError:
                    pass
            pkg = modpath_of.get(f, "")
            # a dotted string that names a module exactly is loaded by name somewhere (markdown
            # extensions, Django settings, plugin registries): followed like an import
            named_imports = [(s, 0, [], ln) for s, ln in v.strings if s in index]
            for mod, level, from_names, line in v.imports + named_imports:
                target = _absolute(pkg, f, mod, level)
                if not target:
                    continue
                found = False
                for cand in [target] + [f"{target}.{n}" for n in from_names]:
                    hits = _resolve(index, cand)
                    found |= bool(hits)
                    for o, _g in hits:
                        if owner == "app" and o != "app":
                            rel_app = os.path.relpath(f, root)
                            # prefer evidence outside migrations: a schema file says less about use
                            if o not in app_imports or ("migrations" in app_imports[o][0] and "migrations" not in rel_app):
                                app_imports[o] = [rel_app, line]
                        if owner != "app" and o not in ("app", owner):
                            seen = importers.setdefault(o, [])
                            where = [owner, _relmod(pkg, f), line]
                            if len(seen) < 8 and not any(s[0] == owner for s in seen):
                                seen.append(where)
                    todo += [t for t in hits if t[1] not in files_done]
                top = target.split(".")[0]
                if not found and level == 0 and top not in sys.stdlib_module_names and top != "__future__":
                    unresolved.setdefault(top, f"{f.name} ({'app' if owner == 'app' else owner})")
        dist_modules: dict[str, set[str]] = {}
        for mod, files in index.items():
            for o, _f in files:
                if o != "app":
                    dist_modules.setdefault(o, set()).add(mod.split(".")[0])
        result = {"reached": sorted(reached), "unresolved": unresolved,
                  "dist_modules": {k: sorted(v) for k, v in dist_modules.items()}, "entries": len(entries), "files": len(files_done),
                  "missing": missing, "opaque": opaque, "native": native, "lazy": sorted(lazy),
                  "computed": computed, "plugin_users": sorted(plugin_users), "importers": importers,
                  "app_imports": app_imports,
                  "plugins_declared": sorted(set(plugins_declared)),
                  "unparsed": {k: Path(v).name for k, v in unparsed.items()},
                  "app_computed": computed.get("app", ""), "app_unparsed": unparsed.get("app", ""),
                  "mentions": sig["mentions"], "seconds": round(time.monotonic() - t0, 1)}
        cf.parent.mkdir(parents=True, exist_ok=True)
        tmp = cf.with_name(cf.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(result))
        os.replace(tmp, cf)
        return result

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        if q.ecosystem != "pypi" or not pkgsrc.enabled():
            return None
        root = Path(q.repo_path)
        g = depgraph.load(root, "pypi")
        if g is None:
            return None
        g = depgraph.with_pypi_metadata(g)
        dep = pylock.normalize(q.dependency)
        targets = {p for p, n in g.nodes.items() if n["name"] == dep and (not q.version or n["version"] == q.version)
                   and not n["dev"]}
        if not targets:
            return None
        t0 = time.monotonic()
        scan = self._scan(q.repo_path)
        if scan is None:
            return None

        def res(verdict, conf, why, evidence=()):
            return JudgeResult(verdict, conf, self.name, rationale=why[:1200], evidence=list(evidence)[:8],
                               latency_s=round(time.monotonic() - t0, 3), cost_usd=0.0, model=f"pyimports@{GUARD}")

        reached = set(scan["reached"])
        label = f"{dep}@{q.version}" if q.version else dep
        if targets & reached:
            return res(Verdict.UNSURE, 0.0, f"pyimports: {label} is imported from the app's code; distribution level "
                                            "only, so nothing about the vulnerable function")
        route = _route(g, targets)
        named = lambda p: f"{g.nodes[p]['name']}@{g.nodes[p]['version']}"     # noqa: E731
        why = []
        if bad := route & set(scan["missing"]):
            why.append("not analysed (source couldn't be fetched and verified): " + ", ".join(sorted(map(named, bad))[:4]))
        if bad := route & set(scan["opaque"]):
            why.append("files left out by size caps in " + ", ".join(sorted(map(named, bad))[:4]))
        hidden = {p: (scan["computed"].get(p) and f"computed import at {scan['computed'][p]}")
                  or (p in scan["unparsed"] and f"a file that doesn't parse ({scan['unparsed'][p]})")
                  or (p in scan["native"] and "compiled extension modules")
                  or (p in scan["plugin_users"] and "entry-point plugin loading")
                  for p in reached}
        frontier = sorted({f"{named(par)} -> {named(c)} ({hidden[par]})" for par, cs in g.edges.items()
                           if hidden.get(par) for c in cs if c in route and c not in reached})
        if frontier:
            why.append("an imported distribution can load modules the analysis doesn't see: " + "; ".join(frontier[:3]))
        edgeless = not any(cs for par, cs in g.edges.items() if par != depgraph.ROOT)
        if loaders := sorted(f"{named(p)} ({hidden[p]})" for p in reached if hidden.get(p) and p in g.nodes
                             and (edgeless or g.nodes[p].get("requires_unknown")) and p not in route):
            why.append("what an imported distribution requires is unknown (no edges in the lock, no PyPI "
                       "metadata), so it could sit under one that loads modules the analysis doesn't see: "
                       + "; ".join(loaders[:3]))
        unreached = [p for p in route if p not in reached]
        unmapped = sorted(p for p in unreached if p not in scan["missing"] and not scan["dist_modules"].get(p))
        if unmapped:
            why.append("couldn't map the modules of " + ", ".join(map(named, unmapped[:4])))
        could = {}
        for p in unreached:
            mods = set(scan["dist_modules"].get(p) or []) | {m.split(".")[0] for m in pylock.import_names(g.nodes[p]["name"])}
            for m in mods & set(scan["unresolved"]):
                could.setdefault(p, (m, scan["unresolved"][m]))
        if could:
            why.append("an import no analysed distribution provides could be one on the route: "
                       + "; ".join(f"`{m}` in {where} -> {named(p)}" for p, (m, where) in sorted(could.items())[:3]))
        if hit := sorted({g.nodes[p]["name"] for p in unreached} & set(scan["mentions"])):
            why.append("the app names " + ", ".join(f"{n} ({scan['mentions'][n]})" for n in hit[:4]))
        if scan["plugin_users"] and (pl := sorted(set(unreached) & set(scan["plugins_declared"]))):
            why.append("an imported distribution loads entry-point plugins, and " + ", ".join(map(named, pl[:3]))
                       + " declares entry points")
        tops = route & set(g.edges.get(depgraph.ROOT, ()))
        if tops and (scan["app_computed"] or scan["app_unparsed"]):
            src = (f"a computed import in the app ({scan['app_computed']})" if scan["app_computed"]
                   else f"an app file that doesn't parse ({Path(scan['app_unparsed']).name})")
            why.append(f"{src}, and the route starts at direct dependency " + ", ".join(sorted(map(named, tops))[:3]))
        if why:
            return res(Verdict.UNSURE, 0.0, f"pyimports: {label} is never imported, but " + "; ".join(why)
                       + ": not_reachable not claimed")
        chain = depgraph.chains(g, dep, q.version, limit=2)
        return res(Verdict.NOT_REACHABLE, 1.0,
                   f"pyimports ({scan['entries']} entry modules, {scan['files']} files parsed, tests excluded): no module "
                   f"of {label} is imported, and no computed import, plugin loader, compiled extension, app string or "
                   f"run command leads to it or the {len(route) - len(targets)} distributions on its route",
                   evidence=[depgraph.describe(g, c) for c in chain])


def _relmod(modpath: str, f: Path) -> str:
    """A distribution file as a package path (`pymdownx/highlight.py`), never a local cache path."""
    if not modpath:
        return f.name
    return modpath.replace(".", "/") + ("/__init__.py" if f.name == "__init__.py" else ".py")


_NOTE_JUDGE: PyImportsJudge | None = None


def _importers(repo_path: str, dependency: str, version: str):
    """[(sort key, importer id, module file, line, declared parent?, why it's near the app)]
    for the distributions whose verified source imports the package, as the scan followed
    them; [] when pkgsrc is off or the package isn't imported."""
    global _NOTE_JUDGE
    if not pkgsrc.enabled():
        return []
    root = Path(repo_path).expanduser()
    g = depgraph.load(root, "pypi")
    if g is None:
        return []
    dep = pylock.normalize(dependency)
    targets = {p for p, n in g.nodes.items() if n["name"] == dep and (not version or n["version"] == version)}
    if not targets:
        return []
    if _NOTE_JUDGE is None:
        _NOTE_JUDGE = PyImportsJudge()
    scan = _NOTE_JUDGE._scan(str(root))
    if not scan:
        return []
    rows = []
    has_edges = any(cs for par, cs in g.edges.items() if par != depgraph.ROOT)
    below: dict[str, set[str]] = {}

    def requires(o: str, tgt: str) -> bool:      # tgt anywhere under o in the lock graph: a chain shows it
        if o not in below:
            seen, todo = set(), [o]
            while todo:
                for c in g.edges.get(todo.pop(), ()):
                    if c not in seen:
                        seen.add(c)
                        todo.append(c)
            below[o] = seen
        return tgt in below[o]
    for tgt in sorted(targets & set(scan["reached"])):
        for o, rel, line in scan.get("importers", {}).get(tgt) or []:
            name = g.nodes[o]["name"] if o in g.nodes else o.rsplit("@", 1)[0]
            # near the app: named in its Python code, or (in a lock with a graph) a direct dependency
            mention = scan["mentions"].get(name, "")
            near = ("the app names it in " + mention if mention.endswith(".py") else
                    "a direct dependency" if has_edges and o in g.edges.get(depgraph.ROOT, ()) else "")
            rank = 0 if near.endswith(".py") else 1 if near else 2
            declared = requires(o, tgt)
            rows.append(((rank, declared), o, rel, line, declared, near))
    return sorted(rows)


def importers_note(repo_path: str, ecosystem: str, dependency: str, version: str) -> str:
    """Which installed distributions import the package, from their verified source, when one
    of them isn't its declared parent in the lock graph. The lockfile chain names the parents
    that REQUIRE a package; a distribution can also import one it only lists under an extra,
    or in a try/except, and that route is invisible in the chain (py3: open-webui's markdown
    with pymdownx.extra highlights fenced code through pygments, which the lock shows only
    under rich; both judges answered "only via rich, never imported"). Third-party paths and
    lines only. "" when not pypi, pkgsrc is off, the package isn't imported, or every
    importer is a declared parent."""
    rows = _importers(repo_path, dependency, version) if ecosystem == "pypi" else []
    if not any(not declared and near for *_, declared, near in rows):
        return ""            # only when an undeclared importer is close to the app: the route the chains hide
    lines = []
    for _k, o, rel, line, declared, near in rows[:6]:
        tags = [x for x in ("" if declared else "doesn't require it in the lock", near) if x]
        lines.append(f"  {o} {rel}:{line}" + (f"  <- {'; '.join(tags)}" if tags else ""))
    stale = pylock.load(Path(repo_path).expanduser()).stale
    return "\n".join([f"WHO IMPORTS {pylock.normalize(dependency)}@{version or '*'} (pyimports: imports followed from "
                      "the app's code and the modules it names in strings, through the verified installed source; "
                      "distribution level, not a call path). Distributions marked \"doesn't require it in the lock\" import it "
                      "although the lock doesn't list it as their requirement (an optional extra or a guarded import), "
                      "so the dependency chains above miss that route:"] + lines
                     + ([f"  (the lock is behind the project's manifests; also installed: {', '.join(stale[:6])})"]
                        if stale else []))


_DEP_IMPORT = r"^\s*(?:from\s+({mods})(?:\.[\w.]+)?\s+import\s+(.+)|import\s+({mods})(?:\.[\w.]+)?(?:\s+as\s+(\w+))?)"
DEPENDENTS_MAX, CALLS_PER_DIST = 6, 3


@functools.lru_cache(maxsize=256)
def _dependents(repo_path: str, dependency: str, version: str, symbols: tuple = ()) -> tuple:
    """((dist id, why the app uses it, ((rank, module file, line, code), ...)), ...): distributions the
    app's own code imports, or names in its settings, whose verified source imports the package,
    with the lines where that source uses what it imported (`Image.open(f)`); () when none."""
    rows = _importers(repo_path, dependency, version)
    if not rows:
        return ()
    scan = _NOTE_JUDGE._scan(str(Path(repo_path).expanduser()))
    app_imp = scan.get("app_imports") or {}
    g = depgraph.load(Path(repo_path).expanduser(), "pypi")
    dep = pylock.normalize(dependency)
    tgt = next((p for p, n in g.nodes.items() if n["name"] == dep and (not version or n["version"] == version)), "")
    mods = "|".join(map(re.escape, (scan.get("dist_modules") or {}).get(tgt) or [dep.replace("-", "_")]))
    pat = re.compile(_DEP_IMPORT.format(mods=mods), re.M)
    out = []
    for _k, o, _rel, _line, _declared, near in rows:
        why = (f"the app imports it ({app_imp[o][0]}:{app_imp[o][1]})" if o in app_imp else
               near if near.startswith("the app names it") else "")
        if not why or len(out) >= DEPENDENTS_MAX:
            continue
        name, ver = o.rsplit("@", 1)
        p = g.nodes.get(o) or {}
        try:
            src = pkgsrc.fetch_pypi(name, ver, ",".join(p.get("hashes") or ()))
        except (pkgsrc.Rejected, OSError):
            continue
        calls, sym = [], re.compile(r"\b(" + "|".join(map(re.escape, symbols)) + r")\b") if symbols else None
        for f in sorted(src.rglob("*.py")):
            rel = f.relative_to(src)
            if is_test_path(rel) or "migrations" in rel.parts or len(calls) >= 400:
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            bound = set()
            for m in pat.finditer(text):
                if m.group(2):
                    for part in m.group(2).strip("() \\").split(","):
                        bits = part.split(" as ")
                        if bits[-1].strip().isidentifier():
                            bound.add(bits[-1].strip())
                elif m.group(3):
                    bound.add(m.group(4) or m.group(3))
            if not bound:
                continue
            # an object a package call returned is the package's too: `with Image.open(f) as img:`
            # then `img.save(...)` (py6: stdimage re-saves each upload; the open alone hid it)
            names = "|".join(map(re.escape, sorted(bound)))
            for m in re.finditer(r"(?:\bwith\s+(?:" + names + r")[\w.]*\(.*?\)\s+as\s+(\w+)|^\s*(\w+)\s*=\s*(?:"
                                 + names + r")[\w.]*\()", text, re.M):
                if (v := m.group(1) or m.group(2)) and v.isidentifier() and v not in ("self", "cls"):
                    bound.add(v)
            use = re.compile(r"\b(" + "|".join(map(re.escape, sorted(bound))) + r")\s*[.(]")
            call = re.compile(r"\b(" + "|".join(map(re.escape, sorted(bound))) + r")(?:\.\w+)*\s*\(")
            for n, ln in enumerate(text.splitlines(), 1):
                t = ln.strip()
                if use.search(ln) and not t.startswith(("import ", "from ", "#", "@")):
                    # the advisory's names first, then calls into the package, then other uses
                    rank = 0 if sym and sym.search(ln) else 1 if call.search(ln) else 2
                    calls.append((rank, str(rel), n, t[:90]))
        if calls:
            out.append((o, why, tuple(sorted(calls)[:CALLS_PER_DIST])))
    return tuple(out)


def dependents_note(repo_path: str, ecosystem: str, dependency: str, version: str, vuln_symbols=()) -> str:
    """Libraries the app uses whose own code calls the vulnerable package (py6: InvenTree's
    part images are django-stdimage fields; stdimage re-saves each rendition through
    PIL.Image in the source format, so a TGA upload reaches Pillow's TGA RLE encoder; opus
    checked every save in the app and never opened stdimage). The app hands its data to
    these, so their calls run on it. "" when not pypi, pkgsrc is off, or none."""
    if ecosystem != "pypi" or not pkgsrc.enabled():
        return ""
    from .pycallers import symbols
    rows = _dependents(str(Path(repo_path).expanduser()), dependency, version, tuple(symbols(vuln_symbols)))
    if not rows:
        return ""
    lines = [f"LIBRARIES THE APP USES THAT CALL {pylock.normalize(dependency)} (pyimports: the app imports them or "
             "names them in its settings, and their verified source calls the package; read these call sites "
             "before deciding not_reachable: data the app hands a library reaches the package through it, "
             "even where the app's own code never calls the package):"]
    for o, why, calls in rows:
        lines.append(f"  {o} <- {why}")
        lines += [f"    {rel}:{n}  {code}" for _rank, rel, n, code in calls]
    return "\n".join(lines)


def dependent_dists(repo_path: str, dependency: str, version: str, vuln_symbols=(), limit: int = 4) -> list[str]:
    """name@version of the first libraries dependents_note names (claude reads their source):
    those whose calls name the advisory's functions first."""
    if not pkgsrc.enabled():
        return []
    from .pycallers import symbols
    rows = _dependents(str(Path(repo_path).expanduser()), dependency, version, tuple(symbols(vuln_symbols)))
    return [o for o, *_ in sorted(rows, key=lambda r: min(c[0] for c in r[2]))][:limit]


def optional_importers(repo_path: str, dependency: str, version: str, limit: int = 2) -> list[tuple[str, str]]:
    """[(name, version)] of the importers the note leads with: not a declared parent, and the
    app names them or depends on them directly. The claude tier reads their source too."""
    out = []
    for _k, o, *_rest, declared, near in _importers(repo_path, dependency, version):
        if not declared and near and len(out) < limit:
            out.append(tuple(o.rsplit("@", 1)))
    return out


def _source_base(src: Path, man: dict) -> Path:
    """Where a distribution's import paths start: the wheel root; an sdist's src/ or the
    directory holding its top-level modules."""
    if str(man.get("file", "")).endswith(".whl"):
        return src
    if (src / "src").is_dir():
        return src / "src"
    want = set(pylock.import_names(man.get("name", ""))) | set(man.get("modules") or [])
    cands = sorted({init.parent.parent for init in src.glob("**/__init__.py")
                    if init.parent.name in {w.split(".")[0] for w in want} and len(init.relative_to(src).parts) <= 4},
                   key=lambda d: ("3" not in d.name, len(d.relative_to(src).parts)))
    return cands[0] if cands else src          # PyYAML 5.1: lib3/ (Python 3) before lib/


def _resolve(index, mod: str) -> list[tuple[str, Path]]:
    """Files an `import mod` runs: each parent package's __init__ and the module itself
    (or, for `from a.b import name`, the longest existing prefix)."""
    parts = mod.split(".")
    out = []
    for i in range(1, len(parts) + 1):
        out += index.get(".".join(parts[:i]), [])
    return out


def _absolute(pkg_mod: str, f: Path, mod: str, level: int) -> str:
    """The absolute module a (possibly relative) import names, from the importing file's
    own module path; "" when a relative import climbs above the top."""
    if level == 0:
        return mod
    package = pkg_mod.split(".") if f.name == "__init__.py" else pkg_mod.split(".")[:-1]
    if level - 1 > len(package) or not pkg_mod:
        return ""
    package = package[:len(package) - (level - 1)]
    return ".".join([*package, mod] if mod else package)


def _route(g, targets: set[str]) -> set[str]:
    parents: dict[str, set[str]] = {}
    for p, cs in g.edges.items():
        for c in cs:
            parents.setdefault(c, set()).add(p)
    seen, todo = set(targets), list(targets)
    while todo:
        for p in parents.get(todo.pop(), ()):
            if p != depgraph.ROOT and p not in seen and not g.nodes[p]["dev"]:
                seen.add(p)
                todo.append(p)
    return seen


def app_signals(root: Path, names: set[str], index) -> dict:
    """Distribution names the app's strings and config name ({name: where}), commands it
    is run with, and modules it runs with `python -m`."""
    by_module: dict[str, str] = {}
    for mod, files in index.items():
        for owner, _f in files:
            if owner != "app":
                by_module.setdefault(mod.split(".")[0], owner)
    mentions: dict[str, str] = {}
    string_modules: dict[str, str] = {}
    commands: set[str] = set()
    modules_run: list[str] = []

    def note(text: str, where: str):
        for m in re.finditer(r"""["']([A-Za-z_][\w.]*(?::\w+)?)["']""", text):
            s = m[1].split(":", 1)[0]
            top = s.split(".")[0]
            for n in {pylock.normalize(top), pylock.normalize(s)} & names:
                mentions.setdefault(n, where)
            if top in by_module and "." in s:          # a dotted module path into a distribution
                mentions.setdefault(by_module[top].rsplit("@", 1)[0], where)
                if s in index:                          # names a module exactly: something loads it by name
                    string_modules.setdefault(s, where)  # (markdown(extensions=["pymdownx.extra"]))
        if not where.endswith(".py"):                  # unquoted dotted paths in YAML/INI/TOML
            for m in re.finditer(r"(?<![\w/.-])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)", text):
                top = m[1].split(".")[0]
                if top in by_module:
                    mentions.setdefault(by_module[top].rsplit("@", 1)[0], where)
                    if m[1] in index:
                        string_modules.setdefault(m[1], where)
        for m in _SA_URL.finditer(text):
            for n in {pylock.normalize(m[1])} & names:
                mentions.setdefault(n, where)
    for p, rel in _app_walk(root):
        if is_test_path(rel) or p.stat().st_size > _MAX_FILE:
            continue
        r = rel.as_posix()
        if p.suffix == ".py" or p.suffix in _CONFIG_EXT or p.name.startswith(".env"):
            if p.name in ("uv.lock", "poetry.lock", "Pipfile.lock") or p.name.startswith("requirements"):
                continue
            if p.name == "pyproject.toml":
                continue                                 # dependency lists name everything
            try:
                note(p.read_text(errors="replace"), r)
            except OSError:
                pass
        if _CMD_FILES.match(p.name) or p.name == "pyproject.toml":
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            for tok in re.split(r"""[\s"'\[\],;&|()=]+""", text):
                if re.fullmatch(r"[A-Za-z][\w.-]*", tok):
                    commands.add(tok)
            modules_run += re.findall(r"python[0-9.]*\s+-m\s+([A-Za-z_][\w.]*)", text)
    return {"mentions": mentions, "commands": sorted(commands), "modules_run": modules_run,
            "string_modules": string_modules}

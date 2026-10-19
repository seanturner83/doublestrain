"""Jelly as a judge tier: which npm packages an app can load at all.

Jelly (cs-au-dk/jelly, BSD-3-Clause) is a static analyser for JavaScript/TypeScript. In
`--modules-only` mode it follows `require`/`import` from the app's own files through
node_modules and reports every package and module it reached. It parses; it never runs
the app or the packages. This tier runs it once per checkout and answers at PACKAGE
level only:

- the advisory's package (that installed version) is loaded -> `unsure`, with the
  finding in the rationale: being loaded says nothing about the vulnerable function;
- it is never loaded, and nothing below explains a load the analysis can't see ->
  not_reachable 1.0. floors.toml marks it `corroborate`: a second tier must agree.

The analysis copy (SSVC_JELLY_WORK, default ~/.cache/ssvc-triage/jelly-work, removed
after the run): the app's JS/TS/JSON files (no node_modules, .git or symlinks), plus
node_modules laid out as package-lock.json says, every package from `pkgsrc`
(integrity-verified tarballs, source files only; nothing installed, no lifecycle
script). Dev-only packages are left out. The checkout is never written. Entry points
are every non-test app source file outside build/browser-asset directories.

Sandboxed: Node runs Jelly under macOS `sandbox-exec` with network denied and writes
confined to the run's own directory (elsewhere, with neither; Jelly itself never
evaluates the code it reads). Only package names and versions leave the machine
(pkgsrc). Static mode only: Jelly's `-d` (dynamic) and `--approx` modes execute code
and are never used.

A package Jelly never saw loaded may still be loaded in ways a static analysis misses.
Each of these makes the answer `unsure` instead of not_reachable, for the advisory's
package and every package on its route from the app (`_route`):

- a package on the route is loaded by a package the analysis did reach (a computed
  `require` in a reached package: sequelize loads its dialect driver by name);
- the app's own files name a package on the route in a string: `'view engine', 'pug'`,
  a `.pug` view file, a config value, a package.json field other than the dependency
  lists (babel presets), a `node_modules/<name>` path served to browsers;
- a package on the route provides a command the package.json scripts run (`pm2 start`,
  `node -r dotenv/config`), or is preloaded with -r/--require/--import;
- the app itself has a `require`/`import()` of a computed name that isn't a local path,
  or a file Jelly couldn't parse (it drops such a file silently), and the route starts
  at one of the app's direct dependencies;
- a package on the route couldn't be fetched and verified, or lost files to pkgsrc's
  size caps.

Not covered: code that isn't JavaScript (`.vue` / `.svelte` single-file components are
only searched for package names), and loads named by data outside the checkout
(environment variables, a database).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .. import pkgsrc
from .._locks import keylock
from . import depgraph
from .base import JudgeResult, ReachQuery, Verdict
from .usage import is_test_path

logger = logging.getLogger(__name__)

GUARD = "guard4"           # bump when the guard rules change: cached scans are keyed on it
_SRC_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")
_COPY_EXT = _SRC_EXT + (".json",)
# text the mention scan reads (searched only; Jelly can't parse the non-JS ones)
_TEXT_EXT = _COPY_EXT + (".vue", ".svelte", ".astro", ".coffee", ".html", ".htm", ".ejs", ".pug", ".jade",
                         ".hbs", ".handlebars", ".mustache", ".njk", ".yaml", ".yml", ".toml", ".env", ".ini",
                         ".babelrc", ".swcrc")
_SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn"}
_NOT_ENTRY_DIRS = {"dist", "build", "coverage", "public", "static", "assets", "vendor"}
_CONFIG = re.compile(r"(^|\.)(config|conf|preset|setup)\.[cm]?[jt]sx?$|^(webpack|rollup|vite|babel|jest|karma|gulpfile"
                     r"|gruntfile|eslint|prettier)\b", re.I)
_MAX_APP_FILE = 10 * 2**20
_STRING = re.compile(r"""(["'`])((?:(?!\1)[^\\\n]|\\.){1,214})\1""")
# require(x) / import(x) whose argument isn't a plain string: a load a static analysis
# can't follow. `\brequire` skips __webpack_require__ and require.resolve; an argument
# opening with a backslash is text inside a string, not code.
_DYN = re.compile(r"""(?<![\w$.])(?:require|import)\s*\(\s*([^)\s][^)]{0,80})""")
_PLAIN = re.compile(r"""^(["'])[^"'\\]*\1\s*$|^`[^`$]*`\s*$""")
# a path built with path.join/resolve is taken as a local file
_LOCAL_DYN = re.compile(r"""^(?:(?:path\.)?(?:join|resolve)\s*\(|__dirname|["'`]\.{1,2}/|`\$\{__dirname\}|"""
                        r"""\\|process\.cwd\(\))""")
# data files the mention scan reads: configuration, not arbitrary JSON (a SARIF report
# or a fixture names every package)
_CONFIGISH = re.compile(r"config|conf\b|settings|rc$|^\.env|knexfile|ormconfig|nodemon|ecosystem|pm2|^default\.|"
                        r"^production\.|^development\.|^staging\.|^local\.|^custom-environment", re.I)
_CODE_TEXT = (".vue", ".svelte", ".astro", ".coffee")       # code Jelly doesn't parse: strings count
_PARSE_ERR = re.compile(r"(?:Unrecoverable parse error|Parse error) for (.+?): ")
_PRELOAD = ("-r", "--require", "--import", "--loader", "--experimental-loader")
_DEP_FIELDS = {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
               "bundledDependencies", "bundleDependencies", "peerDependenciesMeta", "resolutions",
               "overrides", "name", "version", "description", "keywords", "repository", "author",
               "contributors", "license", "homepage", "bugs", "engines", "scripts", "funding"}


def _tools() -> Path:
    return Path(os.environ.get("SSVC_JELLY_HOME", "~/.cache/ssvc-triage/jstools")).expanduser()


def _main() -> Path:
    return _tools() / "node_modules/@cs-au-dk/jelly/lib/main.js"


def _node() -> str:
    return os.environ.get("SSVC_NODE") or shutil.which("node") or "/opt/homebrew/bin/node"


def _workroot() -> Path:
    return Path(os.environ.get("SSVC_JELLY_WORK", "~/.cache/ssvc-triage/jelly-work")).expanduser()


def _sandbox(out: Path) -> list[str]:
    sb = "/usr/bin/sandbox-exec"
    if not Path(sb).is_file():
        return []
    prof = ("(version 1)(allow default)(deny network*)(deny file-write*)"
            f'(allow file-write* (subpath "{out}") (literal "/dev/null") (literal "/dev/stdout")'
            ' (literal "/dev/stderr") (literal "/dev/tty") (regex #"^/dev/fd/"))')
    return [sb, "-p", prof]


def _walk(root: Path):
    """App files under `root` as (path, rel): regular files only, never a symlink."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not Path(dirpath, d).is_symlink()]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            yield p, p.relative_to(root)


def entries(root: Path) -> list[str]:
    """Jelly's entry files: the app's own non-test source, minus build/config files and
    bundles or browser assets under dist/, public/, ..."""
    out = []
    for p, rel in _walk(root):
        if p.suffix not in _SRC_EXT or rel.name.endswith(".d.ts") or is_test_path(rel) or _CONFIG.search(rel.name):
            continue
        if _NOT_ENTRY_DIRS & set(rel.parts[:-1]):
            continue
        out.append(rel.as_posix())
    return sorted(out)


def _names_in(s: str, names: set[str]) -> set[str]:
    """Package names a string literal stands for: the whole string, a path into a package
    (`lodash/fp`, `node_modules/jquery/dist`), or a file extension (`index.pug`)."""
    s = s.strip()
    out = set()
    if s in names:
        out.add(s)
    head = s.split("/")
    if len(head) > 1:
        out |= {n for n in ("/".join(head[:2]), head[0]) if n in names}
    for m in re.finditer(r"node_modules/((?:@[^/\s\"'`]+/)?[^/\s\"'`]+)", s):
        if m[1] in names:
            out.add(m[1])
    if "." in s and " " not in s:
        ext = s.rsplit(".", 1)[1]
        if ext in names:
            out.add(ext)
    return out


def computed_requires(text: str, path: str = "", limit: int = 3) -> list[str]:
    """`file:line: snippet` for each require/import of a computed, non-local name."""
    out = []
    for m in _DYN.finditer(text):
        arg = m[1].strip()
        if _PLAIN.match(arg.split(",")[0].rstrip(")")) or _LOCAL_DYN.match(arg):
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        if text[line_start:m.start()].lstrip().startswith(("//", "*", "/*")):
            continue
        out.append(f"{path}:{text.count(chr(10), 0, m.start()) + 1}: {m.group(0)[:80]}")
        if len(out) >= limit:
            break
    return out


def app_signals(root: Path, names: set[str], entry_files: list[str]) -> dict:
    """What the app's files say about loads Jelly can't see: package names they mention
    ({name: first place}), computed non-local requires in the entry files, and
    command/preload names from package.json scripts. Names are read from string literals
    in the app's source (and .vue/.svelte/... components), from configuration files, as
    view-file extensions (`index.pug`), and as `node_modules/<name>` paths in any file."""
    mentions: dict[str, str] = {}
    for p, rel in _walk(root):
        r = rel.as_posix()
        if is_test_path(rel) or p.name in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
            continue
        for n in names:                                   # a view file named for its engine
            if p.suffix == "." + n:
                mentions.setdefault(n, r)
        source = p.suffix in _SRC_EXT and not (_NOT_ENTRY_DIRS & set(rel.parts[:-1]))
        config = (p.suffix in _TEXT_EXT or p.name.startswith(".")) and p.suffix not in _SRC_EXT and (
            _CONFIGISH.search(p.name) or any(_CONFIGISH.search(d) for d in rel.parts[:-1]))
        strings = source or config or p.suffix in _CODE_TEXT
        if not (strings or p.suffix in _TEXT_EXT):
            continue
        try:
            text = p.read_text(errors="replace") if p.stat().st_size <= _MAX_APP_FILE else ""
        except OSError:
            continue
        if strings:
            for m in _STRING.finditer(text):
                for n in _names_in(m[2], names):
                    mentions.setdefault(n, r)
        for m in re.finditer(r"node_modules/((?:@[^/\s\"'`]+/)?[^/\s\"'`]+)", text):
            if m[1] in names:
                mentions.setdefault(m[1], r)
    dynamic = []
    for e in entry_files:
        try:
            dynamic += computed_requires((root / e).read_text(errors="replace"), e)
        except OSError:
            pass
    commands: dict[str, str] = {}
    try:
        pj = json.loads((root / "package.json").read_text())
    except (OSError, ValueError):
        pj = {}
    for field, val in pj.items():                       # babel presets, nodemonConfig, ...
        if field not in _DEP_FIELDS:
            for m in _STRING.finditer(json.dumps(val)):
                for n in _names_in(m[2], names):
                    mentions.setdefault(n, f"package.json `{field}`")
    for script, cmd in (pj.get("scripts") or {}).items():
        toks = re.split(r"[\s;&|()]+", str(cmd))
        for i, t in enumerate(toks):
            if t:
                commands.setdefault(t, script)
                for n in _names_in(t, names):           # cp node_modules/jquery/dist/... public/
                    commands.setdefault(n, script)
            if t in _PRELOAD and i + 1 < len(toks):
                for n in _names_in(toks[i + 1], names) or {toks[i + 1]}:
                    commands.setdefault(n, script)
    return {"mentions": mentions, "dynamic": dynamic[:20], "commands": commands}


def _package_dynamic(pkg_dir: Path) -> str:
    """The first computed require in a package's source, or ""."""
    for p, rel in _walk(pkg_dir):
        if p.suffix in _SRC_EXT and "node_modules" not in rel.parts:
            try:
                hits = computed_requires(p.read_text(errors="replace"), rel.as_posix(), 1)
            except OSError:
                continue
            if hits:
                return hits[0]
    return ""


def _bins(pkg_dir: Path) -> set[str]:
    try:
        pj = json.loads((pkg_dir / "package.json").read_text())
    except (OSError, ValueError):
        return set()
    b = pj.get("bin")
    if isinstance(b, str):
        return {str(pj.get("name", "")).split("/")[-1]}
    return set(b) if isinstance(b, dict) else set()


def _route(g: depgraph.Graph, targets: set[str]) -> set[str]:
    """The targets and every installed, non-dev package that can reach one of them."""
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


class JellyJudge:
    name = "jelly"

    def __init__(self, timeout: float | None = None):
        self.timeout = timeout or float(os.environ.get("SSVC_JELLY_TIMEOUT", "1200"))
        self.heap_mb = int(os.environ.get("SSVC_JELLY_HEAP_MB", "8192"))
        self._scans: dict[str, dict | None] = {}
        self._version = ""

    def version(self) -> str:
        if not self._version:
            try:
                pj = json.loads((_main().parents[1] / "package.json").read_text())
                self._version = f"jelly@{pj.get('version', '?')}"
            except (OSError, ValueError):
                return ""
        return self._version

    def fingerprint(self) -> str:
        return f"{self.version()}@modules@{GUARD}"

    def app_code_destination(self) -> str:
        return "machine"

    def probe(self) -> tuple[bool, str]:
        if not _main().is_file():
            return False, f"no Jelly at {_main()}"
        if not shutil.which(_node()) and not Path(_node()).is_file():
            return False, "no node"
        if not pkgsrc.enabled():
            return False, "needs dependency source (SSVC_PKGSRC=1 / --pkgsrc)"
        sb = "sandboxed (no network)" if _sandbox(Path("/")) else "NOT sandboxed (no sandbox-exec)"
        return True, f"{self.version()}, modules only, {sb}"

    # --- one scan per checkout ---------------------------------------------------
    def _scan(self, repo: str) -> dict | None:
        with keylock(("jelly", repo)):
            if repo not in self._scans:
                self._scans[repo] = self._scan_locked(Path(repo))
            return self._scans[repo]

    def _key(self, root: Path, files: list[tuple[Path, Path]]) -> str:
        h = hashlib.sha256(self.fingerprint().encode() + str(root.resolve()).encode())
        for p, rel in sorted(files, key=lambda f: f[1].as_posix()):
            h.update(rel.as_posix().encode() + b"\0")
            try:
                h.update(hashlib.sha256(p.read_bytes()).digest())
            except OSError:
                pass
        return h.hexdigest()[:24]

    def _scan_locked(self, root: Path) -> dict | None:
        g = depgraph.load(root, "npm")
        if g is None:
            return None
        files = [(p, rel) for p, rel in _walk(root)
                 if p.suffix in _TEXT_EXT or p.name in _TEXT_EXT or p.name.startswith(".env")]
        key = self._key(root, files)
        cache = Path(os.environ.get("SSVC_JUDGE_CACHE", "~/.cache/ssvc-triage/judge")).expanduser() / "jelly-scans"
        cf = cache / f"{key}.json"
        if cf.is_file():
            return json.loads(cf.read_text())
        t0 = time.monotonic()
        _workroot().mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="run-", dir=_workroot()) as tmp:
            work, out = Path(tmp) / "app", Path(tmp) / "out"
            out.mkdir()
            for p, rel in files:
                if p.suffix in _COPY_EXT and p.stat().st_size <= _MAX_APP_FILE:
                    (work / rel).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(p, work / rel)
            missing, opaque, bins = [], [], {}
            for path, n in g.nodes.items():
                if n["dev"] or "node_modules/" not in path:
                    continue
                try:
                    src = pkgsrc.fetch(n["name"], n["version"] or "", n["integrity"] or "")
                except (pkgsrc.Rejected, OSError) as exc:
                    missing.append(path)
                    logger.info("jelly: %s not analysed: %s", path, exc)
                    continue
                try:
                    st = json.loads(Path(str(src) + ".json").read_text())
                    if st.get("skipped_size") or st.get("skipped_dup"):
                        opaque.append(path)
                except (OSError, ValueError):
                    opaque.append(path)
                shutil.copytree(src, work / path, dirs_exist_ok=True, copy_function=_link)
                for b in _bins(src):
                    bins.setdefault(b, []).append(path)
            ents = entries(work)
            if not ents:
                return None
            srcdirs = {path: work / path for path, n in g.nodes.items()
                       if not n["dev"] and "node_modules/" in path and path not in missing}
            argv = [*_sandbox(out), _node(), f"--max-old-space-size={self.heap_mb}", str(_main()),
                    "--no-print-progress", "--no-tty", "--ignore-unresolved", "--modules-only",
                    "--logfile", str(out / "jelly.log"), "--reachable-file", str(out / "reach.json"), *ents]
            try:
                p = subprocess.run(argv, cwd=work, capture_output=True, text=True, timeout=self.timeout,
                                   stdin=subprocess.DEVNULL,
                                   env={"PATH": "/usr/bin:/bin", "HOME": str(out), "TMPDIR": str(out)})
            except (OSError, subprocess.SubprocessError) as exc:
                logger.warning("jelly %s: %s; no claim", root, exc)
                return None
            log = (out / "jelly.log").read_text(errors="replace") if (out / "jelly.log").is_file() else ""
            if p.returncode != 0 or not (out / "reach.json").is_file():
                logger.warning("jelly %s exit %s: %s; no claim", root, p.returncode,
                               (p.stderr or log).strip()[-400:])
                return None
            reach = json.loads((out / "reach.json").read_text())
            parse_errors = sorted({Path(m[1]).relative_to(work).as_posix() if m[1].startswith(str(work)) else m[1]
                                   for m in _PARSE_ERR.finditer(log + p.stdout + p.stderr)})
            reached = {(r["name"], r.get("version", "")) for r in reach.get("packages") or []}
            # a loaded package with a computed require can load any package it declares
            # (sequelize -> its dialect driver); a reached package's own files may not parse
            dyn = {}
            for path, d in srcdirs.items():
                n = g.nodes[path]
                if (n["name"], n["version"]) in reached:
                    bad = [e for e in parse_errors if e.startswith(path + "/")]
                    if hit := (f"{bad[0]}: couldn't parse" if bad else _package_dynamic(d)):
                        dyn[path] = hit
        names = {n["name"] for n in g.nodes.values()}
        sig = app_signals(root, names, ents)
        result = {"reached": sorted(reached), "entries": len(ents), "missing": missing, "opaque": opaque,
                  "parse_errors": [e for e in parse_errors if "node_modules/" not in e], "dynamic_packages": dyn,
                  "bins": bins, **sig, "seconds": round(time.monotonic() - t0, 1)}
        cache.mkdir(parents=True, exist_ok=True)
        tmpf = cf.with_name(cf.name + f".{os.getpid()}.tmp")
        tmpf.write_text(json.dumps(result))
        os.replace(tmpf, cf)
        return result

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        if q.ecosystem != "npm" or not pkgsrc.enabled() or not _main().is_file():
            return None
        root = Path(q.repo_path)
        g = depgraph.load(root, "npm")
        if g is None:
            return None
        targets = {p for p, n in g.nodes.items() if n["name"] == q.dependency
                   and (not q.version or n["version"] == q.version) and not n["dev"]}
        if not targets:
            return None                     # not installed, or dev-only: not this tier's question
        t0 = time.monotonic()
        scan = self._scan(q.repo_path)
        if scan is None:
            return None

        def res(verdict, conf, why, evidence=()):
            return JudgeResult(verdict, conf, self.name, rationale=why[:1200], evidence=list(evidence)[:8],
                               latency_s=round(time.monotonic() - t0, 3), cost_usd=0.0, model=self.version())

        reached = {tuple(r) for r in scan["reached"]}
        is_reached = {p for p, n in g.nodes.items() if (n["name"], n["version"]) in reached}
        label = f"{q.dependency}@{q.version}" if q.version else q.dependency
        if targets & is_reached:
            return res(Verdict.UNSURE, 0.0, f"jelly (modules only): {label} is loaded from the app's code; "
                                            "package level only, so nothing about the vulnerable function")
        route = _route(g, targets)
        named = lambda p: f"{g.nodes[p]['name']}@{g.nodes[p]['version']}"   # noqa: E731
        why = []
        if bad := route & set(scan["missing"]):
            why.append("not analysed (source couldn't be fetched and verified): "
                       + ", ".join(sorted(named(p) for p in bad)[:4]))
        if bad := route & set(scan["opaque"]):
            why.append("files left out by size caps in " + ", ".join(sorted(named(p) for p in bad)[:4]))
        dyn = scan["dynamic_packages"]
        frontier = sorted({f"{named(par)} -> {named(c)} ({dyn[par]})" for par, cs in g.edges.items() if par in dyn
                           for c in cs if c in route and c not in is_reached})
        if frontier:
            why.append("a loaded package with a computed require declares one on the route: " + "; ".join(frontier[:3]))
        route_names = {g.nodes[p]["name"] for p in route if p not in is_reached}

        def resolvable(p):      # the copy a bare name loads: from the app's files or a loaded package
            parent = p[:p.rfind("node_modules/")].rstrip("/")
            return "node_modules/" not in parent or parent in is_reached
        named_copies = {g.nodes[p]["name"] for p in route if p not in is_reached and resolvable(p)}
        if hit := sorted(n for n in named_copies if n in scan["mentions"]):
            why.append("the app names " + ", ".join(f"{n} ({scan['mentions'][n]})" for n in hit[:4]))
        cmds = scan["commands"]
        via = sorted({named(p) for b, ps in scan["bins"].items() if b in cmds for p in ps
                      if p in route and p not in is_reached}
                     | {n for n in route_names if n in cmds})
        if via:
            why.append("package.json scripts run or preload " + ", ".join(via[:4]))
        tops = route & set(g.edges.get(depgraph.ROOT, ()))
        if tops and (scan["dynamic"] or scan["parse_errors"]):
            src = (f"computed require/import in the app ({scan['dynamic'][0]})" if scan["dynamic"]
                   else f"app files Jelly couldn't parse ({', '.join(scan['parse_errors'][:3])})")
            why.append(f"{src}, and the route starts at direct dependency "
                       + ", ".join(sorted(named(p) for p in tops)[:3]))
        if why:
            return res(Verdict.UNSURE, 0.0, f"jelly (modules only): {label} is never loaded, but "
                                            + "; ".join(why) + ": not_reachable not claimed")
        chain = depgraph.chains(g, q.dependency, q.version, limit=2)
        return res(Verdict.NOT_REACHABLE, 1.0,
                   f"jelly (modules only, {scan['entries']} entry files, tests excluded): no module of {label} "
                   "is loaded, and no computed require in a loaded package, app string, script or computed require in the app "
                   "leads to it "
                   f"or the {len(route) - len(targets)} packages on its route",
                   evidence=[depgraph.describe(g, c) for c in chain])


def _link(src, dst):
    if os.path.lexists(dst):
        return dst                         # a bundled copy from the parent's tarball is already there
    try:
        os.link(src, dst)                  # same filesystem as the pkgsrc cache: no copy
    except OSError:
        shutil.copyfile(src, dst)

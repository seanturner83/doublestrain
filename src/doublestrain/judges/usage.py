"""Static usage pre-pass: how does the app import / call a dependency?

Cheap, deterministic grep over a checkout. Its text is the INPUT to the System-1 judge
(Jev sees only this summary, never the repo); the claude-code judge gets it as a head
start and then reads the code itself.

Deliberately NOT a verdict: "not imported directly" does not mean unreachable — the
package may be transitive and reached through a parent the app does use.

The summary is only CLOSED-WORLD when nothing reaches the dependency dynamically. A
computed member access on its binding (`_[name]`), a non-literal `require()`/`import()`,
or `getattr(mod, ...)` / `import_module(...)` means "zero symbol mentions" proves nothing;
`dynamic_sites` records those, and summary-only judges must not answer not_reachable
while any exist (see `guard_not_reachable`).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_EXTS = {
    "npm": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"),
    "pypi": (".py",),
    "go": (".go",),
    "cargo": (".rs",),
}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
              "__pycache__", ".tox", "coverage", ".next"}
_MAX_FILE_BYTES = 512 * 1024
# Bump when the summary text or its semantics change: judges put it in their cache key,
# so answers given on an older summary are not reused.
PREPASS_VERSION = 8

_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing", "e2e"}
_TEST_FILE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$|^test_.*\.py$|_test\.(py|go)$|^conftest\.py$)")


@dataclass
class Usage:
    import_sites: list[str] = field(default_factory=list)   # "path:line: text"
    symbol_sites: list[str] = field(default_factory=list)
    dynamic_sites: list[str] = field(default_factory=list)  # non-empty => not closed-world
    chains: list[str] = field(default_factory=list)          # lockfile: app -> a@1 -> dep@2
    copies: str = ""                                          # which installed copy this row is about
    entry_sites: list[str] = field(default_factory=list)     # where the app imports chain tops
    files_scanned: int = 0
    text: str = ""
    ecosystem: str = ""

    @property
    def closed_world(self) -> bool:
        return not self.dynamic_sites


def is_test_path(rel: Path) -> bool:
    return bool(_TEST_DIRS & {p.lower() for p in rel.parts[:-1]}) or bool(_TEST_FILE.search(rel.name))


def _bindings(ecosystem: str, line: str, import_name: str, dep: str) -> list[str]:
    """Local names an import line binds the dependency to (for dynamic-access checks)."""
    if ecosystem in ("cargo", "go"):
        return []       # no runtime name lookup to bind: Rust and Go have no dynamic import
    if ecosystem == "pypi":
        mod = import_name or dep.replace("-", "_")
        m = re.match(rf"\s*import\s+{re.escape(mod)}(?:\s+as\s+(\w+))?", line)
        return [m.group(1) or mod] if m else []
    out = []
    for pat in (r"(?:const|let|var)\s+(\w+)\s*=\s*require\(", r"import\s+(\w+)\s*(?:,|from)",
                r"import\s+\*\s+as\s+(\w+)"):
        out += re.findall(pat, line)
    return out


# A non-literal require()/import() whose argument is built from a filesystem path loads a
# LOCAL file (already scanned as app source) — it cannot name an npm package.
_LOCAL_LOAD = re.compile(r"""(?:require|import)\(\s*(?:path\.(?:resolve|join)\(|__dirname|__filename|"""
                         r"""process\.cwd\(\)|['"`]\.{1,2}/)""")

# `join` / `resolve` bound from Node's path module (`const join = require('path').join`,
# `const { join: j } = require('node:path')`, `import { resolve } from 'path'`): a
# require() built by one of them loads a local file just like `path.join(...)`.
_PATH_MOD = r"""['"](?:node:)?path['"]"""
_PATH_FN_DIRECT = re.compile(rf"""\b(\w+)\s*=\s*require\(\s*{_PATH_MOD}\s*\)\.(?:join|resolve)\b""")
_PATH_FN_DESTRUCT = re.compile(rf"""\{{([^}}]*)\}}\s*(?:=\s*require\(\s*|from\s+){_PATH_MOD}""")


def _path_fns(lines) -> set[str]:
    out = set()
    for ln in lines:
        out.update(_PATH_FN_DIRECT.findall(ln))
        for m in _PATH_FN_DESTRUCT.finditer(ln):
            for part in m.group(1).split(","):
                name, _, alias = (x.strip() for x in part.replace(" as ", ":").partition(":"))
                if name in ("join", "resolve"):
                    out.add(alias or name)
    return out


_CFG_TEST = re.compile(r"#\[cfg\((?:all\()?test\b")


def rust_test_lines(lines) -> set[int]:
    """1-based line numbers inside `#[cfg(test)]` items (usually `mod tests { ... }`):
    Rust keeps unit tests in the same file as the code, so the path doesn't say. Brace
    counting ignores braces in strings and comments: a stray one can end the block early
    (lines then count as runtime, the safe side) but not extend it past the file."""
    out, i, n = set(), 0, len(lines)
    while i < n:
        if _CFG_TEST.search(lines[i]):
            depth, started, j = 0, False, i
            while j < n:
                code = lines[j].split("//", 1)[0]
                depth += code.count("{") - code.count("}")
                started |= "{" in code
                out.add(j + 1)
                if (started and depth <= 0) or (not started and code.rstrip().endswith(";")):
                    break
                j += 1
            i = j
        i += 1
    return out


def _is_comment(ecosystem: str, ln: str) -> bool:
    t = ln.lstrip()
    return t.startswith("#") if ecosystem == "pypi" else t.startswith(("//", "/*", "*"))


def _dynamic_res(ecosystem: str, names: list[str]) -> list[re.Pattern[str]]:
    pats = []
    if ecosystem == "pypi":
        pats += [re.compile(r"\bimportlib\.import_module\(|\b__import__\(")]
        if names:
            pats.append(re.compile(rf"\bgetattr\(\s*(?:{'|'.join(map(re.escape, names))})\s*,"))
    elif ecosystem not in ("go", "cargo"):
        pats.append(re.compile(r"""\b(?:require|import)\(\s*(?!['"`]|\))"""))   # non-literal require()/import()
        if names:
            pats.append(re.compile(rf"(?<![\w.$])(?:{'|'.join(map(re.escape, names))})\s*\["))
    return pats


def _import_re(ecosystem: str, dep: str, import_name: str) -> re.Pattern[str]:
    if ecosystem == "pypi":
        mod = re.escape(import_name or dep.replace("-", "_"))
        return re.compile(rf"^\s*(?:import\s+{mod}\b|from\s+{mod}(?:\.\w+)*\s+import\b)")
    d = re.escape(import_name or dep)
    if ecosystem == "go":
        return re.compile(rf'"{d}(?:/[^"]*)?"')
    if ecosystem == "cargo":
        # `use serde_json::Value;`, `serde_json::from_str(..)`, `#[derive(serde::Serialize)]`,
        # `extern crate foo;` -- crate names use `_` in source (`serde-json` -> `serde_json`)
        d = re.escape(import_name or dep.replace("-", "_"))
        return re.compile(rf"(?<![\w:]){d}::|\bextern\s+crate\s+{d}\b|\buse\s+{d}\s*(?:;|\bas\b)")
    # npm (and the default): require('dep'), require('dep/sub'), import ... from 'dep', import('dep')
    return re.compile(rf"""(?:require\(\s*|from\s+|import\s*\(?\s*)['"]{d}(?:/[^'"]*)?['"]""")


def _symbol_tokens(symbols) -> list[str]:
    # "qs.stringify" / "yaml.load()" / "_.template" -> the callable's own name
    out = []
    for s in symbols:
        tok = re.split(r"[.:#]", s.strip().rstrip("()"))[-1]
        if tok and tok not in out:
            out.append(tok)
    return out


def _iter_files(root: Path, exts):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(exts):
                yield Path(dirpath) / fn


def _chain_section(u: Usage, root: Path, ecosystem: str, dependency: str, version: str,
                   exts, max_sites: int) -> list[str]:
    """Lockfile dependency chains + where the app imports each chain's top-level package."""
    from . import depgraph
    if ecosystem not in ("npm", "cargo", "go"):
        return []
    lockname = {"cargo": "Cargo.lock", "go": "go.mod"}.get(ecosystem, "package-lock.json")
    g = depgraph.load(root, ecosystem)
    if g is None:
        return []
    cs = depgraph.chains(g, dependency, version)
    if not cs:
        return [f"lockfile: {dependency}@{version or '*'} not found in the "
                f"{'package-lock' if ecosystem == 'npm' else lockname} graph."]
    if all(len(c) == 1 for c in cs):
        return []      # only a direct dependency: the import sites above already say it all
    u.chains = [depgraph.describe(g, c) for c in cs]
    tops = []
    for c in cs:
        t = depgraph.top_level(g, c)
        if t not in tops:
            tops.append(t)
    lines = [f"dependency chain(s) from {lockname} ({len(cs)} shown, shortest first):"]
    lines += [f"  {s}" for s in u.chains]
    if all(t in g.dev_direct for t in tops):
        lines.append("  every chain enters through a devDependency (build/test tooling)."
                     if ecosystem != "cargo" else
                     "  every chain enters through a dev- or build-dependency (tests, build.rs).")
    for t in tops[:3]:
        imp = _import_re(ecosystem, t, "")
        sites = []
        for f in _iter_files(root, exts):
            try:
                if f.stat().st_size > _MAX_FILE_BYTES:
                    continue
                flines = f.read_text(errors="replace").splitlines()
                tl = rust_test_lines(flines) if ecosystem == "cargo" else set()
                for i, ln in enumerate(flines, 1):
                    if imp.search(ln) and not (ecosystem == "cargo" and _is_comment(ecosystem, ln)):
                        rel = f.relative_to(root)
                        tag = " (test code)" if is_test_path(rel) or i in tl else ""
                        sites.append(f"{rel}:{i}: {ln.strip()[:160]}{tag}")
            except OSError:
                continue
        u.entry_sites += sites[:max_sites]
        lines.append(f"top-level `{t}` imported at ({len(sites)}):" if sites else
                     f"top-level `{t}` is NOT imported by app source (CLI/build tool, or loaded by another package).")
        lines += [f"  {s}" for s in sites[:8]]
    return lines


def copies_note(repo_path: str, ecosystem: str, dependency: str, version: str) -> str:
    """When several versions of the package are installed: which copy this advisory row
    is about, and which copy the app's own imports load. The models' most common error in
    the 2026-10-18 label review was reasoning about the wrong copy (body-parser nested
    under express, lodash under nyc): import sites in the app are evidence only for the
    copy those imports resolve to. "" when only one version is installed. No app source:
    lockfile paths, names and versions only (it goes to the shape tier too)."""
    from . import depgraph
    if not version or ecosystem not in ("npm", "cargo", "go"):
        return ""
    g = depgraph.load(Path(repo_path).expanduser(), ecosystem)
    if g is None:
        return ""
    copies = {p: n for p, n in g.nodes.items() if n["name"] == dependency}
    if len({n["version"] for n in copies.values()}) < 2 or version not in {n["version"] for n in copies.values()}:
        return ""
    parents: dict[str, list[str]] = {}
    for par, cs in g.edges.items():
        for c in cs:
            if c in copies:
                parents.setdefault(c, []).append(par)
    # the copy a bare import in the app's own code loads: npm's top-level node_modules/<name>;
    # elsewhere the one the root depends on
    app_copy = (f"node_modules/{dependency}" if ecosystem == "npm"
                else next((c for c in g.edges.get(depgraph.ROOT, ()) if c in copies), ""))

    def who(path: str) -> str:
        ps = parents.get(path, [])
        names = ["the app (direct dependency)" if p == depgraph.ROOT else
                 f"{g.nodes[p]['name']}@{g.nodes[p]['version']}" for p in ps]
        more = f" and {len(names) - 4} more" if len(names) > 4 else ""
        return ", ".join(names[:4]) + more if names else "nothing (unused)"
    lines = [f"INSTALLED COPIES of {dependency} ({len(copies)}); this advisory row is about {version}:"]
    for path, n in sorted(copies.items(), key=lambda kv: (kv[1]["version"] != version, kv[0])):
        tag = "  <- THIS ROW" if n["version"] == version else ""
        dev = " (dev only)" if n["dev"] else ""
        app = " [an import in the app's own code would load this one]" if path == app_copy else ""
        lines.append(f"  {n['version']} at {path}{dev}{app}{tag}; required by: {who(path)}")
    if app_copy in copies and copies[app_copy]["version"] != version:
        lines.append(f"An import of `{dependency}` in the app's own code loads {copies[app_copy]['version']}, NOT "
                     f"{version}: app import sites are evidence only for that other copy. {version} runs only if "
                     "one of the packages that require it (listed above) calls into it.")
    elif app_copy in copies:
        lines.append(f"The app's own imports load this copy ({version}); the other versions are separate code "
                     "that only their own parents use.")
    return "\n".join(lines)


def usage_summary(repo_path: str, ecosystem: str, dependency: str, vuln_symbols=(),
                  import_name: str = "", max_sites: int = 25, *, version: str = "") -> Usage:
    root = Path(repo_path).expanduser()
    exts = _EXTS.get(ecosystem, sum(_EXTS.values(), ()))
    imp = _import_re(ecosystem, dependency, import_name)
    toks = _symbol_tokens(vuln_symbols)
    sym = re.compile(rf"\b(?:{'|'.join(map(re.escape, toks))})\b") if toks else None

    u = Usage(ecosystem=ecosystem)
    importing, other_sym = [], []
    for f in _iter_files(root, exts):
        try:
            if f.stat().st_size > _MAX_FILE_BYTES:
                continue
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        u.files_scanned += 1
        rel = f.relative_to(root)
        tag = " (test code)" if is_test_path(rel) else ""
        tl = rust_test_lines(lines) if ecosystem == "cargo" and not tag else set()
        site = lambda i, ln: f"{rel}:{i}: {ln.strip()[:160]}{tag or (' (test code)' if i in tl else '')}"  # noqa: E731
        imports = [(i, ln) for i, ln in enumerate(lines, 1) if imp.search(ln)
                   and not (ecosystem == "cargo" and _is_comment(ecosystem, ln))]   # `///` docs name paths
        u.import_sites += [site(i, ln) for i, ln in imports]
        names = [n for _, ln in imports for n in _bindings(ecosystem, ln, import_name, dependency)]
        dyn = _dynamic_res(ecosystem, names) if imports or ecosystem != "pypi" else []
        pf = _path_fns(lines) if dyn and ecosystem != "pypi" else set()
        local_fn = (re.compile(rf"(?:require|import)\(\s*(?:{'|'.join(map(re.escape, sorted(pf)))})\(")
                    if pf else None)
        for i, ln in enumerate(lines, 1):
            if _is_comment(ecosystem, ln):
                continue
            if any(d.search(ln) for d in dyn) and (imports or "require" in ln or "import" in ln):
                if (_LOCAL_LOAD.search(ln) or (local_fn and local_fn.search(ln))) and not any(
                        d.search(ln) for d in dyn[1:]):     # path-built local file load only
                    continue
                u.dynamic_sites.append(site(i, ln))
        if sym:
            # import lines count too: `const { template: compile } = require('lodash')`
            hits = [site(i, ln) for i, ln in enumerate(lines, 1) if sym.search(ln)]
            # symbol mentions in files that import the dependency are the strong signal
            (importing if imports else other_sym).extend(hits)
    u.symbol_sites = importing + other_sym

    parts = [f"dependency {dependency} ({ecosystem}); scanned {u.files_scanned} source files."]
    if u.import_sites:
        parts.append(f"direct import sites ({len(u.import_sites)}):")
        parts += [f"  {s}" for s in u.import_sites[:max_sites]]
    else:
        parts.append("NOT imported directly anywhere in the app source "
                     "(it may still be a transitive dependency used by another package).")
    if toks:
        parts.append(f"vulnerable symbol(s) {', '.join(toks)}: "
                     f"{len(importing)} mention(s) in importing files, {len(other_sym)} elsewhere")
        parts += [f"  {s}" for s in u.symbol_sites[:max_sites]]
    u.copies = copies_note(repo_path, ecosystem, dependency, version)
    if u.copies:
        parts.append(u.copies)
    parts += _chain_section(u, root, ecosystem, dependency, version, exts, max_sites)
    if u.dynamic_sites:
        parts.append(f"DYNAMIC ACCESS ({len(u.dynamic_sites)} site(s)) — computed member access or "
                     "non-literal module loading; this summary is NOT closed-world, so missing "
                     "symbol mentions do not show the vulnerable code is unused:")
        parts += [f"  {s}" for s in u.dynamic_sites[:max_sites]]
    u.text = "\n".join(parts)
    return u


def unmeasured_ecosystems() -> set[str]:
    """Ecosystems whose not_reachable verdicts have no labelled run behind them yet: no
    tier may settle not_reachable there (the floors were measured on npm apps; pypi was
    held from 2026-10-19: three small fixtures were its only labels). Override
    with SSVC_NR_UNMEASURED (comma-separated; empty = none). govulncheck isn't held: it is
    a call graph, not a model judging from excerpts (`reach.resolve_reachability`)."""
    return {e.strip() for e in os.environ.get("SSVC_NR_UNMEASURED", "cargo,go,pypi").split(",") if e.strip()}


def measured_for(role: str) -> set[str]:
    """Ecosystems where this judge role's not_reachable has been measured on labels and
    may settle a row despite the ecosystem's hold (floors.toml `measured_ecosystems`)."""
    if not role:
        return set()
    from .base import _FLOORS_FILE, _table
    roles, _ = _table(os.environ.get("SSVC_FLOORS_FILE") or str(_FLOORS_FILE))
    return set((roles.get(role) or {}).get("measured_ecosystems") or [])


def nr_held(ecosystem: str, role: str = "") -> bool:
    return ecosystem in unmeasured_ecosystems() and ecosystem not in measured_for(role)


def guard_not_reachable(verdict, u: Usage, role: str = ""):
    """Guards for summary-only judges; each downgrades to unsure, so the cascade
    escalates to a judge that reads the code (it never flips a verdict).

    - not_reachable on an open-world summary (dynamic access): absence of symbol
      mentions proves nothing.
    - reachable when every vulnerable-symbol mention is in test code: the summary
      holds no runtime evidence for it.
    """
    from .base import Verdict
    if verdict == Verdict.NOT_REACHABLE and nr_held(u.ecosystem, role):
        return Verdict.UNSURE, (f"not_reachable held: no measured floor for {u.ecosystem} yet "
                                "(the model's not_reachable is kept here for calibration)")
    if verdict == Verdict.NOT_REACHABLE and not u.closed_world:
        return Verdict.UNSURE, "not_reachable downgraded: pre-pass found dynamic access (open world)"
    if (verdict == Verdict.REACHABLE and u.symbol_sites
            and all(s.endswith("(test code)") for s in u.symbol_sites)):
        return Verdict.UNSURE, "reachable downgraded: vulnerable symbol only mentioned in test code"
    return verdict, ""

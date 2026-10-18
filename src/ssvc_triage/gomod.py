"""Go modules: `go.mod` + `go.sum`, read as data.

Nothing is built or run here. What the files give us:

- the main module's `go.mod`: since Go 1.17 it lists every module the build needs
  (`// indirect` marks the ones no package of the main module imports directly), plus
  `replace` directives. That list is the build list we grade.
- `go.sum`: an `h1:` hash per module zip and per module `go.mod`.

The module graph (which module requires which) is not in either file. With
SSVC_GO_PROXY_MODS=1 (the default unless offline) each listed module's own `go.mod` is
fetched from the module proxy (only the module path and version leave the machine),
checked against its `go.sum` hash, cached, and parsed as data; an unverifiable file is
dropped, never used. Without them, chains are just root -> module.

Go has no dev dependencies: a module used only by `_test.go` files is still in the build
list. The pre-pass marks test-only import sites, and govulncheck leaves tests out.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

PROXY = os.environ.get("SSVC_GO_PROXY", "https://proxy.golang.org").rstrip("/")


@dataclass(frozen=True)
class Require:
    path: str
    version: str
    indirect: bool = False


@dataclass
class GoMod:
    module: str = ""
    go: str = ""
    toolchain: str = ""
    requires: list[Require] = field(default_factory=list)
    # old path -> (new path, new version); new version "" = a local directory
    replaces: dict[str, tuple[str, str]] = field(default_factory=dict)


_LINE = re.compile(r"^\s*(\S+)\s+(\S+)(.*)$")


def _unquote(s: str) -> str:
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"`" else s


def parse_gomod(text: str) -> GoMod:
    """The directives we need, from go.mod text (blocks and single lines)."""
    m, block = GoMod(), ""
    for raw in text.splitlines():
        comment = raw.partition("//")[2].strip()
        line = raw.partition("//")[0].strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = ""
                continue
            verb, rest = block, line
        elif line.endswith("(") and len(line.split()) == 2:
            block = line.split()[0]
            continue
        else:
            verb, _, rest = line.partition(" ")
            rest = rest.strip()
        if verb == "module":
            m.module = _unquote(rest)
        elif verb == "go":
            m.go = rest
        elif verb == "toolchain":
            m.toolchain = rest
        elif verb == "require":
            p = rest.split()
            if len(p) >= 2:
                m.requires.append(Require(_unquote(p[0]), p[1], "indirect" in comment.split(";")[0].split()))
        elif verb == "replace" and "=>" in rest:
            old, new = (s.split() for s in rest.split("=>", 1))
            if old and new:
                m.replaces[_unquote(old[0])] = (_unquote(new[0]), new[1] if len(new) > 1 else "")
    return m


def parse_gosum(text: str) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
    """(zip hashes, go.mod hashes), each keyed on (module path, version)."""
    zips, mods = {}, {}
    for ln in text.splitlines():
        p = ln.split()
        if len(p) != 3 or not p[2].startswith("h1:"):
            continue
        if p[1].endswith("/go.mod"):
            mods[(p[0], p[1][: -len("/go.mod")])] = p[2]
        else:
            zips[(p[0], p[1])] = p[2]
    return zips, mods


def escape(path: str) -> str:
    """Module path escaping for proxy URLs and the module cache: upper case -> !lower."""
    return re.sub(r"[A-Z]", lambda c: "!" + c.group(0).lower(), path)


def gomod_h1(data: bytes) -> str:
    """go.sum's `/go.mod h1:` hash of a go.mod file (dirhash Hash1 over one file named go.mod)."""
    summary = f"{hashlib.sha256(data).hexdigest()}  go.mod\n".encode()
    return "h1:" + base64.b64encode(hashlib.sha256(summary).digest()).decode()


def _cache() -> Path:
    return Path(os.environ.get("SSVC_GO_MOD_CACHE", "~/.cache/ssvc-triage/gomodfiles")).expanduser()


def fetch_gomod(path: str, version: str, want_h1: str, *, offline: bool = False) -> str | None:
    """A dependency's go.mod, only if it matches its go.sum hash (cached once verified)."""
    if not want_h1:
        return None
    f = _cache() / escape(path) / f"{version}.mod"
    if f.is_file() and gomod_h1(f.read_bytes()) == want_h1:
        return f.read_text(errors="replace")
    if offline or os.environ.get("SSVC_GO_PROXY_MODS", "1") in ("0", "false", "no", ""):
        return None
    url = f"{PROXY}/{escape(path)}/@v/{escape(version)}.mod"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ssvc-triage"})
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 — fixed proxy, data only
            data = resp.read(2_000_000)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("go.mod %s@%s: %s", path, version, exc)
        return None
    if gomod_h1(data) != want_h1:
        logger.warning("go.mod %s@%s does not match go.sum; ignored", path, version)
        return None
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(data)
    return data.decode(errors="replace")


@dataclass
class Module:
    path: str                 # the path the code imports
    version: str
    indirect: bool
    source: tuple[str, str]   # (path, version) actually fetched: differs under `replace`
    local: bool = False       # replaced by a directory: not a registry module

    @property
    def id(self) -> str:
        return f"{self.path}@{self.version}"


@dataclass
class Build:
    root: Path
    main: GoMod
    modules: dict[str, Module]                 # import path -> module
    edges: dict[str, tuple[str, ...]]          # module id -> module ids (from fetched go.mods)
    sums: dict[tuple[str, str], str] = field(default_factory=dict)


def load(repo: Path, *, offline: bool = False, graph: bool = True) -> Build | None:
    gm = Path(repo) / "go.mod"
    if not gm.is_file():
        return None
    main = parse_gomod(gm.read_text(errors="replace"))
    gs = Path(repo) / "go.sum"
    zips, mods = parse_gosum(gs.read_text(errors="replace")) if gs.is_file() else ({}, {})
    modules = {}
    for r in main.requires:
        new, nv = main.replaces.get(r.path, (r.path, r.version))
        local = new.startswith((".", "/")) and not nv
        modules[r.path] = Module(r.path, r.version, r.indirect, (new, nv or r.version), local)
    edges: dict[str, tuple[str, ...]] = {}
    if graph:
        for m in modules.values():
            if m.local:
                continue
            text = fetch_gomod(*m.source, mods.get(m.source, ""), offline=offline)
            if text is None:
                continue
            edges[m.id] = tuple(modules[q.path].id for q in parse_gomod(text).requires
                                if q.path in modules and q.path != m.path)
    return Build(Path(repo), main, modules, edges, zips)


__all__ = ["parse_gomod", "parse_gosum", "gomod_h1", "escape", "fetch_gomod", "load", "Build", "Module", "GoMod"]

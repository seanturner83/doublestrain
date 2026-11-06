"""PHP Composer projects: `composer.lock` + the `composer.json` beside it, read as data.

Nothing is installed or run (no `composer`: it executes plugins and scripts, and the code
is untrusted). What the files give us:

- `composer.lock`: every resolved package under `packages` (what `composer install
  --no-dev` installs) or `packages-dev` (only reached through `require-dev`), each with
  its version, its own `require` (the graph's edges), what it `replace`s or `provide`s,
  its `autoload` namespaces (how PHP code names it: `use Monolog\\Logger;`), and where it
  came from: a `source` (git URL + the commit it is pinned to) and a `dist` (an archive
  URL, with a `shasum` that is usually empty for GitHub zipballs).
- `composer.json`: the app's own `require` / `require-dev` (the direct dependencies).

Requirements on the platform (`php`, `ext-*`, `lib-*`, `composer-*`) are not packages.
A package with a `path` dist is the app's own code (a monorepo package), not a published
version: it is kept in the graph but never queried.

Several locks: an app can keep one per bundled component (Nextcloud's `3rdparty/`,
`apps/*/`). Every `composer.lock` up to three directories deep is read and merged; a lock
under a tooling directory (`vendor-bin/`, `tools/`, `tests/`, `build/`) only installs dev
tools, so all of its packages count as dev.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_SKIP = {".git", "node_modules", "vendor", "3rdparty-dev", "var", "cache"}
_DEV_DIRS = {"vendor-bin", "tools", "tests", "test", "build", "dev", "ci", ".github"}
_MAX_DEPTH = 3
_PLATFORM = re.compile(r"^(?:php(?:-64bit|-ipv6|-zts|-debug)?|hhvm|ext-.+|lib-.+|composer(?:-plugin|-runtime)?-api|composer)$",
                       re.I)


def normalize(name: str) -> str:
    """Composer package names are case-insensitive `vendor/package`."""
    return name.strip().lower()


def version_of(raw: str) -> str:
    """The version OSV knows: Composer locks write tags as they are (`v1.2.3`); OSV's
    Packagist ranges drop the `v`."""
    v = (raw or "").strip()
    return v[1:] if re.match(r"^v\d", v) else v


@dataclass(frozen=True)
class Pkg:
    name: str
    version: str
    dev: bool = False
    requires: tuple[str, ...] = ()        # normalized package names (platform requirements dropped)
    replaces: tuple[str, ...] = ()        # names this package stands in for (replace + provide)
    namespaces: tuple[str, ...] = ()      # autoload psr-4 / psr-0 prefixes, without the trailing `\`
    git_url: str = ""
    git_ref: str = ""
    dist_url: str = ""
    dist_sha1: str = ""
    local: bool = False                   # a `path` package: the app's own code

    @property
    def id(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Lock:
    root: Path
    files: list[str]                                  # lock paths, relative to root
    pkgs: dict[str, Pkg]                              # id -> package
    prod_roots: set[str] = field(default_factory=set)
    dev_roots: set[str] = field(default_factory=set)
    edges: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def runtime(self) -> set[str]:
        """Ids `composer install --no-dev` installs: Composer already split the lock by
        reachability from `require` (`packages`) versus only `require-dev` (`packages-dev`)."""
        return {i for i, p in self.pkgs.items() if not p.dev}

    def namespaces_of(self, name: str) -> list[str]:
        n = normalize(name)
        return sorted({ns for p in self.pkgs.values() if p.name == n for ns in p.namespaces}, key=len, reverse=True)


def lock_files(repo: Path) -> list[Path]:
    """Every composer.lock at most three directories below `repo` (not under vendor/)."""
    repo = Path(repo)
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        rel = Path(dirpath).relative_to(repo)
        depth = len(rel.parts)
        dirnames[:] = [d for d in dirnames if d not in _SKIP and not d.startswith(".") and depth < _MAX_DEPTH]
        if "composer.lock" in filenames:
            out.append(Path(dirpath) / "composer.lock")
    return sorted(out, key=lambda p: (len(p.relative_to(repo).parts), str(p)))


def _namespaces(autoload: dict) -> tuple[str, ...]:
    out = []
    for kind in ("psr-4", "psr-0"):
        for prefix in (autoload or {}).get(kind) or {}:
            p = str(prefix).strip("\\").strip()
            if p and p not in out:
                out.append(p)
    return tuple(out)


def _pkg(meta: dict, dev: bool) -> Pkg | None:
    name, version = normalize(meta.get("name") or ""), str(meta.get("version") or "")
    if "/" not in name or not version:
        return None
    src, dist = meta.get("source") or {}, meta.get("dist") or {}
    req = tuple(sorted({normalize(r) for r in meta.get("require") or {} if not _PLATFORM.match(r) and "/" in r}))
    rep = tuple(sorted({normalize(r) for k in ("replace", "provide") for r in meta.get(k) or {} if "/" in r}))
    git_ref = str(src.get("reference") or "") if src.get("type") == "git" else ""
    return Pkg(name, version_of(version), dev, req, rep, _namespaces(meta.get("autoload") or {}),
               git_url=str(src.get("url") or "") if git_ref else "", git_ref=git_ref,
               dist_url=str(dist.get("url") or "") if dist.get("type") in ("zip", "tar") else "",
               dist_sha1=str(dist.get("shasum") or "").lower(), local=dist.get("type") == "path")


@lru_cache(maxsize=16)
def _load(root: str, files: tuple[tuple[str, float], ...]) -> Lock | None:
    rootp = Path(root)
    pkgs: dict[str, Pkg] = {}
    prod_roots, dev_roots, used = set(), set(), []
    per_lock: list[tuple[dict[str, str], set[str], set[str]]] = []
    for rel, _mtime in files:
        lp = rootp / rel
        try:
            lock = json.loads(lp.read_text())
        except (OSError, ValueError):
            continue
        tooling = bool(_DEV_DIRS & {p.lower() for p in Path(rel).parts[:-1]})
        here: dict[str, str] = {}                        # name (and replaced names) -> id, in this lock
        for section, dev in (("packages", False), ("packages-dev", True)):
            for meta in lock.get(section) or []:
                p = _pkg(meta, dev or tooling)
                if p is None:
                    continue
                prev = pkgs.get(p.id)
                # the same package in two locks: production in either wins
                pkgs[p.id] = p if prev is None or (prev.dev and not p.dev) else prev
                here[p.name] = p.id
                for r in p.replaces:
                    here.setdefault(r, p.id)
        man_prod, man_dev = set(), set()
        try:
            man = json.loads((lp.parent / "composer.json").read_text())
            man_prod = {normalize(r) for r in man.get("require") or {} if "/" in r and not _PLATFORM.match(r)}
            man_dev = {normalize(r) for r in man.get("require-dev") or {} if "/" in r and not _PLATFORM.match(r)}
        except (OSError, ValueError, AttributeError):
            pass
        per_lock.append((here, man_prod, man_dev))
        if tooling:
            dev_roots |= {here[n] for n in man_prod | man_dev if n in here}
        else:
            prod_roots |= {here[n] for n in man_prod if n in here}
            dev_roots |= {here[n] for n in man_dev if n in here}
        used.append(rel)
    if not used:
        return None
    edges: dict[str, tuple[str, ...]] = {}
    for here, _, _ in per_lock:
        for i in set(here.values()):
            p = pkgs[i]
            kids = tuple(sorted({here[r] for r in p.requires if r in here and here[r] != i}))
            edges[i] = tuple(sorted(set(edges.get(i, ())) | set(kids)))
    # the app's own path packages are app code: what they require is a direct dependency
    # (Mautic's root requires only its `app/` package, which requires everything else)
    for roots in (prod_roots, dev_roots):
        todo = [i for i in roots if pkgs[i].local]
        while todo:
            for c in edges.get(todo.pop(), ()):
                if c not in roots:
                    roots.add(c)
                    if pkgs[c].local:
                        todo.append(c)
    return Lock(rootp, used, pkgs, prod_roots, dev_roots - prod_roots, edges)


def load(repo: Path) -> Lock | None:
    repo = Path(repo).expanduser().resolve()
    fs = lock_files(repo)
    if not fs:
        return None
    return _load(str(repo), tuple((str(f.relative_to(repo)), f.stat().st_mtime) for f in fs))

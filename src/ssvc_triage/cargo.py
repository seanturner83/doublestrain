"""Cargo workspaces: `Cargo.lock` + every member's `Cargo.toml`, read as data.

Nothing is built or run (no `cargo metadata`: it reads remote indexes and the code is
untrusted). What the files give us:

- `Cargo.lock` (v3/v4): every resolved package with its source, checksum and the
  packages it depends on. It does NOT say which edges are dev or build edges, and it is
  feature-independent: an optional dependency some feature enables is listed even when
  no build turns that feature on. So a locked crate may not be compiled in; we keep it
  (grading it is the conservative side).
- each member's `Cargo.toml`: which of a member's edges are [dependencies],
  [dev-dependencies] or [build-dependencies] (also under [target.'cfg'...]), with
  renames (`foo = { package = "bar" }`) and `workspace = true` inheritance.

A crate is `runtime` when a normal edge from a member reaches it, `build` when only
build edges do (build.rs / build tooling: graded like an npm devDependency), else `dev`.
Edges out of non-member crates are taken from the lockfile as they are (normal and
build edges together), so anything a dependency pulls in counts as runtime.

Members are packages without a `source` in the lockfile whose manifest is under the
workspace root. Git and path sources other than members have no checksum and are
reported, not graded.
"""
from __future__ import annotations

import os
import tomllib
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_SKIP = {"target", ".git", "node_modules", "vendor"}
KINDS = ("dependencies", "dev-dependencies", "build-dependencies")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


@dataclass(frozen=True)
class Crate:
    name: str
    version: str
    source: str = ""          # "" for members and path crates
    checksum: str = ""
    deps: tuple[str, ...] = ()   # node ids

    @property
    def id(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def registry(self) -> bool:
        return self.source.startswith("registry+") or self.source.startswith("sparse+")


@dataclass
class Workspace:
    root: Path
    crates: dict[str, Crate]                         # id -> crate
    members: dict[str, dict[str, set[str]]]          # member id -> kind -> dep ids
    member_dirs: dict[str, Path] = field(default_factory=dict)
    renames: dict[str, str] = field(default_factory=dict)   # dep package name -> local ident used in code
    # (manifest path relative to root, table, key, package name, spec): every dependency
    # declaration, so a matcher can see `features = [...]` / `default-features = false`
    decls: list[tuple[str, str, str, str, dict]] = field(default_factory=list)

    def declarations(self, names) -> list[str]:
        """How the members declare these packages: the feature switches they set."""
        out = []
        for path, table, key, pkg, spec in self.decls:
            if pkg in names:
                bits = [f'version "{spec["version"]}"'] if spec.get("version") else []
                if spec.get("default-features") is False or spec.get("default_features") is False:
                    bits.append("default-features = false")
                if spec.get("features"):
                    bits.append(f"features = {list(spec['features'])}")
                if spec.get("optional"):
                    bits.append("optional")
                out.append(f"{path} [{table}] {key}" + (f" = {pkg}" if key != pkg else "")
                           + (": " + ", ".join(bits) if bits else ""))
        return out

    def kind_of(self) -> dict[str, str]:
        """id -> runtime | build | dev for every non-member crate the members reach."""
        out: dict[str, str] = {}
        for kind in ("runtime", "build", "dev"):
            starts = [d for m in self.members.values()
                      for d in m[{"runtime": "dependencies", "build": "build-dependencies",
                                  "dev": "dev-dependencies"}[kind]]]
            seen, q = set(), deque(starts)
            while q:
                c = q.popleft()
                if c in seen:
                    continue
                seen.add(c)
                if c in self.members:      # a path dependency on another member: its normal edges
                    q.extend(self.members[c]["dependencies"])
                    continue
                out.setdefault(c, kind)
                q.extend(self.crates[c].deps if c in self.crates else ())
        return out

    def direct(self) -> dict[str, set[str]]:
        """kind -> ids that some member depends on directly."""
        return {k: {d for m in self.members.values() for d in m[k] if d not in self.members} for k in KINDS}


def _ref(ref: str, by_name: dict[str, list[Crate]]) -> str | None:
    """A lockfile dependency entry: "name", "name version" or "name version (source)"."""
    parts = ref.split(" ", 2)
    cands = by_name.get(parts[0], [])
    if len(parts) > 1:
        cands = [c for c in cands if c.version == parts[1]]
    if len(parts) > 2:
        src = parts[2].strip("()")
        cands = [c for c in cands if c.source == src] or cands
    return cands[0].id if len(cands) == 1 else (cands[0].id if cands else None)


def _manifests(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP and not d.startswith(".")]
        if "Cargo.toml" in filenames:
            yield Path(dirpath) / "Cargo.toml"


def _sections(man: dict):
    """(kind, table) for the top-level and every [target.*] dependency table."""
    for k in KINDS:
        yield k, man.get(k) or {}
    for t in (man.get("target") or {}).values():
        for k in KINDS:
            yield k, (t or {}).get(k) or {}


@lru_cache(maxsize=8)
def _load(lock_path: str, mtime: float) -> Workspace | None:
    root = Path(lock_path).parent
    try:
        lock = tomllib.loads(Path(lock_path).read_text())
    except (OSError, ValueError):
        return None
    raw = lock.get("package") or []
    plain = [Crate(p.get("name", ""), p.get("version", ""), p.get("source", ""), p.get("checksum", ""))
             for p in raw if p.get("name") and p.get("version")]
    by_name: dict[str, list[Crate]] = {}
    for c in plain:
        by_name.setdefault(c.name, []).append(c)
    crates = {}
    for p, c in zip([p for p in raw if p.get("name") and p.get("version")], plain):
        deps = tuple(i for r in p.get("dependencies") or [] if (i := _ref(r, by_name)))
        crates[c.id] = Crate(c.name, c.version, c.source, c.checksum, deps)

    ws_deps = {}
    try:
        top = tomllib.loads((root / "Cargo.toml").read_text())
        ws_deps = ((top.get("workspace") or {}).get("dependencies")) or {}
    except (OSError, ValueError):
        pass

    members, member_dirs, renames, decls = {}, {}, {}, []
    for mp in _manifests(root):
        try:
            man = tomllib.loads(mp.read_text())
        except (OSError, ValueError):
            continue
        pkg = man.get("package") or {}
        name = pkg.get("name")
        local = [c for c in by_name.get(name or "", []) if not c.source]
        if not local:
            continue
        mid = local[0].id
        kinds = {k: set() for k in KINDS}
        for kind, table in _sections(man):
            for key, spec in table.items():
                spec = spec if isinstance(spec, dict) else {"version": spec} if isinstance(spec, str) else {}
                if spec.get("workspace"):
                    w = ws_deps.get(key)
                    spec = {**(w if isinstance(w, dict) else {}), **{k: v for k, v in spec.items() if k != "workspace"}}
                pkg_name = spec.get("package") or key
                if pkg_name != key:
                    renames[pkg_name] = key.replace("-", "_")
                cands = [c.id for c in by_name.get(pkg_name, []) if c.id in crates[mid].deps]
                kinds[kind].update(cands)
                decls.append((str(mp.relative_to(root)), kind, key, pkg_name, spec))
        members[mid] = kinds
        member_dirs[mid] = mp.parent
    return Workspace(root, crates, members, member_dirs, renames, decls)


def load(repo: Path) -> Workspace | None:
    lock = Path(repo) / "Cargo.lock"
    return _load(str(lock), lock.stat().st_mtime) if lock.is_file() else None


def ident(name: str, ws: Workspace | None = None) -> str:
    """The name a crate goes by in Rust source (`serde-json` -> `serde_json`, or its rename)."""
    if ws and name in ws.renames:
        return ws.renames[name]
    return name.replace("-", "_")

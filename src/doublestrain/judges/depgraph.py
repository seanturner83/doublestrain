"""Dependency chains from an npm lockfile (or a Cargo workspace): how does the app pull
in a package?

For a transitive dependency the grep pre-pass only sees "not imported directly". The
chain (`app -> express@4.16.4 -> body-parser@1.18.3`) plus WHERE the app imports the
top-of-chain package is the evidence a summary-only judge needs to tell "reached via a
runtime framework the app uses everywhere" from "only under a build tool".

package-lock v2/v3 (`packages`) is resolved with Node's lookup rule: a dependency of
`node_modules/a/node_modules/b` resolves to the nearest `node_modules/<dep>` walking
up. v1 lockfiles (nested `dependencies`/`requires`) are resolved the same way over the
nested tree.
"""
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = ""


@dataclass(frozen=True)
class Graph:
    nodes: dict          # path -> {"name", "version", "dev", "integrity"}
    edges: dict          # path -> tuple of child paths
    direct: frozenset    # names of the app's direct deps
    dev_direct: frozenset


def _name_of(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def _resolve(pkgs: dict, from_path: str, dep: str) -> str | None:
    base = from_path
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in pkgs:
            return cand
        if not base:
            return None
        i = base.rfind("/node_modules/")
        base = base[:i] if i >= 0 else ""


def _v1_flatten(lock: dict) -> dict:
    """Turn a v1 nested tree into v2-style paths -> meta (with `dependencies` = requires)."""
    out = {ROOT: {"dependencies": {k: v.get("version") for k, v in lock.get("dependencies", {}).items()
                                   if not v.get("dev")},
                  "devDependencies": {k: v.get("version") for k, v in lock.get("dependencies", {}).items()
                                      if v.get("dev")}}}

    def walk(tree, prefix):
        for name, meta in (tree or {}).items():
            p = f"{prefix}node_modules/{name}"
            out[p] = {"version": meta.get("version"), "dev": meta.get("dev", False),
                      "integrity": meta.get("integrity"),
                      "dependencies": meta.get("requires", {})}
            walk(meta.get("dependencies"), p + "/")
    walk(lock.get("dependencies"), "")
    return out


@lru_cache(maxsize=8)
def _load(lock_path: str, mtime: float) -> Graph | None:
    try:
        lock = json.loads(Path(lock_path).read_text())
    except (OSError, ValueError):
        return None
    pkgs = lock.get("packages") or _v1_flatten(lock)
    root = pkgs.get(ROOT, {})
    direct_prod = set(root.get("dependencies", {})) | set(root.get("optionalDependencies", {}))
    direct_dev = set(root.get("devDependencies", {})) - direct_prod
    nodes = {p: {"name": m.get("name") or _name_of(p), "version": m.get("version"), "dev": bool(m.get("dev")),
                 "integrity": m.get("integrity") or ""}
             for p, m in pkgs.items() if p and not m.get("link")}
    edges = {}
    for p, m in pkgs.items():
        if p and p not in nodes:
            continue
        # An installed peer is loaded by the package that declares it: sequelize requires
        # its dialect driver (sqlite3, pg, ...) by name, which is only listed in
        # peerDependencies / peerDependenciesMeta. _resolve drops peers that aren't installed.
        deps = {**m.get("dependencies", {}), **m.get("optionalDependencies", {}),
                **m.get("peerDependencies", {}), **m.get("peerDependenciesMeta", {})}
        if p == ROOT:
            deps.update(root.get("devDependencies", {}))
        edges[p] = tuple(c for d in deps if (c := _resolve(pkgs, p, d)) and c in nodes)
    return Graph(nodes, edges, frozenset(direct_prod), frozenset(direct_dev))


def _from_cargo(repo: Path) -> Graph | None:
    """The same Graph over a Cargo workspace: node ids are `name@version`, ROOT's edges
    are every member's direct dependencies (members themselves are folded into ROOT),
    and `dev` marks crates reached only through dev- or build-dependencies."""
    from .. import cargo
    ws = cargo.load(repo)
    if ws is None:
        return None
    kinds, direct = ws.kind_of(), ws.direct()
    nodes = {i: {"name": c.name, "version": c.version, "dev": kinds[i] != "runtime", "integrity": c.checksum}
             for i, c in ws.crates.items() if i in kinds}
    edges = {i: tuple(d for d in ws.crates[i].deps if d in nodes) for i in nodes}
    edges[ROOT] = tuple(sorted({d for k in direct.values() for d in k if d in nodes}))
    prod = {nodes[d]["name"] for d in direct["dependencies"] if d in nodes}
    dev = {nodes[d]["name"] for k in ("dev-dependencies", "build-dependencies") for d in direct[k] if d in nodes}
    return Graph(nodes, edges, frozenset(prod), frozenset(dev - prod))


def _from_go(repo: Path) -> Graph | None:
    """The Graph over a Go build list: ROOT's edges are go.mod's direct requires, module
    edges come from each module's own (go.sum-verified) go.mod; `gomod.load`."""
    from .. import gomod
    b = gomod.load(repo)
    if b is None:
        return None
    nodes = {m.id: {"name": m.path, "version": m.version, "dev": False, "integrity": b.sums.get(m.source, "")}
             for m in b.modules.values()}
    edges = {i: tuple(d for d in b.edges.get(i, ()) if d in nodes) for i in nodes}
    direct = {m.path for m in b.modules.values() if not m.indirect}
    edges[ROOT] = tuple(sorted(m.id for m in b.modules.values() if not m.indirect))
    # a module whose parents' go.mod files couldn't be fetched and verified has no known
    # path: hang it off ROOT, so it is still in the graph (go.mod lists it, so it builds)
    seen, todo = set(), [ROOT]
    while todo:
        for d in edges.get(todo.pop(), ()):
            if d not in seen:
                seen.add(d)
                todo.append(d)
    edges[ROOT] += tuple(sorted(set(nodes) - seen))
    return Graph(nodes, edges, frozenset(direct), frozenset())


def _from_pypi(repo: Path) -> Graph | None:
    """The Graph over a Python lock (`pylock`): ROOT's edges are the direct dependencies
    (every package when the lock has no roots, e.g. a plain pin list)."""
    from .. import pylock
    lock = pylock.load(repo)
    if lock is None:
        return None
    runtime = lock.runtime()
    nodes = {i: {"name": p.name, "version": p.version, "dev": i not in runtime,
                 "integrity": ",".join(p.hashes)} for i, p in lock.pkgs.items()}
    edges = {i: tuple(c for c in lock.edges.get(i, ()) if c in nodes) for i in nodes}
    roots = (lock.prod_roots | lock.dev_roots) or set(nodes)
    edges[ROOT] = tuple(sorted(r for r in roots if r in nodes))
    prod = {lock.pkgs[i].name for i in lock.prod_roots if i in lock.pkgs} or {p.name for p in lock.pkgs.values()}
    dev = {lock.pkgs[i].name for i in lock.dev_roots if i in lock.pkgs}
    return Graph(nodes, edges, frozenset(prod), frozenset(dev - prod))


def load(repo: Path, ecosystem: str = "npm") -> Graph | None:
    if ecosystem == "pypi":
        return _from_pypi(Path(repo))
    if ecosystem == "cargo":
        return _from_cargo(Path(repo))
    if ecosystem == "go":
        return _from_go(Path(repo))
    lock = Path(repo) / "package-lock.json"
    return _load(str(lock), lock.stat().st_mtime) if lock.is_file() else None


def chains(g: Graph, name: str, version: str = "", limit: int = 3) -> list[list[str]]:
    """Up to `limit` shortest root->target chains (as node paths), one per distinct
    top-level entry point. Target = every installed copy of name (@version if given)."""
    targets = {p for p, n in g.nodes.items() if n["name"] == name and (not version or n["version"] == version)}
    if not targets:
        return []
    out, seen_tops = [], set()
    for top in g.edges.get(ROOT, ()):
        if len(out) >= limit:
            break
        # BFS from this top-level dep, so each chain shows a different entry point
        prev, q, hit = {top: None}, deque([top]), None
        while q:
            p = q.popleft()
            if p in targets:
                hit = p
                break
            for c in g.edges.get(p, ()):
                if c not in prev:
                    prev[c] = p
                    q.append(c)
        if hit and top not in seen_tops:
            path, p = [], hit
            while p is not None:
                path.append(p)
                p = prev[p]
            out.append(path[::-1])
            seen_tops.add(top)
    out.sort(key=len)
    return out


def describe(g: Graph, chain: list[str]) -> str:
    parts = [f"{g.nodes[p]['name']}@{g.nodes[p]['version']}" for p in chain]
    top = g.nodes[chain[0]]["name"]
    kind = "devDependency" if top in g.dev_direct else "dependency"
    return f"app -> " + " -> ".join(parts) + f"   (top-level {kind} `{top}`)"


def top_level(g: Graph, chain: list[str]) -> str:
    return g.nodes[chain[0]]["name"]

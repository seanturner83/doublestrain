"""Inventory: what's installed, and who requires it with which declared range.

Inputs (`load`): a CycloneDX or SPDX JSON SBOM, or an app directory with
package-lock.json (v1/v2/v3). npm components only for now; others are counted and
skipped. Each Component lists its parents and the range each parent declares for it.
Ranges come from the lockfile when there is one; an SBOM doesn't carry them, so they
are filled from the parent's own registry entry (`fill_ranges`), which is where npm got
them in the first place. The app's own ranges (parent "") come from package.json.

An SBOM is input DATA: parsed as JSON with a size cap; names are validated (registry.py)
before anything is fetched for them.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from .judges.depgraph import ROOT, _name_of, _resolve, _v1_flatten

MAX_SBOM = 100 << 20
APP = ""                               # the parent name for the app itself


@dataclass
class Parent:
    name: str                          # "" = the app
    version: str
    range: str | None                  # declared range for the child; None = unknown


@dataclass
class Component:
    name: str
    version: str
    ecosystem: str = "npm"
    direct: bool = False
    dev: bool = False
    parents: list[Parent] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Inventory:
    source: str
    components: dict[str, Component] = field(default_factory=dict)   # key -> Component
    skipped: dict[str, int] = field(default_factory=dict)            # ecosystem -> count
    graph: bool = True                                               # False: SBOM without edges

    def add(self, c: Component) -> Component:
        have = self.components.get(c.key)
        if have is None:
            self.components[c.key] = c
            return c
        have.direct |= c.direct
        have.dev &= c.dev
        for p in c.parents:
            if p not in have.parents:
                have.parents.append(p)
        return have


# --- lockfile ---------------------------------------------------------------------
def from_lockfile(repo: Path) -> Inventory:
    repo = Path(repo)
    lock = json.loads((repo / "package-lock.json").read_text())
    pkgs = lock.get("packages") or _v1_flatten(lock)
    root_ranges = dict(pkgs.get(ROOT, {}).get("dependencies") or {})
    if not lock.get("packages"):                          # v1 root carries versions, not ranges
        try:
            pj = json.loads((repo / "package.json").read_text())
            root_ranges = {**(pj.get("dependencies") or {}), **(pj.get("optionalDependencies") or {}),
                           **(pj.get("devDependencies") or {})}
        except (OSError, ValueError):
            root_ranges = {}
    else:
        r = pkgs.get(ROOT, {})
        root_ranges = {**(r.get("dependencies") or {}), **(r.get("optionalDependencies") or {}),
                       **(r.get("devDependencies") or {})}
    inv = Inventory(source=str(repo / "package-lock.json"))
    meta_of = {p: m for p, m in pkgs.items() if p and not m.get("link")}
    local = {p for p in meta_of if "node_modules/" not in p}     # workspace packages: the app's own
    for p, m in meta_of.items():
        name = m.get("name") or _name_of(p)
        if not m.get("version") or p in local:
            continue
        inv.add(Component(name, m["version"], dev=bool(m.get("dev")),
                          direct=(p == f"node_modules/{name}" and name in root_ranges)))
    for parent_path, m in [(ROOT, pkgs.get(ROOT, {})), *meta_of.items()]:
        deps = {**(m.get("dependencies") or {}), **(m.get("optionalDependencies") or {}),
                **(m.get("peerDependencies") or {})}
        if parent_path == ROOT:
            deps = root_ranges
        if not isinstance(deps, dict):
            continue
        is_app = parent_path == ROOT or parent_path in local
        pname = APP if is_app else (m.get("name") or _name_of(parent_path))
        pver = "" if is_app else str(m.get("version") or "")
        for dep, rng in deps.items():
            child = _resolve(pkgs, parent_path, dep)
            cm = meta_of.get(child) if child else None
            if not cm or not cm.get("version") or child in local:
                continue
            c = inv.components.get(f"{cm.get('name') or _name_of(child)}@{cm['version']}")
            if c is not None:
                par = Parent(pname, pver, rng if isinstance(rng, str) else None)
                if par not in c.parents:
                    c.parents.append(par)
    return inv


# --- SBOMs ------------------------------------------------------------------------
_PURL = re.compile(r"^pkg:([A-Za-z0-9.+-]+)/(.+?)@([^?#]+)")


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """pkg:npm/%40scope/name@1.2.3 -> ("npm", "@scope/name", "1.2.3")."""
    m = _PURL.match(purl or "")
    if not m:
        return None
    name = "/".join(urllib.parse.unquote(p) for p in m.group(2).split("/"))
    return m.group(1).lower(), name, urllib.parse.unquote(m.group(3))


def _read(path: Path) -> dict:
    if path.stat().st_size > MAX_SBOM:
        raise ValueError(f"SBOM over {MAX_SBOM >> 20} MiB")
    try:
        d = json.loads(path.read_text())
    except RecursionError as exc:
        raise ValueError("SBOM JSON nested too deeply") from exc
    if not isinstance(d, dict):
        raise ValueError("SBOM is not a JSON object")
    return d


def from_cyclonedx(d: dict, source: str) -> Inventory:
    inv = Inventory(source=source)
    by_ref: dict[str, Component] = {}

    def walk(comps):
        for c in comps or []:
            if not isinstance(c, dict):
                continue
            pu = parse_purl(c.get("purl", ""))
            if pu and pu[0] == "npm":
                comp = inv.add(Component(pu[1], pu[2], dev=c.get("scope") == "excluded"))
                by_ref[c.get("bom-ref") or c.get("purl")] = comp
            elif pu:
                inv.skipped[pu[0]] = inv.skipped.get(pu[0], 0) + 1
            walk(c.get("components"))
    walk(d.get("components"))
    root = ((d.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if root in by_ref:                       # the app listed among its own components
        app = by_ref.pop(root)
        inv.components.pop(app.key, None)
    for dep in d.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        ref = dep.get("ref")
        parent = by_ref.get(ref)
        for child_ref in dep.get("dependsOn") or []:
            child = by_ref.get(child_ref)
            if child is None:
                continue
            if ref == root:
                child.direct = True
                child.parents.append(Parent(APP, "", None))
            elif parent is not None:
                p = Parent(parent.name, parent.version, None)
                if p not in child.parents:
                    child.parents.append(p)
    inv.graph = bool(d.get("dependencies"))
    return inv


def from_spdx(d: dict, source: str) -> Inventory:
    inv = Inventory(source=source)
    by_id: dict[str, Component] = {}
    # the described package is the app, even when it carries an npm purl: never send its
    # (possibly private) name to the registry, or take ranges from a squatter of it
    roots = set(d.get("documentDescribes") or []) | {
        r.get("relatedSpdxElement") for r in d.get("relationships") or []
        if isinstance(r, dict) and r.get("relationshipType") == "DESCRIBES"}
    for p in d.get("packages") or []:
        if not isinstance(p, dict) or p.get("SPDXID") in roots:
            continue
        purls = [r.get("referenceLocator") for r in p.get("externalRefs") or []
                 if isinstance(r, dict) and r.get("referenceType") == "purl"]
        pu = next((x for x in map(parse_purl, purls) if x), None)
        if pu and pu[0] == "npm":
            by_id[p.get("SPDXID")] = inv.add(Component(pu[1], pu[2]))
        elif pu:
            inv.skipped[pu[0]] = inv.skipped.get(pu[0], 0) + 1
    for r in d.get("relationships") or []:
        if not isinstance(r, dict):
            continue
        a, b, kind = r.get("spdxElementId"), r.get("relatedSpdxElement"), r.get("relationshipType")
        if kind in ("DEPENDS_ON", "CONTAINS"):
            parent_id, child_id = a, b
        elif kind in ("DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF"):
            parent_id, child_id = b, a
        elif kind == "DEV_DEPENDENCY_OF":
            parent_id, child_id = b, a
            if child_id in by_id:
                by_id[child_id].dev = True
        else:
            continue
        child = by_id.get(child_id)
        if child is None:
            continue
        if parent_id in roots:
            child.direct = True
            child.parents.append(Parent(APP, "", None))
        elif parent_id in by_id:
            par = by_id[parent_id]
            p = Parent(par.name, par.version, None)
            if p not in child.parents:
                child.parents.append(p)
    inv.graph = any(c.parents for c in inv.components.values())
    return inv


def load(path: str | Path) -> Inventory:
    path = Path(path).expanduser()
    if path.is_dir():
        return from_lockfile(path)
    if path.name == "package-lock.json":
        return from_lockfile(path.parent)
    d = _read(path)
    if d.get("bomFormat") == "CycloneDX":
        return from_cyclonedx(d, str(path))
    if str(d.get("spdxVersion", "")).startswith("SPDX-"):
        return from_spdx(d, str(path))
    raise ValueError(f"{path}: not a CycloneDX or SPDX JSON SBOM, or an app with package-lock.json")


def fill_ranges(inv: Inventory, packuments: dict[str, dict | None]) -> int:
    """Fill unknown parent ranges from each parent's registry entry. Returns how many."""
    n = 0
    for c in inv.components.values():
        for p in c.parents:
            if p.range is not None or p.name == APP:
                continue
            meta = ((packuments.get(p.name) or {}).get("versions") or {}).get(p.version) or {}
            for k in ("dependencies", "optionalDependencies", "peerDependencies"):
                rng = (meta.get(k) or {}).get(c.name) if isinstance(meta.get(k), dict) else None
                if isinstance(rng, str):
                    p.range, n = rng, n + 1
                    break
    return n

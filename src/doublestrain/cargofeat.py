"""cargofeat: which locked crates are compiled into the deployed binary (rs1).

Cargo.lock is feature-independent: an optional dependency some feature could enable is
listed even when no build turns it on. rs1's not_reachable labels leaned on exactly that:
quinn is locked in every app through reqwest's weak `quinn?/ring` feature with http3 off;
rsa through sqlx's `sqlx-mysql?/...` with mysql off; Kanidm's lock carries the CLI and the
PAM client, which the server image never builds. This replays Cargo's feature resolution
(resolver 2) over the manifests, reading them as data: nothing is built, no `cargo`, no
build script.

- Roots: the workspace packages the image builds (`imagedeps.cargo_builds`: -p / --bin /
  --path, --features, --no-default-features, --all-features). No Dockerfile `cargo build`:
  every member with all its features.
- Manifests: members' Cargo.toml from the checkout (workspace inheritance applied); every
  other crate's from its verified .crate (`pkgsrc.fetch_crate`, normalized by crates.io).
- Edges: normal dependencies only, in [dependencies] and in [target.'cfg(..)'] tables whose
  cfg holds on Linux (x86_64 or aarch64, gnu or musl). Build- and dev-dependencies and
  proc-macro crates run on the build host, not in the binary.
- Features: default + requested ones, `dep:x`, `x/f` (enables x), `x?/f` (only once x is on
  for another reason), implicit features of optional deps; unified per crate.

Widening only, so a crate counts as compiled whenever this can't tell: a crate whose
manifest can't be read (a git fork, a fetch refused by caps) has every locked dependency
compiled with all features; an unknown cfg predicate holds; a dependency that matches
several locked versions activates all of them; resolver 1 (edition < 2021, no
`resolver = "2"`) also unifies build-dependency features into the binary's crates.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tomllib
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from . import cargo, imagedeps, pkgsrc

logger = logging.getLogger(__name__)
RESOLVE_V = "1"
# targets the image may be built for; a cfg holds when any of them satisfies it
_TARGETS = [{"target_os": "linux", "target_family": "unix", "unix": True, "target_arch": arch,
             "target_env": env, "target_pointer_width": "64", "target_endian": "little",
             "target_vendor": "unknown", "target_has_atomic": None}
            for arch in ("x86_64", "aarch64") for env in ("gnu", "musl")]
_TRIPLES = re.compile(r"^(x86_64|aarch64)-unknown-linux-(gnu|musl)$")


# --- cfg(...) ----------------------------------------------------------------------------

def _cfg_tokens(s: str):
    return re.findall(r'"[^"]*"|[A-Za-z_][A-Za-z0-9_]*|[(),=]', s)


def _cfg_eval(tokens: list[str], i: int, t: dict) -> tuple[bool, int]:
    tok = tokens[i]
    if tok in ("all", "any", "not") and i + 1 < len(tokens) and tokens[i + 1] == "(":
        vals, i = [], i + 2
        while tokens[i] != ")":
            v, i = _cfg_eval(tokens, i, t)
            vals.append(v)
            if tokens[i] == ",":
                i += 1
        i += 1
        return (all(vals) if tok == "all" else any(vals) if tok == "any" else not vals[0]), i
    if i + 2 < len(tokens) and tokens[i + 1] == "=":
        key, val = tok, tokens[i + 2].strip('"')
        if key not in t or t[key] is None:
            return True, i + 3                # unknown key (feature = "x", target_feature): holds
        return t[key] == val, i + 3
    if tok in ("unix", "windows", "wasm", "test", "debug_assertions"):
        return (tok == "unix" or tok == "debug_assertions"), i + 1
    return True, i + 1                         # an unknown bare predicate holds


def target_ok(key: str) -> bool:
    """Does a [target.<key>] table apply to a Linux build (any of the image targets)?"""
    key = key.strip()
    if key.startswith("cfg(") and key.endswith(")"):
        try:
            toks = _cfg_tokens(key[4:-1])
            return any(_cfg_eval(toks, 0, t)[0] for t in _TARGETS)
        except (IndexError, ValueError):
            return True
    return bool(_TRIPLES.match(key)) or "linux" in key


# --- manifests ---------------------------------------------------------------------------

@dataclass
class Dep:
    key: str                  # the name features refer to (a rename's local key)
    package: str              # the crate's real name
    optional: bool
    default: bool
    features: tuple[str, ...]
    req: str = ""


@dataclass
class Manifest:
    deps: list[Dep] = field(default_factory=list)         # normal deps that apply to Linux
    build_deps: list[Dep] = field(default_factory=list)
    features: dict[str, list[str]] = field(default_factory=dict)
    proc_macro: bool = False
    known: bool = True


def _spec(key: str, spec, ws_deps: dict) -> Dep:
    spec = spec if isinstance(spec, dict) else {"version": spec} if isinstance(spec, str) else {}
    if spec.get("workspace"):
        w = ws_deps.get(key)
        w = w if isinstance(w, dict) else {"version": w} if isinstance(w, str) else {}
        feats = list(w.get("features") or []) + list(spec.get("features") or [])
        spec = {**w, **{k: v for k, v in spec.items() if k != "workspace"}, "features": feats}
    default = not (spec.get("default-features") is False or spec.get("default_features") is False)
    return Dep(key, spec.get("package") or key, bool(spec.get("optional")), default,
               tuple(spec.get("features") or ()), str(spec.get("version") or ""))


def parse_manifest(text: str, ws_deps: dict | None = None) -> Manifest:
    man = tomllib.loads(text)
    ws_deps = ws_deps or {}
    m = Manifest(features={k: list(v) for k, v in (man.get("features") or {}).items()},
                 proc_macro=bool((man.get("lib") or {}).get("proc-macro") or (man.get("lib") or {}).get("proc_macro")))
    tables = [("dependencies", man.get("dependencies") or {}), ("build-dependencies", man.get("build-dependencies") or {})]
    for tkey, t in (man.get("target") or {}).items():
        if target_ok(tkey):
            tables += [("dependencies", (t or {}).get("dependencies") or {}),
                       ("build-dependencies", (t or {}).get("build-dependencies") or {})]
    for kind, table in tables:
        for key, spec in table.items():
            (m.deps if kind == "dependencies" else m.build_deps).append(_spec(key, spec, ws_deps))
    return m


# --- resolution --------------------------------------------------------------------------

@dataclass
class Resolution:
    compiled: set[str]                    # crate ids linked into the deployed binary
    host: set[str]                        # proc-macros / build-deps (run at build time only)
    opaque: set[str]                      # compiled, manifest unknown: all its locked deps compiled
    roots: list[str]
    features: dict[str, set[str]]

    def why_not(self, ws: cargo.Workspace, cid: str, mans: dict) -> str:
        """Why a locked crate isn't compiled: walk up through the uncompiled crates that
        depend on it to the compiled ones, and say how each declares the edge it doesn't take."""
        parents: dict[str, list[str]] = {}
        for pid, c in ws.crates.items():
            for d in c.deps:
                parents.setdefault(d, []).append(pid)
        seen, q, out = {cid}, deque([cid]), []
        while q and len(out) < 3:
            x = q.popleft()
            name = ws.crates[x].name
            via = "" if x == cid else f" (-> {cid})"
            for pid in parents.get(x, []):
                if pid in self.compiled:
                    m = mans.get(pid)
                    ds = [d for d in (m.deps if m else []) if d.package == name]
                    if not ds:
                        bd = [d for d in (m.build_deps if m else []) if d.package == name]
                        out.append(f"{pid} needs {x}{via} " + ("only as a build-dependency" if bd
                                   else "only on a target the image isn't built for (or as a dev-dependency)"))
                    elif all(d.optional for d in ds):
                        out.append(f"{pid} has `{ds[0].key}`{via} as an optional dependency no enabled feature "
                                   f"turns on (enabled: {', '.join(sorted(self.features.get(pid, ()))[:8]) or 'none'})")
                elif pid in self.host:
                    out.append(f"{x}{via} is a dependency of the build-time crate {pid}")
                elif pid not in seen and pid not in ws.members:
                    seen.add(pid)
                    q.append(pid)
                elif pid in ws.members and pid not in self.compiled:
                    out.append(f"{x}{via} is used by workspace package {ws.crates[pid].name}, which the image doesn't build")
        return "; ".join(dict.fromkeys(out)) or "no compiled crate depends on it"


def _pick(ws: cargo.Workspace, parent: str, dep: Dep) -> list[str]:
    """Locked ids a parent's dependency resolves to (all of them when it's ambiguous)."""
    cands = [d for d in ws.crates[parent].deps if d in ws.crates and ws.crates[d].name == dep.package]
    if len(cands) > 1 and dep.req:
        m = re.match(r"^[\^=~]?\s*(\d+)(?:\.(\d+))?", dep.req)
        if m:
            major, minor = m.group(1), m.group(2)
            keep = [c for c in cands if ws.crates[c].version.split(".")[0] == major
                    and (major != "0" or minor is None or ws.crates[c].version.split(".")[1] == minor)]
            cands = keep or cands
    return cands


def resolve(ws: cargo.Workspace, roots: list[tuple[str, set[str], bool, bool]],
            manifest_of, resolver1: bool = False) -> tuple[Resolution, dict]:
    """roots: (member id, features, use default, all features). manifest_of(id) -> Manifest.
    resolver1: the workspace uses Cargo's first resolver, which unifies build-dependency
    features with the binary's."""
    mans: dict[str, Manifest] = {}

    def man(cid: str) -> Manifest:
        if cid not in mans:
            try:
                mans[cid] = manifest_of(cid) or Manifest(known=False)
            except Exception as exc:          # a manifest that doesn't parse: unknown, so widened
                logger.info("cargofeat: %s manifest unreadable: %s", cid, exc)
                mans[cid] = Manifest(known=False)
        return mans[cid]

    compiled, host, opaque = set(), set(), set()
    feats: dict[str, set[str]] = {}
    on: dict[str, set[str]] = {}               # crate -> optional dep keys switched on
    weak: dict[tuple[str, str], set[str]] = {}  # (crate, dep key) -> features waiting for that dep
    v1_pending: dict[str, list[tuple[bool, tuple]]] = {}
    q: deque = deque()

    def activate(cid: str, default: bool, fs) -> None:
        if cid in host:
            return
        m = man(cid)
        if m.proc_macro:
            host.add(cid)
            return
        new = cid not in compiled
        compiled.add(cid)
        feats.setdefault(cid, set())
        if new:
            if not m.known:
                opaque.add(cid)
                for d in ws.crates.get(cid, cargo.Crate("", "")).deps:
                    activate_all(d)
                return
            for d in m.deps:
                if not d.optional:
                    for t in _pick(ws, cid, d):
                        q.append(("dep", cid, d, t))
            if resolver1:
                for d in m.build_deps:
                    for t in _pick(ws, cid, d):
                        v1_pending.setdefault(t, []).append((d.default, d.features))
            for dflt, fs2 in v1_pending.get(cid, []):
                q.append(("feats", cid, dflt, fs2))
        if default:
            q.append(("feat", cid, "default"))
        for f in fs:
            q.append(("feat", cid, f))

    def activate_all(cid: str) -> None:
        if cid in compiled or cid in host:
            return
        m = man(cid)
        activate(cid, True, tuple(m.features) if m.known else ())

    def enable_dep(cid: str, key: str) -> None:
        m = man(cid)
        if key in on.setdefault(cid, set()):
            return
        ds = [d for d in m.deps if d.key == key and d.optional]
        if not ds:
            return
        on[cid].add(key)
        waiting = weak.pop((cid, key), set())
        for d in ds:
            for t in _pick(ws, cid, d):
                q.append(("dep", cid, d, t))
                for f in waiting:
                    q.append(("feat", t, f))

    for mid, fs, dflt, allf in roots:
        m = man(mid)
        activate(mid, dflt, tuple(m.features) if allf and m.known else tuple(fs))
    while q:
        item = q.popleft()
        if item[0] == "dep":
            _, parent, d, t = item
            activate(t, d.default, d.features)
            continue
        if item[0] == "feats":
            _, cid, dflt, fs = item
            activate(cid, dflt, fs)
            continue
        _, cid, f = item
        if cid not in compiled or f in feats.setdefault(cid, set()):
            continue
        feats[cid].add(f)
        m = man(cid)
        table = m.features.get(f)
        if table is None:
            if any(d.key == f and d.optional for d in m.deps):
                enable_dep(cid, f)            # implicit feature of an optional dependency
            continue
        for v in table:
            if v.startswith("dep:"):
                enable_dep(cid, v[4:])
            elif "/" in v:
                k, sub = v.split("/", 1)
                if k.endswith("?"):
                    k = k[:-1]
                    if k in on.get(cid, set()) or any(d.key == k and not d.optional for d in m.deps):
                        for d in m.deps:
                            if d.key == k:
                                for t in _pick(ws, cid, d):
                                    q.append(("feat", t, sub))
                    else:
                        weak.setdefault((cid, k), set()).add(sub)
                else:
                    if any(d.key == k and d.optional for d in m.deps):
                        enable_dep(cid, k)
                        if k in m.features:
                            q.append(("feat", cid, k))
                    for d in m.deps:
                        if d.key == k:
                            for t in _pick(ws, cid, d):
                                q.append(("feat", t, sub))
            else:
                q.append(("feat", cid, v))
    return Resolution(compiled, host - compiled, opaque, [r[0] for r in roots], feats), mans


# --- the workspace's deployed packages ---------------------------------------------------

def _member_manifest_text(ws: cargo.Workspace, mid: str) -> str:
    return (ws.member_dirs[mid] / "Cargo.toml").read_text()


def _ws_tables(root: Path) -> tuple[dict, bool]:
    """The workspace's inherited dependencies, and whether it uses resolver 1 (`resolver`
    unset and the root package's edition before 2021, or `resolver = "1"`)."""
    try:
        top = tomllib.loads((root / "Cargo.toml").read_text())
    except (OSError, ValueError):
        return {}, True
    w, pkg = top.get("workspace") or {}, top.get("package") or {}
    res = str(w.get("resolver") or pkg.get("resolver") or "")
    ed = pkg.get("edition")
    ed = str(ed) if isinstance(ed, (str, int)) else ("2015" if "package" in top else "2021")
    return (w.get("dependencies") or {}), res == "1" or (not res and ed < "2021")


def _roots(ws: cargo.Workspace, root: Path) -> list[tuple[str, set[str], bool, bool]]:
    builds = imagedeps.cargo_builds(root)
    by_name = {ws.crates[m].name: m for m in ws.members if m in ws.crates}
    if not builds:
        return [(m, set(), True, True) for m in ws.members]          # unknown: everything, all features
    top_pkg = None
    try:
        top_pkg = (tomllib.loads((root / "Cargo.toml").read_text()).get("package") or {}).get("name")
    except (OSError, ValueError):
        pass
    out = []
    for b in builds:
        if any("$" in f for f in b.features):
            allf = True                                                # an unresolved ARG: any feature
        else:
            allf = b.all_features
        pkgs = list(b.packages)
        for binname in b.bins:
            owner = None
            for mid, d in ws.member_dirs.items():
                try:
                    man = tomllib.loads((d / "Cargo.toml").read_text())
                except (OSError, ValueError):
                    continue
                names = [x.get("name") for x in man.get("bin") or []] + [(man.get("package") or {}).get("name")]
                if binname in names:
                    owner = ws.crates[mid].name if mid in ws.crates else None
                    break
            pkgs.append(owner or "*")
        for p in b.paths:
            d = (root / p).resolve()
            owner = next((ws.crates[m].name for m, md in ws.member_dirs.items() if md.resolve() == d and m in ws.crates), None)
            pkgs.append(owner or "*")
        if b.workspace or "*" in pkgs:
            sel = list(ws.members)
        elif pkgs:
            sel = [by_name[p] for p in pkgs if p in by_name]
            if len(sel) < len(pkgs):
                sel = list(ws.members)                                 # a package we can't place: all
        elif top_pkg and top_pkg in by_name:
            sel = [by_name[top_pkg]]
        else:
            sel = list(ws.members)
        for mid in sel:
            name = ws.crates[mid].name if mid in ws.crates else ""
            fs = {f.split("/", 1)[1] if "/" in f else f for f in b.features
                  if "/" not in f or f.split("/", 1)[0] == name}
            out.append((mid, fs, not b.no_default, allf))
    return out


@lru_cache(maxsize=32)
def _key(root: Path) -> str:
    h = hashlib.sha256(f"cargofeat@{RESOLVE_V}@{root.resolve()}".encode())
    for p in sorted(root.rglob("Cargo.toml")) + [root / "Cargo.lock"] + sorted(imagedeps._dockerfiles(root)):
        if any(part in ("target", ".git", "node_modules") for part in p.parts):
            continue
        try:
            h.update(str(p.relative_to(root)).encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
        except OSError:
            pass
    return h.hexdigest()[:24]


@lru_cache(maxsize=16)
def _analyse(root_s: str) -> dict | None:
    root = Path(root_s)
    ws = cargo.load(root)
    if ws is None:
        return None
    cf = Path(os.environ.get("SSVC_JUDGE_CACHE", "~/.cache/ssvc-triage/judge")).expanduser() / "cargofeat" / f"{_key(root)}.json"
    if cf.is_file():
        try:
            return json.loads(cf.read_text())
        except ValueError:
            pass
    ws_deps, resolver1 = _ws_tables(root)

    def manifest_of(cid: str) -> Manifest | None:
        if cid in ws.member_dirs:
            return parse_manifest(_member_manifest_text(ws, cid), ws_deps)
        c = ws.crates.get(cid)
        if not c or not c.checksum or not c.registry:
            return None                                              # git / path source: unknown
        try:
            d = pkgsrc.fetch_crate(c.name, c.version, c.checksum)
            return parse_manifest((d / "Cargo.toml").read_text())
        except (pkgsrc.Rejected, OSError, ValueError) as exc:
            logger.info("cargofeat: %s not read: %s", cid, exc)
            return None

    roots = _roots(ws, root)
    res, mans = resolve(ws, roots, manifest_of, resolver1)
    locked = {cid for cid in ws.crates if cid not in ws.members}
    out = {"compiled": sorted(res.compiled), "host": sorted(res.host), "opaque": sorted(res.opaque),
           "roots": res.roots, "why": {cid: res.why_not(ws, cid, mans) for cid in sorted(locked - res.compiled)}}
    cf.parent.mkdir(parents=True, exist_ok=True)
    cf.write_text(json.dumps(out, indent=1))
    return out


def analyse(repo: str | Path) -> dict | None:
    """{compiled, host, opaque, roots, why: {not-compiled id: reason}} for a Cargo workspace."""
    return _analyse(str(Path(repo).expanduser().resolve()))

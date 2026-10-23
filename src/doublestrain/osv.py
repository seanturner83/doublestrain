"""Lockfile -> OSV advisories -> SSVC candidates (sweep-record shape).

Supported manifests: npm `package-lock.json` (lockfileVersion 1-3) or Bun `bun.lock`
(converted by `npmlock`), pinned pip
`requirements*.txt` (`name==version`), Cargo `Cargo.lock` (crates.io packages; see
`cargo.py`) and Go `go.mod` (the build list; see `gomod.py`). Go reachability comes from
govulncheck (`judges/govulncheck.py`) where it can run.

OSV is queried with /v1/querybatch (package + exact version), then each advisory's
record is fetched from /v1/vulns/<id> and cached on disk (SSVC_FEED_CACHE/osv,
max age SSVC_OSV_MAX_AGE_H, default 72h). Advisories for the same package version that
share any alias (GHSA <-> CVE <-> PYSEC) are merged into ONE candidate, so a CVE
filed under two GHSA ids isn't graded twice. Only package names + versions leave the
machine.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path

from .feeds import cache_dir
from .feeds._http import USER_AGENT, read_json, write_json

logger = logging.getLogger(__name__)

API = os.environ.get("SSVC_OSV_URL", "https://api.osv.dev")
_BATCH = 500


@dataclass
class Dep:
    name: str
    version: str
    ecosystem: str          # OSV ecosystem name: npm | PyPI | crates.io | Go
    direct: bool = False
    dev: bool = False


@dataclass
class Advisory:
    ids: list[str]                      # primary ids + aliases, CVEs first
    package: str
    version: str
    ecosystem: str
    summary: str = ""
    details: str = ""
    fixed: list[str] = field(default_factory=list)
    severity: str = ""
    malicious: bool = False             # a malicious package version, not a vulnerability
    cwes: list[str] = field(default_factory=list)
    # RustSec: the affected functions (`smallvec::SmallVec::insert_many`) and platforms,
    # from the advisory database itself; and "unmaintained" / "notice" / "unsound" for
    # informational advisories.
    functions: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    informational: str = ""


def is_malicious(rec: dict) -> bool:
    """OpenSSF malicious-packages records (MAL-*), their origin metadata, or CWE-506
    (embedded malicious code) — GHSA files npm malware under the same CWE."""
    ds = rec.get("database_specific") or {}
    return (rec.get("id", "").startswith("MAL-")
            or any(a.startswith("MAL-") for a in rec.get("aliases", []))
            or "malicious-packages-origins" in ds
            or "CWE-506" in (ds.get("cwe_ids") or []))


# --- lockfiles -------------------------------------------------------------------

def _npm_name(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def parse_npm_lock(path: Path | dict) -> list[Dep]:
    """npm packages in a package-lock.json (a path, or its data from `npmlock.load`).
    `direct` = declared by the root or a workspace and installed where that one resolves it."""
    from . import npmlock
    lock = json.loads(path.read_text()) if isinstance(path, Path) else path
    deps: dict[tuple[str, str], Dep] = {}
    pkgs = lock.get("packages")
    if pkgs:   # lockfile v2 / v3
        direct = {npmlock.resolve(pkgs, w, dep)
                  for w in npmlock.workspace_dirs(pkgs)
                  for f in ("dependencies", "devDependencies", "optionalDependencies")
                  for dep in pkgs[w].get(f) or {}}
        for p, meta in pkgs.items():
            if not p or "node_modules/" not in p or meta.get("link") or not meta.get("version"):
                continue
            name = meta.get("name") or _npm_name(p)
            d = deps.setdefault((name, meta["version"]), Dep(name, meta["version"], "npm", dev=True))
            d.direct |= p in direct
            d.dev &= bool(meta.get("dev") or meta.get("devOptional"))
    else:      # lockfile v1: nested "dependencies"
        def walk(tree: dict, top: bool):
            for name, meta in (tree or {}).items():
                if not meta.get("version") or meta.get("bundled"):
                    continue
                d = deps.setdefault((name, meta["version"]), Dep(name, meta["version"], "npm", dev=True))
                d.direct |= top
                d.dev &= bool(meta.get("dev"))
                walk(meta.get("dependencies"), False)
        walk(lock.get("dependencies"), True)
    return sorted(deps.values(), key=lambda d: (d.name, d.version))


def parse_requirements(path: Path) -> list[Dep]:
    out = []
    for ln in path.read_text().splitlines():
        m = re.match(r"\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)", ln)
        if m:
            out.append(Dep(m.group(1), m.group(2), "PyPI", direct=True,
                           dev="dev" in path.name or "test" in path.name))
    return out


def parse_cargo_lock(repo: Path) -> list[Dep]:
    """crates.io packages a workspace member reaches. `dev` = reached only through
    dev- or build-dependencies (see `cargo.Workspace.kind_of`)."""
    from . import cargo
    ws = cargo.load(repo)
    if ws is None:
        return []
    kinds, direct = ws.kind_of(), ws.direct()
    is_direct = set().union(*direct.values())
    return sorted((Dep(c.name, c.version, "crates.io", direct=c.id in is_direct, dev=kinds[c.id] != "runtime")
                   for c in ws.crates.values() if c.registry and c.id in kinds),
                  key=lambda d: (d.name, d.version))


def parse_gomod(repo: Path) -> list[Dep]:
    """The main module's build list (go.mod); `direct` = not `// indirect`. A module
    replaced by a local directory isn't a published version, so it isn't queried."""
    from . import gomod
    b = gomod.load(repo, graph=False)
    if b is None:
        return []
    return sorted((Dep(m.source[0], m.source[1], "Go", direct=not m.indirect)
                   for m in b.modules.values() if not m.local), key=lambda d: (d.name, d.version))


def find_deps(repo: Path) -> tuple[list[Dep], list[str]]:
    deps, used = [], []
    if (repo / "go.mod").is_file():
        deps += parse_gomod(repo)
        used.append("go.mod")
    if (repo / "Cargo.lock").is_file():
        deps += parse_cargo_lock(repo)
        used.append("Cargo.lock")
    from . import npmlock
    npm = npmlock.find(repo)
    if npm is not None:
        deps += parse_npm_lock(npmlock.load(repo))
        used.append(npm.name)
    from . import pylock
    lock = pylock.load(repo)
    if lock is not None:
        deps += parse_pylock(lock)
        used += ([lock.kind] if lock.kind != "requirements"
                 else [f.relative_to(repo).as_posix() for f in pylock.requirement_files(repo)])
    return deps, used


def parse_pylock(lock) -> list[Dep]:
    """A Python lock's packages (`pylock`); `dev` = reached only from dev groups/extras."""
    runtime = lock.runtime()
    roots = lock.prod_roots | lock.dev_roots
    return sorted((Dep(p.name, p.version, "PyPI", direct=i in roots or not roots, dev=i not in runtime)
                   for i, p in lock.pkgs.items()), key=lambda d: (d.name, d.version))


# --- OSV -------------------------------------------------------------------------

def _post(path: str, payload: dict):
    import urllib.request
    req = urllib.request.Request(f"{API}{path}", data=json.dumps(payload).encode(),  # noqa: S310
                                 headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _get_vuln(vid: str, offline: bool) -> dict | None:
    from .feeds._http import get_json
    path = cache_dir() / "osv" / f"{vid}.json"
    cached = read_json(path)
    max_age = float(os.environ.get("SSVC_OSV_MAX_AGE_H", "72")) * 3600
    if cached and (offline or time.time() - cached.get("_fetched_at", 0) < max_age):
        return cached
    if offline:
        return None
    try:
        rec = get_json(f"{API}/v1/vulns/{vid}")
        rec["_fetched_at"] = time.time()
        write_json(path, rec)
        return rec
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        logger.warning("OSV %s fetch failed (%s)%s", vid, exc, "; using stale cache" if cached else "")
        return cached


def query(deps: list[Dep], *, offline: bool = False) -> dict[tuple[str, str, str], list[str]]:
    """(ecosystem, name, version) -> advisory ids. Offline: only a cached query result."""
    key = lambda d: (d.ecosystem, d.name, d.version)  # noqa: E731
    qcache_path = cache_dir() / "osv" / "_queries.json"
    qcache = read_json(qcache_path) or {}
    max_age = float(os.environ.get("SSVC_OSV_MAX_AGE_H", "72")) * 3600
    out, todo = {}, []
    for d in deps:
        k = "|".join(key(d))
        hit = qcache.get(k)
        if hit and (offline or time.time() - hit["at"] < max_age):
            out[key(d)] = hit["ids"]
        elif not offline:
            todo.append(d)
    for i in range(0, len(todo), _BATCH):
        chunk = todo[i:i + _BATCH]
        res = _post("/v1/querybatch", {"queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk]})
        for d, r in zip(chunk, res.get("results", [])):
            if r.get("next_page_token"):
                logger.warning("OSV paged results for %s@%s; first page only", d.name, d.version)
            ids = [v["id"] for v in r.get("vulns", [])]
            out[key(d)] = ids
            qcache["|".join(key(d))] = {"ids": ids, "at": time.time()}
    if todo:
        write_json(qcache_path, qcache)
    return out


def _fixed(rec: dict, name: str, eco: str) -> list[str]:
    out = []
    for a in rec.get("affected", []):
        p = a.get("package", {})
        if p.get("name", "").lower() == name.lower() and p.get("ecosystem") == eco:
            out += [e["fixed"] for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e]
    return sorted(set(out))


def _rustsec(rs: list[dict], name: str) -> tuple[list[str], list[str], str]:
    """(affected functions, platforms, informational kind) from RustSec records."""
    funcs, plats, info = [], [], ""
    for r in rs:
        ds = r.get("database_specific") or {}
        info = info or str(ds.get("informational") or "")
        for a in r.get("affected", []):
            if (a.get("package") or {}).get("name", "").lower() != name.lower():
                continue
            info = info or str((a.get("database_specific") or {}).get("informational") or "")
            es = a.get("ecosystem_specific") or {}
            aff = es.get("affects") or {}
            funcs += [f for f in es.get("affected_functions") or [] if f not in funcs]
            funcs += [f for f in aff.get("functions") or [] if f not in funcs]
            plats += [f"{k}={v}" for k in ("os", "arch") for v in aff.get(k) or [] if f"{k}={v}" not in plats]
    return funcs, plats, info


def _goimports(rs: list[dict], name: str) -> tuple[list[str], list[str]]:
    """(`pkgpath.Symbol` list, platforms) from Go vulnerability database records: the
    vulnerable packages, and the functions in them, that govulncheck traces."""
    funcs, plats = [], []
    for r in rs:
        for a in r.get("affected", []):
            if (a.get("package") or {}).get("name") != name:
                continue
            for imp in (a.get("ecosystem_specific") or {}).get("imports") or []:
                path = imp.get("path", "")
                syms = imp.get("symbols") or []
                funcs += [f for f in ([f"{path}.{s}" for s in syms] or [path]) if f not in funcs]
                plats += [f"{k}={v}" for k in ("goos", "goarch") for v in imp.get(k) or []
                          if f"{k}={v}" not in plats]
    return funcs, plats


def advisories(deps: list[Dep], *, offline: bool = False) -> list[Advisory]:
    hits = query(deps, offline=offline)
    out = []
    for d in deps:
        ids = hits.get((d.ecosystem, d.name, d.version)) or []
        if not ids:
            continue
        recs = [r for r in (_get_vuln(v, offline) for v in ids) if r and not r.get("withdrawn")]
        # merge records that share any alias (union-find over alias sets)
        groups: list[tuple[set[str], list[dict]]] = []
        for r in recs:
            names = {r["id"], *r.get("aliases", [])}
            merged = [g for g in groups if g[0] & names]
            for g in merged:
                groups.remove(g)
                names |= g[0]
            groups.append((names, [r] + [x for g in merged for x in g[1]]))
        for names, rs in groups:
            # the most detailed record speaks for the group (duplicates are often stubs)
            primary = max(rs, key=lambda r: (len(r.get("details", "")) + len(r.get("summary", "")),
                                             r["id"].startswith("GHSA-")))
            sev = next((s for r in rs if (s := (r.get("database_specific") or {}).get("severity"))), "")
            funcs, plats, info = _rustsec(rs, d.name) if d.ecosystem == "crates.io" else ([], [], "")
            if d.ecosystem == "Go":
                funcs, plats = _goimports(rs, d.name)
            out.append(Advisory(
                ids=sorted(names, key=lambda x: (not x.startswith("CVE-"), x)),
                package=d.name, version=d.version, ecosystem=d.ecosystem,
                summary=primary.get("summary", ""), details=primary.get("details", ""),
                fixed=sorted({f for r in rs for f in _fixed(r, d.name, d.ecosystem)}), severity=sev,
                malicious=any(is_malicious(r) for r in rs) or any(n.startswith("MAL-") for n in names),
                cwes=sorted({c for r in rs for c in ((r.get("database_specific") or {}).get("cwe_ids") or [])}),
                functions=funcs, platforms=plats, informational=info))
    return out


# --- candidates --------------------------------------------------------------------

_STOP = {"true", "false", "null", "undefined", "options", "object", "string", "function",
         "constructor", "prototype", "__proto__", "package", "npm", "pip", "version"}


def guess_symbols(adv: Advisory, limit: int = 6) -> list[str]:
    """Backticked identifiers in the advisory text (`template`, `qs.parse()`). A heuristic
    hint for the grep pre-pass and the judges — never treated as authoritative."""
    text = f"{adv.summary}\n{adv.details}"
    out = []
    for m in re.finditer(r"`([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)(?:\(\))?`", text):
        s = m.group(1)
        if s.lower() in _STOP or s.lower() == adv.package.lower() or s in out:
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return out


def _eco(osv_eco: str) -> str:
    return {"npm": "npm", "PyPI": "pypi", "crates.io": "cargo", "Go": "go"}.get(osv_eco, osv_eco.lower())


# RustSec informational advisories that are not vulnerabilities in the locked code.
# "unsound" stays: it is a memory-safety bug that safe code can trigger.
_NOT_VULNS = {"unmaintained", "notice"}


def candidates(repo: Path, name: str, *, include_dev: bool = True, offline: bool = False,
               ) -> tuple[list[dict], dict]:
    """Sweep records for every (package version, merged advisory) in the repo's lockfiles."""
    deps, manifests = find_deps(repo)
    if not include_dev:
        deps = [d for d in deps if not d.dev]
    by_key = {(d.ecosystem, d.name, d.version): d for d in deps}
    advs = advisories(deps, offline=offline)
    info = [a for a in advs if a.informational in _NOT_VULNS]
    advs = [a for a in advs if a.informational not in _NOT_VULNS]
    from .judges import malware
    ws = None
    if any(d.ecosystem == "crates.io" for d in deps):
        from . import cargo
        ws = cargo.load(repo)
    records = []
    for n, a in enumerate(advs, 1):
        d = by_key[(a.ecosystem, a.package, a.version)]
        # no structured marker: is the TEXT about a malicious/compromised version?
        sus = (malware.assess(a.package, a.summary, a.details, a.cwes) if not a.malicious
               else {"suspected": False, "hints": [], "check": None})
        records.append({"kind": "keep", "pr": f"{name}#{n}", "facts": {
            "package": a.package, "version": a.version, "ecosystem": _eco(a.ecosystem),
            "is_go": False, "advisories": [a.ids, [a.package]],
            "advisory_summary": ((f"[affects only {', '.join(a.platforms)}] " if a.platforms else "")
                                 + a.summary + (" — " if a.summary and a.details else "") + a.details)[:600],
            "vuln_symbols": a.functions or guess_symbols(a),
            "vuln_symbols_source": ("go-vulndb-imports" if a.functions and a.ecosystem == "Go"
                                    else "osv-affected-functions" if a.functions else "heuristic"),
            "fixed": a.fixed, "severity": a.severity, "direct": d.direct, "dev": d.dev,
            "malicious": a.malicious, "suspected_malicious": sus["suspected"],
            "malware_hints": sus["hints"], "malware_check": sus["check"],
            **({"import_name": cargo.ident(a.package, ws)} if a.ecosystem == "crates.io" else {})}})
    prov = {"manifests": manifests, "deps": len(deps), "advisories": len(advs),
            "informational_skipped": sorted({f"{a.ids[0]} ({a.informational})" for a in info}),
            "vulnerable_packages": len({(a.package, a.version) for a in advs})}
    return records, prov

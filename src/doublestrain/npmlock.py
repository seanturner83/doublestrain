"""The app's npm-ecosystem lockfile, as package-lock.json v2/v3 data.

`load(repo)` reads `package-lock.json` when there is one, else Bun's text lockfile
`bun.lock`, converted to the same shape, so every npm reader (osv, depgraph, inventory,
and through depgraph pkgsrc and the judges) works on Bun projects too. The binary
`bun.lockb` (Bun < 1.2) is not read: `bun install --save-text-lockfile` writes a bun.lock.

bun.lock is JSON with trailing commas:

    {"lockfileVersion": 1,
     "workspaces": {"": {"name": "app", "devDependencies": {...}},
                    "web": {"name": "@app/web", "dependencies": {"react": "19.2.7"}}},
     "packages": {"react": ["react@19.2.7", "", {"dependencies": {...}}, "sha512-..."],
                  "@app/web": ["@app/web@workspace:web"],
                  "a/b": ["b@2.0.0", "", {}, "sha512-..."]}}

A `packages` key is the install path: `a/b` is `b` nested under `a`
(node_modules/a/node_modules/b), and a first segment that names a workspace package
nests under that workspace's directory (web/node_modules/b). The entry is
[name@version, registry URL ("" = npmjs), metadata, integrity]; an alias key keeps
its own name and the entry names the real package.

Conversion:
- workspace directories become package-lock workspace entries (`packages["web"]`, plus
  a `node_modules/@app/web` link), and the root workspace becomes `packages[""]`;
- registry packages get `version`, `resolved` (the npmjs tarball URL when the registry
  is ""), `integrity`, their dependency maps, and `dev`;
- git, file, link and tarball sources keep no `version`, so nothing queries OSV with
  them or fetches their source (the same as Cargo's git sources);
- `dev` is set the way npm sets it: a package is dev unless a workspace's
  dependencies, optionalDependencies or peerDependencies reach it. Bun lists packages
  that no workspace reaches (another platform's optional binaries, for example); those
  are kept as not dev, the conservative side.
"""
from __future__ import annotations

import json
from collections import deque
from pathlib import Path

ROOT = ""
REGISTRY = "https://registry.npmjs.org"
_PROD = ("dependencies", "optionalDependencies", "peerDependencies")
_DEP_FIELDS = (*_PROD, "devDependencies")


def find(repo: Path) -> Path | None:
    """The lockfile `load` reads: package-lock.json first, then bun.lock."""
    for name in ("package-lock.json", "bun.lock"):
        if (Path(repo) / name).is_file():
            return Path(repo) / name
    return None


def load(repo: Path) -> dict | None:
    """package-lock.json data for the app at `repo`, or None if it has no npm lockfile."""
    path = find(repo)
    if path is None:
        return None
    if path.name == "bun.lock":
        return from_bun(loads(path.read_text()))
    return json.loads(path.read_text())


def loads(text: str) -> dict:
    """Parse bun.lock: JSON that allows a comma before `}` or `]`."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\":
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(c)
        else:
            out.append(c)
        i += 1
    return json.loads("".join(out))


def _segments(key: str) -> list[str]:
    """`@s/a/b/@t/c` -> ['@s/a', 'b', '@t/c']."""
    parts, out = key.split("/"), []
    while parts:
        p = parts.pop(0)
        out.append(f"{p}/{parts.pop(0)}" if p.startswith("@") and parts else p)
    return out


def _split_spec(spec: str) -> tuple[str, str]:
    """`@s/a@1.0.0` -> ('@s/a', '1.0.0'); the version part may itself hold `:` or `@`."""
    i = spec.find("@", 1)
    return (spec, "") if i < 0 else (spec[:i], spec[i + 1:])


def _tarball(name: str, version: str) -> str:
    return f"{REGISTRY}/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"


def from_bun(lock: dict) -> dict:
    """Convert parsed bun.lock data to package-lock.json v3 data (see the module doc)."""
    workspaces = lock.get("workspaces") or {}
    ws_dir = {w.get("name"): d for d, w in workspaces.items() if d and w.get("name")}
    pkgs: dict[str, dict] = {}
    for d, w in workspaces.items():
        entry = {k: w[k] for k in ("name", "version", *_DEP_FIELDS) if k in w}
        pkgs[d] = entry
        if d:
            pkgs[f"node_modules/{w['name']}"] = {"resolved": d, "link": True}
    pkgs.setdefault(ROOT, {})

    for key, value in (lock.get("packages") or {}).items():
        if not isinstance(value, list) or not value:
            continue
        segs = _segments(key)
        if len(segs) > 1 and segs[0] in ws_dir:
            path = ws_dir[segs[0]] + "".join(f"/node_modules/{s}" for s in segs[1:])
        else:
            path = "/".join(f"node_modules/{s}" for s in segs)
        name, spec = _split_spec(value[0])
        if spec.startswith("workspace:"):
            continue                                   # the link above stands for it
        meta = value[2] if len(value) > 2 and isinstance(value[2], dict) else {}
        entry: dict = {k: meta[k] for k in (*_PROD, "os", "cpu") if k in meta}
        if name != segs[-1]:
            entry["name"] = name                       # alias: the key keeps the alias name
        if ":" in spec or not spec:                    # git, github, file, link, tarball URL
            entry["source"] = spec or value[0]
        else:
            entry["version"] = spec
            registry = value[1] if len(value) > 1 and isinstance(value[1], str) else ""
            entry["resolved"] = registry or _tarball(name, spec)
            if len(value) > 3 and isinstance(value[3], str):
                entry["integrity"] = value[3]
        pkgs[path] = entry

    own = set(workspace_dirs(pkgs))
    runtime, anything = _reached(pkgs, own, _PROD), _reached(pkgs, own, _DEP_FIELDS)
    for path in anything - runtime:
        pkgs[path]["dev"] = True
    return {"lockfileVersion": 3, "packages": pkgs, "_source": "bun.lock"}


def resolve(pkgs: dict, from_path: str, dep: str) -> str | None:
    """Node's lookup: the nearest node_modules/<dep> walking up from `from_path`."""
    base = from_path
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in pkgs:
            return cand
        if not base:
            return None
        i = base.rfind("/node_modules/")
        base = base[:i] if i >= 0 else ""


def _reached(pkgs: dict, roots: set[str], root_fields: tuple[str, ...]) -> set[str]:
    """Install paths reached from the `root_fields` dependencies of `roots`, then through
    each package's production dependencies (a dependency's devDependencies aren't installed)."""
    seen: set[str] = set()
    q: deque[str] = deque()

    def visit(frm: str, deps) -> None:
        for dep in deps or {}:
            if (c := resolve(pkgs, frm, dep)) and c not in seen:
                seen.add(c)
                q.append(c)

    for r in roots:
        for f in root_fields:
            visit(r, pkgs.get(r, {}).get(f))
    while q:
        p = q.popleft()
        m = pkgs[p]
        if m.get("link"):                              # a workspace depending on a workspace
            target = m.get("resolved", "")
            if target in pkgs and target not in seen:
                seen.add(target)
                q.append(target)
            continue
        for f in _PROD:
            visit(p, m.get(f))
    return {p for p in seen if "node_modules/" in p and not pkgs[p].get("link")}


def workspace_dirs(pkgs: dict) -> list[str]:
    """The app's own packages: the root and every workspace directory."""
    return [p for p, m in pkgs.items()
            if p == ROOT or ("node_modules/" not in p and not m.get("link"))]

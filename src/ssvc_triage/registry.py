"""npm registry metadata (packuments), fetched safely, plus upstream discovery.

A packument is publisher-controlled DATA: it is only ever parsed as JSON. Fetching reuses
pkgsrc's rules: https registry only, name validated before any request, URL built from
the validated name, no redirects, byte cap. What we keep is trimmed to the fields used
here and cached (SSVC_REGISTRY_CACHE, default ~/.cache/ssvc-triage/registry; TTL
SSVC_REGISTRY_MAX_AGE_H, default 24).

Upstream discovery (`upstream`) turns the publisher's `repository` field into a validated
`github.com/<owner>/<repo>` (+ monorepo directory), and `git_head` gives the commit a
version was published from. Both are claims by the publisher, not facts: callers treat a
missing or mismatched repo as a finding, never as a reason to fetch from elsewhere.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import pkgsrc
from .pkgsrc import Rejected

MAX_PACKUMENT = 60 << 20
_KEEP_VERSION = ("deprecated", "gitHead", "dependencies", "optionalDependencies", "peerDependencies",
                 "repository", "engines", "type", "main", "exports", "_npmUser", "maintainers")
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


def cache_root() -> Path:
    return Path(os.environ.get("SSVC_REGISTRY_CACHE", "~/.cache/ssvc-triage/registry")).expanduser()


def _check_name(name: str) -> None:
    if len(name) > 214 or not pkgsrc._NAME.fullmatch(name) or ".." in name:
        raise Rejected(f"invalid package name {name!r}")


def _trim(doc: dict) -> dict:
    versions = {}
    for v, meta in (doc.get("versions") or {}).items():
        if isinstance(meta, dict) and isinstance(v, str) and len(v) <= 64:
            keep = {k: meta[k] for k in _KEEP_VERSION if k in meta}
            if isinstance(keep.get("engines"), dict):
                keep["engines"] = {k: v[:100] for k, v in keep["engines"].items() if isinstance(v, str)}
            scripts = meta.get("scripts") if isinstance(meta.get("scripts"), dict) else {}
            keep["install_scripts"] = sorted(k for k in _INSTALL_SCRIPTS if k in scripts)
            dist = meta.get("dist") if isinstance(meta.get("dist"), dict) else {}
            keep["size"] = dist.get("unpackedSize") if isinstance(dist.get("unpackedSize"), int) else None
            if isinstance(keep.get("exports"), (dict, list, str)):
                keep["exports"] = json.dumps(keep["exports"], sort_keys=True)[:2000]   # compare, don't keep
            versions[v] = keep
    t = doc.get("time") if isinstance(doc.get("time"), dict) else {}
    return {"name": doc.get("name"), "versions": versions,
            "time": {k: v for k, v in t.items() if isinstance(v, str)},
            "dist-tags": doc.get("dist-tags") if isinstance(doc.get("dist-tags"), dict) else {},
            "repository": doc.get("repository"), "_fetched_at": time.time()}


def packument(name: str, *, offline: bool = False) -> dict | None:
    """Trimmed packument for `name`, or None (offline miss / fetch refused)."""
    _check_name(name)
    # case-insensitive filesystems fold JSONStream/jsonstream: key on the exact name too
    path = cache_root() / f"{urllib.parse.quote(name, safe='')}-{hashlib.sha256(name.encode()).hexdigest()[:10]}.json"
    max_age = float(os.environ.get("SSVC_REGISTRY_MAX_AGE_H", "24")) * 3600
    try:
        cached = json.loads(path.read_text())
    except (OSError, ValueError, RecursionError):
        cached = None
    if not isinstance(cached, dict) or cached.get("name") != name:
        cached = None
    if cached and (offline or time.time() - cached.get("_fetched_at", 0) < max_age):
        return cached
    if offline:
        return None
    url = f"{pkgsrc.registry()}/{urllib.parse.quote(name, safe='@')}"
    try:
        doc = json.loads(pkgsrc._get(url, MAX_PACKUMENT))
    except (Rejected, ValueError, RecursionError):     # incl. deeply nested JSON
        return cached
    if not isinstance(doc, dict) or doc.get("name") != name:
        return cached
    out = _trim(doc)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump(out, fh)
    os.replace(tmp, path)
    return out


def packuments(names, *, offline: bool = False, workers: int = 4) -> dict[str, dict | None]:
    names = sorted(set(names))

    def one(n):
        try:
            return n, packument(n, offline=offline)
        except (Rejected, ValueError, RecursionError):
            return n, None
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return dict(ex.map(one, names))


_GH = re.compile(r"^(?:git\+)?(?:https?://|git://|ssh://git@|git@)?(?:www\.)?github\.com[/:]"
                 r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?(?:#.*)?$")
_SHORT = re.compile(r"^(?:github:)?([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})$")


def upstream(pk: dict, version: str = "") -> dict:
    """{"host","owner","repo","directory","git_head"} or {"error": why}. Only github.com
    is recognised; anything else is reported, never followed."""
    meta = (pk.get("versions") or {}).get(version, {}) if version else {}
    repo = meta.get("repository") or pk.get("repository")
    url, directory = (repo.get("url"), repo.get("directory")) if isinstance(repo, dict) else (repo, None)
    if not isinstance(url, str) or not url.strip():
        return {"error": "no repository field"}
    url = url.strip()
    m = _GH.match(url) or _SHORT.match(url)
    if not m:
        return {"error": f"not a github.com repository: {url[:120]!r}"}
    owner, name = m.group(1), m.group(2)
    if set(name) <= {"."} or name == ".git":
        return {"error": f"bad repository name in {url[:120]!r}"}
    if isinstance(directory, str) and (directory.startswith("/") or "\\" in directory
                                       or ".." in directory.split("/") or len(directory) > 200):
        directory = None
    head = meta.get("gitHead")
    return {"host": "github.com", "owner": owner, "repo": name,
            "directory": directory if isinstance(directory, str) else None,
            "git_head": head if isinstance(head, str) and re.fullmatch(r"[0-9a-f]{7,40}", head) else None}


def published(pk: dict) -> list[str]:
    """Published versions, oldest first by publish time (falls back to version order)."""
    from .semver import parse
    vs = [v for v in (pk.get("versions") or {}) if parse(v)]
    t = pk.get("time") or {}
    return sorted(vs, key=lambda v: (t.get(v, ""), parse(v)))

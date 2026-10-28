"""Python dependency locks, read as data: what is installed, and what pulls it in.

Nothing is installed, resolved or run (no `pip`, `uv` or `poetry`: resolving reads
remote indexes, and a project's build hooks are code). In order of preference:

- `uv.lock`: every package with its source, its hashes (wheels and sdist) and its
  dependencies. The root (`source = {editable|virtual = "."}`) names the direct
  dependencies, its extras (`optional-dependencies`) and its dependency groups.
- `poetry.lock`: every package with its file hashes and dependency names. Which are
  direct, and which only for development, comes from `pyproject.toml`
  (`[tool.poetry.dependencies]`, extras, `[tool.poetry.group.<g>.dependencies]`,
  `[tool.poetry.dev-dependencies]`, or PEP 621 `[project]` /
  `[dependency-groups]`).
- `Pipfile.lock`: `default` and `develop` pins with hashes; no graph.
- `requirements*.txt` (also under `requirements/`): `name==version` pins, `--hash`
  options, and pip-compile's `# via` comments, which give the graph. Without `# via`,
  every pin is a direct dependency and there are no edges.

Extras count as production: an app is deployed with the extras it needs (private-gpt
ships its LLM backends as extras), and the lock holds only what some extra resolves.
Dependency groups and extras named like dev/test/lint/docs count as development.
Environment markers are ignored: a package locked for any platform is kept (grading it
is the conservative side).
"""
from __future__ import annotations

import json
import re
import tomllib
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from . import imagedeps

_DEV = re.compile(r"(^|[-_.])(dev|develop|development|test|tests|testing|lint|linting|docs?|typing|mypy|"
                  r"style|format|ci|bench|benchmarks?)($|[-_.])", re.I)
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\]+)")
_HASH = re.compile(r"--hash[=\s]+sha256:([0-9a-fA-F]{64})")


def normalize(name: str) -> str:
    """PEP 503: case-insensitive, runs of -_. are equal."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Pkg:
    name: str                     # normalized
    version: str
    hashes: tuple[str, ...] = ()  # sha256 hex digests of its files (any of them)
    files: tuple[tuple[str, str], ...] = ()   # (filename or url, sha256) when the lock says

    @property
    def id(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Lock:
    kind: str                                   # "uv.lock", "poetry.lock", ...
    pkgs: dict[str, Pkg]                        # id -> package
    edges: dict[str, tuple[str, ...]]           # id -> ids it depends on
    prod_roots: set[str] = field(default_factory=set)
    dev_roots: set[str] = field(default_factory=set)
    stale: tuple[str, ...] = ()                 # ids pinned by the project's manifests but missing from the lock

    def reach(self, roots) -> set[str]:
        seen, todo = set(roots), deque(roots)
        while todo:
            for c in self.edges.get(todo.popleft(), ()):
                if c not in seen:
                    seen.add(c)
                    todo.append(c)
        return seen

    def runtime(self) -> set[str]:
        """Ids a production root reaches. Without any roots (a bare pin list), all."""
        if not self.prod_roots and not self.dev_roots:
            return set(self.pkgs)
        return self.reach(self.prod_roots)

    def is_dev(self, pid: str) -> bool:
        return pid not in self.runtime()

    def direct_names(self) -> set[str]:
        return {self.pkgs[i].name for i in self.prod_roots | self.dev_roots if i in self.pkgs}


def _by_name(pkgs: dict[str, Pkg]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i, p in pkgs.items():
        out.setdefault(p.name, []).append(i)
    return out


def _sha(h: str) -> str:
    return h.split(":", 1)[1].lower() if h.lower().startswith("sha256:") else ""


def _req_name(spec: str) -> str:
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
    return normalize(m.group(1)) if m else ""


# --- uv.lock -------------------------------------------------------------------------

def _uv(path: Path) -> Lock:
    d = tomllib.loads(path.read_text())
    entries = d.get("package") or []
    pkgs, raw, roots = {}, {}, []
    for e in entries:
        src = e.get("source") or {}
        if "editable" in src or "virtual" in src:
            roots.append(e)
            continue
        if not ("registry" in src):
            continue                     # git / path / url sources: no published version to grade
        files = [(f.get("url", ""), _sha(f.get("hash", ""))) for f in ([e["sdist"]] if e.get("sdist") else [])
                 + list(e.get("wheels") or [])]
        p = Pkg(normalize(e["name"]), str(e.get("version", "")), tuple(h for _, h in files if h),
                tuple((u, h) for u, h in files if h))
        pkgs[p.id] = p
        raw[p.id] = e
    names = _by_name(pkgs)

    def resolve(ref: dict) -> list[str]:
        ids = names.get(normalize(ref.get("name", "")), [])
        if ref.get("version"):
            ids = [i for i in ids if pkgs[i].version == ref["version"]] or ids
        return ids

    def refs(e: dict, keys) -> list[dict]:
        out = []
        for k in keys:
            v = e.get(k)
            if isinstance(v, list):
                out += v
            elif isinstance(v, dict):                     # extras / groups: name -> list
                out += [r for lst in v.values() for r in lst]
        return out
    edges = {i: tuple(sorted({c for r in refs(e, ("dependencies", "optional-dependencies")) for c in resolve(r)}))
             for i, e in raw.items()}
    prod, dev = set(), set()
    inst = imagedeps.installed(path.parent)
    for r in roots:
        prod |= {c for ref in r.get("dependencies") or [] for c in resolve(ref)}
        for extra, lst in (r.get("optional-dependencies") or {}).items():
            (dev if _DEV.search(extra) and not inst.extra(extra) else prod).update(c for ref in lst for c in resolve(ref))
        for group, lst in (r.get("dev-dependencies") or {}).items():
            (prod if inst.uv_group(group) else dev).update(c for ref in lst for c in resolve(ref))
    return Lock("uv.lock", pkgs, edges, prod, dev - prod)


# --- poetry.lock ---------------------------------------------------------------------

def _pyproject_roots(repo: Path) -> tuple[set[str], set[str]]:
    """Normalized names of the project's direct production and development dependencies."""
    try:
        pp = tomllib.loads((repo / "pyproject.toml").read_text())
    except (OSError, ValueError):
        return set(), set()
    prod, dev = set(), set()
    inst = imagedeps.installed(repo)          # what the image installs counts as production
    proj = pp.get("project") or {}
    prod |= {_req_name(s) for s in proj.get("dependencies") or []}
    for extra, lst in (proj.get("optional-dependencies") or {}).items():
        (dev if _DEV.search(extra) and not inst.extra(extra) else prod).update(_req_name(s) for s in lst)
    for g, lst in (pp.get("dependency-groups") or {}).items():
        (prod if inst.uv_group(g) else dev).update(_req_name(s) for s in lst if isinstance(s, str))
    po = (pp.get("tool") or {}).get("poetry") or {}
    prod |= {normalize(n) for n in (po.get("dependencies") or {}) if n.lower() != "python"}
    (prod if inst.poetry_group("dev", False) else dev).update(normalize(n) for n in (po.get("dev-dependencies") or {}))
    for g, gd in (po.get("group") or {}).items():
        names = {normalize(n) for n in (gd.get("dependencies") or {})}
        held = _DEV.search(g) or gd.get("optional")
        (dev if held and not inst.poetry_group(g, bool(gd.get("optional"))) else prod).update(names)
    prod.discard("")
    dev.discard("")
    return prod, dev - prod


def _poetry(path: Path) -> Lock:
    d = tomllib.loads(path.read_text())
    meta_files = (d.get("metadata") or {}).get("files") or {}     # lock-version 1.x
    pkgs, raw = {}, {}
    for e in d.get("package") or []:
        if (e.get("source") or {}).get("type") in ("git", "directory", "file", "url"):
            continue
        files = e.get("files") or meta_files.get(e["name"]) or []
        fh = tuple((f.get("file", ""), _sha(f.get("hash", ""))) for f in files if _sha(f.get("hash", "")))
        p = Pkg(normalize(e["name"]), str(e.get("version", "")), tuple(h for _, h in fh), fh)
        pkgs[p.id] = p
        raw[p.id] = e
    names = _by_name(pkgs)
    edges = {}
    for i, e in raw.items():
        deps = set()
        for n in e.get("dependencies") or {}:
            deps |= set(names.get(normalize(n), []))
        edges[i] = tuple(sorted(deps))
    prod_n, dev_n = _pyproject_roots(path.parent)
    prod = {i for n in prod_n for i in names.get(n, [])}
    dev = {i for n in dev_n for i in names.get(n, [])}
    if not prod_n and not dev_n:                                  # no manifest: every package is a root
        prod = set(pkgs)
    return Lock("poetry.lock", pkgs, edges, prod, dev - prod)


# --- Pipfile.lock --------------------------------------------------------------------

def _pipfile(path: Path) -> Lock:
    d = json.loads(path.read_text())
    pkgs, prod, dev = {}, set(), set()
    for section, roots in (("default", prod), ("develop", dev)):
        for n, m in (d.get(section) or {}).items():
            v = str(m.get("version", "")).lstrip("=")
            if not v:
                continue                  # git / path entries
            hs = tuple(_sha(h) for h in m.get("hashes") or [] if _sha(h))
            p = Pkg(normalize(n), v, hs)
            pkgs.setdefault(p.id, p)
            roots.add(p.id)
    return Lock("Pipfile.lock", pkgs, {}, prod, dev - prod)


# --- requirements*.txt ---------------------------------------------------------------

def requirement_files(repo: Path) -> list[Path]:
    files = sorted(repo.glob("requirements*.txt")) + sorted((repo / "requirements").glob("*.txt"))
    return [f for f in files if f.is_file() and not f.is_symlink()]


def _requirements(files: list[Path], root: Path | None = None) -> Lock:
    pkgs: dict[str, Pkg] = {}
    via: dict[str, set[str]] = {}            # child id -> parent names ("-r" = direct)
    prod, dev = set(), set()
    any_via = False
    installed = imagedeps.installed(root).req_closure(files) if root else set()
    for f in files:
        is_dev = bool(_DEV.search(f.stem.replace("requirements", ""))) and f.name not in installed
        lines = f.read_text(errors="replace").splitlines()
        joined, buf = [], ""
        for ln in lines:                      # join backslash continuations
            if ln.rstrip().endswith("\\"):
                buf += ln.rstrip()[:-1] + " "
                continue
            joined.append(buf + ln)
            buf = ""
        current = None
        in_via = False
        for ln in joined:
            m = _PIN.match(ln)
            if m and not ln.lstrip().startswith("#"):
                p = Pkg(normalize(m.group(1)), m.group(2), tuple(h.lower() for h in _HASH.findall(ln)))
                old = pkgs.get(p.id)
                pkgs[p.id] = p if not old or len(p.hashes) > len(old.hashes) else old
                current, in_via = p.id, False
                via.setdefault(current, set())
                (dev if is_dev else prod).add(current)
                if "# via" in ln:
                    any_via = True
                    via[current] |= _via_names(ln.split("# via", 1)[1])
                continue
            s = ln.strip()
            if current and s.startswith("#"):
                body = s.lstrip("#").strip()
                if body.startswith("via"):
                    any_via, in_via = True, True
                    via[current] |= _via_names(body[3:])
                elif in_via and body:
                    via[current] |= _via_names(body)
                continue
            in_via = False
    edges: dict[str, set[str]] = {}
    if any_via:
        names = _by_name(pkgs)
        roots_p, roots_d = set(), set()
        for child, parents in via.items():
            # a parent the files don't pin is the project itself (`-e file:.`, pip-compile's
            # "via apache-superset") or something installed outside them: a root, not a dead end
            if not parents or "-r" in parents or any(par not in names for par in parents - {"-r"}):
                (roots_d if child in dev and child not in prod else roots_p).add(child)
            for par in parents - {"-r"}:
                for pid in names.get(par, []):
                    edges.setdefault(pid, set()).add(child)
        prod, dev = roots_p, roots_d
    return Lock("requirements", pkgs, {k: tuple(sorted(v)) for k, v in edges.items()}, prod, dev - prod)


def _via_names(text: str) -> set[str]:
    out = set()
    for tok in re.split(r"[,\s]+", text.strip()):
        if tok in ("-r", "-c"):
            out.add("-r")
        elif tok and not tok.startswith(("-", "(", "#")) and "/" not in tok and not tok.endswith((".in", ".txt")):
            out.add(normalize(tok))
        elif tok.endswith((".in", ".txt")):
            out.add("-r")
    return out


# --- entry point ---------------------------------------------------------------------

def _declared_pins(root: Path) -> dict[str, str]:
    """Exact production pins (`name==version`) in the project's own manifests: PEP 621
    `[project].dependencies` and the root's non-dev requirements files."""
    pins: dict[str, str] = {}
    try:
        proj = tomllib.loads((root / "pyproject.toml").read_text()).get("project") or {}
        lines = [s for s in proj.get("dependencies") or [] if isinstance(s, str)]
    except (OSError, ValueError):
        lines = []
    for f in requirement_files(root):
        if not _DEV.search(f.stem.replace("requirements", "")):
            lines += f.read_text(errors="replace").splitlines()
    for ln in lines:
        if (m := _PIN.match(ln)) and not ln.lstrip().startswith("#"):
            pins.setdefault(normalize(m.group(1)), m.group(2))
    return pins


def _with_stale(lock: Lock, root: Path) -> Lock:
    """A lock that falls behind its manifests (open-webui v0.4.0: pyproject pins
    pymdown-extensions, uv.lock doesn't have it, the image installs the pins) misses
    installed code, and an import route through it is invisible. Packages the manifests
    pin exactly but the lock lacks by name join as direct production dependencies, with
    no hashes (pkgsrc verifies them against the registry) and no edges. Widening only:
    a version mismatch for a locked name keeps the locked version."""
    have = {p.name for p in lock.pkgs.values()}
    added = [Pkg(n, v) for n, v in sorted(_declared_pins(root).items()) if n not in have]
    if not added:
        return lock
    for p in added:
        lock.pkgs[p.id] = p
        if lock.prod_roots or lock.dev_roots:
            lock.prod_roots.add(p.id)
    lock.stale = tuple(p.id for p in added)
    return lock


@lru_cache(maxsize=16)
def _load(repo: str, stamp: tuple) -> Lock | None:
    root = Path(repo)
    for name, fn in (("uv.lock", _uv), ("poetry.lock", _poetry), ("Pipfile.lock", _pipfile)):
        p = root / name
        if p.is_file() and not p.is_symlink():
            try:
                lock = fn(p)
            except (OSError, ValueError, KeyError, TypeError):
                continue
            return _with_stale(lock, root)
    reqs = requirement_files(root)
    return _requirements(reqs, root) if reqs else None


def load(repo: Path) -> Lock | None:
    """The project's Python lock, or None. Cached on the lock files' mtimes."""
    root = Path(repo)
    files = [root / n for n in ("uv.lock", "poetry.lock", "Pipfile.lock", "pyproject.toml")] + requirement_files(root)
    stamp = tuple((str(f), f.stat().st_mtime) for f in files if f.is_file())
    return _load(str(root), stamp)


# Distribution -> import names where they differ from the distribution name. Exact
# names come from the package source when it is fetched (`pkgsrc`); this covers the
# usage pre-pass without it.
_IMPORTS = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "scikit-learn": ["sklearn"], "scikit-image": ["skimage"],
    "beautifulsoup4": ["bs4"], "opencv-python": ["cv2"], "opencv-python-headless": ["cv2"],
    "opencv-contrib-python": ["cv2"], "protobuf": ["google.protobuf"], "pyjwt": ["jwt"],
    "python-dateutil": ["dateutil"], "python-dotenv": ["dotenv"], "python-multipart": ["multipart", "python_multipart"],
    "pycryptodome": ["Crypto"], "pycryptodomex": ["Cryptodome"], "pymongo": ["pymongo", "bson", "gridfs"],
    "attrs": ["attr", "attrs"], "setuptools": ["setuptools", "pkg_resources"], "djangorestframework": ["rest_framework"],
    "pyopenssl": ["OpenSSL"], "pysocks": ["socks", "sockshandler"], "python-jose": ["jose"], "faiss-cpu": ["faiss"],
    "faiss-gpu": ["faiss"], "msgpack-python": ["msgpack"], "pytorch": ["torch"], "tensorflow-cpu": ["tensorflow"],
    "pymupdf": ["fitz", "pymupdf"], "python-docx": ["docx"], "python-pptx": ["pptx"], "google-generativeai": ["google.generativeai"],
    "markdown-it-py": ["markdown_it"], "llama-cpp-python": ["llama_cpp"], "sentence-transformers": ["sentence_transformers"],
    "huggingface-hub": ["huggingface_hub"], "pydantic-settings": ["pydantic_settings"], "psycopg2-binary": ["psycopg2"],
    "psycopg-binary": ["psycopg"], "mysqlclient": ["MySQLdb"], "pyzmq": ["zmq"], "websocket-client": ["websocket"],
}


def import_names(name: str) -> list[str]:
    """Best-guess module names for a distribution: the table above, else namespaced
    names (`llama-index-llms-ollama` -> `llama_index.llms.ollama`), else `foo_bar`."""
    n = normalize(name)
    if n in _IMPORTS:
        return _IMPORTS[n]
    parts = n.split("-")
    for ns, mod in (("llama-index", "llama_index"), ("google-cloud", "google.cloud"), ("azure", "azure"),
                    ("opentelemetry-instrumentation", "opentelemetry.instrumentation")):
        k = ns.split("-")
        if parts[:len(k)] == k and len(parts) > len(k):
            return [n.replace("-", "_"), mod + "." + ".".join(parts[len(k):])]
    return [n.replace("-", "_")]

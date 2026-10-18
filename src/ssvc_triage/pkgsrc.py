"""Fetch the exact published source of npm dependencies, for the claude judge to READ.

Claude got library-internals questions wrong from memory (body-parser's extended:false
parser, serve-static's directory listener, Apollo 3's opt-in CSRF check). This gives it
the tarball the lockfile pins. The packages are untrusted: possibly vulnerable, possibly
malicious. Nothing here executes them, and the design assumes hostile bytes:

- Only `SSVC_PKGSRC_REGISTRY` (default https://registry.npmjs.org) is contacted, over
  https, with no redirects. The URL is built from a validated name + version; the
  lockfile's `resolved` URL is never followed (it could point anywhere).
- Integrity is checked BEFORE any parsing. A lockfile sha512 must match. A sha1-only
  lockfile entry (old npm) must match AND the registry's sha512 for that exact version
  must match, so a sha1 collision alone can't substitute a tarball.
- No integrity in the lockfile at all (old lockfiles; lockfileVersion 1 entries without
  `integrity`): the registry's sha512 for that exact name@version is the only check
  (SSVC_PKGSRC_REGISTRY_INTEGRITY, default on; "0" refuses these packages, as before).
  That proves the bytes are what the registry publishes for the version, not what this
  app installed; npm doesn't let a published version's tarball change, which narrows the
  gap. The cache manifest records which hashes verified a package (`verified`).
- gzip is inflated with a byte cap; the tar is read from memory with caps on members and
  sizes. Absolute or `..` member names reject the whole package. Symlinks, hardlinks,
  devices and FIFOs are skipped, as is anything that isn't JavaScript/TypeScript source or
  JSON (no native addons, no README text).
- Files are created O_EXCL|O_NOFOLLOW in a fresh staging dir, made read-only (0444, no
  exec bits), then renamed into place. Nothing is installed; no lifecycle script exists
  to run.

What remains is prompt injection: package text can try to steer claude's verdict. The
judge runs `--restricted` (file tools confined to the checkout + these dirs, no
Bash/web), so injected text can't read or send anything else; and its system prompt
says this source is data. Known/suspected malware never reaches the judges at all.

Only package names and versions leave the machine (as with OSV).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

from ._locks import keylock
from .feeds._http import USER_AGENT

logger = logging.getLogger(__name__)

MAX_TGZ = 25 * 2**20          # compressed tarball
MAX_RAW = 150 * 2**20         # inflated tar stream
MAX_MEMBERS = 20_000
MAX_FILE = 2 * 2**20          # larger files (bundles, minified dists) are skipped
MAX_WRITTEN = 60 * 2**20
MAX_META = 5 * 2**20          # registry version document
KEEP_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".json")
CRATE_EXT = (".rs", ".toml")
GO_EXT = (".go",)

# Go modules: a path of slash-separated elements (no `..`), a semver version; the zip's
# every file sits under `<path>@<version>/`, and go.sum's `h1:` is Go's dirhash over all
# of them, which must match before anything is extracted.
_GOMOD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*(?:/[A-Za-z0-9._~+-]+){0,20}$")
_GOVER = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$")

# crates.io: names are ASCII alphanumerics, `-` and `_`, starting with a letter. The
# `.crate` file is a gzipped tar with one top directory `<name>-<version>/`; Cargo.lock
# carries its sha256, which must match before anything is parsed.
_CRATE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_NAME = re.compile(r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


class Rejected(Exception):
    """The package was refused (bad name, integrity mismatch, hostile tarball, ...)."""


def registry() -> str:
    r = os.environ.get("SSVC_PKGSRC_REGISTRY", "https://registry.npmjs.org").rstrip("/")
    if not r.startswith("https://"):
        raise Rejected(f"registry must be https: {r}")
    return r


def go_proxy() -> str:
    r = os.environ.get("SSVC_GO_PROXY", "https://proxy.golang.org").rstrip("/")
    if not r.startswith("https://"):
        raise Rejected(f"Go module proxy must be https: {r}")
    return r


def crates_dl() -> str:
    r = os.environ.get("SSVC_CRATES_DL", "https://static.crates.io/crates").rstrip("/")
    if not r.startswith("https://"):
        raise Rejected(f"crate download host must be https: {r}")
    return r


def cache_root() -> Path:
    return Path(os.environ.get("SSVC_PKGSRC_CACHE", "~/.cache/ssvc-triage/pkgsrc")).expanduser()


def enabled() -> bool:
    return os.environ.get("SSVC_PKGSRC", "").lower() in ("1", "true", "yes", "on")


def _check_spec(name: str, version: str) -> None:
    if len(name) > 214 or not _NAME.fullmatch(name) or ".." in name:
        raise Rejected(f"invalid package name {name!r}")
    if len(version) > 64 or not _VERSION.fullmatch(version):
        raise Rejected(f"invalid version {version!r} for {name}")


def _urls(name: str, version: str) -> tuple[str, str]:
    reg = registry()
    base = name.rsplit("/", 1)[-1]
    meta = f"{reg}/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}"
    tgz = f"{reg}/{name}/-/{base}-{version}.tgz"
    return meta, tgz


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Rejected(f"refusing redirect {code} -> {newurl}")


def _get(url: str, cap: int, timeout: float = 60.0) -> bytes:
    """GET with no redirects and a byte cap. Patched in tests."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — https registry only
            data = resp.read(cap + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise Rejected(f"fetch failed: {url}: {exc}") from exc
    if len(data) > cap:
        raise Rejected(f"too large (> {cap} bytes): {url}")
    return data


def _parse_sri(sri: str) -> dict[str, bytes]:
    """'sha512-<b64> sha1-<b64>' -> {"sha512": digest, ...} (unknown algorithms dropped)."""
    out = {}
    for tok in (sri or "").split():
        algo, _, b64 = tok.partition("-")
        if algo in ("sha512", "sha384", "sha256", "sha1") and b64:
            try:
                out[algo] = base64.b64decode(b64.split("?")[0], validate=True)
            except ValueError:
                continue
    return out


def _matches(data: bytes, want: dict[str, bytes]) -> bool:
    return bool(want) and all(hashlib.new(a, data).digest() == d for a, d in want.items())


def registry_integrity_on() -> bool:
    return os.environ.get("SSVC_PKGSRC_REGISTRY_INTEGRITY", "1") not in ("0", "false", "no", "")


def _registry_strong(name: str, version: str) -> dict[str, bytes]:
    """The registry's non-sha1 integrity for exactly name@version ({} if none)."""
    meta_url, _ = _urls(name, version)
    try:
        doc = json.loads(_get(meta_url, MAX_META))
    except ValueError as exc:
        raise Rejected(f"{name}@{version}: unreadable registry metadata") from exc
    return {a: d for a, d in _parse_sri(((doc or {}).get("dist") or {}).get("integrity", "")).items()
            if a != "sha1"}


def _verify(name: str, version: str, data: bytes, lock_integrity: str) -> dict:
    lock = _parse_sri(lock_integrity)
    if not lock:
        if not registry_integrity_on():
            raise Rejected(f"{name}@{version}: no usable integrity in the lockfile")
        reg = _registry_strong(name, version)
        if not reg or not _matches(data, reg):
            raise Rejected(f"{name}@{version}: no lockfile integrity and no matching registry sha512")
        return {"lockfile": [], "registry": sorted(reg), "registry_only": True}
    if not _matches(data, lock):
        raise Rejected(f"{name}@{version}: tarball does not match the lockfile integrity")
    strong = {a: d for a, d in lock.items() if a != "sha1"}
    checked = {"lockfile": sorted(lock)}
    if not strong:
        # sha1 alone is collision-broken: also require the registry's sha512 for this version
        reg = _registry_strong(name, version)
        if not reg or not _matches(data, reg):
            raise Rejected(f"{name}@{version}: sha1-only lockfile and no matching registry sha512")
        checked["registry"] = sorted(reg)
    return checked


def _inflate(tgz: bytes) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out, buf = bytearray(), tgz
    while buf:
        out += d.decompress(buf, MAX_RAW + 1 - len(out))
        if len(out) > MAX_RAW:
            raise Rejected("inflated tarball exceeds cap")
        buf = d.unconsumed_tail
        if d.eof:
            break
    try:
        out += d.flush()
    except zlib.error as exc:
        raise Rejected(f"bad gzip: {exc}") from exc
    if len(out) > MAX_RAW:
        raise Rejected("inflated tarball exceeds cap")
    return bytes(out)


def _safe_parts(name: str) -> list[str]:
    """Member path minus its top dir (npm uses `package/`). Raises on absolute/`..` names."""
    if "\x00" in name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise Rejected(f"hostile member name {name!r}")
    parts = name.split("/")
    if any(p == ".." for p in parts):
        raise Rejected(f"hostile member name {name!r}")
    parts = [p for p in parts if p not in ("", ".")]
    if len(parts) > 40 or any(len(p) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in p) for p in parts):
        raise Rejected(f"hostile member name {name!r}")
    return parts[1:]


def extract(tgz: bytes, dest: Path, keep: tuple[str, ...] = KEEP_EXT) -> dict:
    """Write the kept source files of a VERIFIED npm tarball (or .crate) under `dest`
    (which must not exist). Returns counts of what was written and skipped."""
    raw = _inflate(tgz)
    stats = {"written": 0, "bytes": 0, "skipped_type": 0, "skipped_ext": 0, "skipped_size": 0,
             "skipped_dup": 0}
    seen: set[str] = set()
    dest.mkdir(mode=0o755)
    try:
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except tarfile.TarError as exc:
        raise Rejected(f"bad tar: {exc}") from exc
    with tf:
        for i, m in enumerate(tf):
            if i >= MAX_MEMBERS:
                raise Rejected("too many tar members")
            parts = _safe_parts(m.name)
            if m.isdir():
                continue
            if not m.isreg():                      # symlink, hardlink, device, fifo, ...
                stats["skipped_type"] += 1
                continue
            if not parts or not parts[-1].lower().endswith(keep):
                stats["skipped_ext"] += 1
                continue
            if m.size > MAX_FILE or stats["bytes"] + m.size > MAX_WRITTEN:
                stats["skipped_size"] += 1
                continue
            key = "/".join(parts).casefold()       # macOS is case-insensitive
            if key in seen:
                stats["skipped_dup"] += 1
                continue
            seen.add(key)
            fh = tf.extractfile(m)
            data = fh.read(MAX_FILE + 1) if fh else b""
            target = dest.joinpath(*parts)
            try:
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except (FileExistsError, NotADirectoryError):   # file/dir name clash
                stats["skipped_dup"] += 1
                continue
            with os.fdopen(fd, "wb") as out:
                out.write(data[:MAX_FILE])
            os.chmod(target, 0o444)
            stats["written"] += 1
            stats["bytes"] += len(data)
    return stats


def fetch(name: str, version: str, lock_integrity: str) -> Path:
    with keylock(("pkgsrc", name, version, lock_integrity)):           # concurrent rows fetch a package once
        return _fetch(name, version, lock_integrity)


def _fetch(name: str, version: str, lock_integrity: str) -> Path:
    """Directory holding name@version's source, fetched and verified once, then cached.
    Raises Rejected."""
    _check_spec(name, version)
    root = cache_root()
    lock = _parse_sri(lock_integrity)
    if not lock and not registry_integrity_on():      # before the cache: off means off
        raise Rejected(f"{name}@{version}: no usable integrity in the lockfile")
    tag = hashlib.sha256(lock_integrity.encode()).hexdigest()[:12]
    final = root / f"{name.replace('/', '+')}@{version}-{tag}"
    manifest = final.with_name(final.name + ".json")
    if final.is_dir() and manifest.is_file():
        return final
    _, tgz_url = _urls(name, version)
    data = _get(tgz_url, MAX_TGZ)
    checked = _verify(name, version, data, lock_integrity)
    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
    try:
        stats = extract(data, staging / "src")
        if final.exists():
            return final                            # a concurrent fetch won
        os.rename(staging / "src", final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    manifest.write_text(json.dumps({"name": name, "version": version, "url": tgz_url,
                                    "lock_integrity": lock_integrity, "verified": checked,
                                    "sha512": hashlib.sha512(data).hexdigest(),
                                    "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                    **stats}, indent=1))
    logger.info("pkgsrc: %s@%s -> %s (%d files)", name, version, final, stats["written"])
    return final


def for_query(repo: str | Path, dependency: str, version: str = "", limit: int = 6,
              ecosystem: str = "npm") -> tuple[list[tuple[str, Path]], list[str]]:
    """Source dirs for the vulnerable package; then the top-level packages it is reached
    through (what apps import: a spec must say whether each reaches the vulnerable code);
    then every package that directly depends on it (`send` <- express AND serve-static);
    then the rest of the shortest lockfile chain. At most `limit`.
    Returns ([(name@version, dir)], [refusal notes])."""
    from .judges import depgraph
    g = depgraph.load(Path(repo).expanduser(), ecosystem)
    if not g:
        return [], []
    cs = depgraph.chains(g, dependency, version)
    if not cs:
        return [], []
    target = cs[0][-1]
    get = {"cargo": fetch_crate, "go": fetch_gomodule}.get(ecosystem, fetch)
    dependents = sorted((p for p, kids in g.edges.items() if p and target in kids),
                        key=lambda p: (p.count("node_modules/"), g.nodes[p]["name"]))
    got, notes, seen = [], [], set()
    tops = [c[0] for c in cs if len(c) > 1]
    for p in [target, *tops, *dependents, *reversed(cs[0][:-1])]:
        if len(got) + len(notes) >= limit:
            break
        n = g.nodes[p]
        spec = f"{n['name']}@{n['version']}"
        if spec in seen:
            continue
        seen.add(spec)
        try:
            got.append((spec, get(n["name"], n["version"] or "", n.get("integrity") or "")))
        except Rejected as exc:
            logger.warning("pkgsrc: %s", exc)
            notes.append(f"{spec}: {exc}")
    return got, notes


def go_dirhash(files: list[tuple[str, bytes]]) -> str:
    """go.sum's h1: sha256 over the sorted lines `<sha256 hex>  <zip file name>\\n`."""
    lines = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files))
    return "h1:" + base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()


def _go_escape(s: str) -> str:
    return re.sub(r"[A-Z]", lambda c: "!" + c.group(0).lower(), s)


def fetch_gomodule(path: str, version: str, h1: str) -> Path:
    with keylock(("pkgsrc", path, version, h1)):           # concurrent rows fetch a package once
        return _fetch_gomodule(path, version, h1)


def _fetch_gomodule(path: str, version: str, h1: str) -> Path:
    """Directory holding a Go module's .go files and go.mod, verified against the app's
    go.sum zip hash (Go's dirhash over every file in the zip) before anything is
    extracted, then cached. Raises Rejected."""
    import zipfile
    if len(path) > 256 or ".." in path or not _GOMOD.fullmatch(path):
        raise Rejected(f"invalid Go module path {path!r}")
    if len(version) > 128 or not _GOVER.fullmatch(version):
        raise Rejected(f"invalid version {version!r} for {path}")
    if not (h1 or "").startswith("h1:"):
        raise Rejected(f"{path}@{version}: no go.sum h1 hash for the module zip")
    root = cache_root()
    tag = hashlib.sha256(h1.encode()).hexdigest()[:12]
    final = root / f"go+{_go_escape(path).replace('/', '+')}@{version}-{tag}"
    manifest = final.with_name(final.name + ".json")
    if final.is_dir() and manifest.is_file():
        return final
    url = f"{go_proxy()}/{_go_escape(path)}/@v/{_go_escape(version)}.zip"
    data = _get(url, MAX_TGZ)
    prefix = f"{path}@{version}/"
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise Rejected(f"{path}@{version}: bad zip: {exc}") from exc
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_MEMBERS:
            raise Rejected("too many zip members")
        if sum(i.file_size for i in infos) > MAX_RAW:
            raise Rejected("zip inflates too large")
        files = []
        for i in infos:
            if not i.filename.startswith(prefix):
                raise Rejected(f"{path}@{version}: zip member outside {prefix}: {i.filename!r:.80}")
            _safe_parts(i.filename)
            files.append((i.filename, zf.read(i)))
    if go_dirhash(files) != h1:
        raise Rejected(f"{path}@{version}: module zip does not match the go.sum hash")
    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
    stats = {"written": 0, "bytes": 0, "skipped_ext": 0, "skipped_size": 0, "skipped_dup": 0}
    try:
        dest = staging / "src"
        dest.mkdir(mode=0o755)
        seen: set[str] = set()
        for name, body in files:
            rel = name[len(prefix):].split("/")
            keep = (rel[-1] == "go.mod" or rel[-1].endswith(GO_EXT)) and not rel[-1].endswith("_test.go") \
                and "testdata" not in rel[:-1]
            if not keep:
                stats["skipped_ext"] += 1
                continue
            if len(body) > MAX_FILE or stats["bytes"] + len(body) > MAX_WRITTEN:
                stats["skipped_size"] += 1
                continue
            key = "/".join(rel).casefold()          # macOS is case-insensitive
            if key in seen:
                stats["skipped_dup"] += 1
                continue
            seen.add(key)
            target = dest.joinpath(*rel)
            try:
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except (FileExistsError, NotADirectoryError):
                stats["skipped_dup"] += 1
                continue
            with os.fdopen(fd, "wb") as out:
                out.write(body)
            os.chmod(target, 0o444)
            stats["written"] += 1
            stats["bytes"] += len(body)
        if final.exists():
            return final
        os.rename(dest, final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    manifest.write_text(json.dumps({"name": path, "version": version, "url": url, "ecosystem": "go",
                                    "verified": {"go.sum": ["h1"]}, "h1": h1,
                                    "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                    **stats}, indent=1))
    logger.info("pkgsrc: go module %s@%s -> %s (%d files)", path, version, final, stats["written"])
    return final


def fetch_crate(name: str, version: str, checksum: str) -> Path:
    with keylock(("pkgsrc", name, version, checksum)):           # concurrent rows fetch a package once
        return _fetch_crate(name, version, checksum)


def _fetch_crate(name: str, version: str, checksum: str) -> Path:
    """Directory holding a crates.io crate's source (.rs / .toml only), verified against
    the Cargo.lock sha256 before parsing, then cached. Raises Rejected."""
    if not _CRATE.fullmatch(name):
        raise Rejected(f"invalid crate name {name!r}")
    if len(version) > 64 or not _VERSION.fullmatch(version):
        raise Rejected(f"invalid version {version!r} for {name}")
    checksum = (checksum or "").lower()
    if not _SHA256.fullmatch(checksum):
        raise Rejected(f"{name}@{version}: no sha256 checksum in Cargo.lock (git/path source?)")
    root = cache_root()
    final = root / f"crates+{name}@{version}-{checksum[:12]}"
    manifest = final.with_name(final.name + ".json")
    if final.is_dir() and manifest.is_file():
        return final
    url = f"{crates_dl()}/{name}/{name}-{version}.crate"
    data = _get(url, MAX_TGZ)
    if hashlib.sha256(data).hexdigest() != checksum:
        raise Rejected(f"{name}@{version}: .crate does not match the Cargo.lock checksum")
    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
    try:
        stats = extract(data, staging / "src", CRATE_EXT)
        if final.exists():
            return final
        os.rename(staging / "src", final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    manifest.write_text(json.dumps({"name": name, "version": version, "url": url, "ecosystem": "cargo",
                                    "verified": {"lockfile": ["sha256"]}, "sha256": checksum,
                                    "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                    **stats}, indent=1))
    logger.info("pkgsrc: crate %s@%s -> %s (%d files)", name, version, final, stats["written"])
    return final

"""Framework defaults a reader of the app's code can't see, for Composer rows: Laravel's HTTP
client gives every Guzzle client it builds a cookie jar.

`Illuminate\\Http\\Client\\PendingRequest::buildClient` creates `new Client(['handler' => ...,
'cookies' => true])`: each request made through the `Http::` facade (or a wrapper around it)
keeps the cookies its responses set for that request and its redirects, whether or not the app
calls `withCookies()`. php2's judges read "no CookieJar / withCookies in the app" as no jar and
answered not_reachable on Guzzle cookie advisories in apps whose outbound calls all go through
`Http::` (Leantime's plugin marketplace and OIDC, LibreNMS's LibreNMS\\Util\\Http).

The note is a fact, checked in the installed laravel/framework's own source (the copy pkgsrc
verified against composer.lock's pinned commit), plus the app's call sites. It is only written
for guzzlehttp/guzzle rows of apps that install laravel/framework (or illuminate/http) in
production.

php3 showed the app's own code isn't enough: Lychee's only `Http::` use is in an installed package (its
log-viewer fork forwards requests with it), so the note also lists call sites in the other installed
production packages' sources (pkgsrc), outside the framework itself and their tests.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_CLIENT_PKGS = ("laravel/framework", "illuminate/http")
_PENDING = {"laravel/framework": "src/Illuminate/Http/Client/PendingRequest.php",
            "illuminate/http": "Client/PendingRequest.php"}
_COOKIES_ON = re.compile(r"['\"]cookies['\"]\s*=>\s*true")
# `Http::get(` / `\Illuminate\Support\Facades\Http::withHeaders(`, the client classes by name,
# and the facade's import
_CALL = re.compile(r"(?<![\w$>])\\?(?:Illuminate\\Support\\Facades\\)?Http::\w+\s*\("
                   r"|Illuminate\\Http\\Client\\(?:Factory|PendingRequest)\b"
                   r"|use\s+Illuminate\\Support\\Facades\\Http\s*;")
# a file counts only when its `Http` is Laravel's: the facade imported (or its global alias `Http`, `\Http::`
# or used unimported outside a namespace), its full name, or the client classes; league/uri, amphp and
# others have their own `Http` classes
_LARAVEL_HTTP = re.compile(r"use\s+(?:Illuminate\\Support\\Facades\\)?Http\s*;"
                           r"|Illuminate\\Support\\Facades\\Http::|(?<![\w\\])\\Http::"
                           r"|Illuminate\\Http\\Client\\(?:Factory|PendingRequest)\b")
_NAMESPACE = re.compile(r"^\s*namespace\s+[\w\\]+\s*[;{]", re.M)
_PKG_SKIP = {"examples", "example", "bench", "benchmarks", "benchmark", "docs", "stubs"}
_MAX_SITES = 12
_MAX_PKGS = 10
_PER_PKG = 2


def _source_dir(repo: Path, pkg) -> Path | None:
    from .. import pkgsrc
    from .depgraph import composer_integrity
    integ = composer_integrity(pkg)
    if not integ:
        return None
    try:
        return pkgsrc.fetch_composer(pkg.name, pkg.version, integ) if pkgsrc.enabled() else _cached(pkg)
    except pkgsrc.Rejected:
        return None


def _cached(pkg) -> Path | None:
    from .. import pkgsrc
    ref = (pkg.git_ref or pkg.dist_sha1)[:12]
    d = pkgsrc.cache_root() / f"composer+{pkg.name.replace('/', '+')}@{pkg.version}-{ref}"
    return d if d.is_dir() and d.with_name(d.name + ".json").is_file() else None


@lru_cache(maxsize=64)
def _jar_line(src: str, rel: str) -> int:
    """Line of `'cookies' => true` in PendingRequest.php, 0 when absent."""
    try:
        for i, ln in enumerate((Path(src) / rel).read_text(errors="replace").splitlines(), 1):
            if _COOKIES_ON.search(ln) and not ln.lstrip().startswith(("//", "*", "#")):
                return i
    except OSError:
        pass
    return 0


def _sites(src: Path, tag_tests: bool) -> list[str]:
    from .usage import _app_files, is_test_path, _MAX_FILE_BYTES, _is_comment
    out = []
    for f, r in _app_files(src, (".php",)):
        test = is_test_path(r)
        if test and not tag_tests:
            continue
        try:
            if f.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if not tag_tests and _PKG_SKIP & {x.lower() for x in r.parts[:-1]}:
            continue
        if not (_LARAVEL_HTTP.search(text) or ("Http::" in text and not _NAMESPACE.search(text))):
            continue
        lines = text.splitlines()
        tag = " (test code)" if test else ""
        out += [f"{r}:{i}: {ln.strip()[:140]}{tag}" for i, ln in enumerate(lines, 1)
                if _CALL.search(ln) and not _is_comment("composer", ln)]
    return out


@lru_cache(maxsize=1024)
def _pkg_sites(src: str) -> tuple[str, ...]:
    return tuple(_sites(Path(src), tag_tests=False))


def _package_sites(root: Path, lock) -> tuple[dict[str, list[str]], int]:
    """Laravel HTTP client call sites in the installed production packages (not the framework's own
    illuminate code), by package, and how many of those packages had no source to read."""
    sites, missing = {}, 0
    for p in sorted(lock.pkgs.values(), key=lambda p: p.name):
        if p.dev or p.name in _CLIENT_PKGS or p.name.startswith("illuminate/"):
            continue
        src = _source_dir(root, p)
        if src is None:
            missing += 1
            continue
        if found := _pkg_sites(str(src)):
            # calls before imports: `Http::post(...)` says more than `use ...\Http;`
            sites[f"{p.name} {p.version}"] = sorted(found, key=lambda x: x.split(": ", 1)[-1].startswith("use "))
    return sites, missing


def http_client_note(repo_path: str, ecosystem: str, dependency: str, version: str = "") -> str:
    """For a guzzlehttp/guzzle row: whether Laravel's HTTP client is installed, that it turns
    Guzzle's cookie jar on (with file:line in the installed source), and the app's call sites."""
    if ecosystem != "composer" or dependency.strip().lower() != "guzzlehttp/guzzle":
        return ""
    from .. import composer
    root = Path(repo_path).expanduser()
    lock = composer.load(root)
    if not lock:
        return ""
    pkg = next((p for n in _CLIENT_PKGS for p in sorted(lock.pkgs.values(), key=lambda p: p.version)
                if p.name == n and not p.dev), None)
    if pkg is None:
        return ""
    src = _source_dir(root, pkg)
    rel = _PENDING[pkg.name]
    line = _jar_line(str(src), rel) if src else 0
    if not line:
        return ""
    sites = _sites(root, tag_tests=True)
    sites.sort(key=lambda s: s.endswith("(test code)"))
    head = (f"framework default: {pkg.name} {pkg.version} is installed; its HTTP client builds every Guzzle "
            f"client with 'cookies' => true ({rel}:{line}, buildClient), so each request made through "
            "Laravel's HTTP client (the Http:: facade, Illuminate\\Http\\Client\\Factory/PendingRequest, or an "
            "app wrapper around them) has a Guzzle CookieJar for that request and its redirects, whether or not "
            "the app calls withCookies(). A Guzzle `new Client()` made directly has no jar unless given a "
            "'cookies' option.")
    pkg_sites, missing = _package_sites(root, lock)
    gap = f" ({missing} installed production packages had no source to read)" if missing else ""
    out = [head + (f" App call sites of Laravel's HTTP client ({len(sites)}):" if sites
                   else " No call site of Laravel's HTTP client in the app source.")]
    out += [f"  {s}" for s in sites[:_MAX_SITES]]
    if pkg_sites:
        n = sum(map(len, pkg_sites.values()))
        out.append(f"Call sites in installed production packages ({n} lines in {len(pkg_sites)} packages; these run "
                   f"when the app uses that package's feature){gap}:")
        for name, lines in list(pkg_sites.items())[:_MAX_PKGS]:
            more = f" (+{len(lines) - _PER_PKG} more)" if len(lines) > _PER_PKG else ""
            out += [f"  {name}: {x}" for x in lines[:_PER_PKG]]
            if more:
                out[-1] += more
        if len(pkg_sites) > _MAX_PKGS:
            out.append(f"  ... and {len(pkg_sites) - _MAX_PKGS} more packages: "
                       + ", ".join(list(pkg_sites)[_MAX_PKGS:]))
    else:
        out.append(f"No call site of Laravel's HTTP client in the installed production packages{gap}.")
    return "\n".join(out)

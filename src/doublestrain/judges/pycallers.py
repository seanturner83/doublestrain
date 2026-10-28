"""pycallers: who calls the advisory's vulnerable functions, in the app and in the
distributions it imports (pypi rows).

Both py4 failures of the tiers were a route through installed code the judges never
read: paperless's django-auditlog middleware (on by default) saves X-Forwarded-For into
a `GenericIPAddressField`, whose `get_prep_value` calls `clean_ipv6_address`, the function
CVE-2024-56374 names; the judges grepped the app, found no call, and said not_reachable.

This lists call sites of the advisory's symbols (`vuln_symbols`, last dotted segment) in
the app's non-test source and in every distribution pyimports found imported, then one
more hop: for a call site inside the vulnerable package itself, the class (for a method)
or function around it is looked up outside that package. Text search with word
boundaries, parsed only to name the enclosing def/class: a superset of real calls, shown
to the judges as places to read, never as proof. Widening only: it adds routes to read;
nothing here clears a row.
"""
from __future__ import annotations

import ast
import functools
import re
from pathlib import Path

from .. import pkgsrc, pylock
from . import depgraph

_TEST = {"tests", "test", "testing", "docs", "examples", "migrations"}     # migrations: schema, not requests
_GENERIC = {"open", "load", "loads", "dump", "dumps", "read", "write", "get", "set", "run", "call", "parse", "close",
            "save", "send", "init", "main", "process", "handle", "update", "render", "decode", "encode", "format",
            "request", "response", "copy", "join", "split", "filter", "debug", "targets", "value", "data", "name"}
MAX_LINES = 10


def symbols(vuln_symbols) -> list[str]:
    """The callable names worth searching for: last dotted segment, an identifier of 5+
    characters that isn't a generic verb (`load`, `open`: everything calls those)."""
    out = []
    for s in vuln_symbols or ():
        tok = re.split(r"[.:#]", str(s).strip().rstrip("()"))[-1]
        if re.fullmatch(r"[A-Za-z_]\w{4,}", tok or "") and tok.lower() not in _GENERIC and tok not in out:
            out.append(tok)
    return out


def _skip(rel: Path) -> bool:
    return any(p in _TEST for p in rel.parts[:-1]) or rel.name.startswith("test_") or rel.name == "conftest.py"


_TOKEN = re.compile(r"[A-Za-z_]\w{4,}")


@functools.lru_cache(maxsize=4)
def _index(repo_path: str) -> dict[str, tuple[int, ...]]:
    """identifier (5+ chars) -> corpus positions of the files that contain it: built once per
    app, so a row searches only the few files that name its symbols."""
    idx: dict[str, list[int]] = {}
    for n, (_o, _r, text) in enumerate(_corpus(repo_path)):
        for tok in set(_TOKEN.findall(text)):
            idx.setdefault(tok, []).append(n)
    return {k: tuple(v) for k, v in idx.items()}


def _files_naming(repo_path: str, names, exclude=frozenset()) -> tuple:
    corpus, idx = _corpus(repo_path), _index(repo_path)
    pos = sorted({n for name in names for n in idx.get(name, ())})
    return tuple(corpus[n] for n in pos if corpus[n][0] not in exclude)


@functools.lru_cache(maxsize=4)
def _corpus(repo_path: str) -> tuple:
    """((owner, rel, text), ...) for the app's non-test .py files and every imported
    distribution's (owner = name@version); () when pkgsrc is off or the scan fails."""
    from . import pyimports
    if not pkgsrc.enabled():
        return ()
    root = Path(repo_path).expanduser()
    j = pyimports._NOTE_JUDGE = pyimports._NOTE_JUDGE or pyimports.PyImportsJudge()
    scan = j._scan(str(root))
    lock = pylock.load(root)
    if not scan or lock is None:
        return ()
    out = []
    for f, rel in pyimports._app_walk(root):
        if f.suffix == ".py" and not _skip(rel):
            out.append(("app", str(rel), f))
    for pid in scan["reached"]:
        p = lock.pkgs.get(pid)
        if p is None:
            continue
        try:
            src = pkgsrc.fetch_pypi(p.name, p.version, ",".join(p.hashes))
        except (pkgsrc.Rejected, OSError):
            continue
        for f in sorted(src.rglob("*.py")):
            rel = f.relative_to(src)
            if not _skip(rel):
                out.append((pid, str(rel), f))
    corpus = []
    for owner, rel, f in out:
        try:
            if f.stat().st_size <= 2 * 2**20:
                corpus.append((owner, rel, f.read_text(errors="replace")))
        except OSError:
            continue
    return tuple(corpus)


@functools.lru_cache(maxsize=512)       # one parse per file, however many hits it has
def _enclosing(text: str) -> dict[int, tuple[str, str]]:
    """line -> (class name or "", function name or "") for every line inside a def/class."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return {}
    where: dict[int, tuple[str, str]] = {}

    def walk(node, cls, fn):
        for ch in ast.iter_child_nodes(node):
            c, f = cls, fn
            if isinstance(ch, ast.ClassDef):
                c, f = ch.name, ""
            elif isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                f = ch.name if not fn else fn
            if isinstance(ch, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                for ln in range(ch.lineno, (ch.end_lineno or ch.lineno) + 1):
                    where[ln] = (c, f)
            walk(ch, c, f)
    walk(tree, "", "")
    return where


def _hits(corpus, names: list[str], skip_defs: bool = True):
    """[(owner, rel, line, name, text)] where a name is used (not where it's defined)."""
    if not names:
        return []
    pat = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\b")
    defn = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+(" + "|".join(map(re.escape, names)) + r")\b")
    out = []
    for owner, rel, text in corpus:
        if not pat.search(text):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if (m := pat.search(line)) and not (skip_defs and defn.match(line)) and not line.lstrip().startswith("#"):
                out.append((owner, rel, n, m.group(1), line.strip()[:100]))
    return out


def callers(repo_path: str, dependency: str, version: str, vuln_symbols) -> list[tuple]:
    return list(_callers(str(Path(repo_path).expanduser()), dependency, version, tuple(symbols(vuln_symbols))))


@functools.lru_cache(maxsize=256)       # asked three times a row: the cache key, the prompt, claude's sources
def _callers(repo_path: str, dependency: str, version: str, names: tuple) -> tuple:
    """[(rank, owner, rel, line, symbol, via)] call sites outside the vulnerable package:
    rank 0 the app, 1 another distribution (hop 1), 2 the app via a hop, 3 a distribution
    via a hop. `via` names the vulnerable package's class/function that calls the symbol."""
    names = list(names)
    if not names:
        return ()
    corpus = _corpus(repo_path)
    if not corpus:
        return ()
    dep = pylock.normalize(dependency)
    target = {o for o, _r, _t in corpus if o != "app" and o.rsplit("@", 1)[0] == dep
              and (not version or o.rsplit("@", 1)[1] == version)}
    rows, hop = [], {}
    first = _files_naming(repo_path, names)
    by_file = {(o, r): t for o, r, t in first}
    hits = _hits(first, names)
    for owner, rel, n, name, _line in hits:
        if owner in target:
            cls, fn = _enclosing(by_file[(owner, rel)]).get(n, ("", ""))
            nxt = cls or fn
            # a class the advisory names can still be a hop: healthchecks uses django's model
            # GenericIPAddressField, whose get_prep_value calls clean_ipv6_address, while the
            # advisory says only the forms field is affected; the route is the news
            if nxt and nxt != name and not nxt.startswith("_") and nxt.lower() not in _GENERIC and len(nxt) >= 5:
                hop.setdefault(nxt, f"{rel}:{n} {cls + '.' if cls else ''}{fn or ''}".rstrip(".") + f" calls {name}")
    for owner, rel, n, name, _line in hits:
        if owner not in target and name not in hop:
            rows.append((0 if owner == "app" else 1, owner, rel, n, name, ""))
    if hop:
        for owner, rel, n, name, _line in _hits(_files_naming(repo_path, hop, frozenset(target)), sorted(hop)):
            rows.append((2 if owner == "app" else 3, owner, rel, n, name, hop[name]))
    seen, out = set(), []
    for r in sorted(rows, key=lambda r: (r[0], r[1], r[2], r[3])):
        k = (r[1], r[2], r[4])                 # one line per file and name
        if k not in seen:
            seen.add(k)
            out.append(r)
    return tuple(out)


def callers_note(repo_path: str, ecosystem: str, dependency: str, version: str, vuln_symbols) -> str:
    """The judges' note: '' unless an installed distribution (not the vulnerable one) uses
    the symbols, or something reaches them through one hop of the vulnerable package's own
    code; the app's direct uses are listed with them."""
    if ecosystem != "pypi":
        return ""
    rows = callers(repo_path, dependency, version, vuln_symbols)
    if not any(r[1] != "app" or r[5] for r in rows):
        return ""            # the app's direct uses are in the usage summary already: installed callers and routes are news
    lines = [f"WHO CALLS {', '.join(symbols(vuln_symbols))} (the advisory's functions; text matches, so read "
             f"each before relying on it). Call sites in the app and in installed distributions the app imports"
             f"{', and one hop through ' + dependency + ' code that calls them' if any(r[0] >= 2 for r in rows) else ''}:"]
    for rank, owner, rel, n, name, via in rows[:MAX_LINES]:
        who = "app" if owner == "app" else owner
        lines.append(f"  {who} {rel}:{n} uses {name}" + (f"  (via {dependency}: {via})" if via else ""))
    if len(rows) > MAX_LINES:
        lines.append(f"  ... and {len(rows) - MAX_LINES} more")
    if any(r[1] != "app" for r in rows):
        lines.append("  A distribution here runs in the app (it is imported): its call can reach the vulnerable "
                     "code even when the app's own code never names it.")
    if any(r[5] for r in rows):
        lines.append(f"  A 'via' line is {dependency}'s own code calling the function from a class or function "
                     "the caller uses: it runs whatever the advisory says about which public API is affected.")
    return "\n".join(lines)


def caller_dists(repo_path: str, dependency: str, version: str, vuln_symbols, limit: int = 2) -> list[str]:
    """name@version of the first distributions (not the vulnerable one) the note names."""
    out = []
    for _rank, owner, *_ in callers(repo_path, dependency, version, vuln_symbols):
        if owner != "app" and owner not in out:
            out.append(owner)
    return out[:limit]

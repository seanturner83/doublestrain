"""Who calls the vulnerable code, from the deployed classpath's bytecode (jv2).

The JVM counterpart of pycallers. jv2's one miss (Stirling-PDF: bcprov's lazy ASN.1 parsing
reached through bcpkix's PEMParser, which the app calls on an uploaded file) was invisible
to both judges: the trigger is inside a library the app calls, two libraries away, and
neither the app's imports nor the declared dependency graph say which library calls which
method. The bytecode does. This reads every class in the release artifact (the app's own
classes and every bundled library), builds a call graph from the invoke instructions
(including method references behind lambdas), and walks it backwards from the advisory's
classes and methods to the app's own code.

It is a class-hierarchy approximation: a call to `Base.m` counts for every override of `m`,
overloads are not told apart, and reflection, ServiceLoader and framework dispatch are not
followed. It errs towards finding a path, never towards proving there is none: "no caller
found" is evidence, not proof (the judges are told so).

The artifact is untrusted data: class files are parsed from memory with bounds checks, a
malformed class is skipped, and nothing is loaded or run.
"""
from __future__ import annotations

import hashlib
import io
import marshal
import os
import re
import struct
import tarfile
import zipfile
import zlib
from collections import deque
from functools import lru_cache
from pathlib import Path

from . import jvmjars

GRAPH_V = "1"
MAX_CLASS = 4 * 2**20
MAX_CLASSES = 400_000
MAX_DEPTH = 10
MAX_VISIT = 60_000

# opcode -> instruction length (1 when absent); switches and wide are handled in _calls
_LEN = {0x10: 2, 0x11: 3, 0x12: 2, 0x13: 3, 0x14: 3, 0x84: 3, 0xa9: 2, 0xbc: 2, 0xc5: 4, 0xc8: 5, 0xc9: 5,
        0xb9: 5, 0xba: 5}
_LEN.update({op: 2 for op in range(0x15, 0x1a)})
_LEN.update({op: 2 for op in range(0x36, 0x3b)})
_LEN.update({op: 3 for op in range(0x99, 0xa9)})
_LEN.update({op: 3 for op in (0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7)})
_INVOKE = (0xb6, 0xb7, 0xb8, 0xb9)


class _Bad(Exception):
    pass


def _cp(b: bytes):
    """The constant pool -> (entries, offset after it). entries[i] = (tag, value)."""
    if b[:4] != b"\xca\xfe\xba\xbe":
        raise _Bad("not a class")
    n = struct.unpack_from(">H", b, 8)[0]
    ent, off, i = [None] * n, 10, 1
    while i < n:
        tag = b[off]
        if tag == 1:
            ln = struct.unpack_from(">H", b, off + 1)[0]
            ent[i] = (1, b[off + 3:off + 3 + ln].decode("utf-8", "replace"))
            off += 3 + ln
        elif tag in (7, 8, 16, 19, 20):
            ent[i] = (tag, struct.unpack_from(">H", b, off + 1)[0]); off += 3
        elif tag in (3, 4):
            off += 5
        elif tag in (5, 6):
            off += 9; i += 1
        elif tag in (9, 10, 11, 12, 17, 18):
            ent[i] = (tag, struct.unpack_from(">HH", b, off + 1)); off += 5
        elif tag == 15:
            ent[i] = (15, (b[off + 1], struct.unpack_from(">H", b, off + 2)[0])); off += 4
        else:
            raise _Bad(f"constant tag {tag}")
        i += 1
    return ent, off


def _utf(ent, i):
    e = ent[i] if 0 < i < len(ent) else None
    if not e or e[0] != 1:
        raise _Bad("bad utf8 ref")
    return e[1]


def _cls(ent, i):
    e = ent[i] if 0 < i < len(ent) else None
    if not e or e[0] != 7:
        raise _Bad("bad class ref")
    return _utf(ent, e[1])


def _member(ent, i):
    """A Methodref/InterfaceMethodref -> (owner, name)."""
    e = ent[i] if 0 < i < len(ent) else None
    if not e or e[0] not in (10, 11):
        return None
    c, nt = e[1]
    nte = ent[nt] if 0 < nt < len(ent) else None
    if not nte or nte[0] != 12:
        return None
    return _cls(ent, c), _utf(ent, nte[1][0])


def _attrs(b, off):
    n = struct.unpack_from(">H", b, off)[0]; off += 2
    out = []
    for _ in range(n):
        name_i, ln = struct.unpack_from(">HI", b, off)
        out.append((name_i, off + 6, ln)); off += 6 + ln
    return out, off


def _calls(code: bytes, ent, bsm) -> set:
    out, pc, n = set(), 0, len(code)
    while pc < n:
        op = code[pc]
        if op in _INVOKE:
            m = _member(ent, struct.unpack_from(">H", code, pc + 1)[0])
            if m:
                out.add(m)
        elif op == 0xba:                                    # invokedynamic: the lambda's target method
            e = ent[struct.unpack_from(">H", code, pc + 1)[0]]
            if e and e[0] == 18 and e[1][0] < len(bsm):
                out.update(bsm[e[1][0]])
        if op == 0xaa:                                      # tableswitch
            p = pc + 1 + ((4 - (pc + 1) % 4) % 4)
            lo, hi = struct.unpack_from(">ii", code, p + 4)
            pc = p + 12 + 4 * max(0, hi - lo + 1)
        elif op == 0xab:                                    # lookupswitch
            p = pc + 1 + ((4 - (pc + 1) % 4) % 4)
            npairs = struct.unpack_from(">i", code, p + 4)[0]
            pc = p + 8 + 8 * max(0, npairs)
        elif op == 0xc4:                                    # wide
            pc += 6 if pc + 1 < n and code[pc + 1] == 0x84 else 4
        else:
            pc += _LEN.get(op, 1)
    return out


def parse_class(b: bytes):
    """(class, super, interfaces, {method name: set of (owner, name) it calls}) from a class
    file's bytes. Raises _Bad on anything malformed."""
    try:
        ent, off = _cp(b)
        _acc, this_i, super_i, ni = struct.unpack_from(">HHHH", b, off); off += 8
        this = _cls(ent, this_i)
        sup = _cls(ent, super_i) if super_i else ""
        ifaces = [_cls(ent, struct.unpack_from(">H", b, off + 2 * k)[0]) for k in range(ni)]
        off += 2 * ni
        nf = struct.unpack_from(">H", b, off)[0]; off += 2
        for _ in range(nf):
            _a, off = _attrs(b, off + 6)
        nm = struct.unpack_from(">H", b, off)[0]; off += 2
        methods = []
        for _ in range(nm):
            _acc, name_i, _desc_i = struct.unpack_from(">HHH", b, off)
            attrs, off = _attrs(b, off + 6)
            methods.append((_utf(ent, name_i), attrs))
        cattrs, _ = _attrs(b, off)
        bsm = []
        for name_i, start, _ln in cattrs:
            if _utf(ent, name_i) == "BootstrapMethods":
                k = struct.unpack_from(">H", b, start)[0]; p = start + 2
                for _ in range(k):
                    _ref, na = struct.unpack_from(">HH", b, p); p += 4
                    targets = set()
                    for a in struct.unpack_from(f">{na}H", b, p):
                        e = ent[a] if 0 < a < len(ent) else None
                        if e and e[0] == 15 and (m := _member(ent, e[1][1])):
                            targets.add(m)
                    p += 2 * na
                    bsm.append(targets)
        out = {}
        for name, attrs in methods:
            for name_i, start, ln in attrs:
                if _utf(ent, name_i) == "Code":
                    clen = struct.unpack_from(">I", b, start + 4)[0]
                    out.setdefault(name, set()).update(_calls(b[start + 8:start + 8 + clen], ent, bsm))
            out.setdefault(name, set())
        return this, sup, ifaces, out
    except (struct.error, IndexError, TypeError, ValueError) as exc:
        raise _Bad(str(exc)) from exc


# --- the artifact's classes, labelled by the coordinate they belong to --------------------------

def _jar_classes(data: bytes, where: str, depth: int):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError):
        return
    for zi in z.infolist():
        n = zi.filename
        if n.endswith(".class") and zi.file_size <= MAX_CLASS and not n.endswith("module-info.class"):
            yield where, n, z.read(zi)
        elif depth < jvmjars.DEPTH and n.endswith(jvmjars.JAR_EXT) and n.startswith(jvmjars._NESTED_DIRS) \
                and zi.file_size <= jvmjars.MAX_NESTED:
            yield from _jar_classes(z.read(zi), f"{where}!{n}", depth + 1)


def _classes(paths):
    for p in map(Path, paths):
        if p.suffix in jvmjars.JAR_EXT:
            yield from _jar_classes(p.read_bytes(), p.name, 0)
        elif p.suffix == ".zip":
            with zipfile.ZipFile(p) as z:
                for zi in z.infolist():
                    if zi.filename.endswith(jvmjars.JAR_EXT) and zi.file_size <= jvmjars.MAX_JAR:
                        yield from _jar_classes(z.read(zi), zi.filename, 0)
        else:
            with tarfile.open(p, mode="r|*") as tf:
                for ti in tf:
                    if ti.isfile() and ti.name.endswith(jvmjars.JAR_EXT) and ti.size <= jvmjars.MAX_JAR:
                        f = tf.extractfile(ti)
                        if f is not None:
                            yield from _jar_classes(f.read(), jvmjars._clean(ti.name), 0)


def _owner_map(ix: dict):
    """Java package -> the coordinate that ships it (exact packages from the index)."""
    pk = {}
    for name, v in ix.items():
        if name != "__app__":
            for p in v.get("packages") or ():
                pk.setdefault(p, name)
    return pk


def _cache_dir() -> Path:
    return Path(os.environ.get("SSVC_JUDGE_CACHE", "~/.cache/ssvc-triage/judge")).expanduser() / "jvm"


def build(repo) -> dict | None:
    """The call graph of a registered checkout's artifact: {"cls": {class: [owner, super,
    [interfaces], {method: [callee ids]}]}, "ids": ["owner#name", ...]}. `owner` is the
    coordinate ("g:a") or "app". Cached per artifact."""
    a = jvmjars.artifact_for(repo)
    ix = jvmjars.index(repo)
    if a is None or ix is None:
        return None
    st = [(p, Path(p).stat().st_size, Path(p).stat().st_mtime_ns) for p in a["paths"]]
    key = hashlib.sha256(repr((GRAPH_V, jvmjars.INDEX_V, st, a.get("first_party"))).encode()).hexdigest()[:24]
    f = _cache_dir() / f"calls-{key}.bin"
    if f.is_file():
        return marshal.loads(zlib.decompress(f.read_bytes()))
    pk = _owner_map(ix)
    ids: dict[str, int] = {}
    cls: dict = {}
    for n, (where, entry, data) in enumerate(_classes(a["paths"])):
        if n >= MAX_CLASSES:
            break
        try:
            this, sup, ifaces, meths = parse_class(data)
        except _Bad:
            continue
        if this in cls:
            continue                      # first copy wins (classpath order)
        pkg = this.rsplit("/", 1)[0].replace("/", ".") if "/" in this else ""
        owner = pk.get(pkg, "app")
        cls[this] = [owner, sup, ifaces,
                     {m: [ids.setdefault(f"{o}#{nm}", len(ids)) for o, nm in sorted(cs)] for m, cs in meths.items()}]
    g = {"cls": cls, "ids": list(ids)}
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(zlib.compress(marshal.dumps(g), 6))
    return g


@lru_cache(maxsize=4)
def _reverse(key: str, repo: str):
    g = build(repo)
    if g is None:
        return None
    ids = g["ids"]
    rev: dict[str, list] = {}                  # "owner#name" -> [(caller class, caller method)]
    for c, (_o, _s, _i, meths) in g["cls"].items():
        for m, callees in meths.items():
            for k in callees:
                rev.setdefault(ids[k], []).append((c, m))
    subs: dict[str, list] = {}
    for c, (_o, sup, ifaces, _m) in g["cls"].items():
        for s in [sup, *ifaces]:
            if s:
                subs.setdefault(s, []).append(c)
    return g, rev, subs


def _supers(g, c, seen=None):
    seen = seen if seen is not None else set()
    if c in seen or c not in g["cls"]:
        return seen
    seen.add(c)
    _o, sup, ifaces, _m = g["cls"][c]
    for s in [sup, *ifaces]:
        if s:
            _supers(g, s, seen)
    return seen


_TOK = re.compile(r"(?:new\s+)?[A-Za-z_$][\w$]*(?:[.#][A-Za-z_$<][\w$>]*)*")


def targets(g, dependency: str, symbols) -> set:
    """(class, method) pairs of `dependency` the advisory's symbols name: a class
    (`ASN1InputStream`, `org.bouncycastle.asn1.ASN1InputStream`: all its methods; `new X`: its
    constructors), `Class.method`, or a distinctive method name."""
    mine = {c: v for c, v in g["cls"].items() if v[0] == dependency}
    by_simple: dict[str, list] = {}
    for c in mine:
        by_simple.setdefault(c.rsplit("/", 1)[-1].split("$")[-1], []).append(c)
    out = set()
    for s in symbols or ():
        for tok in _TOK.findall(str(s)):
            new = tok.startswith("new ")
            tok = tok[4:].strip() if new else tok
            parts = re.split(r"[.#]", tok)
            # Class, pkg.Class, Class.method, pkg.Class.method
            for k in range(len(parts), 0, -1):
                cname, rest = parts[:k], parts[k:]
                hits = (by_simple.get(cname[-1], []) if len(cname) == 1 else
                        [c for c in mine if c.replace("/", ".").replace("$", ".") == ".".join(cname)])
                if hits:
                    for c in hits:
                        ms = mine[c][3]
                        if rest and rest[0] in ms:
                            out.add((c, rest[0]))
                        elif not rest:
                            out.update((c, m) for m in ms if not new or m == "<init>")
                    break
            else:
                if len(tok) >= 6 and tok[0].islower():
                    out.update((c, tok) for c, v in mine.items() if tok in v[3])
    return out


def chains(repo, dependency: str, symbols, limit: int = 6):
    """Shortest call chains from the app's own methods to the advisory's code: a list of
    [(class, method, owner), ...] from the app end; and the coordinates passed through."""
    a = jvmjars.artifact_for(repo)
    if a is None:
        return None
    key = repr(sorted(a["paths"]))
    rv = _reverse(key, str(Path(repo).expanduser().resolve()))
    if rv is None:
        return None
    g, rev, subs = rv
    tgt = targets(g, dependency, symbols)
    if not tgt:
        return None
    def walk(dispatch: bool, prev: dict, apps: list):
        q = deque((t, 0) for t in prev)
        while q and len(prev) < MAX_VISIT:
            (c, m), d = q.popleft()
            if g["cls"].get(c, ["?"])[0] == "app":
                apps.append((c, m))
                if len(apps) >= limit * 4:
                    return
                continue
            if d >= MAX_DEPTH:
                continue
            # a call naming c.m, or a subtype that inherits m; constructors and static
            # initialisers are never dispatched. With `dispatch`, also a call naming a
            # supertype's m (virtual/interface dispatch: possible, weaker evidence)
            keys = {f"{c}#{m}"}
            if m not in ("<init>", "<clinit>"):
                keys |= {f"{s}#{m}" for s in subs.get(c, ()) if m not in g["cls"].get(s, [0, 0, 0, {}])[3]}
                if dispatch:
                    keys |= {f"{s}#{m}" for s in _supers(g, c)}
            for k in keys:
                for caller in rev.get(k, ()):
                    if caller not in prev:
                        prev[caller] = (c, m)
                        q.append((caller, d + 1))

    prev, apps = {t: None for t in tgt}, []
    walk(False, prev, apps)
    exact = len(apps)
    if len({a[0] for a in apps}) < limit:              # few direct paths: allow dispatch through supertypes
        prev2, apps2 = {t: None for t in tgt}, []
        walk(True, prev2, apps2)
        for a in apps2:
            if a not in prev:
                prev.setdefault(a, prev2[a])
                # keep the dispatch path for this app method
                cur = a
                while cur is not None and prev2.get(cur) is not None:
                    prev.setdefault(prev2[cur], prev2.get(prev2[cur]))
                    cur = prev2[cur]
                apps.append(a)
    dispatched = set(apps[exact:])
    out, seen_app = [], set()
    for node in apps:
        if node[0] in seen_app:
            continue
        seen_app.add(node[0])
        path, cur, hops = [], node, 0
        while cur is not None and hops <= MAX_DEPTH + 1:
            path.append((cur[0], cur[1], g["cls"].get(cur[0], ["?"])[0]))
            cur, hops = prev.get(cur), hops + 1
        out.append((path, node in dispatched))
        if len(out) >= limit:
            break
    via = []
    for p, _d in out:
        for _c, _m, o in p:
            if o not in ("app", dependency) and o not in via:
                via.append(o)
    return out, via, len(tgt)


def _fmt(c: str, m: str) -> str:
    return f"{c.rsplit('/', 1)[-1]}.{m}"


def callers_note(repo_path: str, ecosystem: str, dependency: str, version: str, symbols) -> str:
    if ecosystem != "maven" or not symbols:
        return ""
    got = chains(repo_path, dependency, symbols)
    if got is None:
        return ""
    paths, via, ntgt = got
    head = (f"CALLERS IN THE DEPLOYED CLASSPATH (jvmcallers: bytecode call graph over the release's classes; "
            f"a call to a supertype counts for its overrides; reflection and framework dispatch not followed) "
            f"of {ntgt} {dependency} method(s) the advisory names:")
    if not paths:
        return head + ("\n  no method of the app's own classes reaches them through bytecode calls"
                       " (evidence, not proof: frameworks can still dispatch by name).")
    lines = [head]
    for p, disp in paths:
        lines.append("  " + " -> ".join(f"{_fmt(c, m)} [{'app' if o == 'app' else o.split(':')[-1]}]" for c, m, o in p)
                     + ("   (through a call on a supertype: possible, not certain)" if disp else ""))
    if via:
        lines.append(f"  libraries on these paths (their source is provided when available): {', '.join(via)}")
    return "\n".join(lines)


def caller_coords(repo_path: str, dependency: str, symbols, limit: int = 3) -> list[str]:
    """The libraries on the caller chains, nearest the app first: their source goes to the judges."""
    got = chains(repo_path, dependency, symbols) if symbols else None
    return got[1][:limit] if got else []

"""npm semver: version ordering and range matching (node-semver's grammar, minus loose
mode). Used to ask "does a patched version fit the range this parent declares?".

`satisfies` returns None for ranges it can't evaluate (git/file/URL/tag/alias specs), so
callers can say "unknown" instead of guessing.
"""
from __future__ import annotations

import re
from functools import total_ordering

_N = r"(0|[1-9][0-9]{0,15})"                 # ASCII, no leading zeros, bounded (no giant ints)
_PRE = r"(?:-([0-9A-Za-z.-]{1,128}))?(?:\+[0-9A-Za-z.-]{1,128})?"
_V = re.compile(rf"^\s*v?{_N}\.{_N}\.{_N}{_PRE}\s*$")
_PARTIAL = re.compile(rf"^v?({_N[1:-1]}|[xX*])(?:\.({_N[1:-1]}|[xX*]))?(?:\.({_N[1:-1]}|[xX*]))?{_PRE}$")
_COMP = re.compile(r"^(<=|>=|<|>|=|~>|~|\^)?\s*(\S+)$")


def _ident(p: str):
    return int(p) if p.isascii() and p.isdigit() and len(p) <= 16 else p


@total_ordering
class Version:
    __slots__ = ("core", "pre")

    def __init__(self, core: tuple[int, int, int], pre: tuple = ()):
        self.core, self.pre = core, pre

    @classmethod
    def parse(cls, s: str) -> "Version | None":
        m = _V.match(s or "")
        if not m:
            return None
        pre = tuple(_ident(p) for p in m.group(4).split(".")) if m.group(4) else ()
        return cls((int(m.group(1)), int(m.group(2)), int(m.group(3))), pre)

    def _key(self):
        # a release sorts after its prereleases; numeric identifiers sort before alphanumeric
        return (self.core, 0 if self.pre else 1,
                tuple((0, p, "") if isinstance(p, int) else (1, 0, p) for p in self.pre))

    def __eq__(self, o):
        return isinstance(o, Version) and (self.core, self.pre) == (o.core, o.pre)

    def __lt__(self, o):
        return self._key() < o._key()

    def __hash__(self):
        return hash((self.core, self.pre))

    def __repr__(self):
        return ".".join(map(str, self.core)) + ("-" + ".".join(map(str, self.pre)) if self.pre else "")


def parse(s: str) -> Version | None:
    return Version.parse(s)


def compatible(a: Version, b: Version) -> bool:
    """Same caret class: ^a admits b's line (same major; for 0.x the same minor; 0.0.x exact)."""
    if a.core[0] != b.core[0]:
        return False
    if a.core[0] == 0:
        return a.core[1] == b.core[1] and (a.core[1] != 0 or a.core[2] == b.core[2])
    return True


def _lo(major, minor=0, patch=0, pre=()):
    return Version((major, minor, patch), pre)


_ZERO = (0,)            # `<X.Y.Z-0`: below every prerelease of X.Y.Z


def _desugar(op: str, raw: str) -> list[tuple[str, Version]] | None:
    m = _PARTIAL.match(raw)
    if not m:
        return None
    parts = [None if (p is None or p in "xX*") else int(p) for p in m.group(1, 2, 3)]
    pre = tuple(_ident(p) for p in m.group(4).split(".")) if m.group(4) else ()
    M, mi, pa = parts
    if M is None:                                          # *, x
        return [] if op in ("", "=", ">=", "<=", "~", "^") else [("<", _lo(0, 0, 0, _ZERO))]
    if op in ("", "="):
        if mi is None:
            return [(">=", _lo(M)), ("<", _lo(M + 1, 0, 0, _ZERO))]
        if pa is None:
            return [(">=", _lo(M, mi)), ("<", _lo(M, mi + 1, 0, _ZERO))]
        return [("=", _lo(M, mi, pa, pre))]
    if op in ("~", "~>"):
        if mi is None:
            return [(">=", _lo(M)), ("<", _lo(M + 1, 0, 0, _ZERO))]
        return [(">=", _lo(M, mi, pa or 0, pre)), ("<", _lo(M, mi + 1, 0, _ZERO))]
    if op == "^":
        lo = _lo(M, mi or 0, pa or 0, pre)
        if M > 0 or mi is None:
            hi = _lo(M + 1, 0, 0, _ZERO)
        elif mi > 0 or pa is None:
            hi = _lo(0, mi + 1, 0, _ZERO)
        else:
            hi = _lo(0, 0, pa + 1, _ZERO)
        return [(">=", lo), ("<", hi)]
    if op == ">":
        if mi is None:
            return [(">=", _lo(M + 1))]
        if pa is None:
            return [(">=", _lo(M, mi + 1))]
        return [(">", _lo(M, mi, pa, pre))]
    if op == ">=":
        return [(">=", _lo(M, mi or 0, pa or 0, pre))]
    if op == "<":
        return [("<", _lo(M, mi or 0, pa or 0, pre or (_ZERO if mi is None or pa is None else ())))]
    if op == "<=":
        if mi is None:
            return [("<", _lo(M + 1, 0, 0, _ZERO))]
        if pa is None:
            return [("<", _lo(M, mi + 1, 0, _ZERO))]
        return [("<=", _lo(M, mi, pa, pre))]
    return None


def _set(text: str) -> list[tuple[str, Version]] | None:
    text = text.strip()
    hy = re.match(r"^(\S+)\s+-\s+(\S+)$", text)
    if hy:
        a, b = _desugar(">=", hy.group(1)), _desugar("<=", hy.group(2))
        return None if a is None or b is None else a + b
    toks = re.findall(r"(?:<=|>=|<|>|=|~>|~|\^)?\s*[^\s<>=~^]+", text)
    if re.sub(r"\s+", "", "".join(toks)) != re.sub(r"\s+", "", text):
        return None                                        # dangling operator or junk
    out: list[tuple[str, Version]] = []
    for tok in toks:
        m = _COMP.match(tok.strip())
        if not m:
            return None
        d = _desugar(m.group(1) or "", m.group(2))
        if d is None:
            return None
        out += d
    return out


_OPS = {"=": lambda v, c: v == c, ">": lambda v, c: v > c, ">=": lambda v, c: v >= c,
        "<": lambda v, c: v < c, "<=": lambda v, c: v <= c}


def satisfies(version: str | Version, rng: str) -> bool | None:
    """Does version satisfy the npm range? None when the range isn't a semver range."""
    v = version if isinstance(version, Version) else Version.parse(version)
    if v is None or rng is None:
        return None
    rng = rng.strip()
    if len(rng) > 512 or re.match(r"^(?:[a-z+]+:|github:|git|https?:|file:|link:|workspace:|npm:)|/", rng) or \
            (rng and re.fullmatch(r"[A-Za-z][\w.-]*", rng) and not _PARTIAL.match(rng)):
        return None                                        # url, git, alias, dist-tag
    sets = [_set(s) for s in (rng.split("||") if rng else [""])]
    if any(s is None for s in sets):
        return None
    for comps in sets:
        if not all(_OPS[op](v, c) for op, c in comps):
            continue
        # a prerelease only matches a set that names a prerelease of the same core
        if v.pre and not any(c.pre and c.pre != _ZERO and c.core == v.core for _, c in comps):
            continue
        return True
    return False

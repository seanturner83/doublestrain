"""Package names across ecosystems: one place for "are these the same package?".

Each ecosystem spells one package several ways, and every boundary where names meet
(lockfile or classpath -> OSV, OSV -> the dependency graph, the graph -> source dirs, a
model's citation -> source dirs, a package -> the names its code is imported by) used to
compare them its own way. The misses were silent: jv1's specs were all rejected because a
model cited `jackson-databind@2.17.1/...` for `com.fasterxml.jackson.core:jackson-databind`.

- pypi:  PEP 503, case-insensitive with runs of `-_.` equal (`PyYAML` == `pyyaml`,
         `zope.interface` == `zope-interface`).
- cargo: crates.io treats `-` and `_` as one and ignores case (`serde_json` == `serde-json`).
- maven: `group:artifact`, exact; a bare `artifact` names it when the group is left out
         (models and file names drop it), never the other way round.
- npm, go: exact (`@scope/name`; a Go module path).

`spec` strings are `name@version`; npm scopes start with `@`, so the version is after the
LAST `@`.
"""
from __future__ import annotations

import re


def canonical(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "cargo":
        return name.replace("_", "-").lower()
    return name


def _eco_of(name: str, ecosystem: str) -> str:
    # callers that only hold a spec string: a colon only ever appears in Maven names
    return "maven" if not ecosystem and ":" in name else ecosystem


def same(a: str, b: str, ecosystem: str = "") -> bool:
    """Do `a` and `b` name the same package? (`a`/`b` without versions.)"""
    eco = _eco_of(a, ecosystem) or _eco_of(b, ecosystem)
    if canonical(eco, a) == canonical(eco, b):
        return True
    if eco == "maven" and (":" in a) != (":" in b):
        full, bare = (a, b) if ":" in a else (b, a)
        return full.split(":", 1)[1] == bare
    return False


def split_spec(spec: str) -> tuple[str, str]:
    """`name@version` -> (name, version); no version -> (spec, "")."""
    i = spec.rfind("@")
    return (spec[:i], spec[i + 1:]) if i > 0 else (spec, "")


def bare(raw: str) -> str:
    """The name in a model's `name@version` (or plain name)."""
    return split_spec(raw)[0]


def resolve(raw: str, names, ecosystem: str = "") -> str:
    """The name in `names` that a model's `raw` (`name` or `name@version`) refers to; `raw`'s
    name unchanged when none does."""
    n = bare(raw)
    return next((x for x in names if x == n), None) or next((x for x in names if same(x, n, ecosystem)), n)


def cited_in(path: str, spec: str, ecosystem: str = "") -> str | None:
    """When `path` (a model's citation) starts with source `spec` (`name@version`) under any
    spelling of the name, the rest of the path after `<name@version>/`; else None."""
    name, version = split_spec(spec)
    if not version:
        return path[len(spec) + 1:] if path.startswith(spec + "/") else None
    m = path.find("@" + version + "/")
    while m > 0:
        if same(path[:m], name, ecosystem):
            return path[m + len(version) + 2:]
        m = path.find("@" + version + "/", m + 1)
    return None


_STEP = re.compile(r"^(.+?)@([^/@]+)/")      # `<name>@<version>/...`; names may hold `/` (npm scopes, Go)


def steps_in(steps, name: str, ecosystem: str = "") -> bool:
    """Is any verified step (`<name@version>/<file>:<line>`) inside package `name`?"""
    return any((m := _STEP.match(s)) and same(m[1], name, ecosystem) for s in steps)

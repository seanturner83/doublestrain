"""The register of known gaps in advisory text (`advisory_notes.toml`).

Each note says how an advisory's vulnerable code is reached in more ways than its text
admits; `reach.query_for` adds matching notes to the advisory summary, so every tier
reads them. Notes only ever widen: the loader refuses anything that isn't
`kind = "widens"` or whose text reads like a narrowing ("not affected", "only when"...).
`doublestrain advisories check` verifies every evidence step against the published
source of the version it names (pkgsrc; nothing is installed or run).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT = Path(__file__).with_name("advisory_notes.toml")
_NARROWING = re.compile(
    r"\b(not\s+(?:affected|reachable|vulnerable|exploitable|impacted)|unaffected|only\s+(?:when|if|affects|applies|in)|"
    r"(?:does\s+not|doesn't|do\s+not|don't)\s+(?:apply|affect|reach)|cannot\s+be\s+(?:reached|exploited|triggered)|"
    r"no\s+impact|false\s+positive|is\s+safe|are\s+safe|ignore\s+this)\b", re.I)
_FIELDS = ("id", "package", "ecosystem", "versions", "kind", "note", "evidence", "verified")


@dataclass(frozen=True)
class Note:
    id: str
    package: str
    ecosystem: str
    versions: str
    note: str
    evidence: tuple[dict, ...]
    verified: str
    upstream: str = ""


def _norm(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name


@lru_cache(maxsize=4)
def load(path: str = "") -> tuple[Note, ...]:
    """Every note in the register (SSVC_ADVISORY_NOTES names another file; "none" turns
    them off). Raises ValueError on a malformed or narrowing entry."""
    path = path or os.environ.get("SSVC_ADVISORY_NOTES", "") or str(DEFAULT)
    if path.lower() == "none":
        return ()
    doc = tomllib.loads(Path(path).read_text())
    out = []
    for i, e in enumerate(doc.get("advisory") or []):
        missing = [f for f in _FIELDS if not e.get(f)]
        if missing:
            raise ValueError(f"advisory note {i}: missing {', '.join(missing)}")
        if e["kind"] != "widens":
            raise ValueError(f"advisory note {e['id']}: kind must be \"widens\" (a note never narrows)")
        if m := _NARROWING.search(e["note"]):
            raise ValueError(f"advisory note {e['id']}: reads as a narrowing ({m.group(0)!r}); notes only widen")
        for s in e["evidence"]:
            if not (isinstance(s, dict) and s.get("path") and s.get("line") and s.get("quote")):
                raise ValueError(f"advisory note {e['id']}: each evidence step needs path, line and quote")
        out.append(Note(e["id"], _norm(e["ecosystem"], e["package"]), e["ecosystem"], e["versions"],
                        " ".join(e["note"].split()), tuple(e["evidence"]), e["verified"], e.get("upstream", "")))
    return tuple(out)


def _vkey(v: str):
    """A comparable key for npm semver, PEP 440 and Go versions: numeric parts compare as
    numbers, and a pre-release sorts before its release (1.0.0-rc1 < 1.0.0)."""
    v = v.strip().lstrip("v=").split("+", 1)[0]
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return ((0,), (0, v))
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums)) if len(nums) < 4 else nums
    rest = m.group(2).lstrip("-.")
    if not rest:
        return (nums, (1, ""))
    return (nums, (2, rest) if rest.startswith("post") else (0, rest))     # 1.0.post1 > 1.0 > 1.0rc1


def in_range(version: str, spec: str) -> bool:
    """`spec`: comparator lists (`>=2.0.0-0,<2.1.0`) joined by `||`."""
    for alt in spec.split("||"):
        ok = True
        for c in (x.strip() for x in alt.split(",") if x.strip()):
            m = re.match(r"^(<=|>=|<|>|==|=)?\s*(.+)$", c)
            op, bound = m.group(1) or "==", m.group(2)
            a, b = _vkey(version), _vkey(bound)
            ok &= {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "==": a == b, "=": a == b}[op]
        if ok:
            return True
    return False


def notes_for(ids, package: str, ecosystem: str, version: str) -> list[Note]:
    want = {i.upper() for i in ids}
    pkg = _norm(ecosystem, package)
    return [n for n in load() if n.id.upper() in want and n.package == pkg and n.ecosystem == ecosystem
            and (not version or in_range(version, n.versions))]


def annotate(advisory: str, notes: list[Note]) -> str:
    """The advisory summary with each matching note after it, marked as the tool's."""
    if not notes:
        return advisory
    return advisory + "".join(f"\n\n[doublestrain note on the advisory text, checked against the source "
                              f"({n.verified}): {n.note}]" for n in notes)


# --- doublestrain advisories check ------------------------------------------------

def check(notes=None) -> list[str]:
    """Problems with the register's evidence, after fetching each named version's
    published source (registry-verified, since there is no lockfile here)."""
    from . import pkgsrc
    from .judges.claude_code import check_trace
    problems = []
    for n in notes if notes is not None else load():
        by_spec: dict[str, list[dict]] = {}
        for s in n.evidence:
            by_spec.setdefault(s["path"].split("/", 1)[0], []).append(s)
        for spec, steps in by_spec.items():
            name, _, version = spec.rpartition("@")
            try:
                src = (pkgsrc.fetch_pypi(name, version, "") if n.ecosystem == "pypi"
                       else pkgsrc.fetch(name, version, ""))
            except pkgsrc.Rejected as exc:
                problems.append(f"{n.id}: {spec}: {exc}")
                continue
            ok, bad = check_trace(steps, [(spec, src)], name)
            problems += [f"{n.id}: {b}" for b in bad]
            if len(ok) != len(steps) and not bad:
                problems.append(f"{n.id}: {spec}: only {len(ok)} of {len(steps)} steps checked")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="The register of known gaps in advisory text.")
    ap.add_argument("action", choices=("list", "check"))
    args = ap.parse_args(argv)
    notes = load()
    if args.action == "list":
        for n in notes:
            print(f"{n.id}  {n.ecosystem}:{n.package} {n.versions}\n  {n.note}\n")
        return 0
    os.environ.setdefault("SSVC_PKGSRC", "1")
    problems = check(notes)
    for p in problems:
        print("FAIL", p)
    print(f"{len(notes)} notes, {sum(len(n.evidence) for n in notes)} evidence steps: "
          + ("all checked" if not problems else f"{len(problems)} problem(s)"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

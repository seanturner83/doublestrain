"""Classify the no-fix state of an advisory, and how safe the fix path is.

"No fix" isn't one state. Each advisory on an installed package@version is put in one:

  fix_available     a published, unaffected version fits every declared range: upgrade
  blocked_by_parent an unaffected version exists in the same line, but a parent's range
                    excludes it: npm overrides, or upgrade the parent (listed when a newer
                    parent's range admits the fix)
  fix_major_only    unaffected versions exist only across a semver-major (or 0.x minor)
  fixed_unreleased  the advisory names a fixed version that isn't published
  unfixed_upstream  every published version is affected and the project is alive
  abandoned         ... and the project is deprecated or silent for SSVC_NOFIX_STALE_MONTHS
  wont_fix          ... and the advisory is disputed / by design
  data_gap          the advisory has no usable affected ranges for this package, or it is
                    open-ended but releases kept coming after it was published: verify
  withdrawn         every record is withdrawn: drop
  unknown           couldn't tell (no registry data, non-semver version): a human looks

`fork_only` and the upstream half of `fixed_unreleased` (a fix commit with no release)
come from the upstream watch, which builds on registry.upstream(). Classification is
mechanical (OSV ranges, registry versions, declared ranges): no model, nothing to refuse.

Upgrade risk ("semver safety") is a second axis for every candidate fix version:
  current   this upgrade: semver-major / 0.x minor, Node engines raised, ESM-only switch,
            exports or main changed, dependencies added/removed, NEW install scripts,
            a new publisher or maintainer set, size jump, too fresh to trust, deprecated,
            and (for overrides) a version outside the parent's declared range
  historic  the package's record: share of past minor/patch releases that carried
            breaking signals, versions deprecated as broken, unpublished versions
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from . import osv, registry
from .inventory import APP, Component, Inventory, fill_ranges, load
from .semver import Version, compatible, parse, satisfies

ROUTES = {
    "not_affected": "drop (check why the scanner matched)",
    "fix_available": "upgrade",
    "blocked_by_parent": "override or upgrade the parent",
    "fix_major_only": "upgrade-impact analysis; mitigate meanwhile",
    "fixed_unreleased": "vendor the fix or mitigate",
    "fix_prerelease_only": "pin the prerelease with care, or mitigate",
    "fork_only": "vendor or switch (human check)",
    "unfixed_upstream": "mitigate",
    "abandoned": "replace the dependency; mitigate meanwhile",
    "wont_fix": "mitigate or accept the risk",
    "data_gap": "verify, then reclassify",
    "withdrawn": "drop",
    "unknown": "mitigate (state unknown); a human looks",
}


@dataclass
class UpgradeRisk:
    to: str
    level: str                                   # low | caution | high
    current: list[str] = field(default_factory=list)
    historic: list[str] = field(default_factory=list)


@dataclass
class NoFix:
    package: str
    version: str
    advisory: list[str]
    state: str
    route: str
    evidence: list[str] = field(default_factory=list)
    patched: list[str] = field(default_factory=list)       # unaffected newer versions (lowest first)
    blocking: list[str] = field(default_factory=list)      # parent@version declares range
    parent_fixes: list[str] = field(default_factory=list)  # parent@newer whose range admits a fix
    risk: UpgradeRisk | None = None


# --- OSV ranges -------------------------------------------------------------------
def _ranges_for(rec: dict, name: str) -> list[dict]:
    return [a for a in rec.get("affected") or [] if isinstance(a, dict)
            and isinstance(a.get("package"), dict) and a["package"].get("ecosystem") == "npm"
            and str(a["package"].get("name", "")).lower() == name.lower()]


def affected(recs: list[dict], name: str, version: Version) -> bool | None:
    """Is `version` affected by any record? None if no record has npm data for `name`."""
    seen = malformed = False
    for rec in recs:
        for a in _ranges_for(rec, name):
            seen = True
            if str(version) in (a.get("versions") or []):
                return True
            for r in a.get("ranges") or []:
                if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                    continue
                evs = []
                for e in r.get("events") or []:
                    for kind in ("introduced", "fixed", "last_affected", "limit"):
                        if isinstance(e, dict) and kind in e:
                            raw = e[kind]
                            v = Version((0, 0, 0)) if raw == "0" else parse(raw) if isinstance(raw, str) else None
                            if v is None:
                                malformed = True
                            else:
                                evs.append((v, kind))
                state = False
                for v, kind in sorted(evs, key=lambda x: (x[0], x[1] != "introduced")):
                    if kind == "introduced" and version >= v:
                        state = True
                    elif kind == "fixed" and version >= v:
                        state = False
                    elif kind == "last_affected" and version > v:
                        state = False
                    elif kind == "limit" and version >= v:
                        state = False
                if state:
                    return True
    return None if malformed or not seen else False


def _declared_fixes(recs, name) -> set[str]:
    return {e["fixed"] for rec in recs for a in _ranges_for(rec, name)
            for r in a.get("ranges") or [] for e in r.get("events") or [] if "fixed" in e}


def _open_ended(recs, name) -> bool:
    return not any("fixed" in e or "last_affected" in e or "limit" in e
                   for rec in recs for a in _ranges_for(rec, name)
                   for r in a.get("ranges") or [] for e in r.get("events") or [])


_DISPUTED = re.compile(r"\*\*\s*DISPUTED\s*\*\*|^\s*DISPUTED\b|\bdisputed by the (?:vendor|maintainers?|developers?)\b"
                       r"|\bmaintainers? (?:do(?:es)? not consider|disputes?)\b|\bwon'?t fix\b", re.I | re.M)
_CONFIRMED = re.compile(r"\b(?:later|subsequently|since been) (?:confirmed|fixed|acknowledged)\b|\bno longer disputed\b", re.I)


def _disputed(text: str) -> str:
    m = _DISPUTED.search(text)
    return "" if m is None or _CONFIRMED.search(text) else m.group(0).strip()


def _ts(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- upgrade risk (semver safety) --------------------------------------------------
_BROKEN = re.compile(r"\b(?:broken|regression|critical bug|do not use|don'?t use|bad release|mistake)\b", re.I)


def _breaking(a: dict, b: dict) -> list[str]:
    out = []
    ea, eb = (a.get("engines") or {}), (b.get("engines") or {})
    na = _min_node(ea.get("node")) if isinstance(ea, dict) else None
    nb = _min_node(eb.get("node")) if isinstance(eb, dict) else None
    if na is not None and nb is not None and nb > na:      # a raise, not a first declaration
        out.append(f"engines.node raised {ea.get('node')!r} -> {eb.get('node')!r}")
    if b.get("type") == "module" and a.get("type") != "module":
        out.append("switched to ESM (type: module)")
    if b.get("exports") and not a.get("exports"):
        out.append("exports map added (blocks deep imports)")
    elif a.get("exports") and b.get("exports") and a["exports"] != b["exports"]:
        out.append("exports map changed")
    if a.get("main") and b.get("main") and a["main"] != b["main"]:
        out.append(f"main {a['main']!r} -> {b['main']!r}")
    return out


def _min_node(spec) -> tuple[int, ...] | None:
    m = re.search(r"([0-9]{1,6})(?:\.([0-9]{1,6}))?(?:\.([0-9]{1,6}))?", spec[:100]) if isinstance(spec, str) else None
    return tuple(int(x or 0) for x in m.groups()) if m else None


# shown, but on their own not a reason for caution (they change routinely)
_INFO = ("maintainer set changed", "dependencies removed")


def _who(meta: dict) -> str:
    u = meta.get("_npmUser")
    return u.get("name", "") if isinstance(u, dict) else ""


def _maintainers(meta: dict) -> frozenset:
    return frozenset(m.get("name", "") for m in meta.get("maintainers") or [] if isinstance(m, dict))


def upgrade_risk(pk: dict, frm: str, to: str, *, outside_range: list[str] = ()) -> UpgradeRisk:
    vs = pk.get("versions") or {}
    a, b = vs.get(frm) or {}, vs.get(to) or {}
    va, vb = parse(frm), parse(to)
    cur, hist = [], []
    if va and vb and not compatible(va, vb):
        cur.append("semver-major" if va.core[0] != vb.core[0] else "0.x minor (breaking by convention)")
    cur += _breaking(a, b)
    da, db = set(a.get("dependencies") or {}), set(b.get("dependencies") or {})
    if db - da:
        cur.append("dependencies added: " + ", ".join(sorted(db - da))[:200])
    if da - db:
        cur.append("dependencies removed: " + ", ".join(sorted(da - db))[:200])
    if set(b.get("peerDependencies") or {}) != set(a.get("peerDependencies") or {}):
        cur.append("peerDependencies changed")
    new_scripts = sorted(set(b.get("install_scripts") or []) - set(a.get("install_scripts") or []))
    if new_scripts:
        cur.append("NEW install script(s): " + ", ".join(new_scripts))
    if _who(b) and _who(a) and _who(b) != _who(a):
        earlier = {_who(m) for v, m in vs.items() if (pv := parse(v)) and vb and pv < vb}
        if _who(b) not in earlier:
            # a maintainer's first publish is a handover (caution); a stranger's is high
            known = _who(b) in _maintainers(a)
            cur.append(f"first publish by {_who(b)}" + (" (already a maintainer)" if known
                                                        else " (NOT a prior maintainer)"))
    if _maintainers(a) and _maintainers(b) and _maintainers(a) != _maintainers(b):
        cur.append("maintainer set changed")
    if a.get("size") and b.get("size") and b["size"] > 2 * a["size"] and b["size"] > 50_000:
        cur.append(f"unpacked size x{b['size'] / a['size']:.1f}")
    t = _ts((pk.get("time") or {}).get(to, ""))
    min_age = float(os.environ.get("SSVC_UPGRADE_MIN_AGE_DAYS", "3"))
    if t and (_now() - t).total_seconds() < min_age * 86400:
        cur.append(f"published {(_now() - t).total_seconds() / 3600:.0f}h ago (< {min_age:g} days)")
    if b.get("deprecated"):
        cur.append(f"target deprecated: {str(b['deprecated'])[:120]}")
    cur += [f"outside declared range: {r}" for r in outside_range]

    # historic: consecutive releases within a line
    ordered = sorted((parse(v), v) for v in vs if parse(v) and not parse(v).pre)
    steps = breaking_steps = 0
    for (p1, v1), (p2, v2) in zip(ordered, ordered[1:]):
        if compatible(p1, p2):
            steps += 1
            if _breaking(vs[v1], vs[v2]):
                breaking_steps += 1
    if steps:
        rate = breaking_steps / steps
        if breaking_steps:
            hist.append(f"{breaking_steps}/{steps} minor/patch releases carried breaking signals ({rate:.0%})")
    broken = [v for v, m in vs.items() if _BROKEN.search(str(m.get("deprecated") or ""))]
    if broken:
        hist.append(f"{len(broken)} version(s) deprecated as broken (e.g. {', '.join(sorted(broken)[:3])})")
    gone = [k for k in (pk.get("time") or {}) if k not in vs and k not in ("created", "modified", "unpublished")]
    if gone:
        hist.append(f"{len(gone)} unpublished version(s)")
    if vb and vb.core[0] == 0:
        hist.append("0.x line: minors may break by convention")

    high = any(s.startswith(("NEW install", "semver-major", "outside declared")) or s.endswith("prior maintainer)")
               for s in cur)
    caution = [s for s in cur if not s.startswith(_INFO)] or (steps and breaking_steps / steps > 0.1) or broken
    return UpgradeRisk(to, "high" if high else "caution" if caution else "low", cur, hist)


# --- the classifier -----------------------------------------------------------------
def _stale(pk: dict) -> str:
    months = float(os.environ.get("SSVC_NOFIX_STALE_MONTHS", "24"))
    latest = (pk.get("dist-tags") or {}).get("latest")
    dep = ((pk.get("versions") or {}).get(latest) or {}).get("deprecated") if latest else None
    if dep:
        return f"latest ({latest}) deprecated: {str(dep)[:120]}"
    times = [t for k, s in (pk.get("time") or {}).items()
             if k not in ("created", "modified") and (t := _ts(s))]
    if times and (_now() - max(times)).days > months * 30.4:
        return f"no release since {max(times).date()} (> {months:g} months)"
    return ""


def classify(c: Component, ids: list[str], recs: list[dict], pk: dict | None,
             parent_pks: dict[str, dict | None], graph: bool = True) -> NoFix:
    out = NoFix(c.name, c.version, ids, "unknown", "")
    try:
        _classify_top(out, c, recs, pk, parent_pks, graph)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        out.state, out.evidence = "unknown", [f"could not classify: {type(exc).__name__}: {str(exc)[:160]}"]
    out.route = ROUTES[out.state]
    return out


def _classify_top(out: NoFix, c: Component, recs, pk, parent_pks, graph) -> None:
    live = [r for r in recs if not r.get("withdrawn")]
    if not recs:
        out.evidence.append("advisory records unavailable (OSV fetch failed or not cached)")
    elif recs and not live:
        out.state = "withdrawn"
    elif (cur := parse(c.version)) is None:
        out.evidence.append(f"installed version {c.version!r} is not semver")
    elif pk is None:
        out.evidence.append("no registry metadata for the package")
    elif affected(live, c.name, cur) is None:
        out.state = "data_gap"
        out.evidence.append("no npm affected ranges for this package in the advisory")
    else:
        _classify(out, c, cur, live, pk, parent_pks, graph)


def _classify(out: NoFix, c: Component, cur: Version, recs, pk, parent_pks, graph: bool = True) -> None:
    if affected(recs, c.name, cur) is False:
        out.state = "not_affected"
        out.evidence.append("installed version is outside the advisory's affected ranges")
        return
    published = registry.published(pk)
    newer_all = sorted(v for s in published if (v := parse(s)) and v > cur)
    patched = [v for v in newer_all if not v.pre and affected(recs, c.name, v) is False]
    pre_patched = [v for v in newer_all if v.pre and affected(recs, c.name, v) is False]
    out.patched = [str(v) for v in patched[:8]]
    declared = sorted({f for f in _declared_fixes(recs, c.name) if isinstance(f, str)},
                      key=lambda f: parse(f) or Version((0, 0, 0)))
    unreleased = [f for f in declared if f not in (pk.get("versions") or {})]
    unreleased_line = [f for f in unreleased if (v := parse(f)) and compatible(cur, v)]
    if unreleased:
        out.evidence.append(f"advisory names fixed version(s) {', '.join(unreleased)} not on the registry")
    if not patched:
        text = " ".join(f"{r.get('summary', '')} {r.get('details', '')}" for r in recs
                        if isinstance(r.get("summary", ""), str) and isinstance(r.get("details", ""), str))
        stale = _stale(pk)
        adv_time = min((t for r in recs if (t := _ts(r.get("published", "")))), default=None)
        later = [s for s in published
                 if adv_time and (t := _ts((pk.get("time") or {}).get(s, ""))) and t > adv_time]
        if pre_patched:
            out.state = "fix_prerelease_only"
            out.evidence.append(f"unaffected only in prerelease(s): {', '.join(map(str, pre_patched[:4]))}")
            out.risk = upgrade_risk(pk, c.version, str(pre_patched[0]))
        elif unreleased:
            out.state = "fixed_unreleased"
        elif _disputed(text):
            out.state = "wont_fix"
            out.evidence.append("advisory text: " + _disputed(text))
        elif stale:
            out.state = "abandoned"
            out.evidence.append(stale)
        elif _open_ended(recs, c.name) and later:
            out.state = "data_gap"
            out.evidence.append(f"open-ended range, but {len(later)} release(s) since the advisory "
                                f"(latest {later[-1]}): check whether one fixes it")
        else:
            out.state = "unfixed_upstream"
            out.evidence.append("every published newer version is affected")
        return

    # who decides which version npm installs: the parents' declared ranges (and the app's)
    if not c.parents:
        out.evidence.append("who requires it is unknown" + ("" if graph else " (the SBOM has no dependency graph)"))
    libs = [p for p in c.parents if p.name != APP]
    apps = [p for p in c.parents if p.name == APP]

    def fits(v, ps):          # an unevaluable range (alias, tag, git) doesn't block, but is noted
        return all(p.range is None or satisfies(v, p.range) is not False for p in ps)
    unknown = [p for p in c.parents if p.range is None or satisfies(patched[0], p.range) is None]
    if unknown:
        out.evidence.append(f"{len(unknown)} declared range(s) unknown or not semver: "
                            + ", ".join(f"{p.name or 'app'}={p.range!r}" for p in unknown[:4]))
    ok_all = [v for v in patched if fits(v, c.parents)]
    same_line = [v for v in patched if compatible(cur, v)]
    line_ok_libs = [v for v in same_line if fits(v, libs)]
    if ok_all or line_ok_libs:
        target = (next((v for v in ok_all if compatible(cur, v)), ok_all[0]) if ok_all
                  else line_ok_libs[0])
        out.state = "fix_available"
        app_block = [p.range for p in apps if p.range is not None and satisfies(target, p.range) is False]
        out.evidence.append(f"{target} is unaffected and fits the dependents' declared ranges"
                            + ("; your package.json range " + ", ".join(map(repr, app_block))
                               + " must be edited to take it" if app_block else ""))
        out.risk = upgrade_risk(pk, c.version, str(target),
                                outside_range=[f"app {r!r}" for r in app_block])
        return
    if same_line:
        out.state = "blocked_by_parent"
        target = same_line[0]
        for p in libs:
            if p.range is not None and satisfies(target, p.range) is False:
                out.blocking.append(f"{p.name}@{p.version} requires {p.range!r}")
                out.parent_fixes += _parent_fixes(p, c.name, patched, parent_pks.get(p.name))
        out.evidence.append(f"{target} is unaffected but excluded by a dependent's range")
        out.risk = upgrade_risk(pk, c.version, str(target),
                                outside_range=[b.split(" requires ")[1] for b in out.blocking])
        return
    if unreleased_line:
        out.state = "fixed_unreleased"
        out.evidence.append(f"the fix for this line ({', '.join(unreleased_line)}) isn't published; "
                            f"a fix exists across a major ({patched[0]})")
        return
    out.state = "fix_major_only"
    out.evidence.append(f"lowest unaffected version {patched[0]} is outside the installed line")
    for p in libs:
        if p.range is not None and satisfies(patched[0], p.range) is False:
            out.blocking.append(f"{p.name}@{p.version} requires {p.range!r}")
            out.parent_fixes += _parent_fixes(p, c.name, patched, parent_pks.get(p.name))
    out.risk = upgrade_risk(pk, c.version, str(patched[0]))


def _parent_fixes(p, child: str, fixes: list[Version], ppk: dict | None) -> list[str]:
    if not ppk:
        return []
    cur = parse(p.version)
    out = []
    # the smallest newer parent that admits a fix: its own line first, then majors
    cands = sorted((v, s) for s in registry.published(ppk) if (v := parse(s)) and not v.pre and (not cur or v > cur))
    cands.sort(key=lambda x: (not (cur and compatible(cur, x[0])), x[0]))
    for v, s in cands:
        meta = (ppk.get("versions") or {}).get(s) or {}
        rng = next((d[child] for k in ("dependencies", "optionalDependencies", "peerDependencies")
                    if isinstance(d := meta.get(k), dict) and child in d), None)
        if rng is None:
            out.append(f"{p.name}@{s} (no longer depends on {child})")
            break
        if any(satisfies(f, rng) for f in fixes):
            out.append(f"{p.name}@{s}" + ("" if cur and compatible(cur, v) else " (major)"))
            break
    return out


def run(target: str, *, offline: bool = False, include_dev: bool = False) -> tuple[Inventory, list[NoFix]]:
    inv = load(target)
    comps = [c for c in inv.components.values() if include_dev or not c.dev]
    hits = osv.query([osv.Dep(c.name, c.version, "npm") for c in comps], offline=offline)
    todo = [(c, ids) for c in comps if (ids := hits.get(("npm", c.name, c.version)))]
    names = {c.name for c, _ in todo} | {p.name for c, _ in todo for p in c.parents if p.name != APP}
    pks = registry.packuments(names, offline=offline)
    fill_ranges(inv, pks)
    out = []
    for c, ids in todo:
        got = {i: osv._get_vuln(i, offline) for i in ids}
        recs = [r for r in got.values() if isinstance(r, dict)]
        recs = [r for r in recs if not osv.is_malicious(r)]   # malware is gated elsewhere
        missing = [i for i, r in got.items() if not isinstance(r, dict)]
        if missing:                                           # never drop an advisory silently
            out.append(classify(c, missing, [], pks.get(c.name), pks, inv.graph))
        for group in _groups(recs):
            names_ = sorted({str(group[0].get("id", "?")),
                             *[str(a) for r in group for a in r.get("aliases") or []]},
                            key=lambda x: (not x.startswith("CVE-"), x))
            out.append(classify(c, names_, group, pks.get(c.name), pks, inv.graph))
    return inv, out


def _groups(recs: list[dict]) -> list[list[dict]]:
    groups: list[tuple[set, list]] = []
    for r in recs:
        names = {str(r.get("id", "?")), *[str(a) for a in r.get("aliases") or []]}
        merged = [g for g in groups if g[0] & names]
        for g in merged:
            groups.remove(g)
            names |= g[0]
        groups.append((names, [r] + [x for g in merged for x in g[1]]))
    return [rs for _, rs in groups]


def main(argv=None) -> int:
    """doublestrain nofix: classify why each advisory on an app/SBOM has (or lacks) a usable fix."""
    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("target", help="CycloneDX/SPDX JSON SBOM, or an app directory with package-lock.json")
    ap.add_argument("--offline", action="store_true", help="OSV and registry from cache only")
    ap.add_argument("--dev", action="store_true", help="include dev-only components")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    inv, res = run(a.target, offline=a.offline, include_dev=a.dev)
    if a.json:
        print(json.dumps([asdict(r) for r in res], indent=1))
        return 0
    counts: dict[str, int] = {}
    for r in res:
        counts[r.state] = counts.get(r.state, 0) + 1
    print(f"{inv.source}: {len(inv.components)} components, {len(res)} advisories")
    print("  " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda x: -x[1])))
    for r in sorted(res, key=lambda r: (list(ROUTES).index(r.state), r.package)):
        print(f"\n{r.state:17} {r.package}@{r.version}  {r.advisory[0]}  -> {r.route}")
        for e in r.evidence + [f"blocked: {b}" for b in r.blocking] + [f"parent fix: {p}" for p in r.parent_fixes]:
            print(f"    {e}")
        if r.risk:
            print(f"    upgrade to {r.risk.to}: risk {r.risk.level}"
                  + "".join(f"\n      now: {s}" for s in r.risk.current)
                  + "".join(f"\n      history: {s}" for s in r.risk.historic))
    return 0


if __name__ == "__main__":
    sys.exit(main())

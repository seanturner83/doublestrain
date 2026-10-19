"""Reachability judges: null / jev / local / claude / cascade, plus a disk cache.

`get_judge("cascade")` = Jev first (System-1, cheap), escalating to claude-code
(System-2) only when Jev's verdict is below its acceptance floor. Spec syntax:
"null", "jev", "local", "claude", "govulncheck" (Go call graph; no claim for other ecosystems),
"jelly" (npm packages the app can load; needs SSVC_PKGSRC),
"cascade" (== "cascade:jev,claude"), or "cascade:a,b,..."
(e.g. "cascade:jev,local,claude" puts local inference between Jev and claude-code).
Any other name is an OpenAI-compatible endpoint configured by SSVC_<NAME>_BASE_URL etc.
(`local.py`), e.g. "cascade:jev,local,workstation,claude".
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from .._locks import keylock
from .base import Judge, JudgeResult, ReachQuery, Verdict, accept, needs_corroboration, policy, role
from .claude_code import ClaudeCodeJudge
from .govulncheck import GovulncheckJudge
from .jelly import JellyJudge
from .jev import JevJudge
from .local import LocalJudge, OpenAIJudge, configured
from .shape import ShapeJudge
from .split import SplitJudge
from .usage import copies_note

__all__ = ["Judge", "JudgeResult", "ReachQuery", "Verdict", "accept", "get_judge",
           "NullJudge", "JevJudge", "GovulncheckJudge", "JellyJudge", "LocalJudge", "OpenAIJudge", "SplitJudge", "ShapeJudge", "ClaudeCodeJudge", "CascadeJudge", "CachedJudge"]


class NullJudge:
    """No reachability judgement — the pre-judge behaviour (non-Go stays UNAVAILABLE)."""
    name = "null"

    def fingerprint(self) -> str:
        return "null"

    def app_code_destination(self) -> str:
        return "none"

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        return None


def escalate_disagreement_on() -> bool:
    return os.environ.get("SSVC_ESCALATE_DISAGREEMENT", "1") not in ("0", "false", "no", "")


def corroborate_on() -> bool:
    return os.environ.get("SSVC_CORROBORATE", "1") not in ("0", "false", "no", "")


def _strip(r: JudgeResult, note: str = "") -> dict:
    d = {k: v for k, v in r.to_dict().items() if k != "trail"}
    if note:
        d["note"] = note
    return d


class CascadeJudge:
    """Try each tier in order; return the first ACCEPTED verdict, carrying the earlier
    tiers' rejected verdicts in `trail`. If no tier is accepted, return the last
    verdict seen (it won't pass `accept`, so the grader keeps UNAVAILABLE).

    Two toggles (both on by default since 2026-10-18; "0" turns one off) hold back a
    not_reachable that the floors alone would accept, sending
    the row on to later tiers; a held not_reachable is never returned, so a row that
    nothing settles stays unresolved:

    - SSVC_ESCALATE_DISAGREEMENT: one that contradicts an earlier tier's reachable,
      while a later tier remains (the last tier's verdict is accepted as usual). It sends
      most of split's not_reachable rows on to shape (claude quota).
    - SSVC_CORROBORATE: one from a model floors.toml marks `corroborate` settles only
      when a later tier in its `corroborate_by` roles also accepts not_reachable. A
      reachable from a later tier settles as usual; no second read = unresolved."""

    def __init__(self, tiers):
        self.tiers = list(tiers)
        self.name = "cascade:" + ",".join(t.name for t in self.tiers)

    def fingerprint(self) -> str:
        return ("cascade[" + ",".join(getattr(t, "fingerprint", lambda t=t: t.name)() for t in self.tiers) + "]"
                + ("@disagree" if escalate_disagreement_on() else "")
                + ("@corroborate" if corroborate_on() else ""))

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        trail, last = [], None
        held: JudgeResult | None = None      # a not_reachable waiting for its second read
        for i, t in enumerate(self.tiers):
            r = t.judge(q)
            if r is None:
                trail.append({"source": t.name, "verdict": None, "note": "unavailable"})
                continue
            nr = accept(r) and r.verdict == Verdict.NOT_REACHABLE
            if (nr and escalate_disagreement_on() and i < len(self.tiers) - 1
                    and any(e.get("verdict") == Verdict.REACHABLE.value for e in trail)):
                trail.append(_strip(r, "not_reachable escalated: an earlier tier said reachable"))
                continue        # never `last`: a returned last must not pass accept()
            if nr and held is not None:
                # a second read that itself needs one counts only if each lists the other
                # (jelly and an endpoint model: a static analysis and a model fail differently)
                if role(r.source) in policy(held)["corroborate_by"] and (
                        not needs_corroboration(r) or role(held.source) in policy(r)["corroborate_by"]):
                    r.trail = trail + r.trail
                    r.rationale = (f"corroborates {held.source}"
                                   f"{' (' + held.model + ')' if held.model else ''}; " + r.rationale)[:1200]
                    return r
                trail.append(_strip(r, f"not_reachable held: not a second read for {held.source}"))
                continue
            if nr and corroborate_on() and needs_corroboration(r):
                held = r
                trail.append(_strip(r, f"not_reachable held: {r.model or r.source} needs a second read "
                                       f"({', '.join(policy(r)['corroborate_by']) or 'none allowed'})"))
                continue
            if accept(r):
                r.trail = trail + r.trail
                return r
            trail.append(_strip(r))
            last, last_at = r, len(trail) - 1
        if last is not None:
            last.trail = trail[:last_at] + trail[last_at + 1:]   # everything but its own entry
        if last is None and held is not None:
            # every answer was a held not_reachable: report it, below any floor
            last = JudgeResult(Verdict.UNSURE, 0.0, held.source, model=held.model, trail=trail,
                               rationale="not_reachable not corroborated: no later tier agreed")
        return last


class CachedJudge:
    """Disk cache keyed on (judge fingerprint, query). Re-runs of the harness don't
    re-spend Jev calls or claude quota. Only real answers are cached (None is not)."""

    def __init__(self, inner, cache_dir: str | None = None):
        self.inner = inner
        self.name = inner.name
        self.dir = Path(cache_dir or os.environ.get(
            "SSVC_JUDGE_CACHE", "~/.cache/ssvc-triage/judge")).expanduser()

    def fingerprint(self) -> str:
        return self.inner.fingerprint()

    def _path(self, q: ReachQuery) -> Path:
        fp = self.fingerprint().replace("/", "_").replace(":", "_")
        # a judge whose prompt differs by ecosystem keys those answers on it too
        salt = getattr(self.inner, "query_salt", lambda q: "")(q)
        if "@prepass" in fp:
            # tiers that read the usage pre-pass: a row whose package has several installed
            # versions now gets a copies note (usage.copies_note), so only those rows are asked
            # again; the others' prompts are unchanged and keep their answers
            note = copies_note(q.repo_path, q.ecosystem, q.dependency, q.version)
            salt += "-c" + hashlib.sha256(note.encode()).hexdigest()[:8] if note else ""
        return self.dir / fp / f"{q.key()}{salt}.json"

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        p = self._path(q)
        with keylock(("judge-cache", str(p))):     # two rows asking the same question: ask once
            return self._judge(q, p)

    def _judge(self, q: ReachQuery, p: Path) -> JudgeResult | None:
        if p.exists():
            try:
                r = JudgeResult.from_dict(json.loads(p.read_text()))
                r.cached = True
                if not r.model and (am := getattr(self.inner, "answer_model", None)):
                    r.model = am()      # older entries: the model is in this cache key
                if rc := getattr(self.inner, "recheck", None):
                    r = rc(q, r)        # a guard that got stricter since this answer was cached
                return r
            except (ValueError, TypeError, KeyError):
                pass
        r = self.inner.judge(q)
        if r is not None:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(p.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
            tmp.write_text(json.dumps(r.to_dict(), indent=1))
            os.replace(tmp, p)
        return r


# --egress: where first-party (app) source may go. Tiers declare app_code_destination().
EGRESS_MODES = {"any": {"none", "machine", "network", "shape", "offsite"},
                "shape": {"none", "machine", "network", "shape"},     # derived call shapes may leave
                "network": {"none", "machine", "network"},
                "machine": {"none", "machine"}}


def egress_mode() -> str:
    m = os.environ.get("SSVC_APP_CODE_EGRESS", "any").strip() or "any"
    if m not in EGRESS_MODES:
        raise ValueError(f"SSVC_APP_CODE_EGRESS must be one of {sorted(EGRESS_MODES)}, not {m!r}")
    return m


def check_egress_policy(judge, mode: str | None = None) -> None:
    """Raise ValueError naming every tier that would send app code beyond `mode`."""
    mode = mode or egress_mode()
    bad = [f"{t.name} (app code -> {t.app_code_destination()})" for t in tiers(judge)
           if t.app_code_destination() not in EGRESS_MODES[mode]]
    if bad:
        raise ValueError(f"--egress {mode} forbids: {', '.join(bad)}. In this mode use local/LAN "
                         "endpoint tiers, `split` (claude sees dependency source only) and, under "
                         "--egress shape, `shape` (claude also sees abstracted call shapes).")


def get_judge(spec: str, *, cache: bool = True, egress: str | None = None):
    j = _build(spec, cache=cache)
    check_egress_policy(j, egress)
    return j


def _build(spec: str, *, cache: bool = True):
    spec = (spec or "null").strip()
    if spec == "null":
        return NullJudge()
    if spec == "split" or spec.startswith("split:"):
        j = SplitJudge(spec.split(":", 1)[1] if ":" in spec else "local")
    elif spec == "shape":
        j = ShapeJudge()
    elif spec == "jev":
        j = JevJudge()
    elif spec == "govulncheck":
        j = GovulncheckJudge()
    elif spec == "jelly":
        j = JellyJudge()
    elif spec == "local":
        j = LocalJudge()
    elif spec == "claude":
        j = ClaudeCodeJudge()
    elif spec.startswith("cascade"):
        names = spec.split(":", 1)[1].split(",") if ":" in spec else ["jev", "claude"]
        # cache each tier separately, so a cascade reuses single-judge runs' answers
        return CascadeJudge([_build(n.strip(), cache=cache) for n in names])
    elif configured(spec):
        j = OpenAIJudge(spec)
    else:
        raise ValueError(f"unknown judge spec {spec!r} (null|jev|local|claude|govulncheck|jelly|split[:endpoint]|shape|<endpoint>|cascade[:a,b]; "
                         "an endpoint tier needs SSVC_<NAME>_BASE_URL)")
    return CachedJudge(j) if cache else j


def tiers(judge) -> list:
    """The leaf judges, in cascade order (cache wrappers removed)."""
    if isinstance(judge, CascadeJudge):
        return [leaf for t in judge.tiers for leaf in tiers(t)]
    return [judge.inner if isinstance(judge, CachedJudge) else judge]


def preflight(judge) -> tuple[list[str], list[str]]:
    """Probe every tier before a run. Returns (report lines, names of tiers that are down).
    A down tier isn't fatal (its questions escalate, and cached answers still serve), but
    it changes cost and coverage, so the CLIs print it and can refuse (--require-tiers)."""
    ts = tiers(judge)
    lines, down = [], []
    for i, t in enumerate(ts):
        probe = getattr(t, "probe", None)
        ok, detail = probe() if probe else (True, "")
        if not ok:
            down.append(t.name)
            nxt = ts[i + 1].name if i + 1 < len(ts) else None
            detail += (f" -> its questions escalate to {nxt}" if nxt
                       else " -> unresolved advisories stay unresolved (grade like reachable)")
        lines.append(f"  {'ok  ' if ok else 'DOWN'} {t.name}: {detail}")
    return lines, down

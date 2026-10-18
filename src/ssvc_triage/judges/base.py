"""Reachability judge contract.

A judge answers ONE bounded question — "is this dependency advisory's vulnerable code
reachable from the app?" — and returns a verdict + confidence. It supplies a FACT to
the SSVC tree; it never makes the Act/Attend/Track decision.

Acceptance is ASYMMETRIC (see `accept`): a wrong `not_reachable` hides a real risk
(Track instead of Act), a wrong `reachable` only costs triage time. So a judge's
`not_reachable` must clear a much higher floor than its `reachable` before the grader
sees it; anything below its floor is escalated (cascade) or left UNAVAILABLE.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import tomllib
from dataclasses import asdict, dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Protocol


class Verdict(str, Enum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNSURE = "unsure"


@dataclass(frozen=True)
class ReachQuery:
    repo_path: str               # local checkout of the app that consumes the dependency
    ecosystem: str               # npm | pypi | go | ...
    dependency: str              # package name as the manifest names it
    cve: str
    vuln_symbols: tuple[str, ...] = ()
    advisory: str = ""           # short advisory summary (what is vulnerable, how)
    import_name: str = ""        # module name when it differs from the package (PyYAML -> yaml)
    version: str = ""            # installed version (lockfile chain lookup); "" = any copy

    def key(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()[:24]


@dataclass
class JudgeResult:
    verdict: Verdict
    confidence: float            # Jev: top-vs-runner-up MARGIN; claude: self-reported
    source: str                  # judge id that produced this verdict
    rationale: str = ""
    evidence: list[str] = field(default_factory=list)   # file:line pointers
    latency_s: float = 0.0
    cost_usd: float | None = None
    cached: bool = False
    model: str = ""              # the model that answered, when the tier knows it (floors.toml)
    # Earlier tiers' results that were NOT accepted (cascade escalation trail).
    trail: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "JudgeResult":
        d = dict(d)
        d["verdict"] = Verdict(d["verdict"])
        return cls(**d)


class Judge(Protocol):
    name: str

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        """Return a verdict, or None when the backend is unavailable (no claim)."""
        ...


# Floors per judge role and per model live in floors.toml (next to this file): what each
# one was measured on, and which models need a second read before their not_reachable
# settles anything (`corroborate`).
_FLOORS_FILE = Path(__file__).with_name("floors.toml")
_ROLES = ("jev", "claude", "split", "shape", "govulncheck")


@lru_cache(maxsize=4)
def _table(path: str) -> tuple[dict, dict]:
    d = tomllib.loads(Path(path).read_text())
    models = {(m["role"], m["model"].lower()): m for m in d.get("model") or []}
    return d.get("role") or {}, models


def role(source: str) -> str:
    """jev | claude | split | shape | govulncheck | endpoint (any OpenAI-compatible tier)."""
    base = source.partition(":")[0]
    return base if base in _ROLES else "endpoint"


def answering_model(r: "JudgeResult") -> str:
    if r.model:
        return r.model.lower()
    base, _, sub = r.source.partition(":")
    return sub.lower() if base == "shape" else ""     # shape's source names its model


def policy(r: "JudgeResult") -> dict:
    """The floors entry for the model that gave this verdict: its role's defaults, then
    the model's own entry, then SSVC_FLOOR_<TIER>_* overrides."""
    roles, models = _table(os.environ.get("SSVC_FLOORS_FILE") or str(_FLOORS_FILE))
    ro = role(r.source)
    p = {"reachable": math.inf, "not_reachable": 0.9, "corroborate": False, "corroborate_by": [],
         **roles.get(ro, roles.get("endpoint", {})),
         **models.get((ro, answering_model(r)), {})}
    env = r.source.partition(":")[0].upper()
    p["reachable"] = float(os.environ.get(f"SSVC_FLOOR_{env}_REACHABLE", p["reachable"]))
    p["not_reachable"] = float(os.environ.get(f"SSVC_FLOOR_{env}_NOT_REACHABLE", p["not_reachable"]))
    p["role"] = ro
    return p


def floors(source: str, model: str = "") -> tuple[float, float]:
    p = policy(JudgeResult(Verdict.UNSURE, 0.0, source, model=model))
    return p["reachable"], p["not_reachable"]


def accept(r: JudgeResult | None) -> bool:
    """Is this verdict strong enough to hand to the grader as a fact?"""
    if r is None or r.verdict == Verdict.UNSURE:
        return False
    p = policy(r)
    if r.verdict == Verdict.REACHABLE:
        return r.confidence >= p["reachable"]
    return r.confidence >= p["not_reachable"]


def needs_corroboration(r: "JudgeResult") -> bool:
    """Is this model marked as needing a second read before its not_reachable settles?"""
    return r.verdict == Verdict.NOT_REACHABLE and bool(policy(r).get("corroborate"))

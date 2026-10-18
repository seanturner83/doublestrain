"""Exploitability feeds: CISA KEV + FIRST EPSS -> the grader's `enrichment_map`.

Modes (`build_enrichment(..., mode=)`):
  fixture     the caller's injected map only (offline, reproducible — harness default)
  live        fetch/refresh both feeds as needed (results cached on disk)
  cache-only  read the disk cache, never touch the network; anything missing is UNKNOWN

A CVE that EPSS has no score for is UNKNOWN (`epss: None`), never 0 — the grader
already treats "no EPSS" as no claim. Only public CVE IDs leave the machine.

Cache: SSVC_FEED_CACHE (default ~/.cache/ssvc-triage/feeds). Max age before a refresh:
SSVC_FEED_MAX_AGE_H (default 24). A failed refresh falls back to the stale cache (and
says so in the provenance) rather than dropping the signal.
"""
from __future__ import annotations

import os
from pathlib import Path

from . import epss, kev

MODES = ("fixture", "live", "cache-only")


def cache_dir() -> Path:
    return Path(os.environ.get("SSVC_FEED_CACHE", "~/.cache/ssvc-triage/feeds")).expanduser()


def max_age_h() -> float:
    return float(os.environ.get("SSVC_FEED_MAX_AGE_H", "24"))


def build_enrichment(cves, *, mode: str = "fixture", fixture: dict | None = None,
                     ) -> tuple[dict, dict]:
    """Return (enrichment_map, provenance). The map has the grader's shape
    {CVE: {"kev": bool, "epss": float | None, ...extra context}}."""
    if mode not in MODES:
        raise ValueError(f"enrichment mode {mode!r} not in {MODES}")
    cves = sorted({c.upper() for c in cves if c})
    if mode == "fixture":
        return dict(fixture or {}), {"mode": "fixture"}

    offline = mode == "cache-only"
    catalog, kev_prov = kev.load(cache_dir(), max_age_h(), offline=offline)
    scores, epss_prov = epss.scores(cves, cache_dir(), max_age_h(), offline=offline)
    out = {}
    for c in cves:
        k = catalog.get(c) if catalog is not None else None
        s = scores.get(c) or {}
        out[c] = {
            # KEV unavailable (offline, no cache) -> False here, flagged in provenance
            "kev": k is not None,
            "epss": s.get("epss"),
            "epss_percentile": s.get("percentile"),
            "epss_date": s.get("date"),
            **({"kev_date_added": k.get("dateAdded"),
                "kev_ransomware": k.get("knownRansomwareCampaignUse")} if k else {}),
        }
    return out, {"mode": mode, "kev": kev_prov, "epss": epss_prov}

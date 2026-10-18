"""FIRST EPSS scores, fetched in batches and cached per CVE.

EPSS simply omits CVEs it has no score for (too new, rejected, not in NVD yet). Those
are cached as a NEGATIVE entry (`epss: None`) with the fetch time, so they stay
UNKNOWN — never 0 — and aren't re-asked until the entry ages out.
"""
from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.parse
from pathlib import Path

from ._http import get_json, read_json, write_json

logger = logging.getLogger(__name__)

URL = os.environ.get("SSVC_EPSS_URL", "https://api.first.org/data/v1/epss")
BATCH = 50   # keeps the query string short; the API pages at 100


def _fetch(cves: list[str]) -> dict:
    out = {}
    for i in range(0, len(cves), BATCH):
        chunk = cves[i:i + BATCH]
        q = urllib.parse.urlencode({"cve": ",".join(chunk), "limit": len(chunk)})
        data = get_json(f"{URL}?{q}")
        for row in data.get("data", []):
            out[row["cve"].upper()] = {"epss": float(row["epss"]),
                                       "percentile": float(row["percentile"]),
                                       "date": row.get("date")}
    return out


def scores(cves, cache: Path, max_age_h: float, *, offline: bool = False) -> tuple[dict, dict]:
    """Return ({CVE: {epss, percentile, date} or {epss: None}}, provenance)."""
    path = cache / "epss.json"
    db = read_json(path) or {}
    now = time.time()
    stale = [c for c in cves if c not in db or (now - db[c].get("fetched_at", 0)) / 3600 >= max_age_h]
    status, fetched = "cache", 0
    if stale and not offline:
        try:
            got = _fetch(stale)
            for c in stale:
                db[c] = {**got.get(c, {"epss": None, "percentile": None, "date": None}),
                         "fetched_at": now}
            write_json(path, db)
            status, fetched = "fresh", len(stale)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
            logger.warning("EPSS refresh failed (%s); using whatever is cached", exc)
            status = f"stale (refresh failed: {str(exc)[:120]})"
    elif stale:
        status = "cache-only"
    out = {c: db[c] for c in cves if c in db}
    dates = sorted({v["date"] for v in out.values() if v.get("date")})
    return out, {"status": status, "requested": len(cves), "fetched": fetched,
                 "scored": sum(1 for v in out.values() if v.get("epss") is not None),
                 "unknown": [c for c in cves if (out.get(c) or {}).get("epss") is None],
                 "score_dates": dates}

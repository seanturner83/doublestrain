"""CISA Known Exploited Vulnerabilities catalogue (one JSON file, refreshed ~daily)."""
from __future__ import annotations

import logging
import os
import time
import urllib.error
from pathlib import Path

from ._http import get_json, read_json, write_json

logger = logging.getLogger(__name__)

URL = os.environ.get(
    "SSVC_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
_KEEP = ("dateAdded", "knownRansomwareCampaignUse", "dueDate")


def _slim(raw: dict) -> dict:
    return {
        "catalogVersion": raw.get("catalogVersion"),
        "dateReleased": raw.get("dateReleased"),
        "entries": {v["cveID"].upper(): {k: v.get(k) for k in _KEEP}
                    for v in raw.get("vulnerabilities", []) if v.get("cveID")},
    }


def load(cache: Path, max_age_h: float, *, offline: bool = False) -> tuple[dict | None, dict]:
    """Return ({CVE: entry} or None if unavailable, provenance)."""
    path = cache / "kev.json"
    cached = read_json(path)
    age_h = (time.time() - cached["fetched_at"]) / 3600 if cached else None
    fresh = cached is not None and age_h < max_age_h

    if not fresh and not offline:
        try:
            data = {"fetched_at": time.time(), **_slim(get_json(URL))}
            write_json(path, data)
            cached, age_h = data, 0.0
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
            logger.warning("KEV refresh failed (%s); %s", exc,
                           "using stale cache" if cached else "KEV unavailable")
            if cached:
                return cached["entries"], _prov(cached, age_h, "stale (refresh failed)")
            return None, {"status": "unavailable", "error": str(exc)[:200]}
    if cached is None:
        return None, {"status": "unavailable (cache-only, no cache)"}
    return cached["entries"], _prov(cached, age_h, "fresh" if fresh or age_h == 0 else "stale (cache-only)")


def _prov(c: dict, age_h: float, status: str) -> dict:
    return {"status": status, "catalogVersion": c.get("catalogVersion"),
            "dateReleased": c.get("dateReleased"), "entries": len(c.get("entries", {})),
            "age_h": round(age_h, 2)}

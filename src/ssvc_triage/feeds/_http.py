from __future__ import annotations

import json
import os
import tempfile
import urllib.request
from pathlib import Path

USER_AGENT = "ssvc-triage/0.1 (+local SSVC grading)"
TIMEOUT_S = 30.0


def get_json(url: str, timeout: float = TIMEOUT_S):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,  # noqa: S310 — fixed https feeds
                                                "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def write_json(path: Path, data) -> None:
    """Atomic write, so an interrupted refresh never leaves a torn cache file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)

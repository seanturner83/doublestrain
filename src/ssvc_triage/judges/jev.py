"""System-1 reachability judge backed by Jev (TypeSafe System One API).

Jev sees only the static usage summary (never the repo) and answers one bounded
`choice`; its `confidence` is the top-vs-runner-up MARGIN, which is exactly the
System-1 <-> System-2 boundary: obvious cases come back ~1.0, dynamic dispatch low.

Jevstiller is optional: point TYPESAFE_BASE_URL at the local proxy
(e.g. http://localhost:8080) and repeated classifications are answered by the
distilled local student, deferring out-of-distribution queries upstream. Unset, calls
go straight to the hosted Jev API. Key: TYPESAFE_API_KEY, or read from
TYPESAFE_API_KEY_FILE (default ~/.keys/jev.key).
"""
from __future__ import annotations

import json
import logging
import os
import urllib.parse
import socket
import time
import urllib.error
import urllib.request

from .base import JudgeResult, ReachQuery, Verdict
from .usage import PREPASS_VERSION, guard_not_reachable, usage_summary

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.typesafe.ai"

_CRITERIA = {
    "reachable": (
        "the vulnerable symbol is actually reached by the application — the dependency is "
        "imported AND the vulnerable function/path is called (directly or via a used wrapper or "
        "parent package) on a code path the app exercises."
    ),
    "not_reachable": (
        "the vulnerable symbol is NOT reached — the dependency is imported but only a different, "
        "safe part of it is used, and the vulnerable function/path is never called."
    ),
    "unsure": (
        "reachability can't be determined from the usage summary — dynamic dispatch, reflection, "
        "config-driven require()/import, a transitive dependency whose use by its parent package "
        "is unknown, or an indirect path that needs deeper tracing — escalate."
    ),
}


def _base_url() -> str:
    return (os.environ.get("TYPESAFE_BASE_URL", "").strip() or _DEFAULT_BASE_URL).rstrip("/")


def _api_key() -> str | None:
    """TYPESAFE_API_KEY, else the file named by TYPESAFE_API_KEY_FILE (default ~/.keys/jev.key)."""
    if key := os.environ.get("TYPESAFE_API_KEY", "").strip():
        return key
    path = os.path.expanduser(os.environ.get("TYPESAFE_API_KEY_FILE", "~/.keys/jev.key"))
    try:
        with open(path) as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def _post(payload: dict, timeout: float, attempts: int = 3) -> dict:
    """POST with a short retry on 5xx / connection errors: Jevstiller returns 502 while
    its upstream teacher is briefly unreachable (out-of-distribution queries defer
    upstream). 4xx is not retried."""
    for i in range(attempts):
        try:
            return _post_once(payload, timeout)
        except urllib.error.HTTPError as exc:
            if exc.code < 500 or i == attempts - 1:
                raise
        except (urllib.error.URLError, TimeoutError, OSError):
            if i == attempts - 1:
                raise
        time.sleep(2 * (i + 1))
    raise RuntimeError("unreachable")


def _post_once(payload: dict, timeout: float) -> dict:
    headers = {"Content-Type": "application/json"}
    if key := _api_key():
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(  # noqa: S310 — configured base URL, fixed path
        f"{_base_url()}/v1/systemone", data=json.dumps(payload).encode(),
        headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


class JevJudge:
    name = "jev"

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def fingerprint(self) -> str:
        # the backend that answers is part of the cache key (local student vs hosted Jev)
        return f"jev@{_base_url()}@prepass{PREPASS_VERSION}"

    def app_code_destination(self) -> str:
        # the usage summary quotes app source; hosted Jev, and Jevstiller forwards upstream
        return "offsite"

    def probe(self) -> tuple[bool, str]:
        """Cheap availability check (no question asked)."""
        url = _base_url()
        if url == _DEFAULT_BASE_URL:
            return (True, "hosted Jev") if _api_key() else (False, "hosted Jev, no API key")
        u = urllib.parse.urlparse(url)
        try:
            socket.create_connection((u.hostname, u.port or (443 if u.scheme == "https" else 80)), 3).close()
        except OSError as exc:
            return False, f"{url} not answering ({exc})"
        return True, url

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        if _base_url() == _DEFAULT_BASE_URL and not _api_key():
            return None   # hosted Jev without a key: unavailable, no claim
        u = usage_summary(q.repo_path, q.ecosystem, q.dependency, q.vuln_symbols, q.import_name,
                          version=q.version)
        state = {
            "dependency": q.dependency[:120],
            "vulnerable_symbol": ", ".join(q.vuln_symbols)[:200] or "(unspecified)",
            "advisory": q.advisory[:400],
            "app_usage": u.text[:1500],
        }
        payload = {
            "model": "jev-latest",
            "state": json.dumps(state),
            "questions": {"reachability": {
                "type": "choice",
                "instructions": ("Given how the application uses this dependency, is the CVE's "
                                 "vulnerable symbol actually REACHABLE (exercised) by the "
                                 "application, not merely present?"),
                "criteria": _CRITERIA,
            }},
        }
        t0 = time.monotonic()
        try:
            out = _post(payload, self.timeout)
            ans = (out.get("answers") or {}).get("reachability") or {}
            choice = str(ans.get("choice") or "").strip()
            conf = float(ans.get("confidence") or 0.0)
            verdict = Verdict(choice)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
            logger.warning("jev reachability failed (%s); no claim", exc)
            return None
        verdict, guard_note = guard_not_reachable(verdict, u)
        return JudgeResult(verdict=verdict, confidence=conf, source=self.name,
                           rationale="; ".join(filter(None, [
                               f"usage pre-pass: {len(u.import_sites)} import site(s), "
                               f"{len(u.symbol_sites)} symbol mention(s), "
                               f"{len(u.dynamic_sites)} dynamic site(s)", guard_note])),
                           evidence=(u.import_sites + u.symbol_sites)[:10],
                           latency_s=round(time.monotonic() - t0, 3))

"""Read-only GitHub API client for the upstream watch. Everything it returns is
UNTRUSTED DATA written by whoever controls the upstream repo (fresh, unreviewed commits
included): it is fetched as JSON, never cloned, built or executed.

Rules (as pkgsrc): https://api.github.com only; owner/repo/ref/sha validated and each
path segment escaped, so nothing publisher-supplied shapes the URL beyond a validated
segment; redirects followed only within api.github.com (renamed repos); byte caps;
nested-JSON guard; per-file patch text capped. Responses are cached with their ETag, so
an unchanged resource costs a 304 (no rate limit) on the next watch run; commit objects
are immutable by sha and cached for good.

Token: SSVC_GITHUB_TOKEN or GITHUB_TOKEN, else the file SSVC_GITHUB_TOKEN_FILE (default
~/.keys/github.token, then ~/.keys/github.key). Public read only is enough (a fine-grained token with no
permissions). It is sent only to api.github.com and never logged.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

HOST = "api.github.com"
API = f"https://{HOST}"
MAX_JSON = 24 << 20
MAX_PATCH = 64 << 10          # per file, kept for ranking / triage
MAX_MESSAGE = 8000
MAX_FILES = 300

OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")
SHA = re.compile(r"[0-9a-f]{7,40}")
REF = re.compile(r"[A-Za-z0-9@_+][A-Za-z0-9@._/+-]{0,199}")


class GitHubError(Exception):
    pass


class RateLimited(GitHubError):
    def __init__(self, reset: float):
        super().__init__(f"GitHub rate limit; resets at {time.strftime('%H:%M:%S', time.localtime(reset))}")
        self.reset = reset


def _check(owner: str, repo: str, ref: str | None = None) -> None:
    if not (isinstance(owner, str) and OWNER.fullmatch(owner)):
        raise GitHubError(f"invalid owner {owner!r}")
    if not (isinstance(repo, str) and REPO.fullmatch(repo)) or set(repo) <= {"."}:
        raise GitHubError(f"invalid repo {repo!r}")
    if ref is not None and not (isinstance(ref, str) and REF.fullmatch(ref)
                                and ".." not in ref and "//" not in ref and not ref.endswith(("/", ".lock"))):
        raise GitHubError(f"invalid ref {ref!r}")


def token() -> str:
    t = os.environ.get("SSVC_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    files = ([os.environ["SSVC_GITHUB_TOKEN_FILE"]] if os.environ.get("SSVC_GITHUB_TOKEN_FILE")
             else ["~/.keys/github.token", "~/.keys/github.key"])
    for f in files if not t else ():
        try:
            t = Path(f).expanduser().read_text()
            break
        except OSError:
            t = ""
    t = t.strip()
    return t if re.fullmatch(r"[A-Za-z0-9_]{20,255}", t) else ""


def cache_root() -> Path:
    return Path(os.environ.get("SSVC_GITHUB_CACHE", "~/.cache/ssvc-triage/github")).expanduser()


class _SameHost(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlparse(newurl)
        if u.scheme != "https" or u.hostname != HOST:
            raise GitHubError(f"refusing redirect off {HOST}: {newurl[:200]}")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and token():
            new.add_unredirected_header("Authorization", f"Bearer {token()}")
        return new


def _http(url: str, etag: str | None) -> tuple[int, bytes, dict]:
    """GET -> (status, body, headers). Patched in tests."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "ssvc-triage-watch"}
    if etag:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(url, headers=headers)
    if token():
        req.add_unredirected_header("Authorization", f"Bearer {token()}")
    opener = urllib.request.build_opener(_SameHost)
    try:
        with opener.open(req, timeout=60) as resp:  # noqa: S310 — https://api.github.com only
            body = resp.read(MAX_JSON + 1)
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096) if exc.fp else b"", dict(exc.headers or {})
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise GitHubError(f"GET {url}: {exc}") from exc


def _cache_path(url: str) -> Path:
    return cache_root() / f"{hashlib.sha256(url.encode()).hexdigest()}.json"


def _read_cache(url: str) -> dict | None:
    try:
        d = json.loads(_cache_path(url).read_text())
        return d if isinstance(d, dict) and d.get("url") == url else None
    except (OSError, ValueError, RecursionError):
        return None


def _write_cache(url: str, data, etag: str | None, immutable: bool) -> None:
    p = _cache_path(url)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump({"url": url, "etag": etag, "immutable": immutable, "at": time.time(), "data": data}, fh)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def get(segments: list[str], params: dict | None = None, *, immutable: bool = False, offline: bool = False):
    """GET /<escaped segments>?params -> parsed JSON (None on 404). Raises GitHubError."""
    path = "/".join(urllib.parse.quote(s, safe="") for s in segments)
    q = "?" + urllib.parse.urlencode(sorted((params or {}).items())) if params else ""
    url = f"{API}/{path}{q}"
    cached = _read_cache(url)
    if cached and (cached.get("immutable") or offline):
        return cached["data"]
    if offline:
        return None
    for attempt in range(4):                       # transient: dropped connection, 5xx, abuse limit
        try:
            status, body, headers = _http(url, cached.get("etag") if cached else None)
        except GitHubError:
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)
            continue
        retry_after = headers.get("Retry-After")
        if status in (500, 502, 503, 504) or (status == 403 and retry_after):
            if attempt == 3:
                break
            time.sleep(min(60.0, float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt))
            continue
        break
    if status == 304 and cached:
        return cached["data"]
    if status == 404:
        return None
    if status in (403, 429) and (headers.get("X-RateLimit-Remaining") == "0" or status == 429):
        raise RateLimited(float(headers.get("X-RateLimit-Reset") or time.time() + 3600))
    if status != 200:
        raise GitHubError(f"GET {url}: HTTP {status}")
    if len(body) > MAX_JSON:
        raise GitHubError(f"GET {url}: response over {MAX_JSON >> 20} MiB")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise GitHubError(f"GET {url}: bad JSON") from exc
    _write_cache(url, data, headers.get("ETag"), immutable)
    return data


# --- endpoints (trimmed to what the watch uses) ------------------------------------
def _s(v, n: int) -> str:
    return v[:n] if isinstance(v, str) else ""


def repo(owner: str, name: str, *, offline: bool = False) -> dict | None:
    _check(owner, name)
    d = get(["repos", owner, name], offline=offline)
    if not isinstance(d, dict):
        return None
    full = _s(d.get("full_name"), 200)
    return {"full_name": full, "archived": bool(d.get("archived")), "fork": bool(d.get("fork")),
            "default_branch": _s(d.get("default_branch"), 200), "pushed_at": _s(d.get("pushed_at"), 40)}


def _commit_summary(c: dict) -> dict:
    inner = c.get("commit") if isinstance(c.get("commit"), dict) else {}
    author = inner.get("author") if isinstance(inner.get("author"), dict) else {}
    sha = _s(c.get("sha"), 40)
    return {"sha": sha if SHA.fullmatch(sha) else "", "message": _s(inner.get("message"), MAX_MESSAGE),
            "date": _s(author.get("date"), 40),
            "parents": [_s(p.get("sha"), 40) for p in c.get("parents") or [] if isinstance(p, dict)]}


def compare(owner: str, name: str, base: str, head: str, *, max_commits: int = 500,
            offline: bool = False) -> dict | None:
    """Commits on head not on base (oldest first), up to max_commits. {"status",
    "ahead_by", "commits", "truncated"} or None (unknown ref)."""
    _check(owner, name, base)
    _check(owner, name, head)
    out, page = None, 1
    while True:
        d = get(["repos", owner, name, "compare", f"{base}...{head}"], {"per_page": 100, "page": page},
                offline=offline)
        if not isinstance(d, dict):
            return out
        commits = [_commit_summary(c) for c in d.get("commits") or [] if isinstance(c, dict)]
        if out is None:
            out = {"status": _s(d.get("status"), 20), "ahead_by": int(d.get("ahead_by") or 0)
                   if isinstance(d.get("ahead_by"), int) else 0, "commits": [], "truncated": False}
        out["commits"] += [c for c in commits if c["sha"]]
        if len(commits) < 100 or len(out["commits"]) >= min(max_commits, out["ahead_by"] or 0):
            break
        page += 1
    out["truncated"] = len(out["commits"]) < out["ahead_by"]
    out["commits"] = out["commits"][:max_commits]
    return out


def commit(owner: str, name: str, ref: str, *, offline: bool = False) -> dict | None:
    """One commit with its files and (capped) patches. Immutable when ref is a full sha."""
    _check(owner, name, ref)
    d = get(["repos", owner, name, "commits", ref], immutable=bool(re.fullmatch(r"[0-9a-f]{40}", ref)),
            offline=offline)
    if not isinstance(d, dict):
        return None
    c = _commit_summary(d)
    files = []
    for f in (d.get("files") or [])[:MAX_FILES]:
        if not isinstance(f, dict):
            continue
        patch = _s(f.get("patch"), MAX_PATCH + 1)
        files.append({"filename": _s(f.get("filename"), 400), "status": _s(f.get("status"), 20),
                      "additions": f.get("additions") if isinstance(f.get("additions"), int) else 0,
                      "deletions": f.get("deletions") if isinstance(f.get("deletions"), int) else 0,
                      "patch": patch[:MAX_PATCH], "patch_truncated": len(patch) > MAX_PATCH or
                      (not patch and (f.get("changes") or 0) > 0)})
    c["files"] = files
    c["files_truncated"] = len(d.get("files") or []) > MAX_FILES
    return c


# --- text that came from upstream, for display --------------------------------------
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")


def safe_text(s: str, n: int = 400) -> str:
    """Strip control/ANSI/bidi characters before anything prints or renders upstream text."""
    return _CTRL.sub("", re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", s or ""))[:n]

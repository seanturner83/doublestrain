"""govulncheck as a judge tier: call-graph reachability for Go modules.

govulncheck type-checks the app and its dependencies and builds a call graph; it never
builds a binary or runs the code. It is run once per checkout (all advisories at once),
sandboxed:

- GOTOOLCHAIN=local (a go.mod `toolchain` line can't fetch and run another toolchain),
  GOENV=off, GOWORK=off, GOFLAGS=-mod=readonly (the checkout is never written),
  CGO_ENABLED=0 (no C compiler on untrusted code), an empty HOME and GOPATH per run;
- module zips come from the module proxy into SSVC_GO_MODCACHE (default
  ~/.cache/ssvc-triage/gomod), checked against go.sum and the checksum database; only
  module paths and versions leave the machine, and the app's code never does;
- never `go mod download` in a checkout: it adds go.sum lines even under -mod=readonly
  (seen 2026-10-18); govulncheck's own loading doesn't write. With an incomplete go.sum
  the scan fails and the advisory goes on to the next tier;
- for SSVC_GOVULNCHECK_PLATFORMS (default linux/amd64: what a service ships as); with
  several, the strongest finding wins.

Per advisory, govulncheck reports how far it got: the vulnerable function is CALLED
(reachable), its package is only IMPORTED, or its module is only REQUIRED (both
not_reachable; test code is left out, as tests don't ship). Two cases make a
not_reachable unsafe, and are answered `unsure` instead:

- cgo: with CGO_ENABLED=0, files that `import "C"` are left out of the analysis, so a
  call path through them is invisible. A cgo file in the app or any build-list module
  that is in, or imports, one of the advisory's vulnerable packages -> unsure. (Not
  covered: a cgo-only importer of a package that in turn imports the vulnerable one.)
- the advisory isn't in the Go vulnerability database, or govulncheck doesn't think
  the locked version is affected: no claim (None), the next tier answers.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .._locks import keylock
from .base import JudgeResult, ReachQuery, Verdict

logger = logging.getLogger(__name__)

_CGO = re.compile(rb'^\s*import\s+(?:\(\s*[^)]*?)?"C"', re.M)
_IMPORT_PATHS = re.compile(rb'"([\w.\-~/]+)"')
_LEVEL = {1: "required", 2: "imported", 3: "called"}


def _bin() -> str:
    return os.environ.get("SSVC_GOVULNCHECK_BIN") or str(
        Path("~/.cache/ssvc-triage/gotools/bin/govulncheck").expanduser())


def _modcache() -> Path:
    return Path(os.environ.get("SSVC_GO_MODCACHE", "~/.cache/ssvc-triage/gomod")).expanduser()


def _platforms() -> list[tuple[str, str]]:
    out = []
    for p in os.environ.get("SSVC_GOVULNCHECK_PLATFORMS", "linux/amd64").split(","):
        if "/" in p.strip():
            goos, goarch = p.strip().split("/", 1)
            out.append((goos, goarch))
    return out or [("linux", "amd64")]


def _env(home: str, goos: str, goarch: str) -> dict:
    go = shutil.which("go") or "/opt/homebrew/bin/go"
    return {"HOME": home, "PATH": f"{Path(go).parent}:/usr/bin:/bin",
            "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "CGO_ENABLED": "0",
            "GOFLAGS": "-mod=readonly -buildvcs=false", "GOOS": goos, "GOARCH": goarch,
            "GOPROXY": os.environ.get("SSVC_GO_PROXY", "https://proxy.golang.org"),
            "GOSUMDB": "sum.golang.org", "GONOSUMDB": "", "GOPRIVATE": "", "GOINSECURE": "",
            "GOMODCACHE": str(_modcache()), "GOCACHE": f"{home}/build", "GOPATH": f"{home}/gopath"}


def _messages(text: str) -> list[dict]:
    dec, i, out = json.JSONDecoder(), 0, []
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        out.append(obj)
    return out


def _cgo_files(root: Path, import_path: str) -> list[tuple[str, set[str]]]:
    """(package import path, imported paths) for every non-test cgo file under a module
    root whose import path is `import_path`."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("vendor", "testdata", ".git") and not d.startswith(".")]
        for fn in filenames:
            if not fn.endswith(".go") or fn.endswith("_test.go"):
                continue
            try:
                data = (Path(dirpath) / fn).read_bytes()
            except OSError:
                continue
            if not _CGO.search(data[:20000]):
                continue
            rel = Path(dirpath).relative_to(root).as_posix()
            head = data.split(b"\nfunc ", 1)[0]          # the import block comes before any func
            out.append((import_path if rel == "." else f"{import_path}/{rel}",
                        {m.decode() for m in _IMPORT_PATHS.findall(head)}))
    return out


def _cgo_hits(repo: Path, pkgs: list[str]) -> list[str]:
    """Where a file the analysis left out (cgo) is in, or imports, a vulnerable package."""
    from .. import gomod
    b = gomod.load(repo, graph=False)
    roots = [(repo, b.main.module if b else "")]
    if b:
        roots += [(_modcache() / f"{_escape(m.source[0])}@{m.source[1]}", m.path)
                  for m in b.modules.values() if not m.local]
    hits = []
    for root, ip in roots:
        if not root.is_dir():
            continue
        for pkg, imports in _cgo_files(root, ip):
            if pkg in pkgs or imports & set(pkgs):
                hits.append(pkg)
    return sorted(set(hits))


class GovulncheckJudge:
    name = "govulncheck"

    def __init__(self, timeout: float | None = None):
        self.timeout = timeout or float(os.environ.get("SSVC_GOVULNCHECK_TIMEOUT", "900"))
        self._scans: dict[str, dict | None] = {}
        self._version = ""

    def version(self) -> str:
        """`govulncheck@v1.9.0 db 2026-10-08`: in the cache key, so a DB update re-scans."""
        if not self._version:
            try:
                out = subprocess.run([_bin(), "-version"], capture_output=True, text=True, timeout=60,
                                     env=_env(tempfile.gettempdir(), "linux", "amd64")).stdout
            except (OSError, subprocess.SubprocessError):
                return ""
            scanner = re.search(r"Scanner:\s*(\S+)", out)
            db = re.search(r"DB updated:\s*(\S+)", out)
            self._version = f"{scanner[1] if scanner else '?'} db {db[1] if db else '?'}"
        return self._version

    def fingerprint(self) -> str:
        plats = "+".join(f"{o}-{a}" for o, a in _platforms())
        return f"govulncheck@{self.version().replace(' ', '_')}@{plats}@cgo1"

    def app_code_destination(self) -> str:
        return "machine"

    def probe(self) -> tuple[bool, str]:
        if not Path(_bin()).is_file() or not (shutil.which("go") or Path("/opt/homebrew/bin/go").is_file()):
            return False, f"no govulncheck at {_bin()} or no go toolchain"
        return True, f"{self.version()}, platforms {','.join('/'.join(p) for p in _platforms())}, sandboxed"

    # --- one scan per checkout ---------------------------------------------------
    def _scan(self, repo: str) -> dict | None:
        """{osv id: {"aliases": [...], "findings": {module: (level, version, frames)}}}."""
        with keylock(("govulncheck", repo)):        # one scan per checkout, however many rows ask
            return self._scan_locked(repo)

    def _scan_locked(self, repo: str) -> dict | None:
        if repo in self._scans:
            return self._scans[repo]
        root = Path(repo)
        h = hashlib.sha256()
        for f in ("go.mod", "go.sum"):
            p = root / f
            h.update(p.read_bytes() if p.is_file() else b"")
        key = hashlib.sha256((self.fingerprint() + h.hexdigest() + str(root.resolve())).encode()).hexdigest()[:24]
        cache = Path(os.environ.get("SSVC_JUDGE_CACHE", "~/.cache/ssvc-triage/judge")).expanduser() / "govulncheck-scans"
        cf = cache / f"{key}.json"
        if cf.is_file():
            self._scans[repo] = json.loads(cf.read_text())
            return self._scans[repo]
        result: dict = {}
        for goos, goarch in _platforms():
            with tempfile.TemporaryDirectory(prefix="ssvc-gvc-") as home:
                try:
                    p = subprocess.run([_bin(), "-C", str(root), "-format", "json", "./..."],
                                       capture_output=True, text=True, timeout=self.timeout,
                                       env=_env(home, goos, goarch), stdin=subprocess.DEVNULL)
                except (OSError, subprocess.SubprocessError) as exc:
                    logger.warning("govulncheck %s: %s; no claim", repo, exc)
                    self._scans[repo] = None
                    return None
            if p.returncode != 0:
                logger.warning("govulncheck %s (%s/%s) exit %s: %s; no claim", repo, goos, goarch,
                               p.returncode, p.stderr.strip()[-400:])
                self._scans[repo] = None
                return None
            for m in _messages(p.stdout):
                if "osv" in m:
                    o = m["osv"]
                    e = result.setdefault(o["id"], {"aliases": o.get("aliases") or [], "findings": {}})
                    e["pkgs"] = sorted({i.get("path", "") for a in o.get("affected") or []
                                        for i in (a.get("ecosystem_specific") or {}).get("imports") or []} - {""})
                elif "finding" in m:
                    f = m["finding"]
                    tr = f.get("trace") or [{}]
                    lvl = 3 if tr[0].get("function") else 2 if tr[0].get("package") else 1
                    frames = [f"{fr.get('package', '')}.{(fr.get('receiver') or '').lstrip('*') + '.' if fr.get('receiver') else ''}"
                              f"{fr.get('function', '')}"
                              + (f" ({Path(fr['position']['filename']).name}:{fr['position'].get('line')})"
                                 if (fr.get("position") or {}).get("filename") else "")
                              for fr in tr if fr.get("function")]
                    e = result.setdefault(f["osv"], {"aliases": [], "findings": {}})
                    mod = tr[0].get("module", "")
                    old = e["findings"].get(mod)
                    if old is None or lvl > old[0]:
                        e["findings"][mod] = (lvl, tr[0].get("version", ""), frames[:8], f"{goos}/{goarch}")
        cache.mkdir(parents=True, exist_ok=True)
        cf.write_text(json.dumps(result))
        self._scans[repo] = result
        return result

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        if q.ecosystem != "go" or not (Path(q.repo_path) / "go.mod").is_file():
            return None
        t0 = time.monotonic()
        scan = self._scan(q.repo_path)
        if scan is None:
            return None
        ids = {q.cve.upper()}
        entry = next((e for oid, e in scan.items()
                      if oid.upper() in ids or ids & {a.upper() for a in e["aliases"]}), None)
        if entry is None:
            return None                     # not in the Go vulnerability database
        found = entry["findings"].get(q.dependency)
        if found is None or (q.version and found[1] and found[1].lstrip("v") != q.version.lstrip("v")):
            return None                     # govulncheck doesn't consider this version affected
        lvl, _version, frames, plat = found
        oid = next(oid for oid, e in scan.items() if e is entry)
        note = f"govulncheck {oid}: {_LEVEL[lvl]} ({plat}, tests excluded)"
        if lvl == 3:
            return JudgeResult(Verdict.REACHABLE, 1.0, self.name, rationale=note, evidence=frames,
                               latency_s=round(time.monotonic() - t0, 3), cost_usd=0.0, model=self.version())
        pkgs = entry.get("pkgs") or [q.dependency]
        if cgo := _cgo_hits(Path(q.repo_path), pkgs):
            return JudgeResult(Verdict.UNSURE, 0.0, self.name, model=self.version(),
                               rationale=f"{note}; but cgo files in {', '.join(cgo[:4])} are in or import "
                                         f"{', '.join(pkgs[:3])} and the analysis leaves them out "
                                         "(CGO_ENABLED=0): not_reachable not claimed",
                               latency_s=round(time.monotonic() - t0, 3), cost_usd=0.0)
        return JudgeResult(Verdict.NOT_REACHABLE, 1.0, self.name, rationale=note, evidence=frames,
                           latency_s=round(time.monotonic() - t0, 3), cost_usd=0.0, model=self.version())


def _escape(path: str) -> str:
    return re.sub(r"[A-Z]", lambda c: "!" + c.group(0).lower(), path)

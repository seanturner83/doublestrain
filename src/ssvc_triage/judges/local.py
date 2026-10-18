"""OpenAI-compatible reachability judges: any /v1/chat/completions server — LM Studio,
llama.cpp, Ollama, vLLM on this machine or the workstation, or a hosted API.

`local` is the built-in endpoint. Any other tier name is an endpoint configured by its
own env prefix: `cascade:jev,local,workstation,claude` with SSVC_WORKSTATION_BASE_URL etc.
Every endpoint is a summary tier (excerpts, no tools): it can settle `not_reachable` at
its floor, never `reachable` (`base.floors`).

Code egress: these judges SEND SOURCE EXCERPTS of the app. An endpoint whose host isn't
loopback/private (all resolved addresses) is refused unless it is https AND
SSVC_<NAME>_ALLOW_CODE_EGRESS=1 — checked at construction, so a misconfigured run fails
fast instead of shipping code or silently escalating everything to claude.

Sits between Jev and claude-code: it reads more than Jev (the grep summary PLUS the
source around every import / vulnerable-symbol site, a bounded "context pack") but
doesn't drive tools itself — local models are unreliable tool drivers on real repos,
while a single bounded classification over a prepared context is where they hold up.

Its confidence is self-reported by a small model, so it gets Jev-strength floors.

Config, per endpoint (shown for `local`; another tier uses SSVC_<NAME>_...):
SSVC_LOCAL_BASE_URL (default http://localhost:1234/v1 for `local`; required otherwise),
SSVC_LOCAL_MODEL (default: the server's first listed model), SSVC_LOCAL_API_KEY
(optional), SSVC_LOCAL_TIMEOUT (default 180s), SSVC_LOCAL_CONTEXT_CHARS (context pack
budget, default 24000), SSVC_LOCAL_REASONING_EFFORT (default "none": local thinking
models reason on every call unless it is sent explicitly, which is pure latency on a
bounded classification; set it empty to omit the field for servers that reject it),
SSVC_<NAME>_ALLOW_CODE_EGRESS (see above).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .. import accounting
from .base import JudgeResult, ReachQuery, Verdict
from .claude_code import PROMPT_ID, SCHEMA, SYSTEM_PROMPT
from .usage import _EXTS, PREPASS_VERSION, _bindings, _iter_files, guard_not_reachable, is_test_path, usage_summary

# Bump when what the context pack shows changes (endpoint tiers' cache key only).
CONTEXT_VERSION = 10

logger = logging.getLogger(__name__)

_SYSTEM = SYSTEM_PROMPT.replace(
    "The current working directory is an application's source tree.",
    "You are given excerpts of an application's source tree (you cannot open other files).",
).replace("- Cite evidence as path:line.", "- Cite evidence as path:line from the excerpts.") + (
    "\nReachability is whether the vulnerable code runs on attacker data, not how severe "
    "the result is: a bounded impact, or a default limit that caps the damage, does not "
    "make it not_reachable."
    "\nIf the excerpts are not enough to decide, answer unsure. "
    "Reply with ONLY a JSON object, rationale first: work through the uses, then give the "
    "verdict your rationale reached: "
    '{"rationale": "...", "evidence": ["path:line", ...], '
    '"verdict": "reachable|not_reachable|unsure", "confidence": 0-1}'
)


_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def env(name: str, key: str, default: str = "") -> str:
    return os.environ.get(f"SSVC_{name.upper()}_{key}", default)


def configured(name: str) -> bool:
    """Is `name` an endpoint tier (built-in `local`, or one with SSVC_<NAME>_BASE_URL)?"""
    return bool(_NAME.match(name)) and (name == "local" or bool(env(name, "BASE_URL")))


def is_private_host(host: str) -> bool:
    """Loopback / private / link-local, for a literal IP or ALL of a name's addresses."""
    if not host:
        return False
    try:
        addrs = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(ai[4][0].split("%")[0])
                     for ai in socket.getaddrinfo(host, None)}
        except (OSError, ValueError):
            return False
    return bool(addrs) and all(a.is_loopback or a.is_private or a.is_link_local for a in addrs)


def check_egress(name: str, base_url: str) -> bool:
    """Raise ValueError unless sending source excerpts to base_url is allowed. Returns
    True when the endpoint is off-network (hosted)."""
    u = urllib.parse.urlparse(base_url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError(f"{name}: bad base URL {base_url!r}")
    if is_private_host(u.hostname):
        return False
    if u.scheme != "https":
        raise ValueError(f"{name}: off-network endpoint {u.hostname} must use https")
    if env(name, "ALLOW_CODE_EGRESS").lower() not in ("1", "true", "yes"):
        raise ValueError(f"{name}: {u.hostname} is off-network and would receive source excerpts "
                         f"of the app; set SSVC_{name.upper()}_ALLOW_CODE_EGRESS=1 to allow it")
    return True


def context_pack(repo_path: str, sites: list[str], budget: int, radius: int = 12) -> str:
    """Source excerpts (±radius lines) around each `path:line: ...` site, merged per
    file, numbered, until `budget` characters. Manifests first: versions/deps matter."""
    root = Path(repo_path).expanduser()
    out, used = [], 0
    for manifest in ("package.json", "requirements.txt", "pyproject.toml", "go.mod"):
        p = root / manifest
        if p.is_file():
            txt = p.read_text(errors="replace")[:3000]
            out.append(f"=== {manifest}\n{txt}")
            used += len(out[-1])
    by_file: dict[str, set[int]] = {}
    for s in sites:
        m = re.match(r"(.+?):(\d+):", s)
        if m:
            by_file.setdefault(m.group(1), set()).add(int(m.group(2)))
    for rel, lines in by_file.items():
        try:
            src = (root / rel).read_text(errors="replace").splitlines()
        except OSError:
            continue
        keep = sorted({i for ln in lines for i in range(max(1, ln - radius), min(len(src), ln + radius) + 1)})
        chunk, prev = [f"=== {rel}"], 0
        for i in keep:
            if prev and i != prev + 1:
                chunk.append("    ...")
            chunk.append(f"{i:5}  {src[i - 1]}")
            prev = i
        block = "\n".join(chunk)
        if used + len(block) > budget:
            # no room for the surroundings: the site lines themselves still go in
            bare = "\n".join([f"=== {rel} (site lines only: context budget)"] +
                              [f"{ln:5}  {src[ln - 1][:200]}" for ln in sorted(lines) if 0 < ln <= len(src)])
            if used + len(bare) > budget:
                out.append(f"=== {rel} (omitted: context budget)")
                continue
            block = bare
        out.append(block)
        used += len(block)
    return "\n\n".join(out)


def parent_use_sites(repo_path: str, entry_sites: list[str], cap: int = 40) -> list[str]:
    """Every line where the app USES an imported binding (`AdmZip(buf)`, `express.static(...)`,
    `express()`), not just the import line: for the dependency itself (whatever the grep
    tokens were) and for the parent a transitive dependency is reached through."""
    root = Path(repo_path).expanduser()
    out: list[str] = []
    by_file: dict[str, set[str]] = {}
    for site in entry_sites:
        m = re.match(r"(.+?):(\d+): (.*)", site)
        if m:
            by_file.setdefault(m.group(1), set()).update(_bindings("npm", m.group(3), "", ""))
    for rel, names in by_file.items():
        names = {n for n in names if n}
        if not names:
            continue
        use = re.compile(rf"(?<![\w$.])(?:{'|'.join(map(re.escape, sorted(names)))})\s*[.(]")
        try:
            lines = (root / rel).read_text(errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if use.search(line) and not re.search(r"\brequire\(|^\s*import\b", line):
                out.append(f"{rel}:{i}: {line.strip()[:160]}")
                if len(out) >= cap:
                    return out
    return out


_LOCAL_SPEC = re.compile(r"""(?:require\(\s*|from\s+)['"](\.{1,2}/[^'"]+)['"]""")
_DESTRUCTURE = re.compile(r"""(?:(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(|import\s*\{([^}]*)\}\s*from)""")
_MOD_SUFFIX = re.compile(r"\.(?:[cm]?js|tsx?|jsx)$")
_MAX_SCAN = 5000
_REQUESTISH = re.compile(r"(?<![\w$])(?:req|request|ctx|args|input|body|params|query)\b")


def _module_key(rel: str) -> str:
    """`src/models/note.js`, `src/models/note` and `src/models/note/index.js` -> one key."""
    k = _MOD_SUFFIX.sub("", rel)
    return k[:-len("/index")] if k.endswith("/index") else k


def _local_bindings(line: str) -> set[str]:
    names = set(_bindings("npm", line, "", ""))
    for m in _DESTRUCTURE.finditer(line):
        for part in (m.group(1) or m.group(2) or "").split(","):
            part = part.strip()
            alias = re.split(r"\s*(?::|\bas\b)\s*", part)[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", alias):
                names.add(alias)
    return names


def local_module_use_sites(repo_path: str, import_sites: list[str], cap: int = 40, hops: int = 2) -> list[str]:
    """Where the app uses a LOCAL module that wraps the dependency: `models/note.js` does
    `module.exports = mongoose.model(...)` and `controllers/notes.js` calls
    `Note.findOneAndUpdate(q, req.body)` without ever importing mongoose. Follows relative
    require/import up to `hops` local modules deep, and lists the use lines of the bindings."""
    root = Path(repo_path).expanduser().resolve()
    targets = {_module_key(m.group(1)) for s in import_sites if (m := re.match(r"(.+?):\d+:", s))}
    seen: set[str] = set(targets)
    found: list[tuple[tuple, str]] = []
    texts: dict[str, list[str]] = {}
    for n, f in enumerate(_iter_files(root, _EXTS["npm"])):
        if n >= _MAX_SCAN:
            break
        try:
            if f.stat().st_size <= 512 * 1024:
                texts[f.relative_to(root).as_posix()] = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
    for hop in range(hops):
        nxt: set[str] = set()
        for rel, lines in texts.items():
            names: set[str] = set()
            hit = False
            for line in lines:
                for spec in _LOCAL_SPEC.findall(line):
                    tgt = os.path.normpath(os.path.join(os.path.dirname(rel), spec))
                    if not tgt.startswith("..") and _module_key(tgt) in targets:
                        hit = True
                        names |= _local_bindings(line)
            if hit:
                nxt.add(_module_key(rel))       # `module.exports = {Note: require('./note')}` re-exports unbound
            if not names:
                continue
            use = re.compile(rf"(?<![\w$.])(?:{'|'.join(map(re.escape, sorted(names)))})\s*[.(]")
            side = is_test_path(Path(rel)) or rel.split("/")[0] in ("scripts", "script", "tools", "bin")
            for i, line in enumerate(lines, 1):
                if use.search(line) and not re.search(r"\brequire\(|^\s*import\b", line):
                    # request-shaped arguments first, then nearer modules, app code before scripts/tests
                    rank = (not _REQUESTISH.search(line), side, hop, len(found))
                    found.append((rank, f"{rel}:{i}: {line.strip()[:160]}"))
        targets = nxt - seen
        seen |= nxt
        if not targets:
            break
    return [site for _, site in sorted(found)[:cap]]

def app_excerpts(repo_path: str, u, budget: int) -> str:
    """The endpoint tiers' (and the split matcher's) view of the app: imports, symbol and
    entry sites, where the bindings are used, and where app modules wrapping them are used."""
    entry = u.import_sites + u.entry_sites
    return context_pack(repo_path, u.import_sites + u.symbol_sites + u.entry_sites
                        + parent_use_sites(repo_path, entry) + local_module_use_sites(repo_path, entry), budget)


def _parse(content: str) -> dict | None:
    content = re.sub(r"<think>.*?</think>", "", content or "", flags=re.S).strip()
    for cand in (content, *(m.group(0) for m in re.finditer(r"\{.*\}", content, re.S))):
        try:
            d = json.loads(cand)
            if isinstance(d, dict) and "verdict" in d:
                return d
        except json.JSONDecodeError:
            continue
    return None


class OpenAIJudge:
    def __init__(self, name: str = "local", model: str | None = None, timeout: float | None = None):
        if not _NAME.match(name):
            raise ValueError(f"bad endpoint tier name {name!r}")
        self.name = name
        default_url = "http://localhost:1234/v1" if name == "local" else ""
        self.base_url = env(name, "BASE_URL", default_url).rstrip("/")
        self.hosted = check_egress(name, self.base_url)
        self._model = model or env(name, "MODEL")
        self.timeout = timeout or float(env(name, "TIMEOUT", "180"))
        self.budget = int(env(name, "CONTEXT_CHARS", "24000"))

    def _req(self, path: str, payload: dict | None, timeout: float) -> dict:
        headers = {"Content-Type": "application/json"}
        if key := env(self.name, "API_KEY").strip():
            headers["Authorization"] = f"Bearer {key}"
        req = urllib.request.Request(  # noqa: S310 — configured, egress-checked base URL
            f"{self.base_url}{path}", headers=headers,
            data=json.dumps(payload).encode() if payload is not None else None,
            method="POST" if payload is not None else "GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode())

    def model(self) -> str | None:
        if not self._model:
            try:
                data = self._req("/models", None, 10).get("data") or []
                self._model = data[0]["id"] if data else ""
            except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, IndexError):
                return None
        return self._model or None

    def answer_model(self) -> str:
        """The model behind this tier's answers (floors.toml); in the cache key too."""
        return self.model() or ""

    def app_code_destination(self) -> str:
        """machine (loopback) | network (private/link-local) | offsite."""
        host = urllib.parse.urlparse(self.base_url).hostname or ""
        if self.hosted:
            return "offsite"
        try:
            addrs = {ipaddress.ip_address(host)}
        except ValueError:
            try:
                addrs = {ipaddress.ip_address(ai[4][0].split("%")[0]) for ai in socket.getaddrinfo(host, None)}
            except (OSError, ValueError):
                return "offsite"
        return "machine" if addrs and all(a.is_loopback for a in addrs) else "network"

    def complete(self, system: str, user: str, schema: dict, purpose: str = "judge") -> tuple[dict | None, str]:
        """One bounded JSON answer -> (parsed dict with a verdict, "") or (None, why).
        Every call is written to the usage ledger (`accounting`)."""
        model = self.model()
        if not model:
            return None, f"no model at {self.base_url}"
        # constrained decoding emits keys in schema order: put the reasoning before the
        # verdict, or the verdict is chosen before any reasoning (thinking is off here)
        props = schema.get("properties") or {}
        first = [k for k in ("rationale", "evidence") if k in props]
        schema = {**schema, "properties": {k: props[k] for k in first + [k for k in props if k not in first]}}
        payload = {
            "model": model, "temperature": 0,
            **({"reasoning_effort": e} if (e := env(self.name, "REASONING_EFFORT", "none")) else {}),
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "reachability", "strict": True, "schema": schema}},
        }
        t0, acct = time.monotonic(), {"model": model, "endpoint": self.name}
        try:
            out = self._req("/chat/completions", payload, self.timeout)
            acct.update(accounting.endpoint_fields(out))
            d = _parse(out["choices"][0]["message"].get("content") or "")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")[:300] if exc.fp else ""
            accounting.record("endpoint", purpose, outcome="error", latency_s=round(time.monotonic() - t0, 3), **acct)
            return None, f"{exc}: {body}"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
            accounting.record("endpoint", purpose, outcome="timeout" if "timed out" in str(exc) else "error",
                              latency_s=round(time.monotonic() - t0, 3), **acct)
            return None, str(exc)
        accounting.record("endpoint", purpose, outcome="ok" if d else "error",
                          latency_s=round(time.monotonic() - t0, 3), **acct)
        return (d, "") if d else (None, "unparseable reply")

    def probe(self) -> tuple[bool, str]:
        # always ask the server: a configured model name says nothing about whether it's up
        try:
            listed = [d.get("id") for d in self._req("/models", None, 10).get("data") or []]
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, AttributeError) as exc:
            return False, f"{self.base_url} unreachable ({exc})"
        m = self.model()
        if not m:
            return False, f"no model at {self.base_url}"
        if self._model and listed and m not in listed:
            return False, f"{self.base_url} does not list model {m}"
        return True, f"{self.base_url} model {m}"

    def fingerprint(self) -> str:
        # resolve the auto-detected model so the cache never mixes answers from different models
        return (f"{self.name}@{self.base_url}@{self.model() or 'auto'}@prepass{PREPASS_VERSION}@p{PROMPT_ID}"
                f"@ctx{CONTEXT_VERSION}")

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        model = self.model()
        if not model:
            logger.warning("%s judge: no model at %s; no claim", self.name, self.base_url)
            return None
        u = usage_summary(q.repo_path, q.ecosystem, q.dependency, q.vuln_symbols, q.import_name,
                          version=q.version)
        user = (
            f"Advisory: {q.cve} in {q.ecosystem} package `{q.dependency}`"
            + (f" (imported as `{q.import_name}`)" if q.import_name else "") + "\n"
            f"Vulnerable symbol(s): {', '.join(q.vuln_symbols) or '(unspecified)'}"
            + (" (named in the advisory: often internal to the package, and reached through its "
               "public API or through a parent package's API, e.g. a framework middleware the app "
               "mounts; a same-named method on another package is not it)" if q.vuln_symbols else "")
            + "\n"
            f"Advisory summary: {q.advisory or '(none)'}\n\n"
            f"Static pre-pass (grep):\n{u.text}\n\n"
            f"Source excerpts:\n{app_excerpts(q.repo_path, u, self.budget)}\n\n"
            "Is the vulnerable code reachable from this application?"
        )
        t0 = time.monotonic()
        d, err = self.complete(_SYSTEM, user, SCHEMA)
        if d is None:
            logger.warning("%s judge failed (%s); no claim", self.name, err)
            return None
        try:
            verdict = Verdict(d["verdict"])
        except (KeyError, ValueError):
            logger.warning("%s judge: bad verdict; no claim", self.name)
            return None
        # it reads excerpts, not the whole tree: same open-world guard as Jev
        verdict, guard_note = guard_not_reachable(verdict, u)
        return JudgeResult(verdict=verdict, confidence=float(d.get("confidence") or 0.0),
                           source=self.name, model=model,
                           rationale="; ".join(filter(None, [str(d.get("rationale", ""))[:1000], guard_note])),
                           evidence=[str(e) for e in d.get("evidence") or []][:20],
                           latency_s=round(time.monotonic() - t0, 3),
                           cost_usd=None if self.hosted else 0.0)   # hosted pricing unknown here


LocalJudge = OpenAIJudge

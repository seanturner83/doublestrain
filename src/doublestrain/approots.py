"""approots: app code the image installs from outside the directory the grader was given.

py7's one false not_reachable: the Baserow case was rooted at backend/, and backend/Dockerfile
(build context the repo root) copies ./premium/backend and ./enterprise/backend into the image
and `pip install -e`s them into the same venv (Dockerfile:79-95). The langchain-core call the
advisory needs (the premium AI field formatting a user-written prompt template) is in
premium/; every judge searched backend/ only, found no langchain use and said not_reachable.

This reads the Dockerfiles under the root (text only; nothing is built or run): COPY/ADD
sources mapped to their image paths, and the local paths a `pip install` / `uv pip install`
installs. A build context is accepted only if it is the root or one of its parents inside the
same checkout (the `.git` top) and its COPY sources exist there, one of them inside the root.
An installed path that maps back to a directory outside the root, holding a Python project, is
an extra app root. Widening only: more app files to read; nothing here clears a row.
"""
from __future__ import annotations

import functools
import os
import re
import shlex
from pathlib import Path

_SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__", "site-packages"}
_PROJECT = ("pyproject.toml", "setup.py", "setup.cfg")
_PIP = re.compile(r"\b(?:pip3?|uv\s+pip)\s+install\b")


def _dockerfiles(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        dirnames[:] = [d for d in dirnames if d not in _SKIP and not d.startswith(".")] if len(rel.parts) < 2 else []
        for fn in filenames:
            if fn == "Dockerfile" or fn.startswith("Dockerfile.") or fn.endswith(".Dockerfile"):
                yield Path(dirpath) / fn


def _instructions(text: str):
    """(KEYWORD, rest) per instruction, continuation lines joined."""
    cur = ""
    for line in text.splitlines():
        s = line.strip()
        if not cur and (not s or s.startswith("#")):
            continue
        cur += " " + (s[:-1] if s.endswith("\\") else s)
        if not s.endswith("\\"):
            kw, _, rest = cur.strip().partition(" ")
            yield kw.upper(), rest.strip()
            cur = ""


def _args(rest: str) -> list[str]:
    try:
        return shlex.split(rest)
    except ValueError:
        return rest.split()


def _parse(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """([(copy source, image path)], [image paths pip installs])."""
    copies, installs, workdir = [], [], "/"
    for kw, rest in _instructions(text):
        if kw == "WORKDIR":
            workdir = os.path.normpath(os.path.join(workdir, rest.strip()))
        elif kw in ("COPY", "ADD"):
            a = [x for x in _args(rest) if not x.startswith("--")]
            if "--from" in rest or len(a) < 2 or any(x.startswith(("http:", "https:")) for x in a):
                continue                       # another stage's files, or a download
            dst = os.path.normpath(os.path.join(workdir, a[-1]))
            for src in a[:-1]:
                if not any(ch in src for ch in "*?["):
                    copies.append((os.path.normpath(src), dst + ("/" + Path(src).name if len(a) > 2 else "")))
        elif kw == "RUN":
            for part in re.split(r"&&|;|\|\|", rest):
                m = _PIP.search(part)
                if not m:
                    continue
                a = _args(part[m.end():])
                for n, x in enumerate(a):
                    if x.startswith("-") and x not in ("-e", "--editable"):
                        continue
                    if n and a[n - 1] in ("-r", "-c", "--requirement", "--constraint"):
                        continue
                    if x.startswith(("/", ".")) and x not in ("-e", "--editable"):
                        installs.append(os.path.normpath(os.path.join(workdir, x)))
    return copies, installs


def _top(root: Path) -> Path:
    for d in (root, *root.parents):
        if (d / ".git").exists():
            return d
    return root


@functools.lru_cache(maxsize=64)
def _extra_roots(root: str) -> tuple[Path, ...]:
    r = Path(root)
    top = _top(r)
    contexts = [d for d in (r, *r.parents) if d.is_relative_to(top)]
    out: list[Path] = []
    for df in _dockerfiles(r):
        try:
            copies, installs = _parse(df.read_text(errors="replace"))
        except OSError:
            continue
        if not installs or not copies:
            continue
        for ctx in contexts:
            hosts = [(ctx / src).resolve() for src, _ in copies]
            if not all(h.exists() and h.is_relative_to(ctx.resolve()) for h in hosts) \
                    or not any(h.is_relative_to(r) for h in hosts):
                continue
            for t in installs:
                for (src, dst), host in zip(copies, hosts):
                    if t == dst or t.startswith(dst.rstrip("/") + "/"):
                        p = (host / os.path.relpath(t, dst)).resolve()
                        if p.is_dir() and not p.is_relative_to(r) and not r.is_relative_to(p) \
                                and p.is_relative_to(top) and any((p / f).is_file() for f in _PROJECT) \
                                and p not in out:
                            out.append(p)
            break
    return tuple(sorted(out))


def extra_roots(repo_path: str | Path) -> tuple[Path, ...]:
    """Directories outside `repo_path` whose Python project the app's Dockerfile installs
    into the same environment (absolute, sorted); () when there are none."""
    return _extra_roots(str(Path(repo_path).expanduser().resolve()))


def walk(root: Path, walker):
    """`walker(r)` -> (path, rel) for the root and then each extra root, every rel relative to
    `root` (an extra root's files come back as ../premium/backend/..., so root / rel opens them)."""
    yield from walker(root)
    base = Path(root).expanduser().resolve()      # the kernel resolves ../ from the real directory
    for extra in extra_roots(root):
        for p, rel in walker(extra):
            yield p, Path(os.path.relpath(extra / rel, base))


def note(repo_path: str) -> str:
    """One line for the judges' pre-pass: '' when the app is all under its root."""
    ex = extra_roots(repo_path)
    if not ex:
        return ""
    root = Path(repo_path).expanduser().resolve()
    rels = ", ".join(os.path.relpath(p, root) for p in ex)
    return (f"APP CODE OUTSIDE THIS DIRECTORY: the Dockerfile installs {rels} into the same environment, so "
            "that code runs in the deployed app. Its files are searched and listed here with ../ paths: "
            "read them like the app's own before deciding not_reachable.")

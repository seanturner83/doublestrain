"""Dev-server note: for an advisory about a development tool's server mode, what starts it.

Most advisories against Vite, Storybook, Vitest, esbuild and webpack-dev-server are about
the server those tools run while a developer works (`vite` / `vite preview`, `storybook
dev`, `vitest --ui`, esbuild's serve mode): `server.fs` bypasses, cross-origin requests to
the dev server, `launch-editor`. They are exploitable only while that server runs. A
production build (`vite build`, `build-storybook`) does not start it. Measured on a
private set of real applications (2026-10-23): 13 of the claude judge's 18 false
`reachable` answers were these advisories on apps that only ever build with the tool.

This module is NOT a verdict, and nothing here settles `not_reachable`: some apps do serve
production with `vite preview` or a dev server, and a rule would hide that. It gathers the
facts the judge needs, appended to the pre-pass like the other notes:
- the advisory is about the tool's server mode (package in `_TOOLS` and the advisory text
  names server behaviour);
- the app's production entry points (Dockerfile CMD/ENTRYPOINT, start/serve/preview
  scripts, Procfile, Cloudflare Workers config), and which scripts start the server.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

# package (or scope prefix) -> the server it runs and the commands that start it
_TOOLS = {
    "vite": ("the Vite dev server or preview server",
             # vite itself, and frameworks whose dev/preview commands run Vite's server
             (r"\bvite(?:\s+(?:dev|serve|preview)\b|\s*(?:$|[;&|]|--(?!mode\b)))"
              r"|\b(?:astro|svelte-kit|nuxt|nuxi|react-router|remix\s+vite:)\s*(?:dev|preview|start)\b")),
    "storybook": ("the Storybook dev server", r"\bstorybook\s+dev\b|\bstart-storybook\b"),
    "@storybook/": ("the Storybook dev server", r"\bstorybook\s+dev\b|\bstart-storybook\b"),
    "vitest": ("the Vitest UI, API or browser-mode server",
               r"\bvitest\b[^;&|]*--(?:ui|api|browser)\b"),
    "@vitest/": ("the Vitest UI, API or browser-mode server",
                 r"\bvitest\b[^;&|]*--(?:ui|api|browser)\b"),
    "esbuild": ("esbuild's serve mode (the development server)", r"\besbuild\b[^;&|]*--serve(?:dir)?\b"),
    "webpack-dev-server": ("webpack-dev-server", r"\bwebpack(?:-dev-server|\s+serve)\b"),
}
_SERVER_TEXT = re.compile(
    r"dev(?:elopment)?[ -]server|\bserver\.fs\b|launch-editor|\bUI server\b|\bpreview\b"
    r"|\bmiddleware\b|vite-wasm-instance|\bmock registration|\bredirect mock|optimi[sz]ed deps"
    r"|public directory|request-target|returned to the browser|\bserved\b|send (?:any )?requests"
    r"|websocket|serve mode|--host\b",
    re.IGNORECASE)
_PROD_SCRIPTS = ("start", "serve", "preview", "prod", "production")
_SKIP = {".git", "node_modules", "dist", "build", ".venv", "vendor", "coverage", ".next",
         ".opengrep", ".ast-grep", "fixtures", "__fixtures__", "testdata",
         "test", "tests", "__tests__", "spec", "specs", "e2e"}
_MAX_FILES = 400


def tool_of(dependency: str) -> tuple[str, str] | None:
    """(server description, start-command regex) when `dependency` is a dev-server tool."""
    if dependency in _TOOLS:
        return _TOOLS[dependency]
    for prefix, spec in _TOOLS.items():
        if prefix.endswith("/") and dependency.startswith(prefix):
            return spec
    return None


def is_dev_server_advisory(dependency: str, advisory: str) -> bool:
    return tool_of(dependency) is not None and bool(_SERVER_TEXT.search(advisory or ""))


def _files(root: Path, names: tuple[str, ...], prefixes: tuple[str, ...] = ()):
    n = 0
    for p in sorted(root.rglob("*")):
        if n >= _MAX_FILES:
            return
        rel = p.relative_to(root)
        if any(part in _SKIP for part in rel.parts) or not p.is_file():
            continue
        if p.name in names or any(p.name.startswith(x) for x in prefixes):
            n += 1
            yield p, rel


def _final_stage_commands(text: str) -> list[str]:
    """The last stage's base image and its CMD / ENTRYPOINT instructions. Continuation lines
    are joined first, so `HEALTHCHECK ... \\ CMD ...` is not read as the start command."""
    logical = re.sub(r"\\\s*\n\s*", " ", text).splitlines()
    froms = [i for i, ln in enumerate(logical) if re.match(r"(?i)\s*FROM\s", ln)]
    stage = logical[froms[-1]:] if froms else logical
    out = [f"final stage {stage[0].strip()[:120]}"] if froms else []
    return out + [ln.strip()[:160] for ln in stage if re.match(r"(?i)\s*(CMD|ENTRYPOINT)\b", ln)]


@lru_cache(maxsize=64)
def _entrypoints(repo_path: str, start_re: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(production entry points, scripts that start the server), each `path: detail`."""
    root = Path(repo_path).expanduser()
    starts = re.compile(start_re)
    prod, servers = [], []
    for p, rel in _files(root, ("Procfile", "wrangler.toml", "wrangler.json", "wrangler.jsonc",
                                "package.json"), ("Dockerfile", "Containerfile")):
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        if p.name.startswith(("Dockerfile", "Containerfile")):
            for cmd in _final_stage_commands(text):
                prod.append(f"{rel}: {cmd}")
                if starts.search(re.sub(r'[\[\]",]', " ", cmd)):    # exec form: ["npx", "vite", ...]
                    servers.append(f"{rel}: {cmd}")
        elif p.name == "Procfile":
            for ln in text.splitlines():
                if ln.strip():
                    prod.append(f"{rel}: {ln.strip()[:160]}")
                    if starts.search(ln):
                        servers.append(f"{rel}: {ln.strip()[:160]}")
        elif p.name.startswith("wrangler."):
            prod.append(f"{rel}: Cloudflare Workers deployment config")
        else:
            try:
                scripts = (json.loads(text).get("scripts") or {})
            except ValueError:
                continue
            for name, cmd in scripts.items():
                if not isinstance(cmd, str):
                    continue
                line = f"{rel}: scripts.{name} = {cmd[:120]}"
                if name in _PROD_SCRIPTS:
                    prod.append(line)
                if starts.search(cmd):
                    servers.append(line)
    # JS projects first: in a polyglot repo the other services' Dockerfiles say nothing
    # about whether this JS tool's server runs, and the note shows only the first few
    js = lambda entry: not (root / entry.split(":", 1)[0]).parent.joinpath("package.json").is_file()  # noqa: E731
    return tuple(sorted(prod, key=js)), tuple(servers)


def devserver_note(repo_path: str, ecosystem: str, dependency: str, advisory: str) -> str:
    """The note, or "" when the advisory is not about a dev-server tool's server mode."""
    if ecosystem != "npm" or not is_dev_server_advisory(dependency, advisory):
        return ""
    server, start_re = tool_of(dependency)
    prod, servers = _entrypoints(repo_path, start_re)
    lines = [(f"DEV-SERVER ADVISORY: this advisory concerns {server}. It is exploitable only while "
             "that server is running; a production build with the tool (e.g. `vite build`, "
             "`build-storybook`) does not start it. Decide whether this application runs the "
             "server in production (not a verdict; check the deploy path). A server that only "
             "developers start on their own machines (a `dev` or `storybook` script, local "
             "testing) is not the application running it: answer for the deployed application:")]
    lines.append("  candidate production entry points (final Dockerfile stages, Procfile, Workers config, "
                 "start/serve/preview scripts): " + ("none found" if not prod else ""))
    lines += [f"    {x}" for x in prod[:12]]
    lines.append("  scripts / commands that start the server: " + ("none found" if not servers else ""))
    lines += [f"    {x}" for x in servers[:12]]
    return "\n".join(lines)

"""Dev-server note (judges/devserver.py): which advisories get it, what it reports, and
that only those rows are re-keyed in the judge cache."""
import json

from doublestrain.judges import CachedJudge
from doublestrain.judges.base import ReachQuery
from doublestrain.judges.devserver import devserver_note, is_dev_server_advisory

DOCKERFILE = """FROM oven/bun:1.3 AS build
RUN bun run build
FROM nginxinc/nginx-unprivileged:1.29 AS runtime
COPY --from=build /app/dist /usr/share/nginx/html
HEALTHCHECK --interval=30s \\
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
"""


def _app(tmp_path, scripts, dockerfile=DOCKERFILE):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": scripts}))
    (tmp_path / "Dockerfile").write_text(dockerfile)
    fixture = tmp_path / "tests" / "fixtures"
    fixture.mkdir(parents=True)
    (fixture / "Dockerfile").write_text("FROM alpine\nCMD vite preview\n")
    return str(tmp_path)


def test_detects_server_mode_advisories_of_dev_tools_only():
    assert is_dev_server_advisory("vite", "Vite bypasses server.fs.deny when using ?raw??")
    assert is_dev_server_advisory("@storybook/addon-vitest", "Storybook dev server vulnerable to code injection")
    assert is_dev_server_advisory("vitest", "When Vitest UI server is listening, arbitrary file can be read")
    assert not is_dev_server_advisory("vite", "Vite emits a wrong sourcemap comment in the build output")
    assert not is_dev_server_advisory("undici", "development server responses are not validated")


def test_note_reports_build_only_deploys(tmp_path):
    repo = _app(tmp_path, {"dev": "vite", "build": "vite build", "preview": "vite preview"})
    note = devserver_note(repo, "npm", "vite", "Files outside server.fs.allow could be served")
    assert note.startswith("DEV-SERVER ADVISORY") and "not a verdict" in note
    assert "final stage FROM nginxinc/nginx-unprivileged" in note
    assert "HEALTHCHECK" not in note and "wget" not in note       # not the start command
    assert "scripts.dev = vite" in note and "scripts.preview = vite preview" in note
    assert "scripts.build" not in note                            # a build does not start it
    assert "tests/fixtures" not in note                           # fixtures are not the deploy


def test_note_shows_a_production_server(tmp_path):
    repo = _app(tmp_path, {"start": "astro preview --host"},
                dockerfile='FROM node:22\nCMD ["npx", "vite", "preview", "--host"]\n')
    note = devserver_note(repo, "npm", "vite", "Vite dev server allows any website to send requests")
    servers = note.split("start the server:")[1]
    assert "Dockerfile: CMD" in servers and "scripts.start = astro preview --host" in servers


def test_no_note_for_other_advisories_or_ecosystems(tmp_path):
    repo = _app(tmp_path, {"dev": "vite"})
    assert devserver_note(repo, "npm", "express", "dev server") == ""
    assert devserver_note(repo, "pypi", "vite", "dev server") == ""


class _Inner:
    name = "claude"
    devserver_notes = True

    def fingerprint(self):
        return "claude@prepass8"


def test_cache_rekeys_only_rows_with_a_note(tmp_path):
    repo = _app(tmp_path, {"dev": "vite"})
    cj = CachedJudge(_Inner(), cache_dir=str(tmp_path / "cache"))
    dev = ReachQuery(repo, "npm", "vite", "CVE-1", advisory="server.fs.deny bypass")
    other = ReachQuery(repo, "npm", "express", "CVE-2", advisory="open redirect")
    assert cj._path(dev).name != f"{dev.key()}.json" and "-d" in cj._path(dev).name
    assert cj._path(other).name == f"{other.key()}.json"                  # unchanged key
    plain = CachedJudge(type("J", (), {"name": "jev", "fingerprint": lambda s: "jev@prepass8"})(),
                        cache_dir=str(tmp_path / "cache"))
    assert plain._path(dev).name == f"{dev.key()}.json"                   # other judges: unchanged

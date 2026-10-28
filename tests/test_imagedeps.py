"""imagedeps: what the image installs is production, whatever its group or file is called (py8)."""
from pathlib import Path

from doublestrain import imagedeps, pylock

POETRY_LOCK = """
[[package]]
name = "flask"
version = "3.0.0"
files = []
[[package]]
name = "pytest"
version = "8.0.0"
files = []
[[package]]
name = "sphinx"
version = "7.0.0"
files = []
[metadata]
lock-version = "2.0"
"""
PYPROJECT = """
[tool.poetry.dependencies]
python = "^3.10"
flask = "3.0.0"
[tool.poetry.group.dev.dependencies]
pytest = "8.0.0"
[tool.poetry.group.docs]
optional = true
[tool.poetry.group.docs.dependencies]
sphinx = "7.0.0"
"""


def _app(tmp_path: Path, dockerfile: str | None, name: str = "Dockerfile") -> Path:
    (tmp_path / "poetry.lock").write_text(POETRY_LOCK)
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    if dockerfile is not None:
        (tmp_path / name).write_text(dockerfile)
    return tmp_path


def _runtime(root: Path) -> set[str]:
    return {i.split("@")[0] for i in pylock.load(root).runtime()}


def test_groups_the_image_installs_are_production(tmp_path):
    (tmp_path / "a").mkdir()
    assert _runtime(_app(tmp_path / "a", None)) == {"flask"}                # no image: names decide
    # Redash: the groups come from an ARG default
    redash = 'FROM python:3.10\nARG install_groups="main,dev"\nRUN poetry install --only $install_groups --no-root\n'
    (tmp_path / "b").mkdir()
    assert _runtime(_app(tmp_path / "b", redash)) == {"flask", "pytest"}
    # Label Studio: a bare install is every non-optional group; optional ones need --with
    (tmp_path / "c").mkdir()
    assert _runtime(_app(tmp_path / "c", "FROM python:3.12\nRUN poetry install\n")) == {"flask", "pytest"}
    (tmp_path / "d").mkdir()
    assert _runtime(_app(tmp_path / "d", "FROM python:3.12\nRUN poetry install --with=docs --without dev\n")) \
        == {"flask", "sphinx"}
    (tmp_path / "e").mkdir()
    assert _runtime(_app(tmp_path / "e", "FROM python:3.12\nRUN poetry install --only main\n")) == {"flask"}
    # a test image's install says nothing about production
    (tmp_path / "f").mkdir()
    assert _runtime(_app(tmp_path / "f", "FROM python:3.12\nRUN poetry install\n", "Dockerfile.testing")) == {"flask"}


def test_only_the_stages_the_target_is_built_from_count(tmp_path):
    # Mathesar: dev requirements in the development stage; production copies static files from it
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12 AS base\nRUN true\n"
        "FROM base AS development\nRUN pip install -r requirements-dev.txt\n"
        "FROM base AS production\nRUN pip install -r requirements.txt\n"
        "COPY --from=development /code/static ./static\n")
    assert imagedeps.installed(tmp_path).req_files == {"requirements.txt"}
    # Nautobot: site-packages from the main-only stage, a config file from the dev one
    n = tmp_path / "n"
    n.mkdir()
    (n / "Dockerfile").write_text(
        "FROM python:3.12 AS deps\nRUN poetry install --only main --extras all\n"
        "FROM deps AS dev\nRUN poetry install\n"
        "FROM python:3.12 AS final\n"
        "COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages\n"
        "COPY --from=dev /opt/app/config.py /opt/app/config.py\n")
    i = imagedeps.installed(n)
    assert i.poetry == [(frozenset({"main"}), frozenset(), frozenset())] and i.extras == {"all"}
    assert not i.poetry_group("dev", False)


def test_requirements_includes_and_uv_defaults(tmp_path):
    # Superset: lean installs local.txt, which is -r development.txt
    r = tmp_path / "requirements"
    r.mkdir()
    (r / "base.txt").write_text("flask==3.0.0\n")
    (r / "development.txt").write_text("-r base.txt\npytest==8.0.0\n")
    (r / "testing.txt").write_text("-r development.txt\ncoverage==7.0.0\n")
    (r / "local.txt").write_text("-r development.txt\n")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11 AS lean\nRUN --mount=type=cache,target=/root/.cache/pip \\\n    pip install -r requirements/local.txt\n")
    files = pylock.requirement_files(tmp_path)
    assert imagedeps.installed(tmp_path).req_closure(files) == {"local.txt", "development.txt", "base.txt"}
    assert _runtime(tmp_path) == {"flask", "pytest"}                      # testing.txt still dev
    for cmd, groups in (("uv sync --frozen", {"dev"}), ("uv sync --frozen --no-dev", set()),
                        ("uv sync --no-default-groups --group docs", {"docs"}), ("uv sync --all-groups", {"*", "dev"})):
        d = tmp_path / str(abs(hash(cmd)))
        d.mkdir()
        (d / "Dockerfile").write_text(f"FROM python:3.12\nRUN {cmd}\n")
        assert imagedeps.installed(d).uv_groups == groups, cmd
    e = tmp_path / "extras"
    e.mkdir()
    (e / "Dockerfile").write_text("FROM python:3.12\nRUN pip install --no-cache-dir '.[server,dev]'\n")
    assert imagedeps.installed(e).extras == {"server", "dev"}


def test_cargo_builds_across_stages_with_cross_wrappers(tmp_path):
    # Qdrant: xx-cargo in a builder stage, ${X:+alt} flags; the binary is copied out
    (tmp_path / "Dockerfile").write_text(
        "FROM rust AS builder\nARG FEATURES\nARG GPU\n"
        "RUN xx-cargo build --profile release ${FEATURES:+--features} $FEATURES --features=stacktrace ${GPU:+--features=gpu} --bin qdrant\n"
        "RUN cargo install --git https://example.com/x.git tool\n"
        "FROM debian\nCOPY --from=builder /qdrant/target/release/qdrant /qdrant/qdrant\n")
    (b,) = imagedeps.cargo_builds(tmp_path)
    assert b.bins == ("qdrant",) and b.features == ("stacktrace",) and not b.packages

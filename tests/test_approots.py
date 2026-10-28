"""approots: local projects a Dockerfile installs beside the app are app code (py7 Baserow)."""
from pathlib import Path

from doublestrain import approots
from doublestrain.judges.usage import usage_summary

DOCKERFILE = """FROM python:3.12 as base
COPY ./backend/requirements/base.txt /srv/requirements/
RUN pip install -r /srv/requirements/base.txt
COPY --chown=1:1 ./backend /srv/backend
COPY --chown=1:1 ./premium/backend /srv/premium/backend
COPY --from=base /venv /venv
WORKDIR /srv/backend
RUN dos2unix x.sh && \\
    pip install --no-cache-dir -e /srv/backend/ && \\
    pip install --no-cache-dir -e /srv/premium/backend/
"""


def _repo(tmp_path: Path, dockerfile: str = DOCKERFILE) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    be = repo / "backend"
    (be / "requirements").mkdir(parents=True)
    (be / "requirements/base.txt").write_text("langchain-core==0.1.52\n")
    (be / "src/app").mkdir(parents=True)
    (be / "src/app/views.py").write_text("def index():\n    return 'ok'\n")
    (be / "Dockerfile").write_text(dockerfile)
    pb = repo / "premium/backend"
    (pb / "src/app_premium").mkdir(parents=True)
    (pb / "pyproject.toml").write_text("[project]\nname = 'app-premium'\n")
    (pb / "src/app_premium/ai.py").write_text("from langchain_core.prompts import PromptTemplate\n"
                                              "def run(p):\n    return PromptTemplate(template=p).format()\n")
    (repo / "docs").mkdir()                    # copied by no line here; never an app root
    return be


def test_a_project_the_dockerfile_installs_from_the_build_context_is_app_code(tmp_path):
    be = _repo(tmp_path)
    assert approots.extra_roots(be) == ((tmp_path / "repo/premium/backend").resolve(),)
    rels = {rel.as_posix() for _p, rel in approots.walk(be, lambda r: ((f, f.relative_to(r)) for f in r.rglob("*.py")))}
    assert "../premium/backend/src/app_premium/ai.py" in rels and "src/app/views.py" in rels
    u = usage_summary(str(be), "pypi", "langchain-core", ["PromptTemplate"], version="0.1.52")
    assert "APP CODE OUTSIDE THIS DIRECTORY" in u.text and "../premium/backend" in u.text
    assert any(s.startswith("../premium/backend/src/app_premium/ai.py:1:") for s in u.import_sites)
    assert (be / u.import_sites[0].split(":")[0]).is_file()        # root / rel opens it


def test_installing_only_itself_or_an_uncopied_path_adds_nothing(tmp_path):
    be = _repo(tmp_path, DOCKERFILE.replace("    pip install --no-cache-dir -e /srv/premium/backend/\n", "    true\n"))
    assert approots.extra_roots(be) == ()
    assert approots.note(str(be)) == ""
    other = tmp_path / "other"
    other.mkdir()
    # a context outside the checkout (no .git above the root) is never searched
    (other / "Dockerfile").write_text("COPY ./ /srv/x\nCOPY ../premium/backend /srv/p\nRUN pip install -e /srv/p\n")
    assert approots.extra_roots(other) == ()

"""names: one rule per ecosystem for "are these the same package?", at every boundary."""
import pytest

from doublestrain import names

# (ecosystem, canonical source name, spellings that must name it, spellings that must not)
TABLE = [
    ("pypi", "pyyaml", ["PyYAML", "pyyaml", "PYYAML"], ["yaml", "pyyaml2", "py-yaml"]),
    ("pypi", "zope-interface", ["zope.interface", "Zope_Interface"], ["zope"]),
    ("cargo", "serde-json", ["serde_json", "Serde-JSON"], ["serde", "serdejson"]),
    ("maven", "com.fasterxml.jackson.core:jackson-databind",
     ["jackson-databind", "com.fasterxml.jackson.core:jackson-databind"],
     ["jackson-core", "org.other:jackson-databind", "com.fasterxml.jackson.core"]),
    ("npm", "@babel/core", ["@babel/core"], ["core", "babel-core", "@babel/Core"]),
    ("go", "golang.org/x/net", ["golang.org/x/net"], ["net", "golang.org/x/net/html"]),
]


@pytest.mark.parametrize("eco,canon,yes,no", TABLE)
def test_same_and_resolve(eco, canon, yes, no):
    for n in yes:
        assert names.same(n, canon, eco), n
        assert names.resolve(n + "@1.0", [canon, "other"], eco) == canon, n
    for n in no:
        assert not names.same(n, canon, eco), n
        assert names.resolve(n, [canon], eco) != canon, n


@pytest.mark.parametrize("eco,canon,yes,no", TABLE)
def test_citations_and_steps(eco, canon, yes, no):
    spec = f"{canon}@1.2.3"
    for n in yes:
        assert names.cited_in(f"{n}@1.2.3/src/a.x", spec, eco) == "src/a.x", n
        assert names.steps_in([f"{n}@1.2.3/src/a.x:4"], canon, eco), n
    for n in no:
        assert names.cited_in(f"{n}@1.2.3/src/a.x", spec, eco) is None, n
    assert names.cited_in(f"{canon}@9.9.9/src/a.x", spec, eco) is None          # another version


def test_specs_with_scopes_and_paths():
    assert names.split_spec("@babel/core@7.0.0") == ("@babel/core", "7.0.0")
    assert names.split_spec("golang.org/x/net@v0.1.0") == ("golang.org/x/net", "v0.1.0")
    assert names.split_spec("g:a@1") == ("g:a", "1") and names.split_spec("plain") == ("plain", "")
    assert names.bare("jackson-databind@2.17.1") == "jackson-databind"
    # a spec string alone says Maven by its colon
    assert names.same("jackson-databind", "com.fasterxml.jackson.core:jackson-databind")


def test_judges_use_it(tmp_path):
    # the boundaries that compared names their own way now go through `names`
    from doublestrain.judges.claude_code import _in_target, check_trace
    from doublestrain.judges.split import _bare, _steps_in
    d = tmp_path / "s"
    (d / "yaml").mkdir(parents=True)
    (d / "yaml/loader.py").write_text("def load(stream, Loader=None):\n    return x\n")
    ok, bad = check_trace([{"path": "PyYAML@6.0/yaml/loader.py", "line": 1, "quote": "def load(stream, Loader=None):"}],
                          [("pyyaml@6.0", d)], "pyyaml", "pypi")
    assert ok == ["pyyaml@6.0/yaml/loader.py:1"] and not bad
    assert _in_target(ok, "PyYAML", "pypi") and _steps_in(ok, "pyyaml", "pypi")
    assert _bare("jackson-databind@2.17.1", ["com.fasterxml.jackson.core:jackson-databind@2.17.1"], "maven") \
        == "com.fasterxml.jackson.core:jackson-databind"
    assert _bare("PyYAML@6.0", ["pyyaml@6.0"], "pypi") == "pyyaml"

"""shape tier: deterministic call-shape extraction, and what leaves the machine."""
import json
import stat
import sys
from pathlib import Path

import pytest

from ssvc_triage.judges import ReachQuery, Verdict, get_judge
from ssvc_triage.judges.shape import ShapeJudge, extract_shapes, tokenize

SECRET = "sk_live_9f8e7d6c5b4a3210"

SERVER = f"""\
// TODO: rotate {SECRET}
const express = require('express');
const bp = require("body-parser");
const {{ static: serve }} = require('express');
const app = express();
const opts = {{ extended: true, limit: 1000 }};
const re = /['"`(]/g;
app.use(bp.urlencoded(opts));
app.use(bp.json({{ strict: false, type: 'application/json', verify: (req, res, buf) => {{ check('{SECRET}'); }} }}));
app.use('/static', serve(__dirname + '/public', {{ dotfiles: 'allow' }}));
app.get('/download/:name', function (req, res) {{
  const internalName = lookupCustomer(req.params.name);
  res.sendFile(req.params.name, {{ root: __dirname, headers: {{ 'x-key': '{SECRET}' }} }});
}});
app.post('/x', (req, res) => {{ let xml; xml = req.body.doc; dom = require('express').Router; new dom().parseFromString(xml); }});
app.listen(process.env.PORT);
"""

ESM = """\
import express, { Router } from 'express';
import * as bodyParser from 'body-parser';
const r = Router();
r.use(bodyParser.text({ type: `${base}/*` }));
"""


@pytest.fixture
def app(tmp_path):
    repo = tmp_path / "customer-portal"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "server.js").write_text(SERVER)
    (repo / "src" / "esm.mjs").write_text(ESM)
    (repo / "test").mkdir()
    (repo / "test" / "t.test.js").write_text("const bp = require('body-parser');\nbp.raw();\n")
    (repo / "node_modules" / "body-parser").mkdir(parents=True)
    (repo / "node_modules" / "body-parser" / "index.js").write_text("module.exports = require('body-parser')()\n")
    return repo


def _payload(app, **kw):
    sh = extract_shapes(str(app), ["body-parser", "express"], ["sendFile", "static"], target="body-parser", **kw)
    return sh, sh.payload()


def test_shapes_capture_calls_options_and_input_markers(app):
    sh, text = _payload(app)
    calls = [s["call"] for s in sh.shapes]
    # const opts resolved; a package call passed to another is shown inline, once
    assert "express().use(body-parser.urlencoded({extended: true, limit: 1000}))" in calls
    assert 'express().use(body-parser.json({strict: false, type: "application/json", verify: <fn>}))' in calls
    assert 'express().use("<str>", express.static(<expr>, {dotfiles: "allow"}))' in calls  # destructured alias
    assert not any(c.startswith("body-parser.urlencoded") for c in calls)
    assert ('res.sendFile(<request.params>, {root: <dirname>, headers: {<key>: "<str>"}})' in calls)
    assert 'express.Router().use(body-parser.text({type: <template>}))' in calls     # ES modules
    assert "express().listen(<env>)" in calls
    # plain assignment, `new`, a chained call, and one level of request taint
    assert "new express.Router().parseFromString(<var from request.body>)" in calls
    by_call = {s["call"]: s for s in sh.shapes}
    assert by_call['res.sendFile(<request.params>, {root: <dirname>, headers: {<key>: "<str>"}})']["ctx"] \
        == 'in fn passed to express().get'
    assert by_call["body-parser.raw()"]["test"] is True
    assert all("body-parser" in s["call"] for s in sh.shapes[:4])                   # target first
    assert sh.imports == {"body-parser": 3, "express": 2}


def test_nothing_but_shapes_leaves(app):
    _, text = _payload(app)
    for leaked in (SECRET, "rotate", "customer", "server.js", "esm.mjs", "lookupCustomer", "internalName",
                   "/download", "/public", "check(", "opts", "bp.", "x-key", "PORT"):
        assert leaked not in text, leaked
    assert ":7" not in text and "line" not in text


def test_strings_can_be_fully_redacted(app, monkeypatch):
    monkeypatch.setenv("SSVC_SHAPE_STRINGS", "none")
    _, text = _payload(app)
    assert '"application/json"' not in text and '"allow"' not in text and '"<str>"' in text


def test_tokenizer_survives_regex_templates_and_comments():
    toks = tokenize("const re = /[)'\"]/g; /* ( */ x(`a${f(`b`)}c`, 'it\\'s') // )\n y()")
    vals = [t.val for t in toks if t.kind in ("id", "p")]
    assert vals == ["const", "re", "=", ";", "x", "(", ",", ")", "y", "(", ")"]
    assert [t.kind for t in toks if t.kind not in ("id", "p")] == ["re", "tpl", "str"]


def test_truncation_is_reported(app, monkeypatch):
    from ssvc_triage.judges import shape
    monkeypatch.setattr(shape, "SHAPE_MAX", 2)
    sh, text = _payload(app)
    assert sh.truncated and len(sh.shapes) == 2 and "NOT complete" in text


# --- the judge ---------------------------------------------------------------------

def _seq_claude(tmp_path, payloads) -> str:
    script, state = tmp_path / "claude-seq", tmp_path / "calls.json"
    state.write_text("[]")
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"calls = json.load(open({str(state)!r}))\n"
        "calls.append({'argv': sys.argv[1:], 'stdin': sys.stdin.read(), 'cwd': os.getcwd()})\n"
        f"json.dump(calls, open({str(state)!r}, 'w'))\n"
        f"payloads = {payloads!r}\n"
        "print(json.dumps({'type': 'result', 'total_cost_usd': 0.01, 'structured_output': payloads[len(calls) - 1]}))\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.fixture
def dep_src(tmp_path, monkeypatch):
    from ssvc_triage import pkgsrc
    d = tmp_path / "pkgsrc" / "body-parser@1.18.2-abc"
    (d / "lib").mkdir(parents=True)
    (d / "lib" / "urlencoded.js").write_text("function urlencoded(opts) {\n  var extended = opts.extended;\n"
                                             "  return extended ? qs.parse(body) : querystring.parse(body);\n}\n")
    monkeypatch.setattr(pkgsrc, "for_query", lambda repo, dep, ver: ([("body-parser@1.18.2", d)], []))
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "spec-cache"))
    return d


SPEC = {"triggers": [{"package": "body-parser@1.18.2", "entry": "bodyParser.urlencoded(options)",
                      "condition": "extended: true", "input": "urlencoded request body",
                      "trace": [{"path": "body-parser@1.18.2/lib/urlencoded.js", "line": 3,
                                 "quote": "return extended ? qs.parse(body)"}]}],
        "not_triggerable": False, "confidence": 0.9, "rationale": "qs only when extended"}


def _q(repo):
    return ReachQuery(repo_path=str(repo), ecosystem="npm", dependency="body-parser", version="1.18.2",
                      cve="CVE-2026-00001", vuln_symbols=())


def test_shape_judge_sends_shapes_not_source(app, tmp_path, monkeypatch, dep_src):
    sid = next(s["id"] for s in _payload(app)[0].shapes if "urlencoded" in s["call"])
    verdict = {"verdict": "reachable", "confidence": 0.9, "rationale": "extended", "evidence": [sid]}
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [SPEC, verdict]))
    r = ShapeJudge().judge(_q(app))
    spec_call, shape_call = json.loads((tmp_path / "calls.json").read_text())
    for c in (spec_call, shape_call):
        assert Path(c["cwd"]).resolve() == dep_src.resolve() and "--restricted" in c["argv"]
        assert str(app) not in json.dumps(c) and SECRET not in c["stdin"]
    assert "body-parser.urlencoded({extended: true, limit: 1000})" in shape_call["stdin"]
    assert "condition: extended: true" in shape_call["stdin"]
    assert r.source == "shape:opus" and r.verdict == Verdict.REACHABLE and r.cost_usd == pytest.approx(0.02)
    assert r.evidence[0].startswith(f"{sid} = src/server.js:8")                # local mapping, kept local


def test_shape_not_reachable_needs_complete_list(app, tmp_path, monkeypatch, dep_src):
    from ssvc_triage.judges import shape
    monkeypatch.setattr(shape, "SHAPE_MAX", 1)
    nr = {"verdict": "not_reachable", "confidence": 0.95, "rationale": "r", "evidence": []}
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [SPEC, nr]))
    r = ShapeJudge().judge(_q(app))
    assert r.verdict == Verdict.UNSURE and "truncated" in r.rationale


def test_egress_shape_mode():
    assert get_judge("cascade:local,split,shape", cache=False, egress="shape")
    for mode in ("machine", "network"):
        with pytest.raises(ValueError, match="shape"):
            get_judge("cascade:local,shape", cache=False, egress=mode)
    with pytest.raises(ValueError, match="claude"):
        get_judge("cascade:local,shape,claude", cache=False, egress="shape")
    assert get_judge("cascade:jev,local,shape,claude", cache=False, egress="any")


# --- taint through functions and modules -------------------------------------------

def _repo(tmp_path, files):
    repo = tmp_path / "repo"
    for rel, src in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(src)
    return repo


def _calls(repo):
    return [s["call"] for s in extract_shapes(str(repo), ["@xmldom/xmldom", "xml2js", "express"],
                                              ["parseFromString"]).shapes]


def test_taint_through_a_helper_in_the_same_file(tmp_path):
    repo = _repo(tmp_path, {"app.js": """
const { DOMParser } = require('@xmldom/xmldom');
const app = require('express')();
function parseXml(s, opts) { const x = s.trim(); return new DOMParser().parseFromString(x, opts); }
function fixed() { return parseXml('<a/>', 'text/xml'); }
app.post('/a', (req, res) => res.send(parseXml(req.body.xml, 'text/xml')));
"""})
    assert "new @xmldom/xmldom.DOMParser().parseFromString(<var from literal, request.body>, <var from literal>)" in _calls(repo)


def test_taint_across_modules_and_renamed_handler_params(tmp_path):
    repo = _repo(tmp_path, {
        "lib/xml.js": """
const xml2js = require('xml2js');
exports.parse = function (input) { return xml2js.parseStringPromise(input); };
module.exports.unused = (z) => xml2js.parseStringPromise(z);
""",
        "routes/index.js": """
const express = require('express');
const util = require('../lib/xml');
const router = express.Router();
router.post('/b', async (r, s) => { s.json(await util.parse(r.query.q)); });
module.exports = router;
""",
        "test/xml.test.js": "const { unused } = require('../lib/xml');\nunused(req.body);\n"})
    calls = _calls(repo)
    assert "xml2js.parseStringPromise(<var from request.query>)" in calls
    assert "xml2js.parseStringPromise(<var>)" in calls          # only a test pushes into `unused`


def test_controller_passed_to_a_router_gets_the_request(tmp_path):
    repo = _repo(tmp_path, {
        "controllers/notes.js": """
const dom = require('@xmldom/xmldom').DOMParser;
module.exports = {
  create: function (rq, rs) { const doc = new dom().parseFromString(rq.body.note); rs.send(doc); },
  list(rq, rs) { return new dom().parseFromString(rq); },
};
""",
        "routes.mjs": """
import express from 'express';
import ctl from './controllers/notes.js';
const app = express();
app.post('/notes', ctl.create);
"""})
    calls = _calls(repo)
    assert "new @xmldom/xmldom.DOMParser().parseFromString(<request.body>)" in calls
    assert "new @xmldom/xmldom.DOMParser().parseFromString(<var>)" in calls       # list: not routed


def test_local_requires_never_leave_the_repo(tmp_path):
    repo = _repo(tmp_path, {"a.js": "const x = require('../../outside');\nx.run(req.body);\n"})
    (tmp_path / "outside.js").write_text("exports.run = function (v) { require('xml2js').parseString(v); };\n")
    assert _calls(repo) == []


def test_sources_file_env_and_other(tmp_path):
    repo = _repo(tmp_path, {"a.js": """
const fs = require('fs'), path = require('path');
const { DOMParser } = require('@xmldom/xmldom');
let cfg = fs.readFileSync(path.join(__dirname, 'c.xml'), 'utf8');
cfg = cfg.replace(/\\s+/g, ' ');
new DOMParser().parseFromString(cfg);
new DOMParser().parseFromString(fs.readFileSync(req.query.f));
let mixed = cfg;
if (process.env.X) mixed = somethingElse();
new DOMParser().parseFromString(mixed);
new DOMParser().parseFromString(somethingElse());
"""})
    calls = _calls(repo)
    assert "new @xmldom/xmldom.DOMParser().parseFromString(<var from file>)" in calls
    assert "new @xmldom/xmldom.DOMParser().parseFromString(<call on file, request.query>)" in calls
    assert "new @xmldom/xmldom.DOMParser().parseFromString(<var from file, other>)" in calls
    assert "new @xmldom/xmldom.DOMParser().parseFromString(<call>)" in calls


# --- refusals: never an answer; fall back, else no claim ---------------------------

RESOLVE = {"opus": "claude-opus-5-5", "sonnet": "claude-sonnet-5-5", "claude-opus-4-1": "claude-opus-5-5"}


def _model_claude(tmp_path, by_model) -> str:
    """Fake claude answering per --model. A value is a structured answer, or
    {"_env": {...}} for a raw envelope (a refusal), or a list consumed in order."""
    script, state = tmp_path / "claude-models", tmp_path / "calls.json"
    state.write_text("[]")
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"calls = json.load(open({str(state)!r}))\n"
        "model = sys.argv[sys.argv.index('--model') + 1]\n"
        "calls.append({'model': model, 'stdin': sys.stdin.read()})\n"
        f"json.dump(calls, open({str(state)!r}, 'w'))\n"
        f"by_model = {by_model!r}\n"
        "a = by_model[model]\n"
        "if isinstance(a, list): a = a[sum(c['model'] == model for c in calls) - 1]\n"
        "env = {'type': 'result', 'total_cost_usd': 0.01, 'is_error': False, 'stop_reason': 'end_turn',\n"
        f"       'safety_stops': 0, 'modelUsage': {{{RESOLVE!r}.get(model, model): {{}}}}}}\n"
        "env.update(a['_env'] if '_env' in a else {'structured_output': a, 'result': ''})\n"
        "print(json.dumps(env))\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


NR = {"verdict": "not_reachable", "confidence": 0.95, "rationale": "no trigger", "evidence": []}
REFUSALS = [
    {"_env": {"stop_reason": "refusal", "result": ""}},
    {"_env": {"safety_stops": 1, "result": ""}},
    {"_env": {"is_error": True, "result": "API Error: Claude Code is unable to respond to this request, "
                                          "which appears to violate our Usage Policy"}},
    {"_env": {"result": "I can't help with analysing exploitability of this vulnerability."}},
]


@pytest.mark.parametrize("refuse", REFUSALS)
def test_opus_refusal_falls_back_to_the_4_6_generation_and_says_so(app, tmp_path, monkeypatch, dep_src, refuse):
    from ssvc_triage.judges import claude_code
    monkeypatch.setattr(claude_code, "SPEND", {"usd": 0.0, "calls": 0, "over_budget": 0, "refusals": 0})
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _model_claude(
        tmp_path, {"sonnet": [SPEC], "opus": refuse, "claude-opus-4-6": NR}))
    r = ShapeJudge().judge(_q(app))
    calls = [c["model"] for c in json.loads((tmp_path / "calls.json").read_text())]
    assert calls == ["sonnet", "opus", "claude-opus-4-6"]   # same line, older generation; never sonnet
    assert r.verdict == Verdict.NOT_REACHABLE and "opus refused" in r.rationale
    assert "answered by claude-opus-4-6" in r.rationale and r.cost_usd == pytest.approx(0.03)
    assert r.source == "shape:claude-opus-4-6"
    assert claude_code.SPEND["refusals"] == 1


def test_refusal_by_every_model_is_no_claim(app, tmp_path, monkeypatch, dep_src):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _model_claude(
        tmp_path, {"sonnet": [SPEC], "opus": REFUSALS[2], "claude-opus-4-6": REFUSALS[0]}))
    assert ShapeJudge().judge(_q(app)) is None


def test_fallback_alias_resolving_to_the_refuser_is_not_an_answer(app, tmp_path, monkeypatch, dep_src):
    """claude-opus-4-1 was seen to resolve to claude-opus-5-5: not a different model."""
    monkeypatch.setenv("SSVC_SHAPE_FALLBACK", "claude-opus-4-1")
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _model_claude(
        tmp_path, {"sonnet": [SPEC], "opus": REFUSALS[0], "claude-opus-4-1": NR}))
    assert ShapeJudge().judge(_q(app)) is None


def test_spec_refusal_falls_back_too(app, tmp_path, monkeypatch, dep_src):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _model_claude(
        tmp_path, {"sonnet": REFUSALS[0], "claude-sonnet-4-6": [SPEC], "opus": NR}))
    r = ShapeJudge().judge(_q(app))
    assert [c["model"] for c in json.loads((tmp_path / "calls.json").read_text())] == \
        ["sonnet", "claude-sonnet-4-6", "opus"]
    assert r.verdict == Verdict.NOT_REACHABLE


def test_a_refusal_is_never_cached_as_an_answer(app, tmp_path, monkeypatch, dep_src):
    from ssvc_triage.judges import CachedJudge
    monkeypatch.setenv("SSVC_JUDGE_CACHE", str(tmp_path / "jc"))
    monkeypatch.setenv("SSVC_SHAPE_FALLBACK", "")
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _model_claude(tmp_path, {"sonnet": [SPEC], "opus": [REFUSALS[0], NR]}))
    j = CachedJudge(ShapeJudge())
    assert j.judge(_q(app)) is None                       # refused, no fallback: no claim
    assert j.judge(_q(app)).verdict == Verdict.NOT_REACHABLE   # asked again, not served a refusal


def test_ordinary_errors_do_not_fall_back(app, tmp_path, monkeypatch, dep_src):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _model_claude(
        tmp_path, {"sonnet": [SPEC], "claude-opus-4-6": NR, "opus": {"_env": {"is_error": True, "result": "overloaded"}}}))
    assert ShapeJudge().judge(_q(app)) is None
    assert [c["model"] for c in json.loads((tmp_path / "calls.json").read_text())] == ["sonnet", "opus"]


def test_shape_model_is_separate_from_spec_model(monkeypatch):
    monkeypatch.setenv("SSVC_SHAPE_MODEL", "claude-opus-5-5")
    j = ShapeJudge()
    assert j.model == "claude-opus-5-5" and j.spec_model == "sonnet"
    assert j.fallback == ("claude-opus-4-6",) and j.spec_fallback == ("claude-sonnet-4-6",)
    assert "shape@claude-opus-5-5@specsonnet@" in j.fingerprint()     # fallback not in the key
    monkeypatch.setenv("SSVC_SHAPE_FALLBACK", "")
    assert ShapeJudge().fallback == ()


def test_shape_floor_follows_the_model_that_answered(app, tmp_path, monkeypatch, dep_src):
    from ssvc_triage.judges import JudgeResult, accept
    nr = lambda src, c: JudgeResult(Verdict.NOT_REACHABLE, c, src)      # noqa: E731
    assert accept(nr("shape:claude-opus-5-5", 0.85)) and not accept(nr("shape:claude-opus-5-5", 0.8))
    assert not accept(nr("shape:claude-sonnet-5-5", 0.85)) and accept(nr("shape:claude-sonnet-5-5", 0.9))
    assert not accept(nr("shape:opus", 0.85))                       # unresolved alias: default floor
    assert not accept(JudgeResult(Verdict.REACHABLE, 1.0, "shape:claude-opus-5-5"))   # never reachable
    monkeypatch.setenv("SSVC_FLOOR_SHAPE_NOT_REACHABLE", "0.95")
    assert not accept(nr("shape:claude-opus-5-5", 0.9))                               # env still wins
    # an Opus 5.5 refusal answered by Opus 4.6 is held to the default floor (uncalibrated)
    monkeypatch.delenv("SSVC_FLOOR_SHAPE_NOT_REACHABLE")
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _model_claude(
        tmp_path, {"sonnet": [SPEC], "opus": REFUSALS[0], "claude-opus-4-6": {**NR, "confidence": 0.85}}))
    r = ShapeJudge().judge(_q(app))
    assert r.source == "shape:claude-opus-4-6" and not accept(r)


# --- exposures and templates ---------------------------------------------------------
def test_package_exposed_to_templates_and_called_there(tmp_path):
    repo = _repo(tmp_path, {
        "app.js": """
const marked = require('marked');
const express = require('express');
const { Router } = require('express');                 // destructuring: not an exposure
const app = express();
marked.setOptions({ sanitize: true });
app.locals.marked = marked;
app.engine('ejs', require('ejs-locals'));
module.exports = app;                                   // the module object: not a name
""",
        "views/index.ejs": "<ul><% todos.forEach(function (t) { %>\n<li><%- marked(new String(t.content)) %></li>"
                           "\n<li><%= marked(t.title, { gfm: true }) %></li><% }) %></ul>",
        "views/a.hbs": "<div>{{{marked body}}}</div>",
        "views/unused.ejs": "<p>no calls here</p>"})
    sh = extract_shapes(str(repo), ["marked", "express", "ejs-locals"], ["parse"], target="marked")
    calls = {(s["call"], s["ctx"]) for s in sh.shapes}
    assert ("app.locals.marked = marked", "exposes 'marked'") in calls
    assert ("marked(<template data>)", "in template (ejs, raw output); marked = marked") in calls
    assert ("marked(<template data>, {gfm: true})", "in template (ejs, escaped output); marked = marked") in calls
    assert ("marked(<template data>)", "in template (hbs helper, raw output); marked = marked") in calls
    text = sh.payload()
    assert "exports" not in text and "Router =" not in text
    assert "index.ejs" not in text and "todos" not in text and "content" not in text   # pseudonyms, no names


def test_exposure_without_a_sink_shows_only_when_called(tmp_path):
    repo = _repo(tmp_path, {"app.js": "const md = require('markdown-it')();\nconst helpers = { render: md };\n",
                            "views/x.njk": "{{ nothing }}"})
    assert extract_shapes(str(repo), ["markdown-it"], [], target="markdown-it").shapes == [] or \
        not any("exposes" in s["ctx"] for s in extract_shapes(str(repo), ["markdown-it"], []).shapes)
    (repo / "views" / "x.njk").write_text("{{ render(page.body) | safe }}")
    sh = extract_shapes(str(repo), ["markdown-it"], [])
    assert {s["call"] for s in sh.shapes} >= {"{render: …} = markdown-it()", "render(<template data>)"}


def test_reassigned_variable_is_not_shown_as_its_first_literal(tmp_path):
    # express-mongoose-demo: `let log = 'dev'; if (prod) log = {stream}; app.use(morgan(log))`
    (tmp_path / "node_modules" / "morgan").mkdir(parents=True)
    (tmp_path / "node_modules" / "morgan" / "index.js").write_text("module.exports = function () {}\n")
    (tmp_path / "app.js").write_text(
        "const morgan = require('morgan');\nconst fmt = 'tiny';\nlet log = 'dev';\n"
        "if (env !== 'development') {\n  log = { stream: s };\n}\napp.use(morgan(log));\n"
        "let n = 'a';\nn += 'b';\napp.use(morgan(n));\napp.use(morgan(fmt));\n")
    calls = [s["call"] for s in extract_shapes(str(tmp_path), ["morgan"], [], target="morgan").shapes]
    text = " ".join(calls)
    assert calls == ["morgan(<var from literal, other>)", "morgan(<var from literal>)", 'morgan("tiny")']

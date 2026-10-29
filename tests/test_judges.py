"""Judge layer tests — offline: a fake Jev HTTP server and a fake `claude` binary."""
import json
import math
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from doublestrain.judges import (CachedJudge, CascadeJudge, ClaudeCodeJudge, JevJudge,
                                JudgeResult, ReachQuery, Verdict, accept, get_judge)
from doublestrain.judges.usage import usage_summary
from doublestrain.reach import resolve_reachability
from doublestrain.ssvc import Candidate, Decision, Reachability, grade


@pytest.fixture
def app(tmp_path):
    repo = tmp_path / "app"
    (repo / "src").mkdir(parents=True)
    (repo / "src/a.js").write_text("const _ = require('lodash');\nmodule.exports = (o) => _.merge({}, o);\n")
    (repo / "src/b.js").write_text("// mentions template in a comment only\n")
    (repo / "node_modules/lodash").mkdir(parents=True)
    (repo / "node_modules/lodash/template.js").write_text("function template() {}\n")
    return repo


def _q(repo, **kw):
    return ReachQuery(repo_path=str(repo), ecosystem="npm", dependency="lodash",
                      cve="CVE-2021-23337", vuln_symbols=("_.template",), **kw)


class _Fixed:
    def __init__(self, name, result):
        self.name, self.result, self.calls = name, result, 0

    def fingerprint(self):
        return self.name

    def judge(self, q):
        self.calls += 1
        return self.result


# --- usage pre-pass -----------------------------------------------------------

def test_usage_summary_finds_imports_and_skips_node_modules(app):
    u = usage_summary(str(app), "npm", "lodash", ["_.template"])
    assert u.import_sites == ["src/a.js:1: const _ = require('lodash');"]
    assert all("node_modules" not in s for s in u.symbol_sites)
    assert "template" in u.text and "direct import sites (1)" in u.text


def test_usage_summary_pypi_import_name(tmp_path):
    (tmp_path / "m.py").write_text("import yaml\nx = yaml.safe_load(s)\n")
    u = usage_summary(str(tmp_path), "pypi", "PyYAML", ["yaml.full_load"], import_name="yaml")
    assert len(u.import_sites) == 1


def test_usage_summary_flags_possible_transitive(tmp_path):
    (tmp_path / "s.js").write_text("const express = require('express');\n")
    u = usage_summary(str(tmp_path), "npm", "path-to-regexp")
    assert "NOT imported directly" in u.text and "transitive" in u.text


# --- asymmetric acceptance ----------------------------------------------------

@pytest.mark.parametrize("verdict,conf,ok", [
    (Verdict.REACHABLE, 1.0, False),       # summary-only `reachable` always escalates
    (Verdict.NOT_REACHABLE, 0.6, False),   # a weak "not reachable" must not suppress
    (Verdict.NOT_REACHABLE, 0.95, True),
    (Verdict.UNSURE, 1.0, False),
])
def test_accept_is_asymmetric_for_jev(verdict, conf, ok):
    assert accept(JudgeResult(verdict, conf, "jev")) is ok


def test_floor_env_override(monkeypatch):
    monkeypatch.setenv("SSVC_FLOOR_JEV_NOT_REACHABLE", "0.5")
    assert accept(JudgeResult(Verdict.NOT_REACHABLE, 0.6, "jev"))


# --- cascade ------------------------------------------------------------------

def test_cascade_escalates_low_margin_and_keeps_trail(app):
    jev = _Fixed("jev", JudgeResult(Verdict.NOT_REACHABLE, 0.4, "jev"))
    cl = _Fixed("claude", JudgeResult(Verdict.REACHABLE, 0.9, "claude"))
    r = CascadeJudge([jev, cl]).judge(_q(app))
    assert r.source == "claude" and r.verdict == Verdict.REACHABLE
    assert r.trail[0]["source"] == "jev" and r.trail[0]["verdict"] == "not_reachable"


def test_cascade_stops_at_first_accepted(app):
    jev = _Fixed("jev", JudgeResult(Verdict.NOT_REACHABLE, 0.99, "jev"))
    cl = _Fixed("claude", JudgeResult(Verdict.REACHABLE, 0.9, "claude"))
    assert CascadeJudge([jev, cl]).judge(_q(app)).source == "jev"
    assert cl.calls == 0


def test_cascade_escalates_summary_tier_reachable(app):
    jev = _Fixed("jev", JudgeResult(Verdict.REACHABLE, 0.99, "jev"))
    cl = _Fixed("claude", JudgeResult(Verdict.REACHABLE, 0.9, "claude"))
    assert CascadeJudge([jev, cl]).judge(_q(app)).source == "claude"
    assert cl.calls == 1


def test_cascade_unavailable_tier_falls_through(app):
    cl = _Fixed("claude", JudgeResult(Verdict.NOT_REACHABLE, 0.9, "claude"))
    r = CascadeJudge([_Fixed("jev", None), cl]).judge(_q(app))
    assert r.source == "claude" and r.trail[0]["note"] == "unavailable"


def test_cache_round_trip(app, tmp_path):
    inner = _Fixed("jev", JudgeResult(Verdict.REACHABLE, 0.8, "jev", evidence=["a:1"]))
    cj = CachedJudge(inner, cache_dir=str(tmp_path / "cache"))
    first, second = cj.judge(_q(app)), cj.judge(_q(app))
    assert inner.calls == 1 and second.cached and second.evidence == ["a:1"] and not first.cached


# --- resolve: facts in, never the decision ------------------------------------

def _cand(**kw):
    base = dict(repo="local/app", pr_number=1, bumped_package="lodash", ecosystem="npm",
                advisories=[(["CVE-2021-23337"], ["lodash"])], exposure_class="public-internet",
                vuln_symbols=["_.template"])
    base.update(kw)
    return Candidate(**base)


def test_accepted_not_reachable_demotes_act(app):
    c = _cand()
    em = {"CVE-2021-23337": {"epss": 0.02}}
    assert grade(c, enrichment_map={"CVE-2021-23337": {"epss": 0.5}}).decision == Decision.ACT
    resolve_reachability(c, _Fixed("jev", JudgeResult(Verdict.NOT_REACHABLE, 1.0, "jev")),
                         str(app), "CVE-2021-23337")
    assert c.reachability == Reachability.UNREACHABLE and c.reach_source == "jev"
    g = grade(c, enrichment_map=em)
    assert g.decision == Decision.TRACK and "jev" in g.reason


def test_rejected_verdict_leaves_unavailable(app):
    c = _cand()
    r = resolve_reachability(c, _Fixed("jev", JudgeResult(Verdict.NOT_REACHABLE, 0.5, "jev")),
                             str(app), "CVE-2021-23337")
    assert r.verdict == Verdict.NOT_REACHABLE           # returned for the audit log...
    assert c.reachability == Reachability.UNAVAILABLE   # ...but not applied


def test_deterministic_signal_never_overridden(app):
    c = _cand(is_go=True, reachability=Reachability.REACHABLE, reach_source="govulncheck")
    j = _Fixed("jev", JudgeResult(Verdict.NOT_REACHABLE, 1.0, "jev"))
    assert resolve_reachability(c, j, str(app)) is None and j.calls == 0
    assert c.reachability == Reachability.REACHABLE


# --- Jev backend (fake HTTP server) ---------------------------------------------

@pytest.fixture
def fake_jev(monkeypatch):
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, self.headers.get("Authorization"), body))
            out = {"answers": {"reachability": {"choice": "not_reachable", "confidence": 0.97}}}
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("TYPESAFE_BASE_URL", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-key")
    yield seen
    srv.shutdown()


def test_jev_judge_posts_bounded_choice(app, fake_jev):
    r = JevJudge().judge(_q(app))
    assert r.verdict == Verdict.NOT_REACHABLE and r.confidence == 0.97 and r.source == "jev"
    path, auth, body = fake_jev[0]
    assert path == "/v1/systemone" and auth == "Bearer test-key"
    q = body["questions"]["reachability"]
    assert q["type"] == "choice" and set(q["criteria"]) == {"reachable", "not_reachable", "unsure"}
    assert "require('lodash')" in json.loads(body["state"])["app_usage"]


def test_jev_hosted_without_key_is_unavailable(app, monkeypatch):
    monkeypatch.delenv("TYPESAFE_BASE_URL", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setenv("TYPESAFE_API_KEY_FILE", str(app / "no-such-key"))
    assert JevJudge().judge(_q(app)) is None


def test_jev_key_from_file(app, fake_jev, monkeypatch, tmp_path):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    (tmp_path / "k").write_text("file-key\n")
    monkeypatch.setenv("TYPESAFE_API_KEY_FILE", str(tmp_path / "k"))
    JevJudge().judge(_q(app))
    assert fake_jev[0][1] == "Bearer file-key"


def test_jev_unreachable_server_is_no_claim(app, monkeypatch):
    monkeypatch.setenv("TYPESAFE_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    assert JevJudge(timeout=2).judge(_q(app)) is None


# --- claude-code backend (fake binary) -----------------------------------------

def _fake_claude(tmp_path, payload: dict) -> str:
    log = tmp_path / "argv.json"
    script = tmp_path / "claude"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"json.dump({{'argv': sys.argv[1:], 'cwd': os.getcwd(), 'stdin': sys.stdin.read()}}, open({str(log)!r}, 'w'))\n"
        f"print(json.dumps({payload!r}))\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_claude_judge_read_only_and_structured(app, tmp_path, monkeypatch):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _fake_claude(tmp_path, {
        "type": "result", "is_error": False, "total_cost_usd": 0.012,
        "structured_output": {"verdict": "reachable", "confidence": 0.8,
                              "rationale": "called from a.js", "evidence": ["src/a.js:2"]}}))
    r = ClaudeCodeJudge(model="haiku").judge(_q(app))
    assert r.verdict == Verdict.REACHABLE and r.cost_usd == 0.012 and r.evidence == ["src/a.js:2"]
    call = json.loads((tmp_path / "argv.json").read_text())
    argv = call["argv"]
    assert argv[argv.index("--tools") + 1] == "Read,Grep,Glob"
    assert "--system-prompt-file" in argv and "--json-schema" in argv
    assert Path(call["cwd"]).resolve() == app.resolve()
    assert "CVE-2021-23337" in call["stdin"]
    # file tools confined to the checkout; nothing may prompt; no package source unless asked
    assert "--restricted" in argv and argv[argv.index("--permission-prompts") + 1] == "none"
    assert "--add-dir" not in argv and "Dependency source" not in call["stdin"]


def test_claude_judge_pkgsrc_adds_read_only_dirs(app, tmp_path, monkeypatch):
    from doublestrain import pkgsrc
    from doublestrain.judges import claude_code
    src = tmp_path / "lodash@4.17.20-abc"
    src.mkdir()
    monkeypatch.setattr(pkgsrc, "for_query", lambda repo, dep, ver, **kw: ([("lodash@4.17.20", src)], ["x@1.0.0: refused"]))
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _fake_claude(tmp_path, {
        "type": "result", "structured_output": {"verdict": "unsure", "confidence": 0.5,
                                                "rationale": "", "evidence": []}}))
    off, on = ClaudeCodeJudge(pkgsrc=False), ClaudeCodeJudge(pkgsrc=True)
    assert on.fingerprint() == off.fingerprint() + f"@src{claude_code.PKGSRC_ID}"
    on.judge(_q(app))
    call = json.loads((tmp_path / "argv.json").read_text())
    argv = call["argv"]
    assert argv[argv.index("--add-dir") + 1] == str(src) and "--restricted" in argv
    assert f"lodash@4.17.20: {src}" in call["stdin"] and "x@1.0.0: refused" in call["stdin"]


def test_claude_judge_picks_opus_for_pypi_rows(app, tmp_path, monkeypatch):
    # opus for pypi by default (py3-py5b: no false NR where sonnet left one); an explicit
    # SSVC_CLAUDE_MODEL applies everywhere, SSVC_CLAUDE_MODEL_PYPI wins for pypi
    monkeypatch.delenv("SSVC_CLAUDE_MODEL", raising=False)
    monkeypatch.delenv("SSVC_CLAUDE_MODEL_PYPI", raising=False)
    js = _q(app)
    py = ReachQuery(str(app), "pypi", "django", "CVE-1", version="1.0")
    j = ClaudeCodeJudge(pkgsrc=False)
    assert (j.model_for(py), j.model_for(js)) == ("opus", "sonnet")
    c = CachedJudge(j, cache_dir=str(tmp_path / "c"))
    assert c._path(py).parent.name.startswith("claude@opus@") and c._path(js).parent.name.startswith("claude@sonnet@")
    monkeypatch.setenv("SSVC_CLAUDE_MODEL", "sonnet")
    assert ClaudeCodeJudge().model_for(py) == "sonnet"
    monkeypatch.setenv("SSVC_CLAUDE_MODEL_PYPI", "haiku")
    assert (ClaudeCodeJudge().model_for(py), ClaudeCodeJudge().model_for(js)) == ("haiku", "sonnet")
    monkeypatch.delenv("SSVC_CLAUDE_MODEL")
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _fake_claude(tmp_path, {
        "type": "result", "structured_output": {"verdict": "unsure", "confidence": 0.5, "rationale": "", "evidence": []}}))
    ClaudeCodeJudge(pkgsrc=False).judge(py)
    argv = json.loads((tmp_path / "argv.json").read_text())["argv"]
    assert argv[argv.index("--model") + 1] == "haiku"


def test_claude_judge_error_is_no_claim(app, tmp_path, monkeypatch):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _fake_claude(tmp_path, {"type": "result", "is_error": True, "result": "rate limited"}))
    assert ClaudeCodeJudge().judge(_q(app)) is None


def test_get_judge_specs():
    assert get_judge("null").name == "null"
    assert get_judge("cascade").name == "cascade:jev,claude"
    assert get_judge("cascade:claude", cache=False).name == "cascade:claude"
    with pytest.raises(ValueError):
        get_judge("gpt")


# --- local inference backend (fake OpenAI-compatible server) -------------------

@pytest.fixture
def fake_local(monkeypatch):
    seen = []
    reply = {"content": json.dumps({"verdict": "not_reachable", "confidence": 0.92,
                                    "rationale": "only merge", "evidence": ["src/a.js:2"]})}

    class H(BaseHTTPRequestHandler):
        def _send(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            seen.append(("GET", self.path, None))
            self._send({"data": [{"id": "qwen-test"}]})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(("POST", self.path, body))
            self._send({"choices": [{"message": reply}]})

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("SSVC_LOCAL_BASE_URL", f"http://127.0.0.1:{srv.server_port}/v1")
    monkeypatch.delenv("SSVC_LOCAL_MODEL", raising=False)
    yield seen, reply
    srv.shutdown()


def test_local_judge_autodetects_model_and_sends_context(app, fake_local):
    from doublestrain.judges import LocalJudge
    seen, _ = fake_local
    r = LocalJudge().judge(_q(app))
    assert r.verdict == Verdict.NOT_REACHABLE and r.confidence == 0.92 and r.source == "local"
    assert seen[0][:2] == ("GET", "/v1/models")
    method, path, body = seen[1]
    assert path == "/v1/chat/completions" and body["model"] == "qwen-test"
    assert body["response_format"]["type"] == "json_schema"
    assert body["reasoning_effort"] == "none"
    user = body["messages"][1]["content"]
    # context pack: numbered source around the import site, not just the grep line
    assert "=== src/a.js" in user and "module.exports = (o) => _.merge" in user
    assert "node_modules" not in user


def test_local_judge_strips_think_and_finds_json(app, fake_local):
    from doublestrain.judges import LocalJudge
    _, reply = fake_local
    reply["content"] = ('<think>hmm {"verdict": "reachable"}</think>Answer: '
                        '{"verdict": "unsure", "confidence": 0.3, "rationale": "", "evidence": []}')
    assert LocalJudge().judge(_q(app)).verdict == Verdict.UNSURE


def test_local_judge_no_server_is_no_claim(app, monkeypatch):
    from doublestrain.judges import LocalJudge
    monkeypatch.setenv("SSVC_LOCAL_BASE_URL", "http://127.0.0.1:9/v1")
    assert LocalJudge(timeout=2).judge(_q(app)) is None


def test_cascade_with_local_tier_spec():
    assert get_judge("cascade:jev,local,claude").name == "cascade:jev,local,claude"


# --- pre-pass v2: open-world detection, renamed imports, test-code tagging ------

def test_usage_dynamic_member_access_is_open_world(tmp_path):
    (tmp_path / "r.js").write_text("const _ = require('lodash');\nmodule.exports = (k) => _[`${k}late`];\n")
    u = usage_summary(str(tmp_path), "npm", "lodash", ["_.template"])
    assert not u.closed_world and "DYNAMIC ACCESS" in u.text


def test_usage_non_literal_require_is_open_world(tmp_path):
    (tmp_path / "p.js").write_text("const cfg = require('./cfg.json');\nconst m = require(cfg.mod);\n")
    u = usage_summary(str(tmp_path), "npm", "js-yaml", ["load"])
    assert u.dynamic_sites == ["p.js:2: const m = require(cfg.mod);"]


def test_usage_pypi_getattr_is_open_world(tmp_path):
    (tmp_path / "m.py").write_text("import yaml\nL = getattr(yaml, NAME)\n")
    assert not usage_summary(str(tmp_path), "pypi", "PyYAML", ["FullLoader"], import_name="yaml").closed_world


def test_usage_plain_code_is_closed_world(app):
    assert usage_summary(str(app), "npm", "lodash", ["_.template"]).closed_world


def test_usage_counts_renamed_destructure_on_import_line(tmp_path):
    (tmp_path / "s.js").write_text("const { template: compile } = require('lodash');\ncompile(x);\n")
    u = usage_summary(str(tmp_path), "npm", "lodash", ["_.template"])
    assert len(u.symbol_sites) == 1 and "template: compile" in u.symbol_sites[0]


def test_usage_tags_test_code(tmp_path):
    (tmp_path / "test").mkdir()
    (tmp_path / "test/f.js").write_text("const _ = require('lodash');\n_.template('x');\n")
    u = usage_summary(str(tmp_path), "npm", "lodash", ["_.template"])
    assert all(s.endswith("(test code)") for s in u.import_sites + u.symbol_sites)


def test_jev_not_reachable_on_open_world_is_downgraded(tmp_path, fake_jev):
    (tmp_path / "r.js").write_text("const _ = require('lodash');\nmodule.exports = (k) => _[k];\n")
    r = JevJudge().judge(_q(tmp_path))       # fake Jev answers not_reachable @ 0.97
    assert r.verdict == Verdict.UNSURE and "open world" in r.rationale
    assert not accept(r)


def test_jev_reachable_on_test_only_evidence_is_downgraded(tmp_path, monkeypatch, fake_jev):
    (tmp_path / "src").mkdir()
    (tmp_path / "test").mkdir()
    (tmp_path / "src/s.js").write_text("const _ = require('lodash');\n_.merge({}, x);\n")
    (tmp_path / "test/f.js").write_text("const _ = require('lodash');\n_.template('t');\n")
    from doublestrain.judges.usage import guard_not_reachable, usage_summary as us
    u = us(str(tmp_path), "npm", "lodash", ["_.template"])
    v, note = guard_not_reachable(Verdict.REACHABLE, u)
    assert v == Verdict.UNSURE and "test code" in note
    # a runtime mention keeps the verdict
    (tmp_path / "src/r.js").write_text("const _ = require('lodash');\n_.template(req.body);\n")
    assert guard_not_reachable(Verdict.REACHABLE, us(str(tmp_path), "npm", "lodash", ["_.template"]))[0] == Verdict.REACHABLE


# --- pre-pass v5: lockfile chains; local-path requires aren't open-world ----------

def test_path_built_local_require_is_not_open_world(tmp_path):
    (tmp_path / "c.js").write_text(
        "const a = require(path.resolve(__dirname + '/env/' + name + '.js'));\n"
        "const b = require(__dirname + '/x');\nconst d = require(`./plugins/${p}`);\n")
    assert usage_summary(str(tmp_path), "npm", "lodash").closed_world
    (tmp_path / "d.js").write_text("const m = require(cfg.parser);\n")
    assert not usage_summary(str(tmp_path), "npm", "lodash").closed_world


def test_require_through_path_join_binding_or_in_a_comment_is_not_open_world(tmp_path):
    (tmp_path / "server.js").write_text(
        "const join = require('path').join;\nconst models = join(__dirname, 'app/models');\n"
        "fs.readdirSync(models).forEach(file => require(join(models, file)));\n")
    (tmp_path / "a.js").write_text("const { resolve: r } = require('node:path');\nmodule.exports = require(r(dir, f));\n")
    (tmp_path / "b.js").write_text("// const imager = require(config.root + '/imager.js');\n")
    assert usage_summary(str(tmp_path), "npm", "lodash").closed_world
    (tmp_path / "c.js").write_text("const join = (a, b) => a + b;\nconst m = require(join(cfg.pkg, ''));\n")
    assert not usage_summary(str(tmp_path), "npm", "lodash").closed_world   # not path's join


@pytest.fixture
def locked_app(tmp_path):
    lock = {"lockfileVersion": 2, "packages": {
        "": {"dependencies": {"express": "^4", "forever": "^2"}, "devDependencies": {"grunt": "^1"}},
        "node_modules/express": {"version": "4.16.4", "dependencies": {"body-parser": "1.18.3", "qs": "6.5.2"}},
        "node_modules/body-parser": {"version": "1.18.3", "dependencies": {"qs": "6.5.2"}},
        "node_modules/qs": {"version": "6.5.2"},
        "node_modules/forever": {"version": "2.0.0", "dependencies": {"minimist": "^1"}},
        "node_modules/minimist": {"version": "1.2.0"},
        "node_modules/grunt": {"version": "1.0.3", "dev": True, "dependencies": {"minimist": "^0.0.8"}},
        "node_modules/grunt/node_modules/minimist": {"version": "0.0.8", "dev": True},
    }}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    (tmp_path / "server.js").write_text("const express = require('express');\nconst app = express();\n")
    return tmp_path


def test_chain_via_runtime_framework(locked_app):
    u = usage_summary(str(locked_app), "npm", "qs", version="6.5.2")
    assert u.chains[0].startswith("app -> express@4.16.4 -> qs@6.5.2")
    assert "top-level `express` imported at (1)" in u.text and "server.js:1" in u.text
    assert u.entry_sites == ["server.js:1: const express = require('express');"]


def test_chain_resolves_nested_copy_and_flags_dev_entry(locked_app):
    u = usage_summary(str(locked_app), "npm", "minimist", version="0.0.8")
    assert u.chains == ["app -> grunt@1.0.3 -> minimist@0.0.8   (top-level devDependency `grunt`)"]
    assert "every chain enters through a devDependency" in u.text
    u2 = usage_summary(str(locked_app), "npm", "minimist", version="1.2.0")
    assert "forever@2.0.0" in u2.chains[0] and "NOT imported by app source" in u2.text


def test_chain_missing_version_and_direct_only(locked_app):
    assert "not found in the package-lock graph" in usage_summary(str(locked_app), "npm", "qs", version="9.9.9").text
    assert usage_summary(str(locked_app), "npm", "express", version="4.16.4").chains == []


def test_copies_note_says_which_copy_the_row_is_about(locked_app, tmp_path, monkeypatch):
    # minimist: 1.2.0 at the top (under forever), 0.0.8 nested under grunt (dev)
    (locked_app / "cli.js").write_text("const minimist = require('minimist');\n")
    u = usage_summary(str(locked_app), "npm", "minimist", version="0.0.8")
    assert "INSTALLED COPIES of minimist (2); this advisory row is about 0.0.8" in u.text
    assert "0.0.8 at node_modules/grunt/node_modules/minimist (dev only)  <- THIS ROW; required by: grunt@1.0.3" in u.text
    assert "loads 1.2.0, NOT 0.0.8: app import sites are evidence only for that other copy" in u.text
    u = usage_summary(str(locked_app), "npm", "minimist", version="1.2.0")
    assert "The app's own imports load this copy (1.2.0)" in u.copies
    assert usage_summary(str(locked_app), "npm", "qs", version="6.5.2").copies == ""   # one version: no note
    # only rows with a note get a new cache key: the others keep their answers
    inner = _Fixed("local", JudgeResult(Verdict.UNSURE, 0.0, "local"))
    inner.fingerprint = lambda: "local@x@prepass8"
    cj = CachedJudge(inner, cache_dir=str(tmp_path / "cache"))
    q = lambda dep, v: ReachQuery(str(locked_app), "npm", dep, "CVE-1", version=v)   # noqa: E731
    assert cj._path(q("qs", "6.5.2")).name == f"{q('qs', '6.5.2').key()}.json"
    assert cj._path(q("minimist", "0.0.8")).name.startswith(q("minimist", "0.0.8").key() + "-c")
    assert cj._path(q("minimist", "0.0.8")) != cj._path(q("minimist", "1.2.0"))


def test_installed_peer_dependency_is_a_chain_edge(tmp_path):
    from doublestrain.judges import depgraph
    lock = {"lockfileVersion": 2, "packages": {
        "": {"dependencies": {"sequelize": "^6", "sqlite3": "^5"}},
        "node_modules/sequelize": {"version": "6.21.3",
                                   "peerDependenciesMeta": {"sqlite3": {"optional": True}, "pg": {"optional": True}}},
        "node_modules/sqlite3": {"version": "5.0.10"},
    }}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    g = depgraph.load(tmp_path)
    assert g.edges["node_modules/sequelize"] == ("node_modules/sqlite3",)    # pg isn't installed
    assert ["node_modules/sequelize", "node_modules/sqlite3"] in depgraph.chains(g, "sqlite3", "5.0.10")


# --- summary-only tiers never settle `reachable` ------------------------------------

@pytest.mark.parametrize("src", ["jev", "local"])
def test_summary_tiers_reachable_escalates(monkeypatch, src):
    monkeypatch.delenv(f"SSVC_FLOOR_{src.upper()}_REACHABLE", raising=False)
    assert not accept(JudgeResult(Verdict.REACHABLE, 1.0, src))
    assert accept(JudgeResult(Verdict.NOT_REACHABLE, 0.95, src))
    assert accept(JudgeResult(Verdict.REACHABLE, 0.5, "claude"))


def test_summary_tier_reachable_floor_env_override(monkeypatch):
    monkeypatch.setenv("SSVC_FLOOR_LOCAL_REACHABLE", "0.5")
    assert accept(JudgeResult(Verdict.REACHABLE, 0.6, "local"))


# --- verified dependency trace (pkgsrc) -----------------------------------------

@pytest.fixture
def src_dir(tmp_path):
    d = tmp_path / "pkgsrc" / "lodash@4.17.20-abc"
    (d / "lib").mkdir(parents=True)
    (d / "lib" / "template.js").write_text("// header\nfunction template(str, opts) {\n  var src = 'with(obj){' + str;\n  return Function(src);\n}\n")
    (tmp_path / "secret.js").write_text("const KEY = 'do-not-read-me';\n")
    return d


def test_check_trace_accepts_only_real_quotes(src_dir):
    from doublestrain.judges.claude_code import check_trace
    sources = [("lodash@4.17.20", src_dir)]
    ok, bad = check_trace([
        {"path": "lodash@4.17.20/lib/template.js", "line": 4, "quote": "return   Function(src);"},  # ok (ws)
        {"path": f"{src_dir}/lib/template.js", "line": 2, "quote": "function template(str, opts)"},   # abs ok
        {"path": "lodash@4.17.20/lib/template.js", "line": 1, "quote": "return Function(src);"},     # line off by 3
        {"path": "lodash@4.17.20/lib/template.js", "line": 4, "quote": "eval(input)"},               # invented
        {"path": "lodash@4.17.20/../../secret.js", "line": 1, "quote": "const KEY = 'do-not-read-me';"},  # escape
        {"path": "lodash@4.17.20/lib/nope.js", "line": 1, "quote": "anything here"},
        {"path": "underscore@1.0.0/x.js", "line": 1, "quote": "anything here"},
        {"path": "lodash@4.17.20/lib/template.js", "line": 5, "quote": "}"},                         # too short
        {"path": "lodash@4.17.20/lib/template.js"},                                                   # malformed
    ], sources, "lodash")
    assert ok == ["lodash@4.17.20/lib/template.js:4", "lodash@4.17.20/lib/template.js:2"]
    assert len(bad) == 7 and "not on that line" in bad[0] and "no such file" in bad[2]


def _seq_claude(tmp_path, payloads) -> str:
    """Fake claude answering payloads[i] on the i-th call, logging each call's stdin."""
    script = tmp_path / "claude-seq"
    state = tmp_path / "calls.json"
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


def _ans(verdict, trace=(), conf=0.9):
    return {"verdict": verdict, "confidence": conf, "rationale": "r", "evidence": ["app.js:1"],
            "dependency_trace": list(trace)}


GOOD = {"path": "lodash@4.17.20/lib/template.js", "line": 4, "quote": "return Function(src);"}
FAKE = {"path": "lodash@4.17.20/lib/template.js", "line": 4, "quote": "eval(userInput)"}


@pytest.fixture
def with_src(monkeypatch, src_dir):
    from doublestrain import pkgsrc
    monkeypatch.setattr(pkgsrc, "for_query", lambda repo, dep, ver, **kw: ([("lodash@4.17.20", src_dir)], []))


def _calls(tmp_path):
    return json.loads((tmp_path / "calls.json").read_text())


def test_cited_reachable_accepted_first_time(app, tmp_path, monkeypatch, with_src):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [_ans("reachable", [GOOD])]))
    r = ClaudeCodeJudge(pkgsrc=True).judge(_q(app))
    assert r.verdict == Verdict.REACHABLE and r.confidence == 0.9
    assert "dep:lodash@4.17.20/lib/template.js:4" in r.evidence and len(_calls(tmp_path)) == 1


def test_uncited_reachable_retried_then_accepted(app, tmp_path, monkeypatch, with_src):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [_ans("reachable", [FAKE]),
                                                                 _ans("reachable", [GOOD])]))
    r = ClaudeCodeJudge(pkgsrc=True).judge(_q(app))
    calls = _calls(tmp_path)
    assert len(calls) == 2 and "REJECTED" in calls[1]["stdin"] and "not on that line" in calls[1]["stdin"]
    assert r.verdict == Verdict.REACHABLE and r.rationale.startswith("[retried") and r.cost_usd == 0.02


def test_retry_may_change_its_mind(app, tmp_path, monkeypatch, with_src):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [_ans("reachable"),
                                                                 _ans("not_reachable", conf=0.85)]))
    r = ClaudeCodeJudge(pkgsrc=True).judge(_q(app))
    assert r.verdict == Verdict.NOT_REACHABLE and r.confidence == 0.85


def test_uncited_twice_becomes_unsure(app, tmp_path, monkeypatch, with_src):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [_ans("reachable"), _ans("reachable", [FAKE])]))
    r = ClaudeCodeJudge(pkgsrc=True).judge(_q(app))
    assert r.verdict == Verdict.UNSURE and r.confidence == 0.0 and r.rationale.startswith("[uncited")
    assert not accept(r)


def test_not_reachable_and_no_target_source_are_not_trace_checked(app, tmp_path, monkeypatch, src_dir):
    from doublestrain import pkgsrc
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [_ans("not_reachable"), _ans("reachable")]))
    assert ClaudeCodeJudge(pkgsrc=True).judge(_q(app)).verdict == Verdict.NOT_REACHABLE   # (no sources)
    # only a dependent's source was available: can't demand a trace into the target
    monkeypatch.setattr(pkgsrc, "for_query", lambda repo, dep, ver, **kw: ([("express@4.16.4", src_dir)], ["lodash@4.17.20: refused"]))
    assert ClaudeCodeJudge(pkgsrc=True).judge(_q(app)).verdict == Verdict.REACHABLE
    assert len(_calls(tmp_path)) == 2


# --- endpoint tiers, egress guard, budget, preflight ------------------------------

def test_endpoint_tiers_by_name_and_egress_guard(monkeypatch):
    from doublestrain.judges import OpenAIJudge
    from doublestrain.judges.local import check_egress
    with pytest.raises(ValueError, match="unknown judge spec"):
        get_judge("workstation")                                   # not configured
    monkeypatch.setenv("SSVC_WORKSTATION_BASE_URL", "http://10.0.0.2:1234/v1")
    j = get_judge("cascade:jev,local,workstation,claude", cache=False)
    assert j.name == "cascade:jev,local,workstation,claude"
    assert isinstance(j.tiers[2], OpenAIJudge) and j.tiers[2].base_url == "http://10.0.0.2:1234/v1"
    assert check_egress("x", "http://localhost:1234/v1") is False
    with pytest.raises(ValueError, match="https"):
        check_egress("hosted", "http://1.1.1.1/v1")
    with pytest.raises(ValueError, match="ALLOW_CODE_EGRESS"):
        check_egress("hosted", "https://1.1.1.1/v1")
    monkeypatch.setenv("SSVC_HOSTED_ALLOW_CODE_EGRESS", "1")
    assert check_egress("hosted", "https://1.1.1.1/v1") is True


def test_unknown_endpoint_tier_never_settles_reachable(monkeypatch):
    assert not accept(JudgeResult(Verdict.REACHABLE, 1.0, "workstation"))
    assert accept(JudgeResult(Verdict.NOT_REACHABLE, 0.95, "workstation"))
    monkeypatch.setenv("SSVC_FLOOR_WORKSTATION_REACHABLE", "0.8")
    assert accept(JudgeResult(Verdict.REACHABLE, 0.85, "workstation"))


def test_claude_budget_stops_calls(app, tmp_path, monkeypatch):
    from doublestrain.judges import claude_code
    monkeypatch.setattr(claude_code, "SPEND", {"usd": 0.0, "calls": 0, "over_budget": 0})
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [_ans("not_reachable")] * 3))
    monkeypatch.setenv("SSVC_CLAUDE_BUDGET_USD", "0.015")
    j = ClaudeCodeJudge(pkgsrc=False)
    assert j.judge(_q(app)) is not None and j.judge(_q(app)) is not None   # $0.01, then $0.02
    assert j.judge(_q(app)) is None                                        # over budget: no claim
    assert claude_code.SPEND["calls"] == 2 and claude_code.SPEND["over_budget"] == 1


def test_preflight_reports_down_tiers(monkeypatch):
    from doublestrain.judges import preflight
    monkeypatch.setenv("SSVC_LOCAL_BASE_URL", "http://127.0.0.1:9/v1")        # nothing listens
    monkeypatch.setenv("SSVC_CLAUDE_BIN", "/bin/echo")
    lines, down = preflight(get_judge("cascade:local,claude"))
    assert down == ["local"] and "escalate to claude" in lines[0] and lines[1].lstrip().startswith("ok")



# --- split judge + --egress policy ------------------------------------------------

SPEC_OK = {"triggers": [{"package": "lodash@4.17.20", "entry": "_.template(str, options)",
                         "condition": "none", "input": "template string", "trace": [GOOD]},
                        {"package": "lodash@4.17.20", "entry": "_.invented()", "condition": "none",
                         "input": "x", "trace": [FAKE]}],
           "not_triggerable": False, "confidence": 0.9, "rationale": "template compiles via Function"}


def test_split_claude_sees_dependency_source_only(app, tmp_path, monkeypatch, src_dir, fake_local):
    from doublestrain import pkgsrc
    from doublestrain.judges import SplitJudge
    seen, _ = fake_local
    monkeypatch.setattr(pkgsrc, "for_query", lambda repo, dep, ver, **kw: ([("lodash@4.17.20", src_dir)], []))
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "spec-cache"))
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [SPEC_OK]))
    r = SplitJudge().judge(_q(app))
    call, = _calls(tmp_path)
    # claude: cwd = the dependency source, no app path, no app code in the prompt
    assert Path(call["cwd"]).resolve() == src_dir.resolve() and "--restricted" in call["argv"]
    assert str(app) not in json.dumps(call) and "_.merge" not in call["stdin"]
    # the matcher (local endpoint) gets the verified spec + the app excerpts
    user = seen[-1][2]["messages"][1]["content"]
    assert "_.template(str, options)" in user and "_.invented" not in user
    assert "module.exports = (o) => _.merge" in user
    assert r.source == "split" and r.verdict == Verdict.NOT_REACHABLE
    # the spec is per advisory + package versions: a second app reuses it, no claude call
    SplitJudge().judge(_q(app))
    assert len(_calls(tmp_path)) == 1


def test_split_spec_without_verified_trigger_retries_then_no_claim(app, tmp_path, monkeypatch, src_dir, fake_local):
    from doublestrain import pkgsrc
    from doublestrain.judges import SplitJudge
    bad = {**SPEC_OK, "triggers": [SPEC_OK["triggers"][1]]}
    monkeypatch.setattr(pkgsrc, "for_query", lambda repo, dep, ver, **kw: ([("lodash@4.17.20", src_dir)], []))
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "spec-cache"))
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [bad, bad]))
    assert SplitJudge().judge(_q(app)) is None
    calls = _calls(tmp_path)
    assert len(calls) == 2 and "REJECTED" in calls[1]["stdin"]


def test_split_never_settles_reachable_by_default():
    assert not accept(JudgeResult(Verdict.REACHABLE, 1.0, "split"))
    assert accept(JudgeResult(Verdict.NOT_REACHABLE, 0.95, "split:workstation"))


def test_egress_policy_refuses_tiers_that_send_app_code(monkeypatch):
    monkeypatch.setenv("SSVC_WORKSTATION_BASE_URL", "http://10.0.0.2:1234/v1")
    monkeypatch.setenv("SSVC_HOSTED_BASE_URL", "https://1.1.1.1/v1")
    monkeypatch.setenv("SSVC_HOSTED_ALLOW_CODE_EGRESS", "1")
    for mode, spec in (("machine", "cascade:jev,local,claude"), ("machine", "cascade:local,workstation"),
                       ("network", "cascade:local,hosted"), ("network", "split:hosted")):
        with pytest.raises(ValueError, match="forbids"):
            get_judge(spec, cache=False, egress=mode)
    assert get_judge("cascade:local,split", cache=False, egress="machine").name == "cascade:local,split"
    assert get_judge("cascade:local,workstation,split:workstation", cache=False, egress="network")
    assert get_judge("cascade:jev,local,hosted,claude", cache=False, egress="any")
    monkeypatch.setenv("SSVC_APP_CODE_EGRESS", "machine")
    with pytest.raises(ValueError, match="claude"):
        get_judge("claude")


def test_context_pack_shows_how_the_app_uses_a_parent(tmp_path):
    from doublestrain.judges.local import parent_use_sites
    (tmp_path / "main.js").write_text("import express from 'express';\n" + "\n" * 30 +
                                      "const app = express();\napp.use(express.static('public'));\n")
    sites = parent_use_sites(str(tmp_path), ["main.js:1: import express from 'express';"])
    assert sites == ["main.js:32: const app = express();", "main.js:33: app.use(express.static('public'));"]


@pytest.mark.parametrize("entry,want", [
    ("new AdmZip(path|buffer).extractAllTo(targetPath, overwrite)", ["AdmZip", "extractAllTo"]),
    ("express.static(root, options)", ["static"]), ("_.template(str, options)", ["template"]),
    ("st(path[, url][, opts]) handler (Mount.serve)", []), ("marked(src)", ["marked"]),
    ("Default app query parsing (req.query)", []),
    ("Model.updateOne / updateMany / findOneAndUpdate / Query.update (update casting)",
     ["Model", "updateOne", "updateMany", "findOneAndUpdate", "Query", "update"]),
    ("express.json and/or urlencoded parsing", ["json"])])
def test_entry_tokens_are_called_names_never_keywords_or_prose(entry, want):
    from doublestrain.judges.split import _entry_tokens
    assert _entry_tokens([{"entry": entry}]) == want


def test_spec_connects_guard_v2(tmp_path):
    """Downgrade only when the app imports a route package the spec neither triggered
    nor cleared (or never saw)."""
    from doublestrain.judges.split import _app_imports, spec_connects
    _app_imports.cache_clear()
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "a.js").write_text("const mongoose = require('mongoose');\nmongoose.model('X').find(req.body);\n")
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"mongoose": "4"}},
        "node_modules/mongoose": {"version": "4.2.4", "dependencies": {"mongodb": "2"}},
        "node_modules/mongodb": {"version": "2.0.46", "dependencies": {"bson": "0.4"}},
        "node_modules/bson": {"version": "0.4.23"}}}
    (repo / "package-lock.json").write_text(json.dumps(lock))
    q = ReachQuery(repo_path=str(repo), ecosystem="npm", dependency="bson", version="0.4.23", cve="CVE-X")
    srcs = [("bson@0.4.23", tmp_path), ("mongoose@4.2.4", tmp_path), ("mongodb@2.0.46", tmp_path)]
    direct_only = {"triggers": [{"package": "bson@0.4.23", "entry": "BSON.serialize"}], "parents": []}
    assert "mongoose" in spec_connects(q, direct_only, srcs)                       # open: downgrade
    cleared = {**direct_only, "parents": [{"package": "mongoose", "reaches": False, "how": "x"}]}
    assert spec_connects(q, cleared, srcs) == ""                                   # explicitly cleared
    via = {**direct_only, "triggers": [{"package": "mongoose@4.2.4", "entry": "Model.find"}]}
    assert spec_connects(q, via, srcs) == ""                                       # triggered through it
    assert "never saw" in spec_connects(q, cleared, srcs[:1])                       # mongoose not given
    (repo / "b.js").write_text("const BSON = require('bson');\nBSON.calculateObjectSize({});\n")
    _app_imports.cache_clear()
    assert "mongoose" in spec_connects(q, direct_only, srcs)       # a direct import doesn't close the parent route
    (repo / "b.js").unlink()
    _app_imports.cache_clear()
    (repo / "a.js").write_text("// no imports on the route\n")
    _app_imports.cache_clear()
    assert spec_connects(q, direct_only, srcs) == ""                               # tooling-only route


def test_a_clearance_needs_evidence(tmp_path, monkeypatch):
    """A spec's "doesn't reach" for a parent counts only when the parent's source never
    imports the route, or a follow-up read cited every file where it does."""
    from doublestrain.judges import split
    split._app_imports.cache_clear()
    split.route_uses.cache_clear()
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "specs"))
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "a.js").write_text("const mongoose = require('mongoose');\n")
    (repo / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"mongoose": "4"}},
        "node_modules/mongoose": {"version": "4.2.4", "dependencies": {"mongodb": "2"}},
        "node_modules/mongodb": {"version": "2.0.46", "dependencies": {"bson": "0.4"}},
        "node_modules/bson": {"version": "0.4.23"}}}))
    dirs = {n: tmp_path / "src" / n for n in ("bson", "mongoose", "mongodb")}
    for d in dirs.values():
        d.mkdir(parents=True)
    (dirs["bson"] / "index.js").write_text("module.exports = function serialize(o) { return o; };\n")
    (dirs["mongoose"] / "lib.js").write_text("const mongodb = require('mongodb');\nmodule.exports = mongodb.connect;\n")
    (dirs["mongoose"] / "test/x.test.js").parent.mkdir()
    (dirs["mongoose"] / "test/x.test.js").write_text("require('bson')\n")       # tests don't count
    srcs = [("bson@0.4.23", dirs["bson"]), ("mongoose@4.2.4", dirs["mongoose"]), ("mongodb@2.0.46", dirs["mongodb"])]
    q = ReachQuery(repo_path=str(repo), ecosystem="npm", dependency="bson", version="0.4.23", cve="CVE-X")
    spec = {"triggers": [{"package": "bson@0.4.23", "entry": "serialize"}],
            "parents": [{"package": "mongoose", "reaches": False, "how": "never serializes request data"}]}
    assert split.clear_needs(q, spec, srcs) == {"mongoose": ("lib.js",)}
    assert "clears mongoose without checked evidence (mongoose imports the route in lib.js)" in split.spec_connects(q, spec, srcs)
    # backed by its own source: the parent never imports the route
    (dirs["mongoose"] / "lib.js").write_text("module.exports = {};\n")
    split.route_uses.cache_clear()
    assert split.spec_connects(q, spec, srcs) == ""
    (dirs["mongoose"] / "lib.js").write_text("const mongodb = require('mongodb');\nmodule.exports = mongodb.connect;\n")
    split.route_uses.cache_clear()
    # the follow-up read: cites lib.js (checked against the file) -> backed, saved in the spec
    step = {"path": "mongoose@4.2.4/lib.js", "line": 1, "quote": "const mongodb = require('mongodb');"}
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _fake_claude(tmp_path, {
        "type": "result", "total_cost_usd": 0.03, "structured_output": {"parents": [
            {"package": "mongoose", "reaches": False, "how": "connect only", "trace": [step]}]}}))
    why, cost = split.connects(q, spec, srcs, "sonnet", 30)
    assert why == "" and cost == 0.03 and spec["clears"]["mongoose"]["backed"]
    assert "every listed file" in json.loads((tmp_path / "argv.json").read_text())["stdin"]
    saved = json.loads(split._spec_path(q, srcs, "sonnet").read_text())
    assert saved["clears"]["mongoose"]["verified"] == ["mongoose@4.2.4/lib.js:1"]
    # a citation that doesn't check out leaves it unbacked; asked once, not again
    del spec["clears"]
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _fake_claude(tmp_path, {
        "type": "result", "structured_output": {"parents": [
            {"package": "mongoose", "reaches": False, "how": "x", "trace": [{**step, "line": 2, "quote": "made up"}]}]}}))
    why, _ = split.connects(q, spec, srcs, "sonnet", 30)
    assert "without checked evidence" in why and spec["clears"]["mongoose"]["missing"] == ["lib.js"]
    (tmp_path / "argv.json").unlink()
    assert "without checked evidence" in split.connects(q, spec, srcs, "sonnet", 30)[0]
    assert not (tmp_path / "argv.json").exists()
    # the follow-up says it does reach, with a checked step: it becomes a via-parent trigger
    del spec["clears"]
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _fake_claude(tmp_path, {
        "type": "result", "structured_output": {"parents": [
            {"package": "mongoose", "reaches": True, "how": "Model.find serializes the query", "trace": [step]}]}}))
    why, _ = split.connects(q, spec, srcs, "sonnet", 30)
    assert why == "" and spec["parents"][0]["reaches"] and spec["parents"][0]["revised"] == "spec-clears"
    assert any(t.get("from_parent_claim") for t in split.with_parent_triggers(spec)["triggers"])


def test_cached_not_reachable_is_rechecked(tmp_path, monkeypatch):
    inner = _Fixed("split", JudgeResult(Verdict.NOT_REACHABLE, 0.95, "split"))
    inner.recheck = lambda q, r: JudgeResult(Verdict.UNSURE, r.confidence, r.source, rationale="rechecked", cached=r.cached)
    cj = CachedJudge(inner, cache_dir=str(tmp_path))
    q = ReachQuery(str(tmp_path), "npm", "x", "CVE-1")
    assert cj.judge(q).verdict == Verdict.NOT_REACHABLE                   # fresh: the judge applied its guard
    r = cj.judge(q)                                                         # cached: the guard as it is now
    assert r.cached and r.verdict == Verdict.UNSURE and inner.calls == 1


def test_local_module_use_sites_follow_app_wrappers(tmp_path):
    from doublestrain.judges.local import local_module_use_sites
    (tmp_path / "src" / "models").mkdir(parents=True)
    (tmp_path / "src" / "controllers").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "src" / "models" / "note.js").write_text(
        "const mongoose = require('mongoose');\nmodule.exports = mongoose.model('Notes', S);\n")
    (tmp_path / "src" / "models" / "index.js").write_text("module.exports = { Note: require('./note') };\n")
    (tmp_path / "src" / "controllers" / "notes.js").write_text(
        "const Note = require('../models/note');\nconst { Note: N2 } = require('../models');\n"
        "exports.list = () => Note.find({});\nexports.upd = (req) => N2.findOneAndUpdate(q, req.body);\n")
    (tmp_path / "scripts" / "seed.js").write_text("const Note = require('../src/models/note.js');\nNote.deleteMany({});\n")
    sites = local_module_use_sites(str(tmp_path), ["src/models/note.js:1: const mongoose = require('mongoose');"])
    assert sites[0] == "src/controllers/notes.js:4: exports.upd = (req) => N2.findOneAndUpdate(q, req.body);"
    assert "src/controllers/notes.js:3: exports.list = () => Note.find({});" in sites
    assert sites[-1].startswith("scripts/seed.js:2:")                       # side scripts rank last


def test_context_pack_keeps_site_lines_when_over_budget(tmp_path):
    from doublestrain.judges.local import context_pack
    (tmp_path / "a.js").write_text("\n".join(f"// filler {i} " + "x" * 80 for i in range(60)))
    (tmp_path / "b.js").write_text("\n".join(["// pad"] * 20 + ["Note.findOneAndUpdate(q, req.body);"] + ["// pad"] * 20))
    pk = context_pack(str(tmp_path), ["a.js:30: x", "b.js:21: Note"], budget=2700)
    assert "b.js (site lines only" in pk and "Note.findOneAndUpdate(q, req.body);" in pk


def test_build_spec_keeps_parent_triggers_through_a_verified_parent(tmp_path, monkeypatch):
    from doublestrain.judges.split import build_spec
    be, mm = tmp_path / "brace-expansion@1.1.11", tmp_path / "minimatch@3.0.4"
    be.mkdir(); mm.mkdir()
    (be / "index.js").write_text("module.exports = expandTop;\nfunction expandTop(str) { return expand(str); }\n")
    (mm / "minimatch.js").write_text("var expand = require('brace-expansion')\n"
                                     "function braceExpand (pattern) { return expand(pattern) }\n")
    step_mm = {"path": "minimatch@3.0.4/minimatch.js", "line": 2, "quote": "return expand(pattern)"}
    trig = lambda pkg, entry, trace: {"package": pkg, "entry": entry, "condition": "none", "input": "pattern",
                                      "trace": trace}
    out = {"triggers": [
        trig("brace-expansion", "expand(str)", [{"path": "brace-expansion@1.1.11/index.js", "line": 2,
                                                 "quote": "function expandTop(str) { return expand(str); }"}]),
        trig("minimatch@3.0.4", "minimatch.braceExpand(pattern)", [step_mm]),           # stops at the call
        trig("glob", "glob.sync(pattern)", [step_mm])],                                 # glob never cleared
        "not_triggerable": False, "confidence": 0.8, "rationale": "r",
        "parents": [{"package": "minimatch@3.0.4", "reaches": True, "how": "calls expand", "trace": [step_mm]}]}
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _fake_claude(tmp_path, {
        "type": "result", "is_error": False, "total_cost_usd": 0.01, "structured_output": out}))
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "cache"))
    q = ReachQuery(repo_path=str(tmp_path), ecosystem="npm", dependency="brace-expansion", version="1.1.11",
                   cve="CVE-X", advisory="ReDoS")
    spec, _ = build_spec(q, [("brace-expansion@1.1.11", be), ("minimatch@3.0.4", mm)], "opus", 30)
    assert [t["entry"] for t in spec["triggers"]] == ["expand(str)", "minimatch.braceExpand(pattern)"]
    assert spec["triggers"][1]["via_parent"] and "via_parent" not in spec["triggers"][0]
    assert spec["dropped"] == ["glob.sync(pattern): no step in brace-expansion"]


def test_split_matcher_sees_calls_through_app_wrappers(app, tmp_path, monkeypatch, src_dir, fake_local):
    from doublestrain import pkgsrc
    from doublestrain.judges import SplitJudge
    (app / "src/routes.js").write_text("const merge = require('./a');\napp.post('/x', (req) => merge(req.body));\n")
    seen, _ = fake_local
    monkeypatch.setattr(pkgsrc, "for_query", lambda repo, dep, ver, **kw: ([("lodash@4.17.20", src_dir)], []))
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "spec-cache"))
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [SPEC_OK]))
    SplitJudge().judge(_q(app))
    user = seen[-1][2]["messages"][1]["content"]
    assert "app.post('/x', (req) => merge(req.body));" in user and "condition decides" in seen[-1][2]["messages"][0]["content"]


def test_split_not_reachable_floor_is_095():
    from doublestrain.judges.base import accept, floors
    assert floors("split:workstation")[1] == 0.95 and floors("split")[1] == 0.95
    assert not accept(JudgeResult(Verdict.NOT_REACHABLE, 0.9, "split:workstation"))
    assert accept(JudgeResult(Verdict.NOT_REACHABLE, 0.95, "split:workstation"))
    assert not accept(JudgeResult(Verdict.REACHABLE, 0.99, "split"))


def test_endpoint_schema_puts_rationale_before_verdict(monkeypatch):
    # constrained decoding emits keys in schema order; verdict-first meant no reasoning
    # before the verdict (morgan CVE-2026-5078, all10-r2)
    from doublestrain.judges.claude_code import SCHEMA
    from doublestrain.judges.local import OpenAIJudge
    monkeypatch.setenv("SSVC_LOCAL_MODEL", "m")
    j, sent = OpenAIJudge("local"), []

    def fake(path, payload, timeout):
        sent.append(payload)
        return {"choices": [{"message": {"content": '{"rationale": "r", "evidence": [], "verdict": "unsure", "confidence": 0.5}'}}]}
    monkeypatch.setattr(j, "_req", fake)
    d, _ = j.complete("sys", "user", SCHEMA)
    assert d["verdict"] == "unsure"
    assert list(sent[0]["response_format"]["json_schema"]["schema"]["properties"])[:3] == ["rationale", "evidence", "verdict"]
    assert list(SCHEMA["properties"])[0] == "verdict"          # the shared schema is untouched


def test_disagreement_escalation_is_a_toggle(app, monkeypatch):
    # split's not_reachable after the workstation said reachable (morgan, all10-r4)
    ws = lambda: _Fixed("jev", JudgeResult(Verdict.REACHABLE, 0.95, "jev"))           # noqa: E731
    nr = lambda: _Fixed("claude", JudgeResult(Verdict.NOT_REACHABLE, 0.99, "claude"))  # noqa: E731
    sh = lambda v: _Fixed("shape", JudgeResult(v, 0.9, "shape"))                      # noqa: E731
    monkeypatch.setenv("SSVC_ESCALATE_DISAGREEMENT", "0")
    assert CascadeJudge([ws(), nr(), sh(Verdict.REACHABLE)]).judge(_q(app)).source == "claude"   # off
    monkeypatch.delenv("SSVC_ESCALATE_DISAGREEMENT")                                            # default: on
    r = CascadeJudge([ws(), nr(), sh(Verdict.REACHABLE)]).judge(_q(app))
    assert r.source == "shape" and "escalated" in r.trail[-1]["note"] and not accept(r)
    last = sh(Verdict.NOT_REACHABLE)       # the last tier settles as usual
    assert CascadeJudge([ws(), nr(), last]).judge(_q(app)).source == "shape"
    r = CascadeJudge([ws(), nr(), _Fixed("shape", None)]).judge(_q(app))   # next tier down
    assert not accept(r)
    assert CascadeJudge([nr(), sh(Verdict.REACHABLE)]).judge(_q(app)).source == "claude"   # no disagreement
    assert CascadeJudge([ws(), nr()]).judge(_q(app)).source == "claude"   # nothing left to ask


def test_usage_limit_reset_time_and_wait(monkeypatch, tmp_path):
    import datetime as dt

    from doublestrain.judges import claude_code as cc
    now = dt.datetime(2026, 10, 17, 7, 40)
    msg = "You've hit your session limit · resets 8:50am (Europe/London)"
    assert cc.limit_reset(msg, now) == dt.datetime(2026, 10, 17, 8, 50)
    assert cc.limit_reset("You've hit your session limit · resets 1:50pm (Europe/London)", now).hour == 13
    assert cc.limit_reset("resets 3am", dt.datetime(2026, 10, 17, 23, 0)) is None          # not a limit message
    assert cc.limit_reset("hit your usage limit · resets 3am", dt.datetime(2026, 10, 17, 23, 0)).day == 18
    calls, slept = [], []
    answers = [("limit", now), ("ok", {"verdict": "unsure"}, {"total_cost_usd": 0}, 1.0)]
    monkeypatch.setattr(cc, "_invoke", lambda *a, **k: (calls.append(1), answers[len(calls) - 1])[1])
    # stub the wall-clock wait itself: with only time.sleep stubbed, _sleep_until spins until the
    # reset (a minute of busy loop, millions of list appends: CI runners were killed for it)
    monkeypatch.setattr(cc, "_sleep_until", slept.append)
    monkeypatch.setenv("SSVC_CLAUDE_WAIT_ON_LIMIT", "1")
    assert cc.run_claude("claude", "p", "s", {}, cwd=tmp_path, model="m", timeout=1)[0] == {"verdict": "unsure"}
    assert len(calls) == 2 and slept
    calls.clear()
    monkeypatch.setenv("SSVC_CLAUDE_WAIT_ON_LIMIT", "0")
    assert cc.run_claude("claude", "p", "s", {}, cwd=tmp_path, model="m", timeout=1) is None and len(calls) == 1


# --- per-model floors and corroboration (floors.toml) --------------------------------

QWEN = "qwen/qwen3.8-27b"


def test_floors_follow_the_model_that_answered(monkeypatch):
    from doublestrain.judges.base import floors, needs_corroboration, policy
    ws = lambda c, m=QWEN: JudgeResult(Verdict.NOT_REACHABLE, c, "workstation", model=m)   # noqa: E731
    assert floors("workstation", QWEN) == (math.inf, 0.9) and needs_corroboration(ws(0.95))
    assert policy(ws(0.95))["measured"].startswith("all10-r4")
    other = ws(0.95, "some/other-model")                  # unmeasured: role defaults
    assert accept(other) and needs_corroboration(other) and "measured" not in policy(other)
    assert floors("split:workstation", QWEN)[1] == 0.95
    assert not needs_corroboration(JudgeResult(Verdict.NOT_REACHABLE, 0.95, "split:workstation", model=QWEN))
    assert not needs_corroboration(JudgeResult(Verdict.REACHABLE, 0.95, "workstation", model=QWEN))
    monkeypatch.setenv("SSVC_FLOOR_WORKSTATION_NOT_REACHABLE", "0.99")    # the env still wins
    assert not accept(ws(0.95))


def test_floors_file_override(tmp_path, monkeypatch):
    f = tmp_path / "floors.toml"
    f.write_text('[role.endpoint]\nreachable = inf\nnot_reachable = 0.8\n'
                 '[[model]]\nrole = "endpoint"\nmodel = "Big/Model"\nnot_reachable = 0.6\n')
    monkeypatch.setenv("SSVC_FLOORS_FILE", str(f))
    from doublestrain.judges.base import floors, needs_corroboration
    assert floors("workstation", "big/model") == (math.inf, 0.6)          # ids compare lowercased
    assert floors("workstation", "x") == (math.inf, 0.8)
    assert not needs_corroboration(JudgeResult(Verdict.NOT_REACHABLE, 0.9, "workstation", model="x"))


def test_corroboration_is_a_toggle(app, monkeypatch):
    # serve-static nodegoat (all10-r5): the workstation's not_reachable@0.90 was wrong
    ws = lambda: _Fixed("workstation", JudgeResult(Verdict.NOT_REACHABLE, 0.9, "workstation", model=QWEN))  # noqa: E731
    sp = lambda v, c=0.95: _Fixed("split", JudgeResult(v, c, "split:workstation", model=QWEN))           # noqa: E731
    sh = lambda v: _Fixed("shape", JudgeResult(v, 0.9, "shape:claude-opus-5-5"))                         # noqa: E731
    monkeypatch.setenv("SSVC_CORROBORATE", "0")
    assert CascadeJudge([ws(), sp(Verdict.REACHABLE)]).judge(_q(app)).source == "workstation"   # off
    monkeypatch.delenv("SSVC_CORROBORATE")                                                     # default: on
    assert "@corroborate" in CascadeJudge([ws()]).fingerprint()
    r = CascadeJudge([ws(), sp(Verdict.NOT_REACHABLE), sh(Verdict.REACHABLE)]).judge(_q(app))
    assert r.source == "split:workstation" and accept(r) and r.rationale.startswith("corroborates workstation")
    assert "needs a second read" in r.trail[0]["note"]
    # split below its floor, shape agrees: shape is a second read too
    r = CascadeJudge([ws(), sp(Verdict.NOT_REACHABLE, 0.9), sh(Verdict.NOT_REACHABLE)]).judge(_q(app))
    assert r.source == "shape:claude-opus-5-5" and accept(r)
    # nobody agrees: unresolved, never the held not_reachable
    r = CascadeJudge([ws(), sp(Verdict.UNSURE), sh(Verdict.UNSURE)]).judge(_q(app))
    assert not accept(r) and r.source == "shape:claude-opus-5-5"
    assert [e["source"] for e in r.trail] == ["workstation", "split:workstation"]
    r = CascadeJudge([ws()]).judge(_q(app))                    # nothing left to ask
    assert r.verdict == Verdict.UNSURE and not accept(r) and "not corroborated" in r.rationale
    r = CascadeJudge([ws(), _Fixed("split", None)]).judge(_q(app))   # second read down
    assert not accept(r)
    # another weak endpoint agreeing is not a second read
    ws2 = _Fixed("local", JudgeResult(Verdict.NOT_REACHABLE, 0.95, "local", model="other/model"))
    assert not accept(CascadeJudge([ws(), ws2]).judge(_q(app)))


def test_pip_settles_only_split_then_claude(app):
    # py8 (2026-10-26, held-out): split not_reachable >= 0.95 with opus >= 0.7 agreeing, 260 / 0;
    # split alone 277 / 3, the workstation alone 240 / 4, claude alone never measured
    nr = lambda name, c, src, m="": lambda: _Fixed(name, JudgeResult(Verdict.NOT_REACHABLE, c, src, model=m))  # noqa: E731
    ws, sp = nr("workstation", 0.95, "workstation", QWEN), nr("split", 0.95, "split:workstation", QWEN)
    cl, weak = nr("claude", 0.8, "claude"), nr("claude", 0.6, "claude")
    sh = nr("shape", 0.95, "shape:claude-opus-5-5")

    def settles(*tiers, eco="pypi"):
        c = _cand(bumped_package="pillow", ecosystem=eco)
        judge = tiers[0]() if len(tiers) == 1 else CascadeJudge([t() for t in tiers])
        resolve_reachability(c, judge, str(app), "CVE-1")
        return c.reachability == Reachability.UNREACHABLE

    assert settles(sp, cl) and settles(ws, sp, cl)          # the workstation held too: claude reads for both
    r = CascadeJudge([ws(), sp(), cl()]).judge(ReachQuery(str(app), "pypi", "pillow", "CVE-1"))
    assert r.corroborates == "workstation,split:workstation" and r.rationale.startswith("corroborates workstation, split")
    assert not settles(sp, weak) and not settles(sp, sh) and not settles(ws, cl)
    assert not settles(cl) and not settles(sp)               # alone, in a cascade or outside one
    assert not settles(nr("x", 1.0, "pyimports"), ws)         # the other half of the py2 rule: never measured fresh
    assert settles(sp, eco="npm")                             # npm unchanged: split settles alone


def test_cargo_settles_only_split_then_claude(app):
    # rs1-rs3 (2026-10-27): split not_reachable >= 0.95 with opus >= 0.7 agreeing, 159 / 0, 155 / 1, 166 / 0
    nr = lambda name, c, src, m="": lambda: _Fixed(name, JudgeResult(Verdict.NOT_REACHABLE, c, src, model=m))  # noqa: E731
    ws, sp = nr("workstation", 0.95, "workstation", QWEN), nr("split", 0.95, "split:workstation", QWEN)
    cl, weak = nr("claude", 0.8, "claude"), nr("claude", 0.6, "claude")

    def settles(*tiers):
        c = _cand(bumped_package="h2", ecosystem="cargo")
        judge = tiers[0]() if len(tiers) == 1 else CascadeJudge([t() for t in tiers])
        resolve_reachability(c, judge, str(app), "CVE-1")
        return c.reachability == Reachability.UNREACHABLE

    assert settles(sp, cl) and settles(ws, sp, cl)
    assert not settles(sp, weak) and not settles(ws, cl) and not settles(sp) and not settles(cl)


def test_maven_settles_only_split_090_then_claude_and_never_a_gadget(app):
    # jv3 (2026-10-29, held-out): split not_reachable >= 0.90 with opus >= 0.7 agreeing, 159 / 1;
    # the miss a deserialization gadget, which never settles on maven
    from doublestrain.reach import resolve_reachability
    nr = lambda name, c, src, m="": lambda: _Fixed(name, JudgeResult(Verdict.NOT_REACHABLE, c, src, model=m))  # noqa: E731
    sp90, sp85, cl = nr("split", 0.90, "split:workstation", QWEN), nr("split", 0.85, "split:workstation", QWEN), nr("claude", 0.8, "claude")

    def settles(*tiers, eco="maven", summary=""):
        c = _cand(bumped_package="io.netty:netty-codec-http", ecosystem=eco)
        c.advisory_summary = summary
        resolve_reachability(c, CascadeJudge([t() for t in tiers]) if len(tiers) > 1 else tiers[0](), str(app), "CVE-1")
        return c.reachability == Reachability.UNREACHABLE

    assert settles(sp90, cl) and not settles(sp85, cl) and not settles(sp90) and not settles(cl)
    assert not settles(sp90, cl, eco="cargo")                     # cargo keeps split's 0.95 floor
    gadget = "CompactHashMap implements readObject(ObjectInputStream) reading an attacker-controlled count"
    assert not settles(sp90, cl, summary=gadget)
    assert settles(sp90, cl, eco="cargo", summary="") is False and not settles(sp90, cl, summary="Java native deserialization of X")


def test_cargo_and_pypi_default_to_opus(monkeypatch):
    from doublestrain.judges.claude_code import MODEL_BY_ECOSYSTEM
    assert MODEL_BY_ECOSYSTEM == {"pypi": "opus", "cargo": "opus", "maven": "opus"}


def test_cache_fills_in_the_answering_model(app, tmp_path, monkeypatch):
    class _Endpoint(_Fixed):
        def answer_model(self):
            return QWEN
    old = JudgeResult(Verdict.NOT_REACHABLE, 0.95, "workstation")       # cached before `model`
    j = CachedJudge(_Endpoint("workstation", old), cache_dir=str(tmp_path))
    j.judge(_q(app))
    r = CachedJudge(_Endpoint("workstation", None), cache_dir=str(tmp_path)).judge(_q(app))
    assert r.cached and r.model == QWEN


def test_spec_parents_left_out_are_asked_once(tmp_path, monkeypatch):
    # tar reached only via bcrypt (dvws-node, all10-r7): the spec never said whether bcrypt
    # reaches tar, so the connect guard kept every not_reachable at unsure
    from doublestrain.judges.split import build_spec
    tar, bc = tmp_path / "tar@4.4.1", tmp_path / "bcrypt@3.0.0"
    tar.mkdir(); bc.mkdir()
    (tar / "index.js").write_text("module.exports = function extract (opt) { return unpack(opt) }\n")
    (bc / "bcrypt.js").write_text("module.exports.hash = function hash (s) { return binding.hash(s) }\n")
    spec = {"triggers": [{"package": "tar@4.4.1", "entry": "tar.x(opt)", "condition": "none", "input": "archive",
                          "trace": [{"path": "tar@4.4.1/index.js", "line": 1,
                                     "quote": "module.exports = function extract (opt) { return unpack(opt) }"}]}],
            "not_triggerable": False, "confidence": 0.9, "rationale": "r", "parents": []}
    parents = {"parents": [{"package": "bcrypt@3.0.0", "reaches": False, "trace": [],
                            "how": "tar is used only by node-pre-gyp at install time"}]}
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _seq_claude(tmp_path, [spec, parents]))
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "cache"))
    q = ReachQuery(repo_path=str(tmp_path), ecosystem="npm", dependency="tar", version="4.4.1", cve="CVE-T")
    sources = [("tar@4.4.1", tar), ("bcrypt@3.0.0", bc)]
    got, _ = build_spec(q, sources, "sonnet", 30)
    calls = _calls(tmp_path)
    assert len(calls) == 2 and "only for: bcrypt" in calls[1]["stdin"]
    assert got["parents"] == [{"package": "bcrypt", "reaches": False, "verified": [], "completed": True,
                               "how": "tar is used only by node-pre-gyp at install time"}]
    assert got["parents_checked"]
    build_spec(q, sources, "sonnet", 30)                              # cached and checked: no call
    assert len(_calls(tmp_path)) == 2


def test_a_reaching_parent_without_an_entry_point_becomes_a_trigger():
    from doublestrain.judges.split import with_parent_triggers
    step = "yargs@15.4.1/lib/usage.js:10"
    spec = {"triggers": [{"package": "ansi-regex@5.0.0", "entry": "ansiRegex()", "condition": "none", "input": "x"}],
            "not_triggerable": False,
            "parents": [{"package": "yargs", "reaches": True, "how": "help text goes through cliui's stripAnsi",
                         "verified": [step]},
                        {"package": "nodemon", "reaches": True, "how": "claimed, nothing checked", "verified": []},
                        {"package": "typeorm", "reaches": False, "how": "CLI only", "verified": []}]}
    out = with_parent_triggers(spec)
    added = out["triggers"][1:]
    assert [t["package"] for t in added] == ["yargs"] and added[0]["condition"].startswith("help text")
    assert spec["triggers"] == out["triggers"][:1] and len(spec["triggers"]) == 1     # cached spec untouched
    assert with_parent_triggers({"triggers": [], "parents": []}) == {"triggers": [], "parents": []}


def test_local_judge_keys_a_non_baseline_quant(monkeypatch):
    # 2026-10-24: a Q6_K switch under the same model id wrote answers into the Q4 cache
    from doublestrain.judges.local import OpenAIJudge
    monkeypatch.setenv("SSVC_WORKSTATION_BASE_URL", "http://192.0.2.1:1234/v1")
    quant = {"q": "Q4_K_M"}

    def fake(self, path, payload, timeout, root=None):
        if path == "/models":
            return {"data": [{"id": "qwen/x"}]}
        assert root == "http://192.0.2.1:1234" and path == "/api/v0/models"
        return {"data": [{"id": "other", "state": "loaded", "quantization": "F16"},
                         {"id": "qwen/x", "state": "loaded", "quantization": quant["q"]}]}
    monkeypatch.setattr(OpenAIJudge, "_req", fake)
    base = OpenAIJudge("workstation").fingerprint()
    assert base.endswith("@ctx" + str(__import__("doublestrain.judges.local", fromlist=["x"]).CONTEXT_VERSION))  # baseline: older keys
    quant["q"] = "Q6_K"
    assert OpenAIJudge("workstation").fingerprint() == base + "@qQ6_K"

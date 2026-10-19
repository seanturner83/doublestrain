"""Mitigation agent: playbook floor, defeat-spec verification and refusals, localisation,
selection by exploit signal. Offline: claude is faked."""
import json
import stat
import sys
from pathlib import Path

import pytest

from doublestrain import mitigate
from doublestrain.judges.base import ReachQuery


def test_playbook_by_cwe_and_wording_never_empty():
    pp = mitigate.playbook(["CWE-1321"], "")
    assert any("__proto__" in c for c in pp)
    assert any("length" in c for c in mitigate.playbook([], "a ReDoS in the parser"))
    assert mitigate.playbook([], "something new") == mitigate.GENERIC


def test_exploit_signals():
    enr = {"CVE-1": {"kev": True, "kev_ransomware": "Known", "epss": 0.02}, "CVE-2": {"kev": False, "epss": 0.4}}
    assert mitigate.exploit_signals(["CVE-1"], [], enr) == ["KEV CVE-1 (ransomware)"]
    assert mitigate.exploit_signals(["CVE-2"], [], enr) == ["EPSS 0.40 CVE-2"]
    assert mitigate.exploit_signals(["GHSA-x"], [{"references": [{"type": "EVIDENCE", "url": "u"}]}], {}) == \
        ["OSV evidence reference"]
    assert mitigate.exploit_signals(["CVE-3"], [], {}) == []


@pytest.fixture
def src(tmp_path, monkeypatch):
    d = tmp_path / "pkgsrc" / "body-parser@1.18.2-abc"
    (d / "lib").mkdir(parents=True)
    (d / "lib" / "urlencoded.js").write_text("function urlencoded(opts) {\n  var extended = opts.extended;\n"
                                             "  return extended ? qs.parse(body) : querystring.parse(body);\n}\n")
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "cache" / "triggers"))
    return [("body-parser@1.18.2", d)]


def _claude(tmp_path, by_model):
    script, state = tmp_path / "claude", tmp_path / "calls.json"
    state.write_text("[]")
    script.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        f"calls = json.load(open({str(state)!r}))\n"
        "model = sys.argv[sys.argv.index('--model') + 1]\n"
        "calls.append({'model': model, 'stdin': sys.stdin.read(), 'cwd': os.getcwd(), 'argv': sys.argv[1:]})\n"
        f"json.dump(calls, open({str(state)!r}, 'w'))\n"
        f"a = {by_model!r}[model]\n"
        "env = {'type': 'result', 'total_cost_usd': 0.05, 'is_error': False, 'stop_reason': 'end_turn',\n"
        "       'safety_stops': 0, 'modelUsage': {'claude-' + model: {}}}\n"
        "env.update(a['_env'] if '_env' in a else {'structured_output': a, 'result': ''})\n"
        "print(json.dumps(env))\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


GOOD = {"path": "body-parser@1.18.2/lib/urlencoded.js", "line": 3,
        "quote": "return extended ? qs.parse(body) : querystring.parse(body);"}
DEFEAT = {"controls": [
    {"kind": "set_option", "applies_to": "bodyParser.urlencoded(options)", "setting": "extended: false",
     "why": "qs only runs when extended", "trace": [GOOD], "side_effects": "no nested objects", "confidence": 0.9},
    {"kind": "limit_input", "applies_to": "bodyParser.urlencoded(options)", "setting": "parameterLimit 100",
     "why": "w", "trace": [{**GOOD, "quote": "not in the file at all"}], "side_effects": "", "confidence": 0.95}],
    "residual": "query strings still use qs via express"}
SPEC = {"triggers": [{"package": "body-parser@1.18.2", "entry": "bodyParser.urlencoded(options)",
                      "condition": "extended: true", "input": "urlencoded body", "verified": []}]}
Q = ReachQuery(repo_path=".", ecosystem="npm", dependency="body-parser", version="1.18.2", cve="CVE-X",
               advisory="qs prototype pollution")


def test_defeat_controls_are_checked_and_cached(tmp_path, monkeypatch, src):
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _claude(tmp_path, {"opus": DEFEAT}))
    d, cost = mitigate.build_defeat(Q, src, SPEC, "opus", 30)
    call, = json.loads((tmp_path / "calls.json").read_text())
    assert Path(call["cwd"]).resolve() == src[0][1].resolve() and "--restricted" in call["argv"]
    assert "extended: true" in call["stdin"]                         # the trigger spec is the input
    assert [c["setting"] for c in d["controls"]] == ["extended: false", "parameterLimit 100"]
    assert d["controls"][0]["verified"] and not d["controls"][1]["verified"]   # unverified sorts last
    assert mitigate.build_defeat(Q, src, SPEC, "opus", 30)[1] == 0.0          # cached: no second call
    assert len(json.loads((tmp_path / "calls.json").read_text())) == 1


def test_defeat_refusal_falls_back_then_no_spec(tmp_path, monkeypatch, src):
    refuse = {"_env": {"stop_reason": "refusal", "result": ""}}
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _claude(tmp_path, {"opus": refuse, "claude-opus-4-6": DEFEAT}))
    d, _ = mitigate.build_defeat(Q, src, SPEC, "opus", 30, fallback=("claude-opus-4-6",))
    assert "opus refused" in d["refusals"]
    monkeypatch.setenv("SSVC_SPEC_CACHE", str(tmp_path / "cache2" / "triggers"))
    monkeypatch.setenv("SSVC_CLAUDE_BIN", _claude(tmp_path, {"opus": refuse, "claude-opus-4-6": refuse}))
    assert mitigate.build_defeat(Q, src, SPEC, "opus", 30, fallback=("claude-opus-4-6",))[0] is None


def test_schema_has_no_room_for_payloads():
    fields = set(mitigate._CONTROL["properties"])
    assert not fields & {"payload", "exploit", "poc", "reproduction", "steps"}


def test_localise_names_app_call_sites(tmp_path):
    app = tmp_path / "app"
    (app / "src").mkdir(parents=True)
    (app / "src" / "main.js").write_text("const bodyParser = require('body-parser');\nconst app = require('express')();\n"
                                         "app.use(bodyParser.urlencoded({ extended: true }));\n")
    out = mitigate.localise(str(app), ["body-parser", "express"], "body-parser",
                            [DEFEAT["controls"][0]], SPEC["triggers"])
    site, = out[0]["sites"]
    assert site["where"] == ["src/main.js:3"] and "urlencoded({extended: true})" in site["call"]


def test_short_package_names_fall_back_to_package_calls(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "app.js").write_text("var st = require('st');\nvar app = require('express')();\n"
                                "app.use(st({ path: './public', url: '/public' }));\n")
    out = mitigate.localise(str(app), ["st", "express"], "st",
                            [{"kind": "set_option", "applies_to": "st(path[, url][, opts])", "setting": "index: false"}], [])
    assert out[0]["sites"][0]["where"] == ["app.js:3"]


def test_transitive_package_localises_via_its_parent(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "app.js").write_text("var express = require('express');\nvar app = express();\n")
    out = mitigate.localise(str(app), ["qs", "express"], "qs",
                            [{"kind": "limit_input", "applies_to": "qs.parse(str, opts)", "setting": "x"}], [])
    site = out[0]["sites"][0]
    assert site["via"] == "express" and site["where"] == ["app.js:2"]

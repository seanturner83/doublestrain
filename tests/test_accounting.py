"""Usage ledger: every model call is tagged and counted; no prompt or answer text."""
import json

from ssvc_triage import accounting
from ssvc_triage.judges import claude_code as cc


def test_claude_call_is_recorded_with_tags_and_no_content(tmp_path, monkeypatch):
    env = {"total_cost_usd": 0.12, "num_turns": 3, "session_id": "s-1",
           "usage": {"input_tokens": 10, "output_tokens": 20, "cache_read_input_tokens": 300},
           "structured_output": {"verdict": "unsure", "rationale": "SECRET-ANSWER"}}

    class P:
        stdout, stderr, returncode = json.dumps(env), "", 0
    monkeypatch.setattr(cc.subprocess, "run", lambda *a, **k: P())
    accounting.start("ssvc-test", "run-1")
    with accounting.tag(case="c1"), accounting.tag(cve="CVE-1", package="pkg"):
        assert cc.run_claude("claude", "SECRET-PROMPT", "sys", {}, cwd=tmp_path, model="opus",
                             timeout=5, purpose="shape")
    text = (tmp_path / "accounting.jsonl").read_text()
    assert "SECRET" not in text
    d = json.loads(text)
    assert {k: d[k] for k in ("tool", "run", "case", "cve", "package", "kind", "purpose", "model", "outcome")} == {
        "tool": "ssvc-test", "run": "run-1", "case": "c1", "cve": "CVE-1", "package": "pkg",
        "kind": "claude", "purpose": "shape", "model": "opus", "outcome": "ok"}
    assert d["cost_usd"] == 0.12 and d["cache_read_tokens"] == 300 and d["session_id"] == "s-1"
    assert any(r["purpose"] == "shape" and r["calls"] == 1 for r in accounting.totals())


def test_limit_and_endpoint_calls_and_usage_report(tmp_path, monkeypatch, capsys):
    env = {"is_error": True, "result": "You've hit your session limit · resets 1:50pm (Europe/London)"}

    class P:
        stdout, stderr, returncode = json.dumps(env), "", 1
    monkeypatch.setattr(cc.subprocess, "run", lambda *a, **k: P())
    monkeypatch.setenv("SSVC_CLAUDE_WAIT_ON_LIMIT", "0")
    assert cc.run_claude("claude", "p", "s", {}, cwd=tmp_path, model="sonnet", timeout=5, purpose="spec") is None

    from ssvc_triage.judges.local import OpenAIJudge
    monkeypatch.setenv("SSVC_LOCAL_MODEL", "m")
    j = OpenAIJudge("local")
    monkeypatch.setattr(j, "_req", lambda *a: {"usage": {"prompt_tokens": 7, "completion_tokens": 3},
                                               "choices": [{"message": {"content": '{"verdict": "unsure"}'}}]})
    j.complete("s", "u", {"properties": {}}, purpose="match")
    lines = [json.loads(x) for x in (tmp_path / "accounting.jsonl").read_text().splitlines()]
    assert [(x["kind"], x["purpose"], x["outcome"]) for x in lines] == [("claude", "spec", "limit"),
                                                                      ("endpoint", "match", "ok")]
    assert lines[1]["input_tokens"] == 7 and lines[1]["endpoint"] == "local"
    assert accounting.main(["--since", "1h", "--by", "kind,purpose"]) == 0
    out = capsys.readouterr().out
    assert "claude" in out and "endpoint" in out and "match" in out


def test_ledger_off(tmp_path, monkeypatch):
    monkeypatch.setenv("SSVC_ACCOUNTING_LOG", "off")
    accounting.record("claude", "spec", model="m")
    assert not list(tmp_path.iterdir())

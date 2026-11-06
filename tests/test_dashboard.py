"""The dashboard's numbers: a cascade run's funnel, scores against labels, pipeline stages,
the ledger view (metadata only), and the Host check. Offline; the server binds a free
loopback port."""
import json
import threading
import urllib.error
import urllib.request

import pytest

from doublestrain.harness import dashboard as db


def _row(case, label, trail, final, settled="", src="", n=1):
    return {"case": case, "pr": f"local/{case}#{n}", "package": "p", "cve": "CVE-1",
            "expect": {"reachability": label} if label else {},
            "judge": {**final, "trail": trail},
            "got": {"reachability": settled or "unavailable", "reach_source": src,
                    "decision": "Track" if settled == "unreachable" else "Attend"}}


@pytest.fixture
def runs(tmp_path):
    d = tmp_path / "runs" / "20261104-090000-cascade-php1"
    d.mkdir(parents=True)
    rows = [
        # jelly unsure -> workstation NR (held, needs a second read) -> split NR settles: right
        _row("a", "not_reachable", [{"source": "jelly", "verdict": "unsure"},
                                    {"source": "workstation", "verdict": "not_reachable", "note": "not_reachable held: needs a second read"}],
             {"source": "split:workstation", "verdict": "not_reachable", "confidence": 0.95, "cost_usd": 0.1},
             "unreachable", "split:workstation"),
        # settles NR at split but the label says reachable: a wrong settle
        _row("a", "reachable", [{"source": "jelly", "verdict": "unsure"}, {"source": "workstation", "verdict": "unsure"}],
             {"source": "split:workstation", "verdict": "not_reachable", "confidence": 0.95}, "unreachable", "split:workstation", n=2),
        # nothing settles; the last tier's model is named in its source (shape:<model>)
        _row("b", "not_reachable", [{"source": "jelly", "verdict": "unsure"}, {"source": "workstation", "verdict": "unsure"},
                                    {"source": "split:workstation", "verdict": "unsure"}],
             {"source": "shape:claude-opus-5-5", "verdict": "unsure", "cost_usd": 0.3}),
    ]
    (d / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (d / "plan.json").write_text(json.dumps({"judge": "cascade:jelly,workstation,split:workstation,shape",
                                             "rows": 5, "cases": ["a", "b"]}))
    (tmp_path / "cases" / "a").mkdir(parents=True)
    (tmp_path / "cases" / "a" / "repo").mkdir()
    (tmp_path / "cases" / "a" / "repo" / "x.php").write_text("<?php\n")
    (tmp_path / "cases" / "a" / "case.json").write_text(json.dumps({
        "id": "a", "description": "A: PHP dev set (php1), labelled blind", "repo": "repo",
        "candidates": [{"pr": "local/a#1", "facts": {"ecosystem": "composer", "package": "psr/log", "version": "3.0.0"},
                        "expect": {"reachability": "not_reachable"}},
                       {"pr": "local/a#2", "facts": {"ecosystem": "composer", "package": "psr/log", "version": "3.0.0"},
                        "expect": {"reachability": "reachable"}}]}))
    return tmp_path


def test_funnel_follows_each_rows_trail(runs):
    s = db.Store(runs / "runs", runs / "cases")
    r = s.run_detail("20261104-090000-cascade-php1")
    f = {t["tier"]: t for t in r["funnel"]}
    assert [t["tier"] for t in r["funnel"]] == ["jelly", "workstation", "split:workstation", "shape"]
    assert f["jelly"]["entered"] == 3 and f["jelly"]["escalated"] == 3
    assert f["workstation"]["held"] == 1
    assert f["split:workstation"]["settled_not_reachable"] == 2 and f["split:workstation"]["wrong"] == 1
    assert f["shape"]["entered"] == 1 and f["shape"]["cost_usd"] == 0.3        # shape:<model> is the shape tier
    assert (r["nr_right"], r["nr_wrong"], r["nr_labels"], r["coverage"]) == (1, 1, 2, 0.5)
    # answered at the floor: split's 0.95 on both of case a's rows (case b has no case.json, so its own label stays)
    assert (r["said_right"], r["said_wrong"]) == (1, 1)
    assert r["running"] and r["rows"] == 3 and r["planned"] == 5               # plan.json, no summary yet
    assert s.run_detail("../../etc") is None


def test_pipeline_stages(runs, monkeypatch):
    cache = runs / "pkgsrc"
    cache.mkdir()
    (cache / f"composer+psr+log@3.0.0-{'a' * 12}.json").write_text("{}")
    monkeypatch.setenv("SSVC_PKGSRC_CACHE", str(cache))
    monkeypatch.setattr(db, "_SRC_INDEX", (0.0, set()))
    c = db.Store(runs / "runs", runs / "cases").pipeline()[0]
    assert (c["set"], c["rows"], c["packages"], c["sources"], c["labelled"], c["checked_out"]) == ("php1", 2, 1, 1, 2, True)
    assert c["last_run"] == "20261104-090000-cascade-php1" and c["last_nr_right"] == 1


def test_ledger_rows_carry_no_text(tmp_path, monkeypatch):
    p = tmp_path / "ledger.jsonl"
    p.write_text(json.dumps({"ts": "2099-01-01T00:00:00+00:00", "kind": "claude", "purpose": "judge", "model": "opus",
                             "prompt": "SECRET PROMPT", "cost_usd": 0.2}) + "\n")
    monkeypatch.setenv("SSVC_ACCOUNTING_LOG", str(p))
    from datetime import datetime, timezone
    rows = db.ledger_lines(datetime(2000, 1, 1, tzinfo=timezone.utc))
    assert rows[0]["dest"] == "anthropic (claude CLI)" and "prompt" not in rows[0]


def test_config_redacts_secrets(runs, monkeypatch):
    monkeypatch.setenv("SSVC_WORKSTATION_API_KEY", "wfr_x")
    monkeypatch.setenv("SSVC_WORKSTATION_BASE_URL", "https://example.invalid/v1")
    c = db.config(db.Store(runs / "runs", runs / "cases"))
    assert c["env"]["SSVC_WORKSTATION_API_KEY"] == "(set)"
    assert c["env"]["SSVC_WORKSTATION_BASE_URL"] == "https://example.invalid/v1"
    php = next(e for e in c["ecosystems"] if e["ecosystem"] == "composer")
    assert php["case_rows"] == 2 and php["labelled_rows"] == 2


def test_server_refuses_other_hosts(runs):
    from http.server import ThreadingHTTPServer
    store = db.Store(runs / "runs", runs / "cases")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = srv.server_address[1]
    srv.RequestHandlerClass = type("H", (db.Handler,), {"store": store, "port": port})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ok = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/runs", timeout=10).read())
        assert ok[0]["name"] == "20261104-090000-cascade-php1"
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/runs", headers={"Host": "evil.example"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=10)
        assert e.value.code == 403
    finally:
        srv.shutdown()


def test_runs_are_scored_against_the_current_labels(runs):
    cj = runs / "cases" / "a" / "case.json"
    d = json.loads(cj.read_text())
    d["candidates"][1]["expect"] = {"reachability": "not_reachable"}       # a re-review flips a#2
    cj.write_text(json.dumps(d))
    r = db.Store(runs / "runs", runs / "cases").run_detail("20261104-090000-cascade-php1")
    assert (r["nr_right"], r["nr_wrong"]) == (2, 0)

"""Harness smoke: the null judge over the shipped fixture cases (offline)."""
import json
from pathlib import Path

from doublestrain.harness import run

ROOT = Path(__file__).resolve().parent.parent


def test_null_run_over_fixture_cases(tmp_path, capsys):
    assert run.main(["--cases", str(ROOT / "cases"), "--judge", "null", "--out", str(tmp_path)]) == 0
    (run_dir,) = tmp_path.iterdir()
    s = json.loads((run_dir / "summary.json").read_text())
    rows = [json.loads(ln) for ln in (run_dir / "results.jsonl").read_text().splitlines()]
    labelled = [r for r in rows if r["expect"].get("reachability")]
    assert s["labelled"] == len(labelled) >= 10       # OSV-generated real-* cases may be unlabelled
    # no judge -> nothing resolved, nothing wrongly suppressed
    assert s["resolved"] == 0 and s["false_not_reachable"] == 0
    # every not_reachable case is over-escalated without a judge (that's the gap judges close)
    nr = [r for r in labelled if r["expect"]["reachability"] == "not_reachable"]
    assert nr and all(r["got"]["decision"] != r["oracle_decision"] for r in nr)


def test_workers_write_the_same_rows_in_the_same_order(tmp_path):
    import json
    outs = []
    for w in ("1", "4"):
        out = tmp_path / w
        assert run.main(["--cases", str(ROOT / "cases"), "--judge", "null", "--out", str(out),
                         "--workers", w, "--case", "npm-qs-parse", "--case", "npm-lodash-template-used"]) == 0
        rows = [json.loads(l) for l in next(out.glob("*/results.jsonl")).read_text().splitlines()]
        outs.append([(r["case"], r["pr"], r["got"]["decision"]) for r in rows])
    assert outs[0] == outs[1] and outs[0]


def test_concurrent_rows_ask_a_cached_question_once(tmp_path):
    import threading
    import time as _t
    from doublestrain.judges import CachedJudge, JudgeResult, ReachQuery, Verdict

    class Slow:
        name, calls = "slow", 0

        def fingerprint(self):
            return "slow"

        def judge(self, q):
            Slow.calls += 1
            _t.sleep(0.2)
            return JudgeResult(Verdict.REACHABLE, 0.9, "slow")
    j = CachedJudge(Slow(), cache_dir=str(tmp_path))
    q = ReachQuery("/x", "npm", "qs", "CVE-1")
    ts = [threading.Thread(target=j.judge, args=(q,)) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert Slow.calls == 1


def test_claude_concurrency_cap(monkeypatch):
    import threading
    import time as _t
    from doublestrain.judges import claude_code
    monkeypatch.setenv("SSVC_CLAUDE_CONCURRENCY", "2")
    monkeypatch.setattr(claude_code, "_SEM", [])
    live, peak, lock = [0], [0], threading.Lock()

    def call():
        with claude_code._claude_slot():
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
            _t.sleep(0.05)
            with lock:
                live[0] -= 1
    ts = [threading.Thread(target=call) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert peak[0] == 2

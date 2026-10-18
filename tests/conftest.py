import pytest


@pytest.fixture(autouse=True)
def _private_ledger(tmp_path, monkeypatch):
    """Tests never write to the real usage ledger."""
    monkeypatch.setenv("SSVC_ACCOUNTING_LOG", str(tmp_path / "accounting.jsonl"))

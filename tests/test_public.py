from triage.core import (
    normalize_path,
    load_semgrep_sarif,
    load_bandit,
    dedupe,
    gate
)

def test_normalize_path():
    assert normalize_path("diwan_invoicing\\invoicing\\web.py", "diwan_invoicing") == "invoicing/web.py"
    assert normalize_path("file:///home/runner/work/diwan_invoicing/diwan_invoicing/invoicing/web.py", "diwan_invoicing") == "invoicing/web.py"
    assert normalize_path("./invoicing/web.py", "diwan_invoicing") == "invoicing/web.py"

def test_load_fixtures():
    semgrep_findings = load_semgrep_sarif("fixtures/semgrep.sarif", "diwan_invoicing")
    bandit_findings = load_bandit("fixtures/bandit.json", "diwan_invoicing")
    assert len(semgrep_findings) > 0
    assert len(bandit_findings) > 0

def test_dedupe_and_gate():
    semgrep_findings = load_semgrep_sarif("fixtures/semgrep.sarif", "diwan_invoicing")
    bandit_findings = load_bandit("fixtures/bandit.json", "diwan_invoicing")
    groups = dedupe(semgrep_findings + bandit_findings)
    assert len(groups) == 2
    res = gate(groups, "high")
    assert res is False

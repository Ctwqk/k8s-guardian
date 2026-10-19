from __future__ import annotations

import json
from pathlib import Path

from k8s_guardian.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_check_policy_prints_a_summary(capsys):
    assert main(["check-policy", str(EXAMPLES / "policy.demo.yaml")]) == 0
    out = capsys.readouterr().out
    assert "demo-1" in out and "writable: demo" in out and "payments-*" in out


def test_check_policy_rejects_a_dangerous_file(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("writable_namespaces: ['*']\n")
    assert main(["check-policy", str(bad)]) == 2
    assert "exact names" in capsys.readouterr().err


def test_check_policy_rejects_unknown_actions(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - {namespace: '*', workload: '*', allowed_actions: [delete_pod]}\n")
    assert main(["check-policy", str(bad)]) == 2


def test_once_against_the_fake_backend(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("GUARDIAN_BACKEND", "fake")
    monkeypatch.setenv("GUARDIAN_DB_PATH", str(tmp_path / "g.db"))
    monkeypatch.setenv("GUARDIAN_POLICY_FILE", str(EXAMPLES / "policy.demo.yaml"))
    assert main(["once"]) == 0
    out = capsys.readouterr().out
    report = json.loads(out[out.index("{") :])
    outcomes = {d["target"]: d["outcome"] for d in report["decisions"]}
    assert outcomes == {
        "demo/batch-worker": "skipped",
        "demo/crashy-api": "dry_run",
        "demo/payments-executor": "blocked_policy",
    }


def test_invalid_configuration_exits_with_status_2(monkeypatch, capsys):
    monkeypatch.setenv("GUARDIAN_ANALYZER", "llm")  # without endpoint / models
    assert main(["once"]) == 2
    assert "GUARDIAN_LLM_BASE_URL" in capsys.readouterr().err

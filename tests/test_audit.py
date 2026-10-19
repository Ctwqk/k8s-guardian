from __future__ import annotations

from k8s_guardian.audit import AuditLog
from k8s_guardian.models import ClusterSnapshot, Outcome

from .conftest import NOW, make_pod


def rec(audit: AuditLog, ts: float, target: str = "demo/api", result: Outcome = Outcome.EXECUTED, **kw) -> int:
    return audit.record(
        ts=ts,
        rule="crash_loop",
        severity="high",
        target=target,
        namespace="demo",
        details="d",
        action="rollout_restart",
        result=result,
        dry_run=kw.pop("dry_run", False),
        **kw,
    )


def test_only_live_attempts_count_towards_cooldown_and_budget(audit):
    rec(audit, NOW - 50, result=Outcome.DRY_RUN)
    rec(audit, NOW - 40, result=Outcome.BLOCKED_POLICY)
    rec(audit, NOW - 30, result=Outcome.COOLDOWN)
    assert audit.last_attempt_ts("demo/api") is None
    assert audit.attempts_since(NOW - 3600) == 0

    rec(audit, NOW - 20, result=Outcome.EXECUTED)
    rec(audit, NOW - 10, target="demo/web", result=Outcome.FAILED)
    assert audit.last_attempt_ts("demo/api") == NOW - 20
    assert audit.attempts_since(NOW - 3600) == 2
    assert audit.attempts_since(NOW - 15) == 1  # window boundary


def test_write_ahead_row_counts_until_it_is_settled(audit):
    row = rec(audit, NOW, result=Outcome.ALLOWED)
    assert audit.attempts_since(NOW - 1) == 1  # a crash mid-action still consumes budget
    audit.finish(row, Outcome.DRY_RUN, reason="dry-run", command="rollout restart deployment/api -n demo")
    assert audit.attempts_since(NOW - 1) == 0
    [entry] = audit.recent()
    assert entry["result"] == "dry_run" and entry["command"].startswith("rollout restart")


def test_recent_is_newest_first_and_filterable(audit):
    rec(audit, NOW - 3, target="demo/a")
    rec(audit, NOW - 2, target="demo/b")
    rec(audit, NOW - 1, target="demo/a")
    assert [r["ts"] for r in audit.recent()] == [NOW - 1, NOW - 2, NOW - 3]
    assert [r["target"] for r in audit.recent(target="demo/a")] == ["demo/a", "demo/a"]
    assert len(audit.recent(limit=1, offset=1)) == 1
    assert audit.count() == 3


def test_cooldown_targets(audit):
    rec(audit, NOW - 100, target="demo/a")
    rec(audit, NOW - 5000, target="demo/old")
    rec(audit, NOW - 50, target="demo/dry", result=Outcome.DRY_RUN)
    assert audit.cooldown_targets(NOW, 600) == {"demo/a": NOW - 100}


def snapshot(restarts: int) -> ClusterSnapshot:
    return ClusterSnapshot(pods=[make_pod(restarts=restarts)])


def test_restart_baseline_prefers_a_snapshot_at_least_an_hour_old(audit):
    audit.save_snapshot(NOW - 7200, snapshot(1), 0)
    audit.save_snapshot(NOW - 3700, snapshot(2), 0)
    audit.save_snapshot(NOW - 600, snapshot(9), 0)
    assert audit.restart_baseline(NOW) == {"demo/web-6d5f7c9b8-abcde": 2}


def test_restart_baseline_falls_back_to_the_oldest_when_history_is_short(audit):
    assert audit.restart_baseline(NOW) is None
    audit.save_snapshot(NOW - 900, snapshot(3), 0)
    audit.save_snapshot(NOW - 100, snapshot(4), 0)
    assert audit.restart_baseline(NOW) == {"demo/web-6d5f7c9b8-abcde": 3}
    assert audit.last_snapshot_ts() == NOW - 100


def test_prune_drops_old_rows(audit):
    rec(audit, NOW - 10 * 86400)
    rec(audit, NOW - 100)
    audit.save_snapshot(NOW - 10 * 86400, snapshot(1), 0)
    audit.prune(NOW, retention_days=7)
    assert audit.count() == 1
    assert audit.restart_baseline(NOW) is None


def test_database_persists_across_reopen(tmp_path):
    path = tmp_path / "nested" / "dir" / "a.db"
    first = AuditLog(path)
    rec(first, NOW)
    first.close()
    second = AuditLog(path)
    assert second.last_attempt_ts("demo/api") == NOW  # cooldowns survive a restart
    second.close()


def test_interrupted_dry_run_never_consumes_live_limits_after_reopen(tmp_path):
    path = tmp_path / "interrupted.db"
    with_dry_run = AuditLog(path)
    rec(with_dry_run, NOW, result=Outcome.ALLOWED, dry_run=True)
    with_dry_run.close()  # interrupted before finish(), like a process exit
    reopened = AuditLog(path)
    try:
        assert reopened.attempts_since(NOW - 3600) == 0
        assert reopened.last_attempt_ts("demo/api") is None
        assert reopened.cooldown_targets(NOW, 600) == {}
        rec(reopened, NOW + 1, result=Outcome.ALLOWED, dry_run=False)
        assert reopened.attempts_since(NOW - 3600) == 1
        assert reopened.last_attempt_ts("demo/api") == NOW + 1
        assert reopened.cooldown_targets(NOW + 1, 600) == {"demo/api": NOW + 1}
    finally:
        reopened.close()

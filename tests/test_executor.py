from __future__ import annotations

import pytest

from k8s_guardian.cluster.fake import FakeCluster
from k8s_guardian.executor import Executor
from k8s_guardian.models import Outcome, PolicyVerdict


def verdict(**kw) -> PolicyVerdict:
    base = dict(
        allowed=True,
        outcome=Outcome.ALLOWED,
        reason="ok",
        action="rollout_restart",
        namespace="demo",
        workload="api",
        target="demo/api",
    )
    base.update(kw)
    return PolicyVerdict(**base)


async def test_dry_run_never_touches_the_cluster():
    cluster = FakeCluster()
    result = await Executor(cluster, dry_run=True).execute(verdict())
    assert result.outcome is Outcome.DRY_RUN
    assert result.command == "rollout restart deployment/api -n demo"
    assert cluster.restarts == []


async def test_live_run_restarts_exactly_the_approved_deployment():
    cluster = FakeCluster()
    result = await Executor(cluster, dry_run=False).execute(verdict())
    assert result.outcome is Outcome.EXECUTED
    assert cluster.restarts == [("demo", "api")]


async def test_backend_failures_are_reported_not_raised():
    cluster = FakeCluster()
    cluster.fail_restart = True
    result = await Executor(cluster, dry_run=False).execute(verdict())
    assert result.outcome is Outcome.FAILED and "fake restart failure" in result.message


async def test_unexpected_exceptions_are_also_captured():
    cluster = FakeCluster()
    cluster.on_restart = lambda ns, name: (_ for _ in ()).throw(RuntimeError("kaboom"))
    result = await Executor(cluster, dry_run=False).execute(verdict())
    assert result.outcome is Outcome.FAILED and "RuntimeError" in result.message


@pytest.mark.parametrize(
    "bad",
    [
        dict(allowed=False, outcome=Outcome.BLOCKED_POLICY),
        dict(action="do_nothing"),
        dict(action="delete_pod"),
        dict(workload="api; rm -rf /"),
        dict(namespace="Demo NS"),
    ],
)
async def test_executor_refuses_anything_the_gate_did_not_approve(bad):
    cluster = FakeCluster()
    with pytest.raises(ValueError):
        await Executor(cluster, dry_run=False).execute(verdict(**bad))
    assert cluster.restarts == []

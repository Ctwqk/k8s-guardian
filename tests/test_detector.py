from __future__ import annotations

import pytest

from k8s_guardian.detector import Detector, merge_by_target
from k8s_guardian.models import ClusterSnapshot, DeploymentInfo, NodeInfo, Severity

from .conftest import NOW, make_pod


def detect(pods=(), deployments=(), nodes=(), *, detector=None, now=NOW, baseline=None):
    snap = ClusterSnapshot(pods=list(pods), deployments=list(deployments), nodes=list(nodes))
    return (detector or Detector()).detect(snap, now, baseline)


def rules(anomalies):
    return sorted((a.target, a.rule) for a in anomalies)


def test_healthy_cluster_has_no_anomalies():
    assert detect([make_pod()], [DeploymentInfo(name="web", namespace="demo", available=1)]) == []


def test_crash_loop_is_high_and_actionable_for_deployments():
    [a] = detect([make_pod("api-1", deploy="api", status="CrashLoopBackOff", restarts=4)])
    assert (a.rule, a.severity, a.target) == ("crash_loop", Severity.HIGH, "demo/api")
    assert a.actionable and a.owner_kind == "Deployment" and a.pod_name == "api-1"


def test_crash_loop_in_statefulset_is_not_actionable():
    [a] = detect([make_pod("redis-0", deploy="redis", owner_kind="StatefulSet", status="CrashLoopBackOff", restarts=2)])
    assert a.rule == "crash_loop" and not a.actionable


def test_ownerless_pod_is_never_actionable():
    [a] = detect([make_pod("lonely", deploy="", owner_kind="", status="CrashLoopBackOff")])
    assert a.target == "demo/lonely" and not a.actionable


def test_oom_killed_beats_crash_loop_when_last_termination_was_oom():
    pod = make_pod("api-1", deploy="api", status="CrashLoopBackOff", restarts=3, last_terminated_reason="OOMKilled")
    [a] = detect([pod])
    assert a.rule == "oom_killed"
    assert not a.actionable  # a restart cannot raise a memory limit: humans only


def test_old_oom_on_a_healthy_pod_is_not_an_anomaly():
    assert detect([make_pod(restarts=1, last_terminated_reason="OOMKilled")]) == []


def test_image_pull_failure_is_medium_and_never_actionable():
    pod = make_pod("api-1", deploy="api", status="ImagePullBackOff", phase="Pending", waiting_reason="ImagePullBackOff")
    [a] = detect([pod])
    assert (a.rule, a.severity, a.actionable) == ("image_pull_fail", Severity.MEDIUM, False)


def test_stuck_pending_needs_to_exceed_the_timeout():
    young = make_pod("api-1", deploy="api", status="pending", phase="Pending", age_seconds=60)
    old = make_pod("api-2", deploy="api", status="pending", phase="Pending", age_seconds=900)
    assert detect([young]) == []
    [a] = detect([old])
    assert a.rule == "stuck_pending" and "900s" in a.details


def test_pending_with_container_creating_is_also_caught():
    pod = make_pod("api-1", deploy="api", status="ContainerCreating", phase="Pending", age_seconds=900)
    assert [a.rule for a in detect([pod])] == ["stuck_pending"]


def test_restart_flapping_uses_the_baseline_delta():
    pod = make_pod("api-1", deploy="api", restarts=12)
    assert detect([pod], baseline={"demo/api-1": 8}) == []  # +4 < 5
    [a] = detect([pod], baseline={"demo/api-1": 6})  # +6
    assert a.rule == "restart_flapping" and "6 times" in a.details


def test_flapping_is_not_assessed_without_history():
    assert detect([make_pod(restarts=50)], baseline=None) == []


def test_new_pod_missing_from_the_baseline_counts_from_zero():
    assert [a.rule for a in detect([make_pod(restarts=6)], baseline={})] == ["restart_flapping"]


def test_replica_mismatch_waits_for_the_grace_period():
    det = Detector(replica_mismatch_grace_seconds=120)
    dep = DeploymentInfo(name="api", namespace="demo", desired=2, available=1)
    assert detect(deployments=[dep], detector=det, now=NOW) == []
    assert detect(deployments=[dep], detector=det, now=NOW + 100) == []
    [a] = detect(deployments=[dep], detector=det, now=NOW + 121)
    assert (a.rule, a.severity, a.actionable) == ("replica_mismatch", Severity.HIGH, True)


def test_replica_mismatch_timer_resets_when_the_deployment_recovers():
    det = Detector(replica_mismatch_grace_seconds=120)
    bad = DeploymentInfo(name="api", namespace="demo", desired=1, available=0)
    good = DeploymentInfo(name="api", namespace="demo", desired=1, available=1)
    detect(deployments=[bad], detector=det, now=NOW)
    detect(deployments=[good], detector=det, now=NOW + 60)
    assert detect(deployments=[bad], detector=det, now=NOW + 200) == []  # timer restarted at +200


def test_node_pressure_and_not_ready():
    nodes = [
        NodeInfo(name="n1", ready="True", disk_pressure=True),
        NodeInfo(name="n2", ready="False"),
        NodeInfo(name="n3", ready="True"),
    ]
    found = detect(nodes=nodes)
    assert rules(found) == [("node/n1", "node_pressure"), ("node/n2", "node_pressure")]
    assert all(not a.actionable for a in found)
    assert "DiskPressure" in found[0].details or "DiskPressure" in found[1].details


def test_duplicates_collapse_per_target_and_rule_and_order_is_by_severity():
    pods = [
        make_pod("api-1", deploy="api", status="CrashLoopBackOff", restarts=2),
        make_pod("api-2", deploy="api", status="CrashLoopBackOff", restarts=9),
        make_pod("img-1", deploy="img", status="ErrImagePull", phase="Pending", waiting_reason="ErrImagePull"),
    ]
    found = detect(pods)
    assert rules(found) == [("demo/api", "crash_loop"), ("demo/img", "image_pull_fail")]
    assert [a.severity for a in found] == [Severity.HIGH, Severity.MEDIUM]


def test_merge_by_target_gives_a_workload_one_anomaly_led_by_the_most_specific_rule():
    pods = [make_pod("api-1", deploy="api", status="CrashLoopBackOff", restarts=9, last_terminated_reason="OOMKilled")]
    deployments = [DeploymentInfo(name="api", namespace="demo", desired=1, available=0)]
    det = Detector(replica_mismatch_grace_seconds=0)
    detect(pods, deployments, detector=det, now=NOW)
    found = detect(pods, deployments, detector=det, now=NOW + 1, baseline={"demo/api-1": 0})
    assert {a.rule for a in found} == {"oom_killed", "replica_mismatch", "restart_flapping"}

    [merged] = merge_by_target(found)
    assert merged.rule == "oom_killed" and merged.severity is Severity.HIGH
    assert "replica_mismatch" in merged.details and "restart_flapping" in merged.details


def test_merge_by_target_keeps_distinct_targets_ordered_by_severity():
    pods = [
        make_pod("img-1", deploy="img", status="ErrImagePull", phase="Pending", waiting_reason="ErrImagePull"),
        make_pod("api-1", deploy="api", status="CrashLoopBackOff", restarts=2),
    ]
    assert [a.target for a in merge_by_target(detect(pods))] == ["demo/api", "demo/img"]


def test_crash_loop_is_still_detected_between_backoff_waits():
    """Real clusters flicker: the container is Terminated(Error) or Running, not Waiting(CrashLoopBackOff)."""
    pod = make_pod("api-1", deploy="api", status="not_ready", restarts=4, terminated_reason="Error", phase="Running")
    [a] = detect([pod])
    assert a.rule == "crash_loop" and "keeps crashing (Error)" in a.details


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(restarts=2, terminated_reason="Error"),  # too few restarts to call it a loop
        dict(restarts=9, terminated_reason="Completed"),  # clean exits are not crashes
        dict(restarts=9, status="running"),  # currently healthy: flapping covers this, not crash_loop
        dict(restarts=9, terminated_reason="Error", phase="Succeeded"),  # finished Job pod
    ],
)
def test_repeated_restarts_that_are_not_a_crash_loop(kwargs):
    base = dict(deploy="api", status="not_ready", phase="Running")
    base.update(kwargs)
    assert [a.rule for a in detect([make_pod("api-1", **base)])] == []

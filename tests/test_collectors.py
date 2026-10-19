from __future__ import annotations

from k8s_guardian.cluster.base import ClusterError
from k8s_guardian.cluster.fake import FakeCluster
from k8s_guardian.collectors import (
    LogBundle,
    PodLog,
    collect_logs,
    collect_snapshot,
    filter_log_text,
    find_error_lines,
    redact,
)
from k8s_guardian.models import Anomaly, DeploymentInfo, NodeInfo, Severity

from .conftest import make_pod, make_policy


def test_filter_removes_probe_noise_and_blank_lines():
    raw = '\n10.0.0.1 "GET /healthz HTTP/1.1" 200\nreal line\n\nGET /readyz\n'
    assert filter_log_text(raw) == "real line"


def test_filter_collapses_consecutive_duplicates():
    raw = "a\nb\nb\nb\nc\nc"
    assert filter_log_text(raw).splitlines() == [
        "a",
        "b",
        "  [... repeated 2 more times]",
        "c",
        "  [... repeated 1 more times]",
    ]


def test_find_error_lines():
    text = "all good\nERROR: boom\nTraceback (most recent call last):\nfatal problem\nFATAL: x"
    found = find_error_lines(text)
    assert "ERROR: boom" in found and "FATAL: x" in found
    assert "all good" not in found
    assert "Traceback (most recent call last):" in found


def test_redact_secrets():
    cases = [
        ("Authorization: Bearer abcdefghijklmnop1234", "abcdefghijklmnop1234"),
        ("password=hunter2hunter2", "hunter2hunter2"),
        ('{"api_key": "sk-live-abcdefghijklmnopqrstuv"}', "abcdefghijklmnopqrstuv"),
        ("connect postgres://app:s3cr3tpw@db:5432/x", "s3cr3tpw"),
        ("key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
        (
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "dozjgNryP4J3",
        ),
    ]
    for line, secret in cases:
        assert secret not in redact(line), line
    assert redact("connect postgres://app:s3cr3tpw@db:5432/x").startswith("connect postgres://[REDACTED]@db")


def test_redact_leaves_ordinary_lines_alone():
    line = "ERROR: cannot connect to redis:6379 (connection refused)"
    assert redact(line) == line


def test_collect_snapshot_filters_by_policy_watch_scope():
    cluster = FakeCluster(
        pods=[make_pod(), make_pod("coredns-1", namespace="kube-system", deploy="coredns")],
        deployments=[
            DeploymentInfo(name="web", namespace="demo"),
            DeploymentInfo(name="coredns", namespace="kube-system"),
        ],
        nodes=[NodeInfo(name="n1")],
    )
    snap = collect_snapshot(cluster, make_policy())
    assert [p.name for p in snap.pods] == ["web-6d5f7c9b8-abcde"]
    assert [d.name for d in snap.deployments] == ["web"]
    assert len(snap.nodes) == 1


async def test_collect_logs_falls_back_to_previous_container_logs_for_restarted_pods():
    pod = make_pod("crashy-1", deploy="crashy", status="CrashLoopBackOff", restarts=3)
    cluster = FakeCluster(pods=[pod], previous_logs={("demo", "crashy-1"): "FATAL: db unreachable"})
    bundle = await collect_logs(cluster, [pod], since_seconds=900, tail_lines=50)
    [entry] = bundle.pods
    assert entry.from_previous
    assert entry.error_lines == ["FATAL: db unreachable"]


async def test_collect_logs_skips_pods_without_logs_and_redacts():
    ok = make_pod("a-1", deploy="a")
    missing = make_pod("b-1", deploy="b")
    cluster = FakeCluster(pods=[ok, missing], logs={("demo", "a-1"): "token=supersecretvalue123\nhello"})
    bundle = await collect_logs(cluster, [ok, missing], since_seconds=900, tail_lines=50)
    assert [p.pod for p in bundle.pods] == ["a-1"]
    assert "supersecretvalue123" not in bundle.pods[0].text


async def test_collect_logs_prioritises_unhealthy_pods_under_the_cap():
    healthy = [make_pod(f"ok-{i}", deploy="ok") for i in range(5)]
    sick = make_pod("sick-1", deploy="sick", status="CrashLoopBackOff", restarts=2)
    logs = {("demo", p.name): "line" for p in [*healthy, sick]}
    cluster = FakeCluster(pods=[*healthy, sick], logs=logs)
    bundle = await collect_logs(cluster, [*healthy, sick], since_seconds=900, tail_lines=50, max_pods=2)
    assert "sick-1" in [p.pod for p in bundle.pods]
    assert len(bundle.pods) == 2


async def test_collect_logs_survives_a_backend_error_on_one_pod():
    class Flaky(FakeCluster):
        def pod_logs(self, namespace, pod, container, **kw):
            if pod == "bad-1":
                raise ClusterError("boom")
            return super().pod_logs(namespace, pod, container, **kw)

    good, bad = make_pod("good-1", deploy="g"), make_pod("bad-1", deploy="b")
    cluster = Flaky(pods=[good, bad], logs={("demo", "good-1"): "hello"})
    bundle = await collect_logs(cluster, [good, bad], since_seconds=900, tail_lines=50)
    assert [p.pod for p in bundle.pods] == ["good-1"]


def test_bundle_matches_evidence_to_anomalies():
    bundle = LogBundle(
        pods=[
            PodLog("demo", "api-1", "api", "ERROR: x", ["ERROR: x"]),
            PodLog("demo", "other-1", "other", "ERROR: y", ["ERROR: y"]),
            PodLog("prod", "api-2", "api", "ERROR: z", ["ERROR: z"]),
        ]
    )
    anomaly = Anomaly(rule="crash_loop", severity=Severity.HIGH, target="demo/api", namespace="demo", deploy="api")
    assert bundle.errors_for(anomaly) == ["[demo/api-1] ERROR: x"]
    assert [p.pod for p in bundle.orphan_error_pods([anomaly])] == ["other-1", "api-2"]
    assert bundle.total_error_lines == 3


def test_bundle_render_truncates():
    bundle = LogBundle(pods=[PodLog("demo", "p", "w", "x" * 100)])
    assert bundle.render(max_chars=50).endswith("[... truncated]")

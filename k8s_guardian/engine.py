"""The poll cycle: collect -> detect -> triage -> decide -> policy gate -> act -> audit.

Flow (a cheap tier filters, a stronger tier decides, a deterministic gate has the last word):

1. collect pods / deployments / nodes, then pod logs (filtered and redacted)
2. rule-based detection (free, instant)
3. triage, unless every anomaly already has error-line evidence ("fast path")
4. per anomaly, highest severity first: pre-screen with the gate (is *any* restart possible?),
   ask the decision tier, run the gate on its proposal, execute (or dry-run), audit, notify
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .analysis import Analyzer, DecisionContext, TriageContext
from .audit import AuditLog
from .cluster.base import ClusterBackend, ClusterError
from .collectors import LogBundle, collect_logs, collect_snapshot
from .config import Settings
from .detector import Detector, merge_by_target
from .executor import Executor
from .models import (
    ACTION_DO_NOTHING,
    ACTION_ROLLOUT_RESTART,
    Anomaly,
    ClusterSnapshot,
    Decision,
    DecisionReport,
    Outcome,
    PolicyVerdict,
    PollReport,
    Severity,
    TriageResult,
)
from .notify import Notifier, NullNotifier
from .policy import GateLimits, PolicyConfig, PolicyGate

log = logging.getLogger("guardian")

# Used to ask the gate "is a restart of this anomaly's workload possible at all right now?"
# without spending a model call. It carries no target, so only the stateful/structural checks apply.
_PRESCREEN = Decision(action=ACTION_ROLLOUT_RESTART, confidence=1.0, reasoning="pre-screen: is any restart permitted?")


@dataclass
class _Candidate:
    anomaly: Anomaly
    evidence: list[str] = field(default_factory=list)


class Guardian:
    def __init__(
        self,
        settings: Settings,
        cluster: ClusterBackend,
        policy: PolicyConfig,
        audit: AuditLog,
        analyzer: Analyzer,
        notifier: Notifier | None = None,
        *,
        executor: Executor | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.cluster = cluster
        self.policy = policy
        self.audit = audit
        self.analyzer = analyzer
        self.notifier: Notifier = notifier or NullNotifier()
        self.executor = executor or Executor(cluster, dry_run=settings.dry_run)
        self.clock = clock
        self.gate = PolicyGate(
            policy,
            GateLimits(
                confidence_threshold=settings.confidence_threshold,
                cooldown_seconds=settings.cooldown_seconds,
                repeat_window_seconds=settings.repeat_window_seconds,
                max_actions_per_hour=settings.max_actions_per_hour,
            ),
            audit,
        )
        self.detector = Detector(
            pending_timeout_seconds=settings.pending_timeout_seconds,
            restart_flap_threshold=settings.restart_flap_threshold,
            replica_mismatch_grace_seconds=settings.replica_mismatch_grace_seconds,
        )
        self._lock = asyncio.Lock()  # a manual /api/poll must not overlap the background loop
        self.last_report: PollReport | None = None
        self.last_snapshot: ClusterSnapshot | None = None
        self.last_triage: TriageResult | None = None
        self._model_calls = 0  # decision-tier calls in the current poll, bounded by max_decisions_per_poll

    # ------------------------------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------------------------------

    async def run_forever(self) -> None:
        log.info(
            "guardian loop started (interval=%ds dry_run=%s analyzer=%s triage=%s decision=%s)",
            self.settings.poll_interval_seconds,
            self.executor.dry_run,
            self.analyzer.name,
            self.analyzer.triage_model,
            self.analyzer.decision_model,
        )
        while True:
            try:
                await self.poll_once()
            except Exception:
                log.exception("poll cycle crashed")
            await asyncio.sleep(self.settings.poll_interval_seconds)

    async def poll_once(self) -> PollReport:
        async with self._lock:
            report = await self._poll()
            self.last_report = report
            return report

    def status(self) -> dict[str, Any]:
        now = self.clock()
        report, snap = self.last_report, self.last_snapshot
        cooldowns = self.audit.cooldown_targets(now, self.settings.cooldown_seconds)
        return {
            "ok": bool(report and report.ok and not report.anomalies),
            "last_poll_ok": bool(report and report.ok),
            "last_poll_error": report.error if report else "",
            "last_poll_ts": report.ts if report else 0.0,
            "dry_run": self.executor.dry_run,
            "analyzer": self.analyzer.name,
            "triage_model": self.analyzer.triage_model,
            "decision_model": self.analyzer.decision_model,
            "policy_version": self.policy.version,
            "pod_count": len(snap.pods) if snap else 0,
            "healthy_count": snap.healthy_pods if snap else 0,
            "anomaly_count": len(report.anomalies) if report else 0,
            "anomalies": [a.model_dump(mode="json") for a in report.anomalies] if report else [],
            "nodes": [n.model_dump(mode="json") for n in snap.nodes] if snap else [],
            "actions_last_hour": self.audit.attempts_since(now - 3600),
            "max_actions_per_hour": self.settings.max_actions_per_hour,
            "cooldowns": {t: round(ts + self.settings.cooldown_seconds - now) for t, ts in cooldowns.items()},
            "last_triage": self.last_triage.overall_assessment if self.last_triage else "",
            "errors_found": bool(report and report.error_lines),
        }

    # ------------------------------------------------------------------------------------------
    # one cycle
    # ------------------------------------------------------------------------------------------

    async def _poll(self) -> PollReport:
        now = self.clock()
        report = PollReport(ts=now, ok=False, dry_run=self.executor.dry_run)
        self._model_calls = 0
        try:
            snapshot = await asyncio.to_thread(collect_snapshot, self.cluster, self.policy)
        except ClusterError as exc:
            report.error = str(exc)
            log.error("cluster collection failed: %s", exc)
            return report
        self.last_snapshot = snapshot
        report.ok = True
        report.pod_count, report.healthy_count = len(snapshot.pods), snapshot.healthy_pods

        anomalies = self.detector.detect(snapshot, now, self.audit.restart_baseline(now))
        report.anomalies = anomalies
        self._maybe_snapshot(now, snapshot, anomalies)

        logs = await self._collect_logs(snapshot)
        report.error_lines = logs.total_error_lines

        triage = await self._triage(snapshot, anomalies, logs)
        self.last_triage = triage
        report.triage = triage

        for candidate in self._candidates(anomalies, logs, triage, report):
            await self._handle(candidate, logs, snapshot, report)

        log.info(
            "poll complete: pods=%d healthy=%d anomalies=%d error_lines=%d decisions=%d dry_run=%s",
            report.pod_count,
            report.healthy_count,
            len(anomalies),
            report.error_lines,
            len(report.decisions),
            report.dry_run,
        )
        return report

    def _maybe_snapshot(self, now: float, snapshot: ClusterSnapshot, anomalies: list[Anomaly]) -> None:
        last = self.audit.last_snapshot_ts()
        # 10% slack so poll-interval jitter does not make every second poll skip its snapshot.
        if last is None or now - last >= self.settings.snapshot_interval_seconds * 0.9:
            self.audit.save_snapshot(now, snapshot, len(anomalies))
            self.audit.prune(now, self.settings.retention_days)

    async def _collect_logs(self, snapshot: ClusterSnapshot) -> LogBundle:
        try:
            return await collect_logs(
                self.cluster,
                snapshot.pods,
                since_seconds=self.settings.log_since_seconds,
                tail_lines=self.settings.log_tail_lines,
                concurrency=self.settings.log_concurrency,
                max_pods=self.settings.log_max_pods,
            )
        except Exception:
            log.exception("log collection failed; continuing without logs")
            return LogBundle()

    async def _triage(
        self, snapshot: ClusterSnapshot, anomalies: list[Anomaly], logs: LogBundle
    ) -> TriageResult | None:
        unexplained = logs.orphan_error_pods(anomalies)
        all_have_evidence = bool(anomalies) and all(logs.errors_for(a) for a in anomalies)
        if (all_have_evidence and not unexplained) or not (anomalies or logs.pods):
            # Fast path (error lines already explain every anomaly) or nothing to look at.
            return None
        return await self.analyzer.triage(
            TriageContext(
                pod_count=len(snapshot.pods),
                healthy_count=snapshot.healthy_pods,
                anomalies=anomalies,
                logs=logs.render(),
                unexplained_errors={p.key: p.error_lines for p in unexplained},
                log_window_minutes=max(1, self.settings.log_since_seconds // 60),
            )
        )

    def _candidates(
        self, anomalies: list[Anomaly], logs: LogBundle, triage: TriageResult | None, report: PollReport
    ) -> list[_Candidate]:
        """Decide which anomalies deserve a decision. Triage may declare evidence-free ones benign."""
        out: list[_Candidate] = []
        for anomaly in anomalies:
            evidence = logs.errors_for(anomaly)
            if triage is not None and not triage.has_issues and not evidence:
                self._record(
                    anomaly,
                    Outcome.TRIAGE_BENIGN,
                    reason=f"triage: benign - {triage.overall_assessment}",
                    decision=None,
                    verdict=None,
                    model=self.analyzer.triage_model,
                    report=report,
                )
                continue
            out.append(_Candidate(anomaly, evidence))

        if triage is not None:
            known = {p.key: p for p in logs.pods}
            covered = {a.pod_name for a in anomalies}
            for issue in triage.issues:
                pod_log = known.get(issue.pod)
                if pod_log is None or pod_log.pod in covered:
                    continue
                ns = pod_log.namespace
                out.append(
                    _Candidate(
                        Anomaly(
                            rule="log_issue",
                            severity=issue.severity,
                            target=f"{ns}/{pod_log.workload or pod_log.pod}",
                            namespace=ns,
                            pod_name=pod_log.pod,
                            deploy=pod_log.workload,
                            details=issue.summary or "issue found in logs",
                            actionable=False,
                        ),
                        evidence=[f"[{pod_log.key}] {ln}" for ln in pod_log.error_lines[:20]],
                    )
                )
                covered.add(pod_log.pod)
        # Pods of one workload may raise several rules; the workload gets a single decision.
        by_target: dict[str, list[str]] = {}
        for c in out:
            bucket = by_target.setdefault(c.anomaly.target, [])
            bucket.extend(line for line in c.evidence if line not in bucket)
        return [_Candidate(a, by_target[a.target]) for a in merge_by_target([c.anomaly for c in out])]

    # ------------------------------------------------------------------------------------------
    # one anomaly
    # ------------------------------------------------------------------------------------------

    async def _handle(self, cand: _Candidate, logs: LogBundle, snapshot: ClusterSnapshot, report: PollReport) -> None:
        anomaly = cand.anomaly

        # 1. Cheap, deterministic: can any restart happen at all? If not, don't ask a model.
        pre = self.gate.evaluate(_PRESCREEN, anomaly, self.clock())
        if not pre.allowed:
            observed = Decision(
                action=ACTION_DO_NOTHING,
                target=anomaly.target,
                confidence=1.0,
                reasoning=pre.reason,
                needs_human=pre.needs_human,
            )
            self._record(
                anomaly,
                pre.outcome,
                reason=pre.reason,
                decision=observed,
                verdict=pre,
                model="gate",
                report=report,
                action=ACTION_DO_NOTHING,
            )
            await self._notify_if_needed(anomaly, pre.reason, pre.needs_human, pre.target)
            return

        if self._model_calls >= self.settings.max_decisions_per_poll:
            self._record(
                anomaly,
                Outcome.DEFERRED,
                reason="per-poll decision budget exhausted; retry next poll",
                decision=None,
                verdict=pre,
                model="gate",
                report=report,
                action=ACTION_DO_NOTHING,
            )
            return

        # 2. Ask the decision tier.
        ctx = DecisionContext(
            anomaly=anomaly,
            rule=self.policy.rule_for(pre.namespace, pre.workload),
            evidence=cand.evidence,
            log_excerpt=logs.excerpt_for(anomaly),
            pod_count=len(snapshot.pods),
            healthy_count=snapshot.healthy_pods,
            nodes=snapshot.nodes,
            recent_actions=self.audit.recent(limit=5, target=pre.target),
            policy_lines=self.policy.guidance_lines(),
            cooldown_seconds=self.settings.cooldown_seconds,
            now=self.clock(),
        )
        self._model_calls += 1
        decision = await self.analyzer.decide(ctx)
        if decision is None:
            reason = "decision tier unavailable; no action taken"
            self._record(
                anomaly,
                Outcome.LLM_UNAVAILABLE,
                reason=reason,
                decision=None,
                verdict=None,
                model=self.analyzer.decision_model,
                report=report,
                needs_human=True,
            )
            log.warning("%s (%s)", reason, anomaly.target)
            return

        # 3. The gate has the last word (and re-reads cooldown / budget from the audit log).
        verdict = self.gate.evaluate(decision, anomaly, self.clock())
        if not verdict.allowed:
            self._record(
                anomaly,
                verdict.outcome,
                reason=verdict.reason,
                decision=decision,
                verdict=verdict,
                model=self.analyzer.decision_model,
                report=report,
            )
            await self._notify_if_needed(
                anomaly, f"{verdict.reason}. {decision.reasoning}", verdict.needs_human, verdict.target
            )
            return

        # 4. Write-ahead audit row, then act.
        row_id = self.audit.record(
            ts=self.clock(),
            rule=anomaly.rule,
            severity=anomaly.severity.value,
            target=verdict.target,
            namespace=verdict.namespace,
            details=anomaly.details,
            action=verdict.action,
            result=Outcome.ALLOWED,
            reason=verdict.reason,
            reasoning=decision.reasoning,
            confidence=decision.confidence,
            needs_human=False,
            dry_run=self.executor.dry_run,
            model=self.analyzer.decision_model,
        )
        result = await self.executor.execute(verdict)
        self.audit.finish(row_id, result.outcome, reason=result.message, command=result.command)
        report.decisions.append(
            DecisionReport(
                target=verdict.target,
                rule=anomaly.rule,
                decision=decision,
                verdict=verdict,
                outcome=result.outcome,
                detail=result.message,
                model=self.analyzer.decision_model,
            )
        )
        log.info(
            "action target=%s rule=%s outcome=%s detail=%s",
            verdict.target,
            anomaly.rule,
            result.outcome.value,
            result.message,
        )
        if result.outcome is Outcome.EXECUTED:
            await self._notify(
                "Auto-remediation executed",
                f"`{result.command}`\nReason: {decision.reasoning}\nResult: {result.message}",
                "info",
                verdict.target,
                f"action_{verdict.action}",
            )
        elif result.outcome is Outcome.FAILED:
            await self._notify(
                "Auto-remediation failed",
                f"`{result.command}`\nReason: {decision.reasoning}\nError: {result.message}\n"
                "Manual intervention needed.",
                "high",
                verdict.target,
                f"action_failed_{verdict.action}",
            )

    # ------------------------------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------------------------------

    def _record(
        self,
        anomaly: Anomaly,
        outcome: Outcome,
        *,
        reason: str,
        decision: Decision | None,
        verdict: PolicyVerdict | None,
        model: str,
        report: PollReport,
        needs_human: bool | None = None,
        action: str | None = None,
    ) -> None:
        human = needs_human if needs_human is not None else bool(verdict and verdict.needs_human)
        target = verdict.target if verdict and verdict.target else anomaly.target
        self.audit.record(
            ts=self.clock(),
            rule=anomaly.rule,
            severity=anomaly.severity.value,
            target=target,
            namespace=anomaly.namespace,
            details=anomaly.details,
            action=action or (verdict.action if verdict else ACTION_DO_NOTHING),
            result=outcome,
            reason=reason,
            reasoning=decision.reasoning if decision else "",
            confidence=decision.confidence if decision else 0.0,
            needs_human=human,
            dry_run=self.executor.dry_run,
            model=model,
        )
        report.decisions.append(
            DecisionReport(
                target=target,
                rule=anomaly.rule,
                decision=decision,
                verdict=verdict,
                outcome=outcome,
                detail=reason,
                model=model,
            )
        )
        log.info(
            "decision target=%s rule=%s outcome=%s needs_human=%s reason=%s",
            target,
            anomaly.rule,
            outcome.value,
            human,
            reason,
        )

    async def _notify_if_needed(self, anomaly: Anomaly, text: str, needs_human: bool, target: str) -> None:
        # Low-severity observations (e.g. stray ERROR lines) are audited but never page anyone.
        if needs_human and anomaly.severity is not Severity.LOW:
            await self._notify(
                "Human attention needed",
                f"Issue: {anomaly.details}\n{text}",
                anomaly.severity.value,
                target,
                anomaly.rule,
            )

    async def _notify(self, title: str, text: str, severity: str, target: str, rule: str) -> None:
        try:
            await self.notifier.send(title, text, severity=severity, target=target, rule=rule)
        except Exception:
            log.exception("notification failed")

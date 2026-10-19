"""Remediation executor: the only code that can change the cluster.

It is deliberately tiny and re-checks its inputs. It only runs on a gate-approved verdict, supports
exactly one action (``rollout_restart``), and does nothing but log in dry-run mode.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .cluster.base import ClusterBackend, ClusterError
from .models import ACTION_ROLLOUT_RESTART, Outcome, PolicyVerdict
from .policy import SAFE_NAME_RE


@dataclass(frozen=True)
class ExecutionResult:
    outcome: Outcome  # DRY_RUN, EXECUTED or FAILED
    command: str  # kubectl-equivalent, for the audit log (never run through a shell)
    message: str


class Executor:
    def __init__(self, cluster: ClusterBackend, *, dry_run: bool = True) -> None:
        self.cluster = cluster
        self.dry_run = dry_run

    @staticmethod
    def describe(verdict: PolicyVerdict) -> str:
        return f"rollout restart deployment/{verdict.workload} -n {verdict.namespace}"

    async def execute(self, verdict: PolicyVerdict) -> ExecutionResult:
        if not verdict.allowed or verdict.action != ACTION_ROLLOUT_RESTART:
            raise ValueError(f"refusing to execute a verdict that was not approved: {verdict.outcome}")
        if not SAFE_NAME_RE.match(verdict.workload) or not SAFE_NAME_RE.match(verdict.namespace):
            raise ValueError("refusing to execute against an invalid resource name")

        command = self.describe(verdict)
        if self.dry_run:
            return ExecutionResult(Outcome.DRY_RUN, command, f"dry-run: would run `{command}`")
        try:
            message = await asyncio.to_thread(self.cluster.restart_deployment, verdict.namespace, verdict.workload)
        except ClusterError as exc:
            return ExecutionResult(Outcome.FAILED, command, str(exc))
        except Exception as exc:  # never let an unexpected client error escape the audit trail
            return ExecutionResult(Outcome.FAILED, command, f"{type(exc).__name__}: {exc}")
        return ExecutionResult(Outcome.EXECUTED, command, message)

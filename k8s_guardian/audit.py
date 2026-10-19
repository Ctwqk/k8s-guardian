"""SQLite audit log: every decision is recorded, whatever its outcome. Also the source of truth for
cooldowns and rate limits, so those survive restarts."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import ClusterSnapshot, Outcome

# Outcomes that count as "the guardian touched (or tried to touch) the cluster".
LIVE_OUTCOMES = (Outcome.ALLOWED.value, Outcome.EXECUTED.value, Outcome.FAILED.value)
# Only "?" placeholders are interpolated into SQL below; every value is bound as a parameter.
_LIVE_MARKS = ",".join("?" * len(LIVE_OUTCOMES))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    target TEXT NOT NULL,
    namespace TEXT NOT NULL,
    details TEXT,
    action TEXT NOT NULL,
    command TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    reasoning TEXT,
    confidence REAL,
    needs_human INTEGER NOT NULL DEFAULT 0,
    dry_run INTEGER NOT NULL DEFAULT 1,
    model TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_target_ts ON audit_log (target, ts);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    pod_count INTEGER,
    healthy_count INTEGER,
    anomaly_count INTEGER,
    restart_counts_json TEXT
);
"""


class AuditLog:
    """Thread-safe wrapper around one SQLite connection (single writer: run one guardian per DB)."""

    def __init__(self, path: Path | str) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- writes -------------------------------------------------------------------------------

    def record(
        self,
        *,
        ts: float,
        rule: str,
        severity: str,
        target: str,
        namespace: str,
        details: str,
        action: str,
        result: Outcome,
        reason: str = "",
        reasoning: str = "",
        confidence: float = 0.0,
        command: str = "",
        needs_human: bool = False,
        dry_run: bool = True,
        model: str = "",
    ) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO audit_log (ts, rule, severity, target, namespace, details, action, command,"
                " result, reason, reasoning, confidence, needs_human, dry_run, model)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ts,
                    rule,
                    severity,
                    target,
                    namespace,
                    details,
                    action,
                    command,
                    result.value,
                    reason,
                    reasoning,
                    confidence,
                    int(needs_human),
                    int(dry_run),
                    model,
                ),
            )
            self._db.commit()
            return int(cur.lastrowid or 0)

    def finish(self, row_id: int, result: Outcome, *, reason: str, command: str = "") -> None:
        """Settle an ``ALLOWED`` row (written *before* the cluster is touched) with the real outcome."""
        with self._lock:
            self._db.execute(
                "UPDATE audit_log SET result=?, reason=?, command=? WHERE id=?",
                (result.value, reason, command, row_id),
            )
            self._db.commit()

    def save_snapshot(self, ts: float, snapshot: ClusterSnapshot, anomaly_count: int) -> None:
        counts = {f"{p.namespace}/{p.name}": p.restarts for p in snapshot.pods}
        with self._lock:
            self._db.execute(
                "INSERT INTO snapshots (ts, pod_count, healthy_count, anomaly_count, restart_counts_json)"
                " VALUES (?,?,?,?,?)",
                (ts, len(snapshot.pods), snapshot.healthy_pods, anomaly_count, json.dumps(counts)),
            )
            self._db.commit()

    def prune(self, now: float, retention_days: int) -> None:
        cutoff = now - retention_days * 86400
        with self._lock:
            self._db.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
            self._db.execute("DELETE FROM snapshots WHERE ts < ?", (cutoff,))
            self._db.commit()

    # -- reads: ActionHistory protocol ---------------------------------------------------------

    def last_attempt_ts(self, target: str) -> float | None:
        with self._lock:
            row = self._db.execute(
                f"SELECT MAX(ts) AS ts FROM audit_log WHERE target=? AND result IN ({_LIVE_MARKS})",  # noqa: S608
                (target, *LIVE_OUTCOMES),
            ).fetchone()
        return None if row is None or row["ts"] is None else float(row["ts"])

    def attempts_since(self, ts: float) -> int:
        with self._lock:
            row = self._db.execute(
                f"SELECT COUNT(*) AS c FROM audit_log WHERE ts >= ? AND result IN ({_LIVE_MARKS})",  # noqa: S608
                (ts, *LIVE_OUTCOMES),
            ).fetchone()
        return int(row["c"])

    # -- reads: reporting ---------------------------------------------------------------------

    def recent(self, limit: int = 50, offset: int = 0, target: str | None = None) -> list[dict[str, Any]]:
        query, params = "SELECT * FROM audit_log", []
        if target is not None:
            query += " WHERE target=?"
            params.append(target)
        query += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        with self._lock:
            rows = self._db.execute(query, (*params, limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"])

    def cooldown_targets(self, now: float, window_seconds: int) -> dict[str, float]:
        """Targets with a live attempt inside ``window_seconds``, mapped to the attempt time."""
        with self._lock:
            rows = self._db.execute(
                f"SELECT target, MAX(ts) AS ts FROM audit_log WHERE ts >= ? AND result IN ({_LIVE_MARKS})"  # noqa: S608
                " GROUP BY target",
                (now - window_seconds, *LIVE_OUTCOMES),
            ).fetchall()
        return {r["target"]: float(r["ts"]) for r in rows}

    def restart_baseline(self, now: float, min_age_seconds: int = 3600) -> dict[str, int] | None:
        """Per-pod restart counts from the newest snapshot at least ``min_age_seconds`` old.

        If the guardian has been running for less than that, fall back to the oldest snapshot so
        flapping is measured "since we started watching". ``None`` means there is no history.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT restart_counts_json FROM snapshots WHERE ts <= ? ORDER BY ts DESC LIMIT 1",
                (now - min_age_seconds,),
            ).fetchone()
            if row is None:
                row = self._db.execute("SELECT restart_counts_json FROM snapshots ORDER BY ts ASC LIMIT 1").fetchone()
        if row is None or not row["restart_counts_json"]:
            return None
        loaded = json.loads(row["restart_counts_json"])
        return {str(k): int(v) for k, v in loaded.items()}

    def last_snapshot_ts(self) -> float | None:
        with self._lock:
            row = self._db.execute("SELECT MAX(ts) AS ts FROM snapshots").fetchone()
        return None if row is None or row["ts"] is None else float(row["ts"])

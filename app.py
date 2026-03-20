"""k8s-guardian — AI-driven K8s cluster guardian agent.

Two-tier LLM architecture:
  1. Every 15 min: collect pod status + logs from all pods
  2. Pre-filter logs (strip health probes, dedup, tail per pod)
  3. If ERROR/FATAL found → send directly to M2.5 for decision
  4. Otherwise → send filtered logs to M2 for triage
  5. If M2 finds issues → escalate to M2.5 for decision + action
  6. Rule-based detection runs in parallel (free, instant)
"""

import asyncio
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

import httpx
from fastapi import FastAPI, Query
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
log = logging.getLogger("guardian")

# ── Config ──────────────────────────────────────────────────────────────────

MINIMAX_API_BASE = os.getenv("MINIMAX_API_BASE", "https://api.minimax.com/v1").rstrip("/")
MINIMAX_API_KEY = os.getenv("MINIMAX_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
MODEL_TRIAGE = os.getenv("MINIMAX_MODEL_TRIAGE", "MiniMax-M2")       # cheap, fast triage
MODEL_DECISION = os.getenv("MINIMAX_MODEL_DECISION", "MiniMax-M2.5")  # capable decision-maker

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "900"))  # 15 minutes
COOLDOWN_SECONDS = int(os.getenv("GUARDIAN_COOLDOWN_SECONDS", "600"))
MAX_ACTIONS_PER_HOUR = int(os.getenv("GUARDIAN_MAX_ACTIONS_HOUR", "5"))
CONFIDENCE_THRESHOLD = float(os.getenv("GUARDIAN_CONFIDENCE_THRESHOLD", "0.6"))
SNAPSHOT_INTERVAL = int(os.getenv("SNAPSHOT_INTERVAL_SECONDS", "900"))
DB_PATH = os.getenv("GUARDIAN_DB_PATH", "/data/guardian.db")

WATCHED_NS_PREFIX = "constructure-"
PENDING_TIMEOUT = 300  # 5 minutes
RESTART_FLAP_THRESHOLD = 5
REPLICA_MISMATCH_GRACE = 120  # 2 minutes

# Log collection config
LOG_TAIL_PER_POD = 50          # max lines per pod
LOG_SINCE = "15m"              # collect last 15 min of logs
# Patterns to strip from logs (health probes, repetitive noise)
LOG_NOISE_PATTERNS = re.compile(
    r'GET /health|GET /healthz|GET /readyz|GET /livez|'
    r'health.*200 OK|readiness.*200 OK|liveness.*200 OK|'
    r'"GET /health HTTP/\d\.\d" 200',
    re.IGNORECASE,
)
# Patterns that indicate errors — fast-path to M2.5
ERROR_PATTERNS = re.compile(
    r'\bERROR\b|\bFATAL\b|\bPANIC\b|\bCRITICAL\b|'
    r'OOMKilled|CrashLoopBackOff|ImagePullBackOff|ErrImagePull|'
    r'Traceback \(most recent|Exception:|Error:',
    re.IGNORECASE,
)

# Discord notification cooldown: avoid spamming the same issue
_discord_cooldowns: dict[str, float] = {}  # "target:rule" -> last_sent_ts
DISCORD_COOLDOWN = 1800  # 30 min between repeat notifications for same issue


# ── Security: namespace & action allowlists ─────────────────────────────────
POLICY_VERSION = "constructure-guardian-2026-03-18"

WRITABLE_NAMESPACES = frozenset({
    "constructure-arb",
    "constructure-news",
    "constructure-bots",
    "constructure-dashboard",
    "constructure-tools",
})
ALLOWED_ACTIONS = frozenset({"rollout_restart", "do_nothing"})
_SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,252}$")

RESTART_ONLY_ACTIONS = frozenset({"rollout_restart", "do_nothing"})
OBSERVE_ONLY_ACTIONS = frozenset({"do_nothing"})

TARGET_POLICIES = {
    ("constructure-arb", "collector"): {
        "allowed_actions": RESTART_ONLY_ACTIONS,
        "reason": "Market data collector with no direct order placement. Controlled restart is acceptable.",
    },
    ("constructure-arb", "resolver"): {
        "allowed_actions": RESTART_ONLY_ACTIONS,
        "reason": "Matching/indexing worker. Controlled restart is acceptable, but persistent failures need human review.",
    },
    ("constructure-arb", "validator"): {
        "allowed_actions": RESTART_ONLY_ACTIONS,
        "reason": "Read-only validation worker. Controlled restart is acceptable.",
    },
    ("constructure-arb", "strategy"): {
        "allowed_actions": OBSERVE_ONLY_ACTIONS,
        "reason": "Emits live trade signals. Autonomous remediation is disabled.",
    },
    ("constructure-arb", "executor-kalshi"): {
        "allowed_actions": OBSERVE_ONLY_ACTIONS,
        "reason": "Places live Kalshi orders. Human review is required.",
    },
    ("constructure-arb", "executor-polymarket"): {
        "allowed_actions": OBSERVE_ONLY_ACTIONS,
        "reason": "Places live Polymarket orders through the VPN path. Human review is required.",
    },
    ("constructure-news", "news-server"): {
        "allowed_actions": RESTART_ONLY_ACTIONS,
        "reason": "Stateless API backed by Postgres. Controlled restart is acceptable.",
    },
    ("constructure-news", "news-collector"): {
        "allowed_actions": RESTART_ONLY_ACTIONS,
        "reason": "Idempotent ingestion worker. Controlled restart is acceptable.",
    },
    ("constructure-news", "news-publisher-x"): {
        "allowed_actions": OBSERVE_ONLY_ACTIONS,
        "reason": "External posting workflow with persistent state and CDP/browser dependencies. Human review is required.",
    },
    ("constructure-bots", "x-bot"): {
        "allowed_actions": RESTART_ONLY_ACTIONS,
        "reason": "Single-instance posting API attached to host Chrome CDP. Restart only; no scaling or pod deletion.",
    },
    ("constructure-dashboard", "dashboard"): {
        "allowed_actions": RESTART_ONLY_ACTIONS,
        "reason": "Stateless dashboard with hostPort exposure. Controlled restart is acceptable.",
    },
    ("constructure-tools", "gmail-bridge"): {
        "allowed_actions": RESTART_ONLY_ACTIONS,
        "reason": "Single-instance OAuth bridge with persistent token storage. Controlled restart is acceptable.",
    },
    ("constructure-tools", "job-autoflow"): {
        "allowed_actions": OBSERVE_ONLY_ACTIONS,
        "reason": "Interactive browser automation with local runtime state. Autonomous restart can disrupt active sessions.",
    },
}

DEFAULT_TARGET_POLICY = {
    "allowed_actions": OBSERVE_ONLY_ACTIONS,
    "reason": "Unknown or side-effecting workload. Require human review.",
}

POLICY_GUIDANCE = (
    "constructure-arb/collector, resolver, validator -> rollout_restart only",
    "constructure-arb/strategy, executor-kalshi, executor-polymarket -> do_nothing + needs_human=true",
    "constructure-news/news-server, news-collector -> rollout_restart only",
    "constructure-news/news-publisher-x -> do_nothing + needs_human=true",
    "constructure-bots/x-bot -> rollout_restart only",
    "constructure-dashboard/dashboard -> rollout_restart only",
    "constructure-tools/gmail-bridge -> rollout_restart only",
    "constructure-tools/job-autoflow -> do_nothing + needs_human=true",
    "constructure-monitor and constructure-infra are always read-only, including worldmonitor, exo-watchdog, k8s-guardian, and future worldmonitor-hourly jobs",
    "Automatic remediation in this cluster never uses scale_up or delete_pod",
)


def _target_policy(namespace: str, workload: str) -> dict:
    return TARGET_POLICIES.get((namespace, workload), DEFAULT_TARGET_POLICY)


def _allowed_action_text(policy: dict) -> str:
    allowed = sorted(a for a in policy["allowed_actions"] if a != "do_nothing")
    return ", ".join(allowed) if allowed else "observe_only"


def _resolve_action_target(decision_target: str, anomaly: dict) -> tuple[str, str, str, dict]:
    namespace = anomaly.get("namespace", "")
    resource_name = ""
    if decision_target and "/" in decision_target:
        prefix, resource_name = decision_target.split("/", 1)
        if prefix.startswith(WATCHED_NS_PREFIX):
            namespace = prefix
    elif decision_target:
        resource_name = decision_target

    workload_name = anomaly.get("deploy") or resource_name or anomaly.get("pod_name", "")
    if namespace and workload_name:
        effective_target = f"{namespace}/{workload_name}"
    else:
        effective_target = decision_target or anomaly.get("target", "")

    return namespace, workload_name, effective_target, _target_policy(namespace, workload_name)


def _can_auto_restart_anomaly(anomaly: dict) -> bool:
    if not anomaly.get("actionable"):
        return False
    workload_name = anomaly.get("deploy", "")
    if not workload_name:
        return False
    policy = _target_policy(anomaly.get("namespace", ""), workload_name)
    return "rollout_restart" in policy["allowed_actions"]


def _policy_rows() -> list[dict]:
    rows = []
    for (namespace, deployment), policy in sorted(TARGET_POLICIES.items()):
        rows.append({
            "namespace": namespace,
            "deployment": deployment,
            "allowed_actions": sorted(policy["allowed_actions"]),
            "reason": policy["reason"],
        })
    return rows

# ── State ───────────────────────────────────────────────────────────────────

@dataclass
class GuardianState:
    last_poll_ts: float = 0.0
    last_poll_ok: bool = False
    pods: list = field(default_factory=list)
    deployments: list = field(default_factory=list)
    node_conditions: list = field(default_factory=list)
    anomalies: list = field(default_factory=list)
    actions_this_hour: int = 0
    actions_hour_start: float = 0.0
    cooldowns: dict = field(default_factory=dict)
    replica_mismatch_since: dict = field(default_factory=dict)
    last_snapshot_ts: float = 0.0
    restart_baseline: dict = field(default_factory=dict)
    # Log analysis state
    last_log_summary: str = ""
    last_triage_result: str = ""
    errors_found: bool = False


_state = GuardianState()
_db_conn: Optional[sqlite3.Connection] = None

# ── Database ────────────────────────────────────────────────────────────────

def _db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _db_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
        _db_conn.execute("PRAGMA journal_mode=WAL")
        _db_conn.execute("PRAGMA synchronous=NORMAL")
        _db_conn.executescript("""
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                anomaly_rule TEXT NOT NULL,
                anomaly_severity TEXT NOT NULL,
                target TEXT NOT NULL,
                namespace TEXT NOT NULL,
                anomaly_details TEXT,
                llm_reasoning TEXT,
                llm_confidence REAL,
                action TEXT NOT NULL,
                action_cmd TEXT,
                result TEXT,
                success INTEGER,
                needs_human INTEGER DEFAULT 0,
                model_used TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                pod_count INTEGER,
                healthy_count INTEGER,
                anomaly_count INTEGER,
                restart_counts_json TEXT
            );
        """)
        # Add model_used column if missing (migration from old schema)
        try:
            _db_conn.execute("SELECT model_used FROM actions LIMIT 1")
        except sqlite3.OperationalError:
            _db_conn.execute("ALTER TABLE actions ADD COLUMN model_used TEXT DEFAULT ''")
        _db_conn.commit()
    return _db_conn


def _record_action(anomaly: dict, reasoning: str, confidence: float,
                   action: str, cmd: str, result: str, success: bool,
                   needs_human: bool, model: str = ""):
    _db().execute(
        "INSERT INTO actions (ts, anomaly_rule, anomaly_severity, target, namespace, "
        "anomaly_details, llm_reasoning, llm_confidence, action, action_cmd, result, "
        "success, needs_human, model_used) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (time.time(), anomaly.get("rule", ""), anomaly.get("severity", ""),
         anomaly.get("target", ""), anomaly.get("namespace", ""),
         anomaly.get("details", ""), reasoning, confidence,
         action, cmd, result, int(success), int(needs_human), model),
    )
    _db().commit()


def _save_snapshot():
    now = time.time()
    if now - _state.last_snapshot_ts < SNAPSHOT_INTERVAL and not _state.anomalies:
        return
    restart_counts = {}
    for p in _state.pods:
        key = f"{p['namespace']}/{p['name']}"
        restart_counts[key] = p.get("restarts", 0)
    _db().execute(
        "INSERT INTO snapshots (ts, pod_count, healthy_count, anomaly_count, restart_counts_json) "
        "VALUES (?,?,?,?,?)",
        (now, len(_state.pods),
         sum(1 for p in _state.pods if p["status"] == "running"),
         len(_state.anomalies),
         json.dumps(restart_counts)),
    )
    _db().commit()
    _state.last_snapshot_ts = now
    _db().execute("DELETE FROM actions WHERE ts < ?", (now - 7 * 86400,))
    _db().execute("DELETE FROM snapshots WHERE ts < ?", (now - 7 * 86400,))
    _db().commit()


def _get_restart_baseline() -> dict:
    row = _db().execute(
        "SELECT restart_counts_json FROM snapshots WHERE ts < ? ORDER BY ts DESC LIMIT 1",
        (time.time() - 3600,),
    ).fetchone()
    if row and row["restart_counts_json"]:
        return json.loads(row["restart_counts_json"])
    return {}


def _recent_actions(limit: int = 10) -> list:
    rows = _db().execute(
        "SELECT * FROM actions ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ── Discord Notifications ──────────────────────────────────────────────────

async def _notify_discord(title: str, description: str, severity: str = "medium",
                          target: str = "", rule: str = ""):
    """Send a Discord webhook notification. Respects per-issue cooldown."""
    if not DISCORD_WEBHOOK_URL:
        return

    # Cooldown check — don't spam the same issue
    cooldown_key = f"{target}:{rule}" if target else title
    now = time.time()
    if cooldown_key in _discord_cooldowns:
        if now - _discord_cooldowns[cooldown_key] < DISCORD_COOLDOWN:
            log.debug("Discord: skipping (cooldown) %s", cooldown_key)
            return
    _discord_cooldowns[cooldown_key] = now

    color_map = {"high": 0xFF0000, "medium": 0xFF8C00, "low": 0xFFD700, "info": 0x3498DB}
    color = color_map.get(severity, 0xFF8C00)
    emoji = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(severity, "🔵")

    embed = {
        "title": f"{emoji} Guardian: {title}",
        "description": description[:2000],
        "color": color,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "footer": {"text": "k8s-guardian"},
    }
    if target:
        embed["fields"] = [{"name": "Target", "value": target, "inline": True}]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                DISCORD_WEBHOOK_URL,
                json={"embeds": [embed]},
            )
            if resp.status_code == 204:
                log.info("Discord: sent notification — %s", title)
            else:
                log.warning("Discord: webhook returned %d", resp.status_code)
    except Exception as e:
        log.error("Discord: failed to send — %s", e)


# ── Cluster State Collection ───────────────────────────────────────────────

def _kubectl(args: list) -> dict:
    result = subprocess.run(
        ["kubectl"] + args, capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "kubectl failed")
    return json.loads(result.stdout)


def _kubectl_text(args: list) -> str:
    """Run kubectl and return raw text output."""
    result = subprocess.run(
        ["kubectl"] + args, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return f"[kubectl error: {result.stderr.strip()}]"
    return result.stdout


def _collect_pods() -> list:
    data = _kubectl(["get", "pods", "--all-namespaces", "-o", "json"])
    pods = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        ns = meta.get("namespace", "")
        if not ns.startswith(WATCHED_NS_PREFIX):
            continue
        spec = item.get("spec", {})
        status = item.get("status", {})
        phase = status.get("phase", "Unknown")
        cstatuses = status.get("containerStatuses", [])
        restarts = sum(cs.get("restartCount", 0) for cs in cstatuses)
        ready_count = sum(1 for cs in cstatuses if cs.get("ready"))
        total_count = len(cstatuses) or len(spec.get("containers", []))
        waiting_reason = ""
        terminated_reason = ""
        for cs in cstatuses:
            w = cs.get("state", {}).get("waiting", {})
            t = cs.get("state", {}).get("terminated", {})
            if w.get("reason"):
                waiting_reason = w["reason"]
            if t.get("reason"):
                terminated_reason = t["reason"]
        if phase == "Running" and ready_count == total_count:
            disp = "running"
        elif phase == "Running":
            disp = waiting_reason or "not_ready"
        elif phase == "Pending":
            disp = waiting_reason or "pending"
        elif phase == "Succeeded":
            disp = "completed"
        else:
            disp = waiting_reason or terminated_reason or phase.lower()
        owners = meta.get("ownerReferences", [])
        owner_kind = ""
        deploy_name = ""
        for o in owners:
            owner_kind = o.get("kind", "")
            if owner_kind == "ReplicaSet":
                rs = o.get("name", "")
                deploy_name = "-".join(rs.split("-")[:-1]) if "-" in rs else rs
            elif owner_kind == "StatefulSet":
                deploy_name = o.get("name", "")
        pods.append({
            "name": meta.get("name", ""),
            "namespace": ns,
            "status": disp,
            "phase": phase,
            "restarts": restarts,
            "ready": f"{ready_count}/{total_count}",
            "waiting_reason": waiting_reason,
            "terminated_reason": terminated_reason,
            "deploy": deploy_name,
            "owner_kind": owner_kind,
            "created": meta.get("creationTimestamp", ""),
        })
    return pods


def _collect_deployments() -> list:
    data = _kubectl(["get", "deployments", "--all-namespaces", "-o", "json"])
    deps = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        ns = meta.get("namespace", "")
        if not ns.startswith(WATCHED_NS_PREFIX):
            continue
        spec = item.get("spec", {})
        status = item.get("status", {})
        deps.append({
            "name": meta.get("name", ""),
            "namespace": ns,
            "desired": spec.get("replicas", 1),
            "available": status.get("availableReplicas", 0) or 0,
            "ready": status.get("readyReplicas", 0) or 0,
        })
    return deps


def _collect_nodes() -> list:
    data = _kubectl(["get", "nodes", "-o", "json"])
    nodes = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        conditions = {c["type"]: c["status"] for c in item.get("status", {}).get("conditions", [])}
        nodes.append({
            "name": meta.get("name", ""),
            "memory_pressure": conditions.get("MemoryPressure", "False"),
            "disk_pressure": conditions.get("DiskPressure", "False"),
            "pid_pressure": conditions.get("PIDPressure", "False"),
            "ready": conditions.get("Ready", "Unknown"),
        })
    return nodes


# ── Log Collection & Filtering ─────────────────────────────────────────────

def _collect_pod_logs(pod_name: str, namespace: str) -> str:
    """Collect recent logs from a single pod, return filtered text."""
    raw = _kubectl_text([
        "logs", pod_name, "-n", namespace,
        f"--since={LOG_SINCE}", f"--tail={LOG_TAIL_PER_POD}",
    ])
    if raw.startswith("[kubectl error"):
        return raw
    # Filter out noise
    lines = []
    for line in raw.strip().split("\n"):
        if not line.strip():
            continue
        if LOG_NOISE_PATTERNS.search(line):
            continue
        lines.append(line)
    # Dedup consecutive identical lines
    deduped = []
    prev = None
    dup_count = 0
    for line in lines:
        if line == prev:
            dup_count += 1
        else:
            if dup_count > 0:
                deduped.append(f"  [... repeated {dup_count} more times]")
            deduped.append(line)
            prev = line
            dup_count = 0
    if dup_count > 0:
        deduped.append(f"  [... repeated {dup_count} more times]")
    return "\n".join(deduped)


async def _collect_all_logs() -> tuple[str, list[str]]:
    """Collect logs from all constructure-* pods.

    Returns:
        (filtered_log_text, error_lines)
    """
    pods = _state.pods
    if not pods:
        return "", []

    # Collect logs in parallel (batches of 5 to avoid overwhelming kubectl)
    async def _get_log(p):
        return p["namespace"], p["name"], await asyncio.to_thread(
            _collect_pod_logs, p["name"], p["namespace"]
        )

    results = await asyncio.gather(*[_get_log(p) for p in pods], return_exceptions=True)

    all_log_sections = []
    error_lines = []

    for r in results:
        if isinstance(r, Exception):
            continue
        ns, pod_name, log_text = r
        if not log_text or log_text.startswith("[kubectl error"):
            continue

        section = f"=== {ns}/{pod_name} ===\n{log_text}"
        all_log_sections.append(section)

        # Extract error lines
        for line in log_text.split("\n"):
            if ERROR_PATTERNS.search(line):
                error_lines.append(f"[{ns}/{pod_name}] {line.strip()}")

    combined = "\n\n".join(all_log_sections)
    log.info("Collected logs: %d pods, %d chars, %d error lines",
             len(all_log_sections), len(combined), len(error_lines))
    return combined, error_lines


# ── Anomaly Detection (rule-based, free) ──────────────────────────────────

def _detect_anomalies() -> list:
    anomalies = []
    now = time.time()
    baseline = _get_restart_baseline()

    for p in _state.pods:
        ns = p["namespace"]
        target = f"{ns}/{p['deploy'] or p['name']}"
        is_statefulset = p.get("owner_kind") == "StatefulSet"

        if p["waiting_reason"] == "CrashLoopBackOff":
            anomalies.append({
                "rule": "crash_loop", "severity": "high",
                "target": target, "namespace": ns,
                "pod_name": p["name"], "deploy": p["deploy"],
                "details": f"Pod {p['name']} in CrashLoopBackOff, {p['restarts']} restarts",
                "actionable": not is_statefulset,
            })
        elif p["terminated_reason"] == "OOMKilled":
            anomalies.append({
                "rule": "oom_killed", "severity": "high",
                "target": target, "namespace": ns,
                "pod_name": p["name"], "deploy": p["deploy"],
                "details": f"Pod {p['name']} OOMKilled, {p['restarts']} restarts",
                "actionable": not is_statefulset,
            })
        elif p["waiting_reason"] in ("ImagePullBackOff", "ErrImagePull"):
            anomalies.append({
                "rule": "image_pull_fail", "severity": "medium",
                "target": target, "namespace": ns,
                "pod_name": p["name"], "deploy": p["deploy"],
                "details": f"Pod {p['name']} {p['waiting_reason']}",
                "actionable": False,
            })
        elif p["status"] == "pending" and p.get("created"):
            try:
                from datetime import datetime, timezone
                created = datetime.fromisoformat(p["created"].replace("Z", "+00:00"))
                age_s = (datetime.now(timezone.utc) - created).total_seconds()
                if age_s > PENDING_TIMEOUT:
                    anomalies.append({
                        "rule": "stuck_pending", "severity": "medium",
                        "target": target, "namespace": ns,
                        "pod_name": p["name"], "deploy": p["deploy"],
                        "details": f"Pod {p['name']} pending for {int(age_s)}s",
                        "actionable": not is_statefulset,
                    })
            except Exception:
                pass

        pod_key = f"{ns}/{p['name']}"
        baseline_restarts = baseline.get(pod_key, 0)
        if p["restarts"] - baseline_restarts >= RESTART_FLAP_THRESHOLD:
            anomalies.append({
                "rule": "restart_flapping", "severity": "medium",
                "target": target, "namespace": ns,
                "pod_name": p["name"], "deploy": p["deploy"],
                "details": f"Pod {p['name']} restarted {p['restarts'] - baseline_restarts} times in ~1h (total: {p['restarts']})",
                "actionable": not is_statefulset,
            })

    for d in _state.deployments:
        if d["available"] < d["desired"]:
            key = f"{d['namespace']}/{d['name']}"
            if key not in _state.replica_mismatch_since:
                _state.replica_mismatch_since[key] = now
            elif now - _state.replica_mismatch_since[key] > REPLICA_MISMATCH_GRACE:
                anomalies.append({
                    "rule": "replica_mismatch", "severity": "high",
                    "target": key, "namespace": d["namespace"],
                    "pod_name": "", "deploy": d["name"],
                    "details": f"Deployment {d['name']}: {d['available']}/{d['desired']} available for >{REPLICA_MISMATCH_GRACE}s",
                    "actionable": True,
                })
        else:
            key = f"{d['namespace']}/{d['name']}"
            _state.replica_mismatch_since.pop(key, None)

    for n in _state.node_conditions:
        pressures = []
        if n["memory_pressure"] == "True":
            pressures.append("MemoryPressure")
        if n["disk_pressure"] == "True":
            pressures.append("DiskPressure")
        if n["pid_pressure"] == "True":
            pressures.append("PIDPressure")
        if pressures:
            anomalies.append({
                "rule": "node_pressure", "severity": "high",
                "target": f"node/{n['name']}", "namespace": "",
                "pod_name": "", "deploy": "",
                "details": f"Node {n['name']}: {', '.join(pressures)}",
                "actionable": False,
            })

    seen = {}
    sev_order = {"high": 0, "medium": 1, "low": 2}
    for a in anomalies:
        key = (a["target"], a["rule"])
        if key not in seen or sev_order.get(a["severity"], 9) < sev_order.get(seen[key]["severity"], 9):
            seen[key] = a
    return list(seen.values())


# ── Rate Limiting ──────────────────────────────────────────────────────────

def _can_act() -> bool:
    now = time.time()
    if now - _state.actions_hour_start > 3600:
        _state.actions_this_hour = 0
        _state.actions_hour_start = now
    return _state.actions_this_hour < MAX_ACTIONS_PER_HOUR


def _check_cooldown(target: str) -> bool:
    last = _state.cooldowns.get(target, 0.0)
    return (time.time() - last) >= COOLDOWN_SECONDS


# ── LLM Calls ──────────────────────────────────────────────────────────────

TRIAGE_SYSTEM_PROMPT = """You are a Kubernetes cluster log analyst for the Constructure platform (k3s, 7 namespaces, ~20 pods).

Your job is to analyze pod logs and determine if there are any issues that need attention.

RULES:
1. Respond with valid JSON only. No markdown, no explanation outside JSON.
2. Focus on real problems: recurring errors, connection failures, resource issues, application crashes.
3. Ignore normal operational noise: periodic polling, successful health checks, routine log messages.
4. Do NOT flag normal warnings or informational messages as issues.

RESPONSE FORMAT (JSON only):
{
  "has_issues": false,
  "issues": [
    {
      "pod": "namespace/pod-name",
      "severity": "high|medium|low",
      "summary": "brief description of the issue",
      "relevant_logs": "key log lines that show the problem"
    }
  ],
  "overall_assessment": "one sentence cluster health summary"
}"""

DECISION_SYSTEM_PROMPT = """You are a Kubernetes cluster guardian for the Constructure platform (k3s, 7 namespaces, ~20 pods). You analyze cluster anomalies and decide remediation actions.

SECURITY CONSTRAINTS:
- You may ONLY take write actions in these namespaces: constructure-arb, constructure-news, constructure-bots, constructure-dashboard, constructure-tools.
- You MUST NOT touch constructure-infra (contains StatefulSets: redis, postgres, qdrant) or constructure-monitor (contains this guardian).
- You have NO access to secrets, configmaps, or exec. Do not attempt to read or reference secret values.
- Automatic remediation in this cluster is limited to rollout_restart. Never scale Deployments and never delete Pods.
- Actions targeting forbidden namespaces will be automatically blocked.

CONSTRUCTURE WORKLOAD POLICY:
- constructure-arb/collector, resolver, validator -> rollout_restart only
- constructure-arb/strategy, executor-kalshi, executor-polymarket -> do_nothing with needs_human=true
- constructure-news/news-server, news-collector -> rollout_restart only
- constructure-news/news-publisher-x -> do_nothing with needs_human=true
- constructure-bots/x-bot -> rollout_restart only
- constructure-dashboard/dashboard -> rollout_restart only
- constructure-tools/gmail-bridge -> rollout_restart only
- constructure-tools/job-autoflow -> do_nothing with needs_human=true
- Anything in constructure-monitor or constructure-infra, including worldmonitor, exo-watchdog, k8s-guardian, and future worldmonitor-hourly jobs, is observe-only

RULES:
1. Respond with valid JSON only. No markdown, no explanation outside JSON.
2. Conservative approach: prefer "do_nothing" if uncertain. Clusters self-heal often.
3. Never escalate beyond the allowed actions.
4. Consider recent action history to avoid loops — if we already acted on the same target recently and it crashed again, choose do_nothing with needs_human=true.
5. OOMKilled pods usually need resource limit adjustments which you cannot do — flag needs_human=true.
6. CrashLoopBackOff right after an image change is likely a code bug — do_nothing, needs_human=true.
7. For replica mismatches, rollout_restart is the only automatic action.
8. ImagePullBackOff cannot be fixed by restart — always do_nothing, needs_human=true.
9. Node pressure (memory/disk) cannot be fixed by pod operations — do_nothing, needs_human=true.
10. If the workload policy says observe-only, always return do_nothing with needs_human=true.
11. For anomalies in constructure-infra or constructure-monitor, always do_nothing with needs_human=true.
12. If the owner workload is unclear, or the issue only shows up in logs without a confident Deployment target, return do_nothing with needs_human=true.

ALLOWED ACTIONS:
- "rollout_restart": restart a Deployment (only for restart-only workloads in writable namespaces)
- "do_nothing": log observation only

RESPONSE FORMAT (JSON only):
{"action": "do_nothing", "target": "namespace/deployment", "reasoning": "brief explanation", "confidence": 0.8, "needs_human": false}"""


async def _call_llm(model: str, system_prompt: str, user_prompt: str,
                    max_tokens: int = 500, temperature: float = 0.2,
                    source: str = "k8s-guardian") -> Optional[dict]:
    """Call watchdog or direct provider and parse JSON response."""
    client_request_id = f"{source}:{uuid.uuid4()}"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"{MINIMAX_API_BASE}/chat/completions"
            headers = {"Content-Type": "application/json"}
            if LLM_BASE_URL:
                url = f"{LLM_BASE_URL}/chat/completions"
                if LLM_API_KEY:
                    headers["Authorization"] = f"Bearer {LLM_API_KEY}"
            else:
                if not MINIMAX_API_KEY:
                    log.warning("Neither LLM_BASE_URL nor MINIMAX_API_KEY is set, skipping LLM call")
                    return None
                headers["Authorization"] = f"Bearer {MINIMAX_API_KEY}"

            resp = await client.post(
                url,
                headers=headers,
                json={
                    "source": source,
                    "client_request_id": client_request_id,
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"].strip()
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content)
            result = json.loads(content)
            log.info(
                "LLM [%s] response client_request_id=%s watchdog_job_id=%s: %s",
                model,
                client_request_id,
                resp.headers.get("x-watchdog-job-id"),
                json.dumps(result, ensure_ascii=False)[:300],
            )
            return result
    except json.JSONDecodeError as e:
        log.error("LLM [%s] invalid JSON client_request_id=%s: %s — %s", model, client_request_id, e,
                  content[:200] if 'content' in dir() else "")
        return None
    except Exception as e:
        log.error("LLM [%s] API error client_request_id=%s: %s", model, client_request_id, e)
        return None


def _build_triage_prompt(filtered_logs: str, anomalies: list) -> str:
    """Build prompt for M2 triage — log analysis."""
    healthy = sum(1 for p in _state.pods if p["status"] == "running")
    total = len(_state.pods)

    lines = [f"CLUSTER OVERVIEW: {total} pods, {healthy} running, {total - healthy} unhealthy"]
    lines.append("")

    if anomalies:
        lines.append("RULE-BASED ANOMALIES DETECTED:")
        for a in anomalies[:5]:
            lines.append(f"- [{a['severity']}] {a['target']}: {a['rule']} — {a['details']}")
        lines.append("")

    lines.append("POD LOGS (last 15 minutes, filtered):")
    # Truncate logs to ~8K tokens (~30K chars)
    max_chars = 30000
    if len(filtered_logs) > max_chars:
        filtered_logs = filtered_logs[:max_chars] + "\n[... truncated]"
    lines.append(filtered_logs)

    lines.append("")
    lines.append("Analyze these logs for any issues, errors, or concerning patterns. "
                 "Distinguish between real problems and normal operational behavior.")

    return "\n".join(lines)


def _build_decision_prompt(context: str, anomalies: list) -> str:
    """Build prompt for M2.5 decision — what action to take."""
    now = time.time()
    healthy = sum(1 for p in _state.pods if p["status"] == "running")
    total = len(_state.pods)

    lines = [f"CLUSTER STATE (ts={int(now)}):"]
    lines.append(f"Total pods: {total} | Running: {healthy} | Unhealthy: {total - healthy}")
    lines.append("")

    lines.append("ISSUES REQUIRING ATTENTION:")
    lines.append(context)
    lines.append("")

    lines.append("CLUSTER REMEDIATION POLICY:")
    for item in POLICY_GUIDANCE:
        lines.append(f"- {item}")
    lines.append("")

    if anomalies:
        lines.append("RULE-BASED ANOMALIES:")
        for a in anomalies[:5]:
            lines.append(f"- [{a['severity']}] {a['target']}: {a['rule']} — {a['details']}")
            policy = _target_policy(a["namespace"], a.get("deploy", ""))
            lines.append(f"  Policy: {_allowed_action_text(policy)} — {policy['reason']}")
            cooldown_active = not _check_cooldown(a["target"])
            if cooldown_active:
                lines.append(f"  ⚠ COOLDOWN ACTIVE — was acted on <{COOLDOWN_SECONDS}s ago")
            if not a.get("actionable"):
                lines.append(f"  ⚠ NOT ACTIONABLE — cannot be fixed by kubectl operations")
        lines.append("")

    lines.append("NODE STATUS:")
    for n in _state.node_conditions:
        lines.append(f"- {n['name']}: Ready={n['ready']} Memory={n['memory_pressure']} Disk={n['disk_pressure']}")
    lines.append("")

    recent = _recent_actions(5)
    if recent:
        lines.append("RECENT ACTIONS (last 5):")
        for a in recent:
            ts_str = time.strftime("%H:%M:%S", time.localtime(a["ts"]))
            lines.append(f"- [{ts_str}] {a['action']} on {a['target']}: "
                         f"{'OK' if a['success'] else 'FAILED'} — {a['llm_reasoning']}")
    else:
        lines.append("RECENT ACTIONS: None.")
    lines.append("")

    lines.append("Decide the single best action. "
                 "If cooldown is active, the workload is observe-only, or the owner is unclear, choose do_nothing.")

    return "\n".join(lines)


# ── Action Execution ───────────────────────────────────────────────────────

async def _execute_action(decision: dict, anomaly: dict, model: str) -> None:
    action = decision.get("action", "do_nothing")
    confidence = decision.get("confidence", 0.0)
    reasoning = decision.get("reasoning", "")
    needs_human = decision.get("needs_human", False)
    target = decision.get("target", anomaly.get("target", ""))
    namespace, workload_name, effective_target, policy = _resolve_action_target(target, anomaly)
    target = effective_target

    if action not in ALLOWED_ACTIONS:
        log.warning("BLOCKED: LLM returned disallowed action '%s'", action)
        _record_action(anomaly, f"[BLOCKED: disallowed action '{action}'] {reasoning}",
                       confidence, action, "", "blocked", False, True, model)
        return

    if action == "do_nothing" or confidence < CONFIDENCE_THRESHOLD:
        if confidence < CONFIDENCE_THRESHOLD and action != "do_nothing":
            reasoning = f"[OVERRIDDEN: confidence {confidence} < {CONFIDENCE_THRESHOLD}] {reasoning}"
            action = "do_nothing"
        _record_action(anomaly, reasoning, confidence, action, "", "skipped", True, needs_human, model)
        log.info("Guardian [%s]: do_nothing for %s — %s", model, target, reasoning)
        # Notify Discord if human intervention needed
        if needs_human:
            await _notify_discord(
                "需要人工处理",
                f"**问题**: {anomaly.get('details', reasoning)}\n"
                f"**原因**: {reasoning}\n"
                f"**建议**: 需要 sudo 或物理介入",
                severity=anomaly.get("severity", "medium"),
                target=target,
                rule=anomaly.get("rule", "needs_human"),
            )
        return

    if action not in policy["allowed_actions"]:
        blocked_reason = (
            f"[BLOCKED: policy forbids {action} on {target}] "
            f"Allowed={_allowed_action_text(policy)} — {policy['reason']}. {reasoning}"
        )
        log.warning("BLOCKED: policy forbids %s on %s", action, target)
        _record_action(anomaly, blocked_reason, confidence, action, "", "blocked_policy", False, True, model)
        await _notify_discord(
            "策略阻止自动修复",
            f"**目标**: `{target}`\n"
            f"**动作**: `{action}`\n"
            f"**原因**: {policy['reason']}\n"
            f"**需要**: 手动介入",
            severity=anomaly.get("severity", "medium"),
            target=target,
            rule=anomaly.get("rule", "blocked_policy"),
        )
        return

    if namespace not in WRITABLE_NAMESPACES:
        log.warning("BLOCKED: namespace '%s' is not in WRITABLE_NAMESPACES", namespace)
        _record_action(anomaly, f"[BLOCKED: namespace '{namespace}' is read-only] {reasoning}",
                       confidence, action, "", "blocked_ns", False, True, model)
        await _notify_discord(
            "受保护资源异常",
            f"**目标**: `{target}` (受保护 namespace)\n"
            f"**问题**: {anomaly.get('details', '')}\n"
            f"**LLM建议**: {action} — {reasoning}\n"
            f"**需要**: sudo/手动处理",
            severity="high", target=target, rule=anomaly.get("rule", "blocked_ns"),
        )
        return

    if not workload_name or not _SAFE_NAME_RE.match(workload_name):
        log.warning("BLOCKED: invalid resource name '%s'", workload_name)
        _record_action(anomaly, f"[BLOCKED: invalid name '{workload_name}'] {reasoning}",
                       confidence, action, "", "blocked_name", False, True, model)
        return

    if action != "rollout_restart":
        _record_action(anomaly, reasoning, confidence, action, "", "unknown action", False, True, model)
        return

    cmd_args = ["kubectl", "rollout", "restart", f"deployment/{workload_name}", "-n", namespace]

    cmd_str = " ".join(cmd_args)
    log.info("Guardian [%s]: executing %s", model, cmd_str)

    try:
        result = await asyncio.to_thread(
            subprocess.run, cmd_args, capture_output=True, text=True, timeout=30,
        )
        success = result.returncode == 0
        output = result.stdout.strip() or result.stderr.strip()
        _record_action(anomaly, reasoning, confidence, action, cmd_str, output, success, needs_human, model)
        _state.cooldowns[target] = time.time()
        _state.actions_this_hour += 1
        log.info("Guardian [%s]: %s → %s", model, cmd_str, "OK" if success else f"FAILED: {output}")
        if success:
            await _notify_discord(
                "已自动修复",
                f"**动作**: `{cmd_str}`\n**原因**: {reasoning}\n**结果**: ✅ 成功",
                severity="info", target=target, rule=f"action_{action}",
            )
        else:
            await _notify_discord(
                "自动修复失败",
                f"**动作**: `{cmd_str}`\n**原因**: {reasoning}\n**结果**: ❌ {output}\n**需要**: 手动介入",
                severity="high", target=target, rule=f"action_fail_{action}",
            )
    except Exception as e:
        _record_action(anomaly, reasoning, confidence, action, cmd_str, str(e), False, True, model)
        log.error("Guardian [%s]: execution failed: %s", model, e)
        await _notify_discord(
            "执行异常",
            f"**动作**: `{cmd_str}`\n**错误**: {e}\n**需要**: 手动介入",
            severity="high", target=target, rule="exec_exception",
        )


# ── Main Loop (Two-tier) ─────────────────────────────────────────────────

async def _poll_once():
    # Step 1: Collect cluster state (pods, deployments, nodes)
    await _collect_cluster_state()
    if not _state.last_poll_ok:
        return

    # Step 2: Rule-based anomaly detection (free, instant)
    anomalies = _detect_anomalies()
    _state.anomalies = anomalies
    _save_snapshot()

    # Step 3: Collect and filter logs from all pods
    filtered_logs, error_lines = await _collect_all_logs()
    _state.errors_found = len(error_lines) > 0

    # Step 4: Decide which path to take
    has_rule_anomalies = bool(anomalies)
    has_error_logs = len(error_lines) > 0

    if not has_rule_anomalies and not has_error_logs:
        # All clear — still do M2 triage if we have logs
        if filtered_logs:
            triage = await _call_llm(
                MODEL_TRIAGE, TRIAGE_SYSTEM_PROMPT,
                _build_triage_prompt(filtered_logs, anomalies),
                max_tokens=500, temperature=0.1,
                source="k8s-guardian-triage",
            )
            if triage:
                _state.last_triage_result = triage.get("overall_assessment", "")
                if triage.get("has_issues") and triage.get("issues"):
                    # M2 found something in the logs — escalate to M2.5
                    log.info("M2 triage found %d issues, escalating to M2.5",
                             len(triage["issues"]))
                    issues_text = json.dumps(triage["issues"], ensure_ascii=False)
                    await _handle_llm_decision(issues_text, anomalies)
                else:
                    log.info("M2 triage: all clear — %s", _state.last_triage_result)
            else:
                log.info("No anomalies, M2 unavailable, skipping triage")
        else:
            log.info("No anomalies, no logs to analyze")
        return

    if has_error_logs:
        # Fast path: ERROR lines found → go directly to M2.5
        log.info("ERROR lines found (%d), fast-path to M2.5", len(error_lines))
        error_context = "ERROR LINES FOUND IN LOGS:\n" + "\n".join(error_lines[:20])
        if len(error_lines) > 20:
            error_context += f"\n[... {len(error_lines) - 20} more error lines]"
        await _handle_llm_decision(error_context, anomalies)
        return

    if has_rule_anomalies:
        # Rule anomalies but no error logs — M2 triage first
        log.info("Rule anomalies detected (%d), running M2 triage", len(anomalies))
        triage = await _call_llm(
            MODEL_TRIAGE, TRIAGE_SYSTEM_PROMPT,
            _build_triage_prompt(filtered_logs, anomalies),
            max_tokens=500, temperature=0.1,
            source="k8s-guardian-triage",
        )
        if triage:
            _state.last_triage_result = triage.get("overall_assessment", "")
            if triage.get("has_issues") and triage.get("issues"):
                log.info("M2 confirmed issues, escalating to M2.5")
                issues_text = json.dumps(triage["issues"], ensure_ascii=False)
                await _handle_llm_decision(issues_text, anomalies)
            else:
                log.info("M2 triage: anomalies are benign — %s", _state.last_triage_result)
                # Record that we observed but took no action
                for a in anomalies:
                    _record_action(a, f"M2 triage: benign — {_state.last_triage_result}",
                                   0.0, "do_nothing", "", "triage_ok", True, False, MODEL_TRIAGE)
        else:
            # M2 unavailable — fall back to direct M2.5 for rule anomalies
            log.warning("M2 unavailable, falling back to M2.5 for rule anomalies")
            context = "RULE-BASED ANOMALIES (M2 triage unavailable):\n"
            for a in anomalies:
                context += f"- [{a['severity']}] {a['target']}: {a['details']}\n"
            await _handle_llm_decision(context, anomalies)


async def _handle_llm_decision(context: str, anomalies: list):
    """Send context to M2.5 for decision and execute."""
    actionable = [a for a in anomalies if _can_auto_restart_anomaly(a) and _check_cooldown(a["target"])]

    if not _can_act():
        log.warning("Hourly action limit reached (%d/%d), logging only",
                     _state.actions_this_hour, MAX_ACTIONS_PER_HOUR)
        for a in anomalies:
            _record_action(a, "hourly limit reached", 0.0, "do_nothing",
                           "", "rate_limited", True, True, MODEL_DECISION)
        return

    decision_prompt = _build_decision_prompt(context, anomalies)
    decision = await _call_llm(
        MODEL_DECISION, DECISION_SYSTEM_PROMPT,
        decision_prompt, max_tokens=300, temperature=0.2,
        source="k8s-guardian-decision",
    )

    if not decision:
        log.warning("M2.5 unavailable, no action taken")
        for a in anomalies:
            _record_action(a, "M2.5 unavailable", 0.0, "do_nothing",
                           "", "llm_unavailable", True, True, MODEL_DECISION)
        return

    # Find the matching anomaly for the target, or use first actionable
    target = decision.get("target", "")
    matched = next((a for a in anomalies if a["target"] == target), None)
    if not matched:
        matched = actionable[0] if actionable else (anomalies[0] if anomalies else {
            "rule": "log_analysis", "severity": "medium",
            "target": target, "namespace": target.split("/")[0] if "/" in target else "",
            "details": "Issue detected via log analysis", "actionable": True,
        })

    await _execute_action(decision, matched, MODEL_DECISION)


async def _guardian_loop():
    log.info("Guardian loop started (interval=%ds, triage_model=%s, decision_model=%s)",
             POLL_INTERVAL, MODEL_TRIAGE, MODEL_DECISION)
    while True:
        try:
            await _poll_once()
        except Exception as e:
            log.error("Guardian loop error: %s", e)
        await asyncio.sleep(POLL_INTERVAL)


# ── FastAPI ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(application: FastAPI):
    _db()
    task = asyncio.create_task(_guardian_loop())
    log.info("k8s-guardian started (two-tier: %s → %s)", MODEL_TRIAGE, MODEL_DECISION)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    if _db_conn:
        _db_conn.close()


app = FastAPI(title="k8s-guardian", lifespan=lifespan)


@app.get("/health")
async def health():
    return {
        "ok": _state.last_poll_ok,
        "last_poll_ts": _state.last_poll_ts,
        "uptime": time.time() - _state.actions_hour_start if _state.actions_hour_start else 0,
    }


@app.get("/api/status")
async def status():
    healthy = sum(1 for p in _state.pods if p["status"] == "running")
    return {
        "ok": _state.last_poll_ok and len(_state.anomalies) == 0,
        "policy_version": POLICY_VERSION,
        "last_poll_ts": _state.last_poll_ts,
        "pod_count": len(_state.pods),
        "healthy_count": healthy,
        "anomaly_count": len(_state.anomalies),
        "anomalies": _state.anomalies,
        "actions_this_hour": _state.actions_this_hour,
        "cooldowns": {k: v for k, v in _state.cooldowns.items() if time.time() - v < COOLDOWN_SECONDS},
        "nodes": _state.node_conditions,
        "triage_model": MODEL_TRIAGE,
        "decision_model": MODEL_DECISION,
        "last_triage": _state.last_triage_result,
        "errors_found": _state.errors_found,
    }


@app.get("/api/policy")
async def policy():
    return {
        "policy_version": POLICY_VERSION,
        "targets": _policy_rows(),
    }


@app.get("/api/actions")
async def actions(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = _db().execute(
        "SELECT * FROM actions ORDER BY ts DESC LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()
    total = _db().execute("SELECT COUNT(*) as c FROM actions").fetchone()["c"]
    return {"actions": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}


@app.post("/api/poll")
async def force_poll():
    await _poll_once()
    return {
        "ok": True,
        "anomaly_count": len(_state.anomalies),
        "anomalies": _state.anomalies,
        "last_triage": _state.last_triage_result,
        "errors_found": _state.errors_found,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

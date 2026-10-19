#!/usr/bin/env bash
# End-to-end demo / e2e test on a throwaway kind cluster.
#
#   scripts/kind-demo.sh            create cluster, deploy crashing workloads + guardian, assert, delete cluster
#   KEEP=1 scripts/kind-demo.sh     same, but leave the cluster running (delete it yourself afterwards)
#   CLUSTER=... IMAGE=... OUT=dir   cluster name, guardian image tag to build, directory for transcript artefacts
#
# Needs: docker, kind, kubectl, curl, python3. Never touches your default kubeconfig: everything uses
# a private kubeconfig file, and the cluster is named $CLUSTER (default "guardian-demo").
set -euo pipefail

CLUSTER="${CLUSTER:-guardian-demo}"
IMAGE="${IMAGE:-k8s-guardian:0.2.0}"
WORKLOAD_IMAGE="${WORKLOAD_IMAGE:-python:3.12-slim}"
PORT="${PORT:-18765}"
OUT="${OUT:-}"   # optional directory: transcript artefacts are written there
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
export KUBECONFIG="$WORK/kubeconfig"   # overrides any ambient KUBECONFIG on purpose
PF_PID=""

log() { printf '\n==> %s\n' "$*"; }

cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
  if [ "${KEEP:-0}" != "1" ]; then
    log "deleting kind cluster $CLUSTER"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  else
    log "cluster kept. kubeconfig: $KUBECONFIG   delete with: kind delete cluster --name $CLUSTER"
    return
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

log "creating kind cluster $CLUSTER"
kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --wait 180s

log "building guardian image and loading images into the cluster"
docker build -q -t "$IMAGE" "$ROOT" >/dev/null
docker image inspect "$WORKLOAD_IMAGE" >/dev/null 2>&1 || docker pull -q "$WORKLOAD_IMAGE" >/dev/null
kind load docker-image --name "$CLUSTER" "$IMAGE" "$WORKLOAD_IMAGE" >/dev/null

log "deploying demo workloads (one healthy, three broken)"
kubectl apply -f "$ROOT/examples/demo-workloads.yaml"
kubectl -n demo rollout status deploy/web --timeout=120s

log "waiting for the broken workloads to start crash-looping"
for _ in $(seq 1 60); do
  n=$(kubectl -n demo get pods --no-headers 2>/dev/null | grep -cE 'CrashLoopBackOff|Error|OOMKilled' || true)
  [ "$n" -ge 3 ] && break
  sleep 3
done
kubectl -n demo get pods

log "deploying k8s-guardian (live mode, restricted to namespace 'demo')"
# The manifests reference the image as k8s-guardian:<tag>; point them at the image we just built.
kubectl kustomize "$ROOT/deploy/k8s/overlays/demo" | sed -E "s#image: k8s-guardian:.*#image: $IMAGE#" | kubectl apply -f -
kubectl -n k8s-guardian rollout status deploy/k8s-guardian --timeout=180s

log "port-forwarding to the guardian API"
kubectl -n k8s-guardian port-forward svc/k8s-guardian "$PORT:8000" >/dev/null 2>&1 &
PF_PID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done

# Poll interval is 30s and the restart cooldown 60s, so the full story takes ~2 minutes:
# restart -> cooldown -> "restarted already and still broken" -> escalate to a human.
log "waiting (up to 6 min) for the guardian to restart crashy-api once and then escalate"
deadline=$((SECONDS + 360))
until curl -fs "http://127.0.0.1:$PORT/api/actions?limit=200" > "$WORK/actions.json" \
      && python3 - "$WORK/actions.json" <<'PY'
import json, sys
by = {}
for r in json.load(open(sys.argv[1]))["actions"]:
    by.setdefault(r["target"], []).append(r["result"])
done = (
    {"executed", "repeat_failure"} <= set(by.get("demo/crashy-api", []))
    and "blocked_policy" in by.get("demo/payments-executor", [])
    and "blocked_not_actionable" in by.get("demo/batch-worker", [])
)
sys.exit(0 if done else 1)
PY
do
  [ "$SECONDS" -lt "$deadline" ] || { echo "timed out waiting for the escalation"; break; }
  sleep 10
done

log "guardian logs"
kubectl -n k8s-guardian logs deploy/k8s-guardian | grep -E "decision |action |poll complete|loop started" | tail -n 25 | tee "$WORK/guardian.log"
curl -fs "http://127.0.0.1:$PORT/api/status" > "$WORK/status.json"

log "audit trail (oldest first)"
python3 - "$WORK/actions.json" <<'PY'
import json, sys
rows = sorted(json.load(open(sys.argv[1]))["actions"], key=lambda r: r["ts"])
for r in rows:
    print(f'{r["target"]:<24} {r["rule"]:<12} {r["result"]:<15} human={r["needs_human"]} {r["reason"][:70]}')
PY

log "workloads after the guardian's work"
kubectl -n demo get pods

log "what actually happened to the Deployments (restart annotation + rollout generation)"
for d in web crashy-api payments-executor batch-worker; do
  ann=$(kubectl -n demo get deploy "$d" -o jsonpath='{.spec.template.metadata.annotations.kubectl\.kubernetes\.io/restartedAt}')
  gen=$(kubectl -n demo get deploy "$d" -o jsonpath='{.metadata.generation}')
  printf '%-20s generation=%s restartedAt=%s\n' "$d" "$gen" "${ann:--}"
done

log "asserting expected behaviour"
python3 - "$WORK/actions.json" "$ROOT" <<'PY'
import json, subprocess, sys
rows = json.load(open(sys.argv[1]))["actions"]
by = {}
for r in rows:
    by.setdefault(r["target"], []).append(r["result"])
def need(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        need.failed = True
need.failed = False
need(by.get("demo/crashy-api", []).count("executed") == 1, "crashy-api was restarted exactly once")
need("repeat_failure" in by.get("demo/crashy-api", []), "crashy-api escalated to a human instead of restart-looping")
need(set(by.get("demo/payments-executor", [])) == {"blocked_policy"}, "payments-executor was blocked by policy on every poll")
need("executed" not in by.get("demo/payments-executor", []) + by.get("demo/batch-worker", []), "policy-protected / OOM workloads were never restarted")
need("demo/web" not in by, "healthy web was never considered")
sys.exit(1 if need.failed else 0)
PY

if [ -n "$OUT" ]; then
  mkdir -p "$OUT"
  cp "$WORK/guardian.log" "$WORK/actions.json" "$WORK/status.json" "$OUT/"
fi
log "demo OK"

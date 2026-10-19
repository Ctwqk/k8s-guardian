"""Safety checks for the throwaway-cluster demo, without Docker or a Kubernetes cluster."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def test_demo_never_deletes_a_cluster_that_already_existed(tmp_path):
    kind = tmp_path / "kind"
    kind.write_text("""#!/bin/sh
case "$1 $2" in
  "get clusters") echo already-there ;;
  "create cluster") echo "cluster already exists" >&2; exit 1 ;;
  "delete cluster") touch "$DELETED_MARKER" ;;
esac
""")
    kind.chmod(0o755)
    deleted = tmp_path / "deleted"
    script = Path(__file__).resolve().parents[1] / "scripts" / "kind-demo.sh"
    result = subprocess.run(
        ["bash", str(script)],
        env={
            **os.environ,
            "PATH": f"{tmp_path}:{os.defpath}",
            "TMPDIR": str(tmp_path),
            "CLUSTER": "already-there",
            "KEEP": "0",
            "DELETED_MARKER": str(deleted),
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert not deleted.exists(), "a failed demo must not delete a pre-existing cluster"

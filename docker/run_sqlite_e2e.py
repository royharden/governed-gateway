"""Offline public-dev evaluator + actual durable SQLite demo; preserves evidence.

Launch with --network none and a new labelled m8-r03-* local named volume at
/m8-runtime. No cleanup/deletion, live APIs, listeners, or credential-file I/O.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import sys
import uuid


def main():
    parent = Path("/m8-runtime")
    if not parent.is_dir():
        raise RuntimeError("explicit durable local volume required")
    runtime = parent / ("journey-" + uuid.uuid4().hex)
    runtime.mkdir(exist_ok=False)
    now = datetime.now(timezone.utc)
    config = json.loads(Path("/app/fixtures/bootstrap/simulation.example.json").read_text())
    # New isolated test authority, never a renewal of the expired sample authority.
    # Original monetary cap, attempt quota and authorization maxima are unchanged.
    config.update(runtime_root=str(runtime), authority_id="rv2-docker-" + uuid.uuid4().hex,
                  created_utc=(now - timedelta(minutes=1)).isoformat(),
                  deadline_utc=(now + timedelta(hours=1)).isoformat())
    config_path = runtime / "simulation.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    os.environ["GATEWAY_RUNTIME_ROOT"] = str(runtime)
    os.environ["M8_TEST_RUNTIME_PARENT"] = str(parent)
    os.environ["M8_DOCKER_CONFIG"] = str(config_path)
    results = []
    for label, command in (
        ("public-development", [sys.executable, "-m", "pytest", "/app/tests/eval", "-q", "--tb=short", "-p", "no:cacheprovider"]),
        ("sqlite-controller-journey", [sys.executable, "-m", "pytest", "/app/tests/docker", "-q", "--tb=short", "-p", "no:cacheprovider"]),
    ):
        completed = subprocess.run(command, capture_output=True, text=True, timeout=600)
        log = runtime / (label + ".log")
        log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        results.append(dict(label=label, command=command, exit_code=completed.returncode,
                            log_sha256=hashlib.sha256(log.read_bytes()).hexdigest()))
        print(completed.stdout, end="")
        print(completed.stderr, end="", file=sys.stderr)
    record = dict(schema_version=1, kind="m8-rv2-docker-public-dev", mode="simulation",
        platform=platform.platform(), python=platform.python_version(), runtime=str(runtime),
        config_sha256=hashlib.sha256(config_path.read_bytes()).hexdigest(), checks=results,
        live="not-run:no-keys-no-spend", holdout="not-run:public-development-only",
        product_acceptance="incomplete", passed=all(r["exit_code"] == 0 for r in results))
    (runtime / "docker-result.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record, sort_keys=True))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

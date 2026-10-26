"""One explicitly approved expired authority; never refresh its fixed tuple."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest


def test_expired_config_refuses_before_funding():
    approval_path = os.environ.get("M8_EXPIRY_APPROVAL")
    if not approval_path:
        pytest.skip("Requires an explicit INT-approved fresh expiry tuple")
    approval = json.loads(Path(approval_path).read_bytes())
    plan_path = Path(os.environ["M8_EXPIRY_PLAN"])
    assert hashlib.sha256(plan_path.read_bytes()).hexdigest() == approval["plan_sha256"]
    plan = json.loads(plan_path.read_bytes())
    assert approval["verdict"] == "APPROVED"
    source = approval.get("source", approval.get("candidate"))
    assert source == plan.get("source", plan.get("candidate"))
    proposal = Path(plan.get("config_bytes_proposal", plan.get("proposed_config")))
    config_bytes = proposal.read_bytes()
    assert hashlib.sha256(config_bytes).hexdigest() == approval["config_sha256"]
    assert plan["config_sha256"] == approval["config_sha256"]
    raw = json.loads(config_bytes)
    assert plan["tuple"] == approval["tuple"]
    assert {key: raw[key] for key in approval["tuple"]} == approval["tuple"]
    root = Path(plan.get("source_root", os.environ["M8_SOURCE_ROOT"])).resolve()
    runtime = Path(raw["runtime_root"]).resolve()
    config = runtime / "simulation.json"
    assert runtime.parent == Path("C:/agent-runtime").resolve()
    assert raw["authority_id"].startswith("m8-") and runtime.name == raw["authority_id"]
    assert not runtime.exists(), "Approved authority must never be reused"
    now = datetime.now(timezone.utc)
    created = datetime.fromisoformat(raw["created_utc"])
    deadline = datetime.fromisoformat(raw["deadline_utc"])
    assert created < deadline < now
    assert 0 < (now - created).total_seconds() < 172800
    assert raw["cap_usd"] == "0.004500" and raw["max_outbound_attempts"] == 256
    sample = json.loads((root / "fixtures/bootstrap/simulation.example.json").read_bytes())
    changed = {key for key in sample if sample[key] != raw[key]}
    assert changed == {"authority_id", "runtime_root", "created_utc", "deadline_utc"}

    def source_pin():
        head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        assert head == source
        assert not subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True).strip()
        return head

    import gateway.bootstrap
    assert Path(gateway.bootstrap.__file__).resolve() == root / "src/gateway/bootstrap.py"
    evidence_path = Path(os.environ["M8_EXPIRY_EVIDENCE"])
    record = {"source_before": source_pin(), "tuple": approval["tuple"],
              "config_sha256": approval["config_sha256"], "prelaunch_utc": now.isoformat(),
              "runtime_existed_before": False, "timeout_seconds": 30,
              "import_witness": gateway.bootstrap.__file__,
              "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    with evidence_path.open("x", encoding="utf-8") as target:
        json.dump(record, target, indent=2)
    environment = os.environ.copy()
    environment.update(plan.get("env", {}))
    command = plan.get("command", plan.get("bounded_subprocess_command"))
    assert Path(command[0]).resolve() == Path(sys.executable).resolve()
    assert command[1:4] == ["-m", "gateway.bootstrap", "--config"]
    assert Path(command[4]).resolve() == config and command[5:] == ["--initialize"]
    assert plan.get("timeout_seconds", 30) == 30
    assert Path(environment["M8_SOURCE_ROOT"]).resolve() == root
    assert [Path(value).resolve() for value in environment["PYTHONPATH"].split(os.pathsep)] == [
        root / "src", Path(__file__).resolve().parent]
    started = time.monotonic()
    try:
        runtime.mkdir(exist_ok=False)
        assert runtime.is_dir() and not runtime.is_symlink() and not list(runtime.iterdir())
        with config.open("xb") as target:
            assert target.write(config_bytes) == len(config_bytes)
        assert config.parent == runtime and config.read_bytes() == config_bytes
        assert hashlib.sha256(config.read_bytes()).hexdigest() == approval["config_sha256"]
        assert list(runtime.iterdir()) == [config], "Only the approved config may precede launch"
        record.update(prepared_files=[path.name for path in runtime.iterdir()],
                      config_path=str(config), command=command, runtime_empty_before_config=True)
        try:
            result = subprocess.run(command, env=environment,
                                    capture_output=True, text=True, timeout=30)
            record.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                          timed_out=False)
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
            record.update(stdout=decoded(error.stdout), stderr=decoded(error.stderr), timed_out=True)
            raise
        finally:
            record["elapsed_seconds"] = time.monotonic() - started
            record["databases"] = {}
            for name in ("policy.sqlite3", "accounting.sqlite3"):
                path = runtime / name
                counts = None
                if path.exists():
                    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
                    try:
                        tables = [row[0] for row in connection.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
                        counts = {table: connection.execute('SELECT COUNT(*) FROM "' +
                                  table.replace('"', '""') + '"').fetchone()[0] for table in tables}
                    finally:
                        connection.close()
                record["databases"][name] = {"exists": path.exists(), "counts": counts}
        assert record["exit_code"] == 2
        errors = []
        for line in record["stderr"].splitlines():
            if line.startswith('{"error":'):
                errors.append(json.loads(line)["error"])
        assert errors == ["stale_evidence"], record["stderr"]
        policy = record["databases"]["policy.sqlite3"]["counts"]
        if policy is not None:
            for table in ("permits", "operations", "evaluations", "activation_events"):
                assert policy[table] == 0
        accounting = record["databases"]["accounting.sqlite3"]["counts"]
        if accounting is not None:
            for table in ("operations", "attempts", "children"):
                assert accounting[table] == 0
        record["assertions_passed"] = True
    finally:
        record["source_after"] = source_pin()
        evidence_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

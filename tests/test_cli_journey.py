"""Real subprocess no-key public-fixture journey, never a seeded passing report."""
import json
import os
from pathlib import Path
import subprocess
import sys


def test_public_fixture_cli_journey(simulation_config):
    root = Path(os.environ.get("M8_SOURCE_ROOT", Path(__file__).resolve().parents[1])).resolve()
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    environment["GATEWAY_RUNTIME_ROOT"] = str(simulation_config.parent)
    result = subprocess.run([sys.executable, "-m", "gateway.bootstrap", "--config", str(simulation_config), "--initialize"],
        env=environment, capture_output=True, text=True, timeout=180)
    (simulation_config.parent / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (simulation_config.parent / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    assert result.returncode == 0, f"CLI exit={result.returncode}; {result.stderr[-1500:]}; artifacts={simulation_config.parent}"
    for expected in ("SIMULATION ONLY", "Original retained result replayed", "Boundary request rejected", "stale CAS rejected"):
        assert expected in result.stdout
    assert "different_target_unobserved" in result.stdout
    assert (simulation_config.parent / "policy.sqlite3").is_file()
    assert (simulation_config.parent / "accounting.sqlite3").is_file()


def test_mock_config_is_new_authority_not_sample_reset(simulation_config, loaded_simulation):
    raw = json.loads(simulation_config.read_text())
    spec, plans, original, boundary, caller = loaded_simulation
    assert spec.authority_id.startswith("m8-rv1-")
    assert spec.authority_id != "explicit-simulation-example-20261024"
    assert str(spec.cap_usd) == "0.004500"
    assert len(plans) == 2 and len(plans[0].tasks) == 60
    assert raw["mode"] == "simulation"

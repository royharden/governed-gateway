"""Routine-runner selection controls; no CLI, process or journey is executed."""
import importlib.util
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest


@pytest.fixture
def runner():
    path = Path(__file__).resolve().parents[1] / "scripts" / "check.py"
    spec = importlib.util.spec_from_file_location("r04_routine_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_routine_selection_never_collects_grant_bound_tests(runner, monkeypatch):
    # what_bug_this_catches: a routine CI invocation collecting an ungranted
    # full journey or expiry authority as a side effect of recursive discovery.
    monkeypatch.setattr(sys, "argv", ["check.py", "--collect-only", "-q", "-k", "clock", "--tb=short"])
    monkeypatch.setattr(runner.subprocess, "check_output", Mock(return_value="a" * 40))
    execute = Mock(return_value=0)
    monkeypatch.setattr(runner.subprocess, "call", execute)
    assert runner.main() == 0
    command = execute.call_args.args[0]
    selected = [Path(value) for value in command if value.endswith(".py")]
    assert selected and all(path.is_file() for path in selected)
    assert {path.name for path in selected}.isdisjoint({"test_cli_journey.py", "test_cli_expiry.py", "test_sqlite_journey.py"})
    assert all("docker" not in path.parts for path in selected)
    assert "test_r04_clock_refusal.py" in {path.name for path in selected}
    assert "test_governance.py" in {path.name for path in selected}
    assert "--collect-only" in command
    assert command[command.index("-k") + 1] == "clock"
    environment = execute.call_args.kwargs["env"]
    assert environment["M8_SOURCE_ROOT"] == str(Path(runner.__file__).resolve().parents[1])


@pytest.mark.parametrize("extra", [
    ["tests/test_cli_journey.py"], ["--pyargs", "gateway"],
    ["--override-ini", "testpaths=tests/docker"],
])
def test_unknown_path_or_pytest_override_refused_before_spawn(runner, monkeypatch, extra):
    # what_bug_this_catches: raw forwarded pytest arguments widening the
    # explicit routine selection into a held execution path.
    monkeypatch.setattr(sys, "argv", ["check.py", *extra])
    execute = Mock()
    monkeypatch.setattr(runner.subprocess, "call", execute)
    with pytest.raises(SystemExit) as failure:
        runner.main()
    assert failure.value.code == 2
    execute.assert_not_called()

"""Routine-runner selection controls; no CLI, process or journey is executed."""
import asyncio
import importlib.util
import os
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
    ["--", "tests/test_cli_journey.py"], ["--", "--pyargs", "gateway"],
    ["-c", "pytest.ini"], ["-o", "addopts=tests/test_cli_journey.py"],
    ["-p", "unapproved_plugin"], ["--rootdir", "tests/docker"],
    ["--confcutdir", "tests/docker"],
    ["--collect-only=tests/test_cli_journey.py"],
    ["--junit", "report.xml", "tests/test_cli_journey.py"],
    ["-k", "clock", "tests/test_cli_journey.py"],
])
def test_unknown_path_or_pytest_override_refused_before_spawn(runner, monkeypatch, extra):
    # what_bug_this_catches: raw forwarded pytest arguments widening the
    # explicit routine selection into a held execution path.
    monkeypatch.setattr(sys, "argv", ["check.py", *extra])
    provenance = Mock()
    monkeypatch.setattr(runner.subprocess, "check_output", provenance)
    execute = Mock()
    monkeypatch.setattr(runner.subprocess, "call", execute)
    with pytest.raises(SystemExit) as failure:
        runner.main()
    assert failure.value.code == 2
    provenance.assert_not_called()
    execute.assert_not_called()


@pytest.fixture
def mocked_run(runner, monkeypatch):
    # Every runner process boundary is mocked, including Git provenance reads.
    monkeypatch.setattr(sys, "argv", ["check.py"])
    monkeypatch.setattr(runner.subprocess, "check_output", Mock(return_value="a" * 40))
    execute = Mock(return_value=0)
    monkeypatch.setattr(runner.subprocess, "call", execute)
    return execute


@pytest.mark.parametrize(("name", "value"), [
    ("PYTEST_ADDOPTS", "tests/test_cli_journey.py"),
    ("PYTEST_ADDOPTS", "-- tests/test_cli_expiry.py"),
    ("PYTEST_ADDOPTS", "-p unapproved_plugin --override-ini testpaths=tests/docker"),
    ("PYTEST_PLUGINS", "unapproved_plugin"),
    ("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "0"),
    ("PYTEST_DISABLE_PLUGIN_AUTOLOAD", ""),
    ("PYTEST_DEBUG", "1"),
    ("PYTEST_FUTURE_CONTROL", "tests/test_cli_journey.py"),
    ("pytest_addopts", "tests/test_cli_journey.py"),
])
def test_inherited_pytest_controls_cannot_widen_selection(
    runner, monkeypatch, mocked_run, name, value,
):
    # what_bug_this_catches: pytest can widen an explicit file list from its
    # environment, even when the runner rejects arbitrary command arguments.
    monkeypatch.setenv(name, value)
    monkeypatch.setenv("M8_UNIT_UNRELATED", "retained")
    assert runner.main() == 0
    command = mocked_run.call_args.args[0]
    environment = mocked_run.call_args.kwargs["env"]
    assert {key: item for key, item in environment.items()
            if key.upper().startswith("PYTEST_")} == {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    assert environment["M8_UNIT_UNRELATED"] == "retained"
    assert os.environ[name] == value  # Do not mutate the caller's environment.
    selected = {Path(item).name for item in command if item.endswith(".py")}
    assert selected.isdisjoint({"test_cli_journey.py", "test_cli_expiry.py", "test_sqlite_journey.py"})
    assert "test_governance.py" in selected
    assert "unapproved_plugin" not in command


def test_explicit_empty_config_ignores_project_and_ancestor_settings(
    runner, monkeypatch, mocked_run, artifact_dir,
):
    # what_bug_this_catches: pytest's automatic config discovery can prepend
    # held paths/plugins through addopts or import paths before file selection.
    from _pytest.config.findpaths import determine_setup

    root = artifact_dir / "project"
    test_root = root / "tests"
    test_root.mkdir(parents=True)
    for name in ("test_routine.py", "test_cli_journey.py", "test_cli_expiry.py"):
        (test_root / name).write_text("", encoding="utf-8")
    (artifact_dir / "pytest.ini").write_text(
        "[pytest]\naddopts = tests/test_cli_journey.py -p ancestor_plugin\n", encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "tests/test_cli_expiry.py -p project_plugin"\n'
        'pythonpath = ["tests/docker"]\ntestpaths = ["tests/docker"]\n', encoding="utf-8",
    )
    # The fixture files remain trusted; unrelated ancestor conftests are cut off.
    (test_root / "conftest.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(runner, "__file__", str(root / "scripts" / "check.py"))
    assert runner.main() == 0
    command = mocked_run.call_args.args[0]
    assert command[command.index("-c") + 1] == os.devnull
    assert command[command.index("--rootdir") + 1] == str(root)
    assert command[command.index("--confcutdir") + 1] == str(test_root)
    assert "--noconftest" not in command
    assert [Path(item).name for item in command if item.endswith(".py")] == ["test_routine.py"]
    # Exercise pinned pytest's config resolver, without collection or a process.
    # This also proves Windows NUL is accepted as an empty explicit config.
    resolved_root, config_path, config = determine_setup(
        inifile=command[command.index("-c") + 1], args=[str(test_root / "test_routine.py")],
        rootdir_cmd_arg=command[command.index("--rootdir") + 1], invocation_dir=artifact_dir,
    )
    assert resolved_root == root
    assert config_path is not None
    assert config == {}


@pytest.mark.asyncio
async def test_only_declared_async_plugin_is_enabled(runner, mocked_run):
    # what_bug_this_catches: disabling all autoload without an explicit asyncio
    # plugin silently drops support that the pinned dev dependency provides.
    from _pytest.config import PytestPluginManager

    assert runner.main() == 0
    command = mocked_run.call_args.args[0]
    plugins = [command[index + 1] for index, item in enumerate(command) if item == "-p"]
    assert plugins == ["no:cacheprovider", "pytest_asyncio.plugin"]
    assert mocked_run.call_args.kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    manager = PytestPluginManager()
    manager.import_plugin(plugins[1])  # Pure plugin registration, no pytest run.
    assert manager.hasplugin("pytest_asyncio.plugin")
    assert manager.get_plugin("pytest_asyncio.plugin").__name__ == "pytest_asyncio.plugin"
    await asyncio.sleep(0)  # The declared plugin must also handle this async unit.


def test_selection_output_and_source_options_remain_available(
    runner, monkeypatch, mocked_run, artifact_dir,
):
    # what_bug_this_catches: hardening must retain documented selection/output
    # options as single values instead of interpreting them as extra arguments.
    source = artifact_dir / "source with spaces"
    source.mkdir()
    report = artifact_dir / "output with spaces" / "report.xml"
    keyword = "clock or governance"
    monkeypatch.setattr(sys, "argv", [
        "check.py", "--source-root", str(source), "--junit", str(report),
        "--collect-only", "--keyword", keyword, "--quiet", "--tb=no",
    ])
    mocked_run.return_value = 5
    assert runner.main() == 5
    command = mocked_run.call_args.args[0]
    assert command.count("--collect-only") == 1
    assert command[command.index("-k") + 1] == keyword
    assert "--junitxml=" + str(report.resolve()) in command
    assert "-q" in command and "-v" not in command and "--tb=no" in command
    root = Path(runner.__file__).resolve().parents[1]
    environment = mocked_run.call_args.kwargs["env"]
    assert environment["M8_SOURCE_ROOT"] == str(source.resolve())
    assert environment["PYTHONPATH"].split(os.pathsep) == [str(source / "src"), str(root / "tests")]
    assert not report.exists()  # The mocked runner never creates a report/process.

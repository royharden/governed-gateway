"""Pinned local CI entrypoint; no installation, provider calls, or artifact deletion."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("-k", "--keyword")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--tb", choices=("auto", "long", "short", "line", "native", "no"), default="short")
    parser.add_argument("--collect-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = args.source_root.resolve(strict=True) if args.source_root else root
    # Pytest prepends inherited ADDOPTS and imports PLUGINS before collection.
    # Start with no inherited pytest controls, including plugin-disable flags.
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith("PYTEST_")}
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["M8_SOURCE_ROOT"] = str(source)
    environment["PYTHONPATH"] = os.pathsep.join((str(source / "src"), str(root / "tests")))
    source_commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    test_commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    print(f"M8_SOURCE_ROOT={source}; source_commit={source_commit}; test_commit={test_commit}", flush=True)
    # Routine CI never collects grant-bound CLI/expiry/Docker execution. Do not
    # forward arbitrary pytest paths/options that can broaden this selection.
    test_root = root / "tests"
    held = {"test_cli_journey.py", "test_cli_expiry.py"}
    selected = sorted(path for path in test_root.glob("test_*.py") if path.name not in held)
    selected.extend(sorted((test_root / "eval").glob("test_*.py")))
    if not selected:
        parser.error("No routine tests found")
    # An empty explicit config prevents discovery of project/ancestor addopts,
    # pythonpath and plugin settings. Retain only this suite's trusted conftests
    # and the pinned dev dependency needed for async fixtures/tests.
    command = [sys.executable, "-B", "-m", "pytest", "-c", os.devnull,
               "--rootdir", str(root), "--confcutdir", str(test_root),
               "-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin",
               "-q" if args.quiet else "-v", "--tb=" + args.tb, *map(str, selected)]
    if args.keyword:
        command.extend(("-k", args.keyword))
    if args.collect_only:
        command.append("--collect-only")
    if args.junit:
        command.append("--junitxml=" + str(args.junit.resolve()))
    return subprocess.call(command, env=environment)


if __name__ == "__main__":
    raise SystemExit(main())

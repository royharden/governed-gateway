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
    args, extra = parser.parse_known_args()
    root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root / "tests")))
    command = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-v", str(root / "tests")]
    if args.junit:
        command.append("--junitxml=" + str(args.junit.resolve()))
    return subprocess.call(command + extra, env=environment)


if __name__ == "__main__":
    raise SystemExit(main())

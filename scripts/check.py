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
    args, extra = parser.parse_known_args()
    root = Path(__file__).resolve().parents[1]
    source = args.source_root.resolve(strict=True) if args.source_root else root
    environment = os.environ.copy()
    environment["M8_SOURCE_ROOT"] = str(source)
    environment["PYTHONPATH"] = os.pathsep.join((str(source / "src"), str(root / "tests")))
    source_commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    test_commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    print(f"M8_SOURCE_ROOT={source}; source_commit={source_commit}; test_commit={test_commit}", flush=True)
    command = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-v", str(root / "tests")]
    if args.junit:
        command.append("--junitxml=" + str(args.junit.resolve()))
    return subprocess.call(command + extra, env=environment)


if __name__ == "__main__":
    raise SystemExit(main())

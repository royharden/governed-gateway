"""Review-owned public eval checks, with durable command/environment/count evidence.

Use the pinned project interpreter; no acquisition, hidden data, provider or key I/O.
Example: .venv/Scripts/python.exe eval/run_public_checks.py --output C:/agent-runtime/m8-r03-rv2
"""
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import uuid
from xml.etree import ElementTree


def main():
    parser = argparse.ArgumentParser(description="Public development checks only; never product acceptance")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve(strict=True)
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(root):
        parser.error("output must be an absolute directory outside the product checkout")
    output = args.output / ("public-checks-" + uuid.uuid4().hex)
    output.mkdir(parents=True, exist_ok=False)
    tests = Path(__file__).resolve().parents[1] / "tests/eval"
    env = dict(os.environ, PYTHONPATH=str(root / "src"), M8_TEST_RUNTIME_PARENT=str(output))
    command = [sys.executable, "-m", "pytest", str(tests), "-q", "--tb=short",
               "-p", "no:cacheprovider", "--junitxml", str(output / "junit.xml")]
    result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=600)
    log = output / "checks.log"
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    suites = ElementTree.parse(output / "junit.xml").getroot().iter("testsuite")
    counts = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for suite in suites:
        for key in counts:
            counts[key] += int(suite.get(key, "0"))
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True)
    record = dict(schema_version=1, kind="m8-public-development-checks", mode="simulation",
        source_root=str(root), commit=commit.stdout.strip() if commit.returncode == 0 else None,
        source_dirty=bool(dirty.stdout) if dirty.returncode == 0 else None,
        test_files_sha256={str(path.relative_to(tests)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(tests.glob("*.py"))},
        command=command, exit_code=result.returncode, counts=counts,
        python=platform.python_version(), platform=platform.platform(),
        packages={name: version(name) for name in ("pydantic", "cryptography", "pytest")},
        log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
        completed_utc=datetime.now(timezone.utc).isoformat(),
        live="not-run:keyless-no-spend", holdout="not-run:development-only",
        product_acceptance="incomplete")
    (output / "result.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(dict(output=str(output), **record), sort_keys=True))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

"""Public synthetic checks; no credential lookup or automatic artifact cleanup."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    def local_plumbing(method):
        def guarded(sock, address):
            # Windows asyncio implements its internal wake pipe using loopback.
            if isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1"):
                return method(sock, address)
            raise AssertionError("Reviewer suite forbids external network access")
        return guarded
    def denied(*args, **kwargs):
        raise AssertionError("Reviewer suite forbids network access")
    monkeypatch.setattr(socket.socket, "connect", local_plumbing(original_connect))
    monkeypatch.setattr(socket.socket, "connect_ex", local_plumbing(original_connect_ex))
    monkeypatch.setattr(socket, "create_connection", denied)


@pytest.fixture(scope="session")
def preserved_root():
    base = Path(os.environ.get("M8_TEST_ARTIFACT_ROOT", "C:/agent-runtime/m8-rv1" if os.name == "nt" else "/tmp/m8-rv1"))
    root = base / ("run-" + uuid.uuid4().hex)
    root.mkdir(parents=True, exist_ok=False)
    return root


@pytest.fixture
def artifact_dir(preserved_root):
    root = preserved_root / ("case-" + uuid.uuid4().hex)
    root.mkdir()
    return root


@pytest.fixture
def simulation_config(artifact_dir):
    # This is a NEW authority, never renewal/reset of a spent sample authority.
    now = datetime.now(timezone.utc)
    raw = json.loads((ROOT / "fixtures/bootstrap/simulation.example.json").read_text())
    raw.update(runtime_root=str(artifact_dir), authority_id="m8-rv1-" + uuid.uuid4().hex,
               created_utc=(now - timedelta(seconds=10)).isoformat(),
               deadline_utc=(now + timedelta(hours=2)).isoformat())
    path = artifact_dir / "simulation.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


@pytest.fixture
def loaded_simulation(simulation_config, monkeypatch):
    from gateway.bootstrap import _load_demo_configuration
    monkeypatch.setenv("GATEWAY_RUNTIME_ROOT", str(simulation_config.parent))
    return _load_demo_configuration(simulation_config)

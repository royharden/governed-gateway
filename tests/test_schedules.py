"""100 barrier-controlled admission schedules, distributed across 1/2/8 processes.

This covers S3 admission only. Crash boundaries and the controller matrix remain
separate obligations. A seed chooses graph/cap; it does not replay OS scheduling.
"""
from concurrent.futures import ProcessPoolExecutor
from decimal import Decimal
import json
import multiprocessing
import random

import pytest

from integer_oracle import micros
from ledger_support import configuration, inputs, open_ledger, race_admit, race_initialize


@pytest.mark.parametrize("processes,schedules", [(1, 34), (2, 33), (8, 33)])
def test_near_empty_admission_schedules(artifact_dir, processes, schedules):
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(processes)
    receipts = []
    with ProcessPoolExecutor(processes, mp_context=context, initializer=race_initialize, initargs=(barrier,)) as pool:
        for seed in range(schedules):
            rng = random.Random(seed)
            children = rng.choice([1, 2])
            affordable = rng.choice([1, 2])
            # One synthetic child is 65536 input +1024 output*2 =67584 micro-USD.
            budget = 67584 * children * affordable
            config = configuration(authority_id=f"m8-race-{processes}-{seed}", cap=f"{budget // 1_000_000}.{budget % 1_000_000:06d}")
            database = artifact_dir / f"m8-race-{seed}.sqlite3"
            ledger = open_ledger(database, config)
            ledger.close()
            jobs = [(config, str(database), f"op-{worker}", children) for worker in range(processes)]
            result = list(pool.map(race_admit, jobs))
            accepted = sum(row["status"] == "funded" for row in result)
            assert accepted == min(affordable, processes), result
            assert all(row["status"] in ("funded", "budget_rejected") for row in result), result
            ledger = open_ledger(database, config)
            try:
                total = ledger.totals()
            finally:
                ledger.close()
            assert micros(total["total_exposure_usd"]) == accepted * children * 67584
            assert micros(total["total_exposure_usd"]) <= budget
            assert total["dispatched_attempts"] == 0
            receipts.append({"seed": seed, "processes": processes, "children": children, "budget_micros": budget, "clock": "fixed UTC and monotonic zero, admission isolation only", "barrier": "all-open-ledgers-before-admit", "results": result, "totals": total})
    (artifact_dir / "schedules.json").write_text(json.dumps(receipts, indent=2), encoding="utf-8")
    assert len(receipts) == schedules

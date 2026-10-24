"""Body-free operator presentation over actual supplied producer snapshots."""
from __future__ import annotations

from typing import TextIO

from gateway.schemas import canonical_bytes
from gateway.schemas.operator import OperationSummary, OverviewSnapshot, PolicySummary


def render_overview(snapshot: OverviewSnapshot, *, output: TextIO) -> None:
    output.write("SIMULATION ONLY; runtime unverified. External dispatch disabled.\n")
    output.write(canonical_bytes(snapshot).decode("utf-8") + "\n")
    output.write("Exposure = K + F + A + U + D. X is already in K; retained U is never a refund.\n")
    output.write("Maximum credible late charge and uncovered D are separate; incidents cannot be cleared here.\n")


def render_operations(rows: tuple[OperationSummary, ...], *, output: TextIO) -> None:
    output.write("SIMULATION ONLY; body-free request summaries; runtime unverified.\n")
    output.write("Each accounting row is per-operation. cap_usd labels the authority ceiling, not an operation wallet or headroom.\n")
    output.write(canonical_bytes(rows).decode("utf-8") + "\n")


def render_policies(rows: tuple[PolicySummary, ...], *, output: TextIO) -> None:
    output.write("Policy eligibility does not constitute activation or human approval.\n")
    output.write(canonical_bytes(rows).decode("utf-8") + "\n")

"""Plan M8 evaluation contract; synthetic public outcomes are never acceptance."""
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal, localcontext
from io import StringIO
import json

import pytest

from gateway.cli.evaluation import main as evaluation_main
from gateway.evaluation.artifacts import validate_artifacts
from gateway.evaluation.dataset import load_development
from gateway.evaluation.reporting import evaluation_json, render_evaluation
from gateway.evaluation.scoring import _paired, _wilson
from gateway.schemas import GatewayError, canonical_bytes, digest


def run(case, receipts=None, **overrides):
    runner = case["runner"](**overrides)
    report = runner.run(case["spec"], case["manifest"],
                        case["receipts"] if receipts is None else tuple(receipts))
    return report, runner.artifacts_for(report)


def overall(report, route):
    return next(row for row in report.route_rows if row.route == route and row.family is None)


@pytest.mark.parametrize("mode,code", [("mock", "dependency_unavailable"),
                                      ("live", "external_disabled"), ("recorded", "external_disabled")])
def test_cli_never_acquires_or_reads_paths_without_injected_services(mode, code, capsys):
    assert evaluation_main(["--mode", mode, "--spec", "not-read-spec.json", "--policy",
                            "not-read-policy.json", "--authorization", "not-read-auth.json"]) == 2
    captured = capsys.readouterr()
    assert not captured.out and json.loads(captured.err) == {"error": code}


def test_exact_public_development_split(evaluation_case):
    case = evaluation_case
    assert len(case["tasks"]) == 60
    assert {family: sum(t.family == family for t in case["tasks"])
            for family in ("extraction", "evidence_qa", "transformation")} == {
                "extraction": 20, "evidence_qa": 20, "transformation": 20}


def test_complete_outcomes_without_authority_never_pass(evaluation_case):
    report, artifacts = run(evaluation_case)
    assert report.task_count == 60 and report.attempt_count == 120
    assert report.missing_observation_count == 0
    assert report.status != "pass" and report.compatibility_status != "pass"
    assert report.authority_invariant_evidence_sha256 is None
    assert report.benefit_status == "unmeasured"
    assert {r.route for r in report.route_rows} == {"B0", "B1", "C", "s3_offline"}
    for route in ("B0", "B1", "C", "s3_offline"):
        row = overall(report, route)
        assert row.success.success_count == row.success.assigned_count == 60
        assert row.total_cost_usd == Decimal("0.000240")
    assert all(pair.noninferiority != "noninferior" for pair in report.paired_differences)
    validate_artifacts(report, artifacts)


def test_missing_provider_keeps_denominator_and_unknown_cost(evaluation_case):
    receipts = [r for r in evaluation_case["receipts"] if r.target_id == "B0"]
    report, _ = run(evaluation_case, receipts)
    row = overall(report, "C")
    assert report.missing_observation_count == 60 and report.attempt_count == 60
    assert row.success.assigned_count == 60 and row.success.success_count == 0
    assert row.success.observed_count == 0 and row.success.assigned_rate == 0
    assert row.success.observed_rate is None
    assert row.total_cost_usd is row.cost_per_success_usd is None
    assert report.status != "pass"


@pytest.mark.parametrize("status", ["refused", "truncated", "provider_error", "cancelled", "timeout"])
def test_failure_counts_stay_assigned_and_zero_success_cost_unavailable(evaluation_case, status):
    receipts = [r.model_copy(update={"outcome_status": status, "response_text": None})
                if r.target_id == "B1" else r for r in evaluation_case["receipts"]]
    report, _ = run(evaluation_case, receipts)
    row = overall(report, "C")
    assert row.success.assigned_count == 60 and row.success.success_count == 0
    assert row.cost_per_success_usd is None


def test_unknown_billing_retains_liability_and_partial_known_subtotal(evaluation_case):
    receipts = list(evaluation_case["receipts"])
    index = next(i for i, r in enumerate(receipts) if r.target_id == "B1")
    receipts[index] = receipts[index].model_copy(update={"known_cost_usd": None,
        "original_acquisition_cost_usd": None, "retained_liability_usd": Decimal("0.002048")})
    report, artifacts = run(evaluation_case, receipts)
    row = overall(report, "C")
    assert row.cost_known_count == 59 and row.known_cost_sum_usd == Decimal("0.000236")
    assert row.total_cost_usd is row.cost_per_success_usd is None
    assert row.retained_liability_usd == Decimal("0.002048")
    data = json.loads(evaluation_json(report, artifacts=artifacts))
    assert data and report.status != "pass"


def test_identical_duplicate_not_new_attempt_but_conflict_refuses(evaluation_case):
    receipts = evaluation_case["receipts"]
    report, _ = run(evaluation_case, (*receipts, receipts[0]))
    assert report.attempt_count == 120
    with pytest.raises(GatewayError):
        run(evaluation_case, (*receipts, receipts[0].model_copy(update={"response_text": "incorrect"})))


@pytest.mark.parametrize("field", ["request_sha256", "parameters_sha256", "profile_sha256",
                                  "adapter_sha256", "price_sha256", "bound_sha256"])
def test_wrong_provenance_refuses(evaluation_case, field):
    receipts = list(evaluation_case["receipts"])
    receipts[0] = receipts[0].model_copy(update={field: "f" * 64})
    with pytest.raises(GatewayError):
        run(evaluation_case, receipts)


def test_stale_original_cannot_be_renewed_by_reuse(evaluation_case):
    case = evaluation_case
    original = case["receipts"][0].model_copy(update={
        "acquired_utc": case["now"] - timedelta(seconds=case["spec"].freshness_seconds + 1)})
    source = digest(original)
    reused = original.model_copy(update={"acquired_utc": case["now"], "reused": True,
        "reuse_source_sha256": source, "attempt_count": 0, "current_reuse_cost_usd": Decimal("0")})
    with pytest.raises(GatewayError):
        run(case, (reused, *case["receipts"][1:]), reuse_sources={source: original})


def test_reuse_adds_no_calls_and_preserves_original_cost(evaluation_case):
    sources = {digest(r): r for r in evaluation_case["receipts"]}
    reused = [r.model_copy(update={"reused": True, "reuse_source_sha256": digest(r),
        "attempt_count": 0, "current_reuse_cost_usd": Decimal("0")})
        for r in evaluation_case["receipts"]]
    report, artifacts = run(evaluation_case, reused, reuse_sources=sources)
    assert report.attempt_count == 0
    assert overall(report, "C").total_cost_usd == Decimal("0.000240")
    diagnostics = validate_artifacts(report, artifacts)
    assert diagnostics["acquisition_summary"]["historical_source_attempt_count"] == 120


def test_frozen_report_and_diagnostics_tamper_refuses(evaluation_case):
    report, artifacts = run(evaluation_case)
    with pytest.raises(GatewayError):
        validate_artifacts(report.model_copy(update={"attempt_count": 0}), artifacts)
    data = json.loads(artifacts.diagnostics_canonical)
    data["report_id"] = "tampered"
    with pytest.raises(GatewayError):
        validate_artifacts(report, replace(artifacts, diagnostics_canonical=canonical_bytes(data)))


def assert_payload_free(value, canary):
    if isinstance(value, dict):
        assert not {"response_text", "input_text", "expected_answers", "messages"}.intersection(value)
        for child in value.values():
            assert_payload_free(child, canary)
    elif isinstance(value, list):
        for child in value:
            assert_payload_free(child, canary)
    elif isinstance(value, str):
        assert canary not in value


def test_report_bundle_deterministic_and_payload_free(evaluation_case):
    # Exact body keys and opaque body canaries are forbidden; a response digest
    # is required provenance and is not a plaintext response. The old substring
    # assertion falsely rejected response_text_sha256; retain this distinction.
    canary = "M8_PRIVATE_RESPONSE_CANARY_22f403e74ef64d5c"
    receipts = list(evaluation_case["receipts"])
    receipts[0] = receipts[0].model_copy(update={"response_text": canary})
    report, artifacts = run(evaluation_case, receipts)
    again, other = run(evaluation_case, receipts)
    assert canonical_bytes(report) == canonical_bytes(again)
    assert artifacts == other
    output = evaluation_json(report, artifacts=artifacts)
    assert_payload_free(json.loads(output), canary)
    assert "response_text_sha256" in output
    markdown = StringIO()
    render_evaluation(report, output=markdown, artifacts=artifacts)
    assert "SIMULATION" in markdown.getvalue() and "unavailable" in markdown.getvalue()
    assert canary not in markdown.getvalue()


@pytest.mark.parametrize("leak", [{"response_text": "private-canary"},
    {"nested": [{"unrelated_field": "prefix-private-canary-suffix"}]},
    {"nested": {"input_text": "something else"}}])
def test_privacy_check_detects_injected_key_and_value_leaks(leak):
    with pytest.raises(AssertionError):
        assert_payload_free(leak, "private-canary")


def test_integer_known_wilson_endpoints_and_negative_paired_result(evaluation_case):
    low, high = _wilson(0, 20)
    assert low == 0 and Decimal("0.16") < high < Decimal("0.17")
    low, high = _wilson(20, 20)
    assert high == 1 and Decimal("0.83") < low < Decimal("0.84")
    task = evaluation_case["tasks"][0]
    good = evaluation_case["receipts"][0]
    bad = good.model_copy(update={"response_text": "incorrect"})
    with localcontext() as context:
        context.prec = 3
        pair = _paired(task.family, [(task, bad, good)] * 20, 1729)
    assert pair.point == pair.lower95 == pair.upper95 == -1
    assert pair.noninferiority == "regression" and pair.resamples == 10000


def test_development_label_mutation_refuses(evaluation_case):
    case = evaluation_case
    directory = case["runtime"] / "mutated-development"
    directory.mkdir()
    root = __import__("pathlib").Path(__file__).resolve().parents[2] / "fixtures/tasks/dev"
    for name in ("manifest.json", "matching-rules.json", "tasks.json"):
        (directory / name).write_bytes((root / name).read_bytes())
    raw = json.loads((directory / "tasks.json").read_text())
    raw["tasks"][0]["expected_answers"] = ["mutated"]
    (directory / "tasks.json").write_text(json.dumps(raw))
    with pytest.raises(GatewayError):
        load_development(directory)

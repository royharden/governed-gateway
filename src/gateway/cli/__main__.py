"""Local CLI. Composition is explicit; absent trusted services fail closed."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import TYPE_CHECKING, Callable, Sequence

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.schemas import (
    ApprovalPayload, ApprovalRecord, ErrorCode, EvaluationAuthorization,
    EvaluationAuthorizationPayload, EvaluationRecord, GatewayError, PolicyBundle,
    canonical_bytes,
)
from gateway.schemas.operator import EvaluationReport, QuoteRequest
from .operator import OperatorServices, activate, register_evaluation, rollback
from .reports import render_operations, render_overview, render_policies
from .signing import confirmation_digest, sign_approval, sign_evaluation_authorization
from gateway.evaluation.artifacts import read_report_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="M8 local operator: simulation source; runtime unverified")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("overview")
    for name in ("requests", "policies"):
        commands.add_parser(name).add_argument("--limit", type=int, default=100)
    for name in ("freeze", "approve", "authorize-evaluation", "evaluation", "quote"):
        commands.add_parser(name).add_argument("file", type=Path)
    for name in ("inspect-approval", "inspect-evaluation-authorization"):
        commands.add_parser(name).add_argument("file", type=Path)
    for name in ("sign-approval", "sign-evaluation-authorization"):
        command = commands.add_parser(name)
        command.add_argument("file", type=Path)
        command.add_argument("--confirm-tuple", required=True)
        command.add_argument("--key-env", default="GATEWAY_OPERATOR_SIGNING_KEY_PATH")
    command = commands.add_parser("register-evaluation")
    command.add_argument("--report", type=Path, required=True)
    command.add_argument("--authorization", type=Path, required=True)
    command.add_argument("--record", type=Path, required=True)
    for name in ("activate", "rollback"):
        command = commands.add_parser(name)
        command.add_argument("approval_sha256")
        command.add_argument("--expected-generation", type=int, required=True)
        if name == "rollback":
            command.add_argument("--reason", required=True)
    return parser


def _read(model, path: Path):
    # No errors containing validation inputs/paths/raw JSON cross the presentation boundary.
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("artifact_too_large")
        return model.model_validate_json(path.read_bytes())
    except (OSError, ValueError, TypeError):
        raise GatewayError(ErrorCode.INVALID_EVIDENCE) from None


def main(argv: Sequence[str] | None = None, *, services: OperatorServices | None = None,
         protected_key_loader: Callable[[str], Ed25519PrivateKey] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        command = args.command
        if command in ("inspect-approval", "sign-approval", "inspect-evaluation-authorization", "sign-evaluation-authorization"):
            approval = command.endswith("approval")
            payload = _read(ApprovalPayload if approval else EvaluationAuthorizationPayload, args.file)
            if command.startswith("inspect-"):
                value = {"payload": payload, "confirmed_tuple_sha256": confirmation_digest(payload),
                         "warning": "Review every hash, domain, reason, account and timestamp before explicit confirmation"}
            else:
                signer = sign_approval if approval else sign_evaluation_authorization
                value = signer(payload, key_env_name=args.key_env, confirmed_tuple_sha256=args.confirm_tuple,
                               protected_key_loader=protected_key_loader)
        elif command == "evaluation":
            from gateway.evaluation.reporting import render_evaluation
            report, artifacts = read_report_bundle(args.file.read_bytes())
            render_evaluation(report, output=sys.stdout, artifacts=artifacts)
            return 0
        elif command == "quote":
            from gateway.evaluation.quote import quote_acquisition
            value = quote_acquisition(_read(QuoteRequest, args.file))
        else:
            if services is None:
                raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE)
            if command == "overview":
                render_overview(services.overview(), output=sys.stdout)
                return 0
            if command in ("requests", "policies"):
                if not 1 <= args.limit <= 1000:
                    raise GatewayError(ErrorCode.INVALID_REQUEST)
                if command == "requests":
                    render_operations(services.operations(args.limit), output=sys.stdout)
                else:
                    render_policies(services.policies(args.limit), output=sys.stdout)
                return 0
            if command == "freeze":
                value = {"policy_sha256": services.governance.freeze(_read(PolicyBundle, args.file))}
            elif command == "approve":
                value = {"decision_sha256": services.governance.verify_approval(_read(ApprovalRecord, args.file))}
            elif command == "authorize-evaluation":
                authorization = _read(EvaluationAuthorization, args.file)
                if authorization.mode != "simulation":
                    raise GatewayError(ErrorCode.EXTERNAL_DISABLED)
                value = {"authorization_sha256": services.governance.authorize_evaluation(authorization)}
            elif command == "register-evaluation":
                report, artifacts = read_report_bundle(args.report.read_bytes())
                value = {"evaluation_sha256": register_evaluation(
                    services, report, _read(EvaluationAuthorization, args.authorization),
                    _read(EvaluationRecord, args.record), artifacts=artifacts)}
            elif command == "activate":
                value = activate(services, args.approval_sha256, expected_generation=args.expected_generation)
            elif command == "rollback":
                value = rollback(services, args.approval_sha256, expected_generation=args.expected_generation,
                                 reason=args.reason)
            else:
                raise GatewayError(ErrorCode.UNSUPPORTED_REQUEST)
        sys.stdout.write(canonical_bytes(value).decode("utf-8") + "\n")
        return 0
    except GatewayError as error:
        sys.stderr.write(canonical_bytes({"error": error.code.value}).decode("utf-8") + "\n")
        return 2
    except (OSError, ValueError, TypeError, ImportError):
        sys.stderr.write('{"error":"dependency_unavailable"}\n')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

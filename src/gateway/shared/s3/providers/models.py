"""Strict, portable request/answer declarations without provider/network execution."""

import json
import math
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import Field, JsonValue, model_serializer, model_validator

from ..callledger.models import (
    Allocation,
    BudgetAuthority,
    CallContext,
    Digest,
    ErrorCode,
    Identifier,
    Limits,
    Money,
    NormalizedUsage,
    Status,
    WireModel,
    canonical_digest,
    decode_wire_json,
)

Name = Annotated[str, Field(min_length=1, max_length=255)]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]
JsonInstruction = str | dict[str, JsonValue] | list[JsonValue]
SUM_TOLERANCE = 1e-6
SCORE_TOLERANCE = 1e-3


class NoulCriteria(WireModel):
    true: JsonInstruction | None = None
    false: JsonInstruction | None = None

    @model_serializer(mode="wrap")
    def omit_absent(self, handler):
        return {key: value for key, value in handler(self).items() if value is not None}

    @model_validator(mode="after")
    def present_descriptions(self) -> Self:
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("Noul descriptions must be structured instructions, not null")
        return self


class ChoiceSpec(WireModel):
    type: Literal["choice"]
    instructions: JsonInstruction
    criteria: Annotated[dict[Name, JsonInstruction | None], Field(min_length=1, max_length=255)]


class NoulSpec(WireModel):
    type: Literal["noul"]
    instructions: JsonInstruction
    criteria: NoulCriteria | None = None

    @model_serializer(mode="wrap")
    def omit_absent(self, handler):
        value = handler(self)
        if self.criteria is None:
            value.pop("criteria", None)
        return value

    @model_validator(mode="after")
    def omitted_not_null(self) -> Self:
        if "criteria" in self.model_fields_set and self.criteria is None:
            raise ValueError("absent Noul criteria must be omitted, not null")
        return self


class ScoreSpec(WireModel):
    type: Literal["score"]
    instructions: JsonInstruction
    criteria: Annotated[list[JsonInstruction], Field(min_length=2, max_length=10)]


QuestionSpec = Annotated[ChoiceSpec | NoulSpec | ScoreSpec, Field(discriminator="type")]


def check_distribution(probabilities: dict[str, float]) -> None:
    if abs(math.fsum(probabilities.values()) - 1.0) > SUM_TOLERANCE:
        raise ValueError("probability distribution must sum to one within 1e-6")


class ChoiceAnswer(WireModel):
    type: Literal["choice"]
    choice: Name
    probabilities: Annotated[dict[Name, Probability], Field(min_length=1, max_length=255)]
    confidence: Probability

    @model_validator(mode="after")
    def distribution(self) -> Self:
        check_distribution(self.probabilities)
        if self.choice not in self.probabilities:
            raise ValueError("chosen option is absent from distribution")
        if self.probabilities[self.choice] + SUM_TOLERANCE < max(self.probabilities.values()):
            raise ValueError("chosen option is not a maximum")
        return self


class NoulAnswer(WireModel):
    type: Literal["noul"]
    noul: Probability


class ScoreAnswer(WireModel):
    type: Literal["score"]
    score: NonNegativeFloat
    legend: Annotated[dict[str, str], Field(min_length=2, max_length=10)]
    probabilities: Annotated[dict[str, Probability], Field(min_length=2, max_length=10)]
    confidence: Probability

    @model_validator(mode="after")
    def distribution(self) -> Self:
        indices = {str(i) for i in range(len(self.legend))}
        if set(self.legend) != indices or set(self.probabilities) != indices:
            raise ValueError("Score keys must exactly cover zero-based legend indices")
        check_distribution(self.probabilities)
        if self.score > len(self.legend) - 1:
            raise ValueError("Score outside supplied legend")
        weighted = math.fsum(int(i) * p for i, p in self.probabilities.items())
        if abs(weighted - self.score) > SCORE_TOLERANCE:
            raise ValueError("Score is inconsistent with its probability-weighted position")
        return self


AnswerSpec = Annotated[ChoiceAnswer | NoulAnswer | ScoreAnswer, Field(discriminator="type")]


class TextPart(WireModel):
    type: Literal["text"]
    text: str


class ImagePart(WireModel):
    type: Literal["local_image"]
    execution_ref: Annotated[str, Field(min_length=1, max_length=4096)]
    content_sha256: Digest
    media_type: Literal["image/png", "image/jpeg"]
    byte_length: Annotated[int, Field(gt=0)]
    decoded_width: Annotated[int, Field(gt=0)]
    decoded_height: Annotated[int, Field(gt=0)]
    rendition_sha256: Digest
    source_generation: Identifier
    transform_sha256: Digest
    detail: Literal["low", "high", "auto"]

    @model_validator(mode="after")
    def local_reference(self) -> Self:
        reference = self.execution_ref.replace("\\", "/")
        if (
            "://" in reference
            or reference.lower().startswith("file:")
            or "\x00" in reference
            or ".." in reference.split("/")
        ):
            raise ValueError("image execution reference must be local and nontraversing")
        return self

    def identity_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"execution_ref"})


ContentPart = Annotated[TextPart | ImagePart, Field(discriminator="type")]


class Message(WireModel):
    role: Literal["system", "user", "assistant"]
    content: Annotated[list[ContentPart], Field(min_length=1)]


class GenerateRequest(WireModel):
    schema_version: Literal[1]
    kind: Literal["generate"]
    model: Name
    messages: Annotated[list[Message], Field(min_length=1)]
    output_schema: dict[str, JsonValue] | None = Field(default=None, alias="schema")
    max_output_tokens: Annotated[int, Field(gt=0)]
    stream: bool
    reasoning_effort: str | None = None
    temperature: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None

    def identity_payload(self) -> dict:
        payload = self.model_dump(mode="json", by_alias=True)
        payload["messages"] = [
            {
                "role": message.role,
                "content": [
                    part.identity_payload()
                    if isinstance(part, ImagePart)
                    else part.model_dump(mode="json")
                    for part in message.content
                ],
            }
            for message in self.messages
        ]
        return payload


class TypedJudgmentRequest(WireModel):
    schema_version: Literal[1]
    kind: Literal["typed_judgment"]
    model: Name
    state: str | dict[str, JsonValue] | list[str]
    questions: Annotated[dict[Name, QuestionSpec], Field(min_length=1, max_length=256)]

    def question_identity(self) -> list:
        result = []
        for question_id, question in self.questions.items():
            value = question.model_dump(mode="json", exclude_unset=True)
            if isinstance(question, ChoiceSpec):
                value["criteria"] = list(question.criteria.items())
            result.append([question_id, value])
        return result

    @property
    def question_spec_sha256(self) -> str:
        return canonical_digest(self.question_identity())

    def identity_payload(self) -> dict:
        payload = self.model_dump(mode="json", exclude={"questions"})
        payload["questions"] = self.question_identity()
        return payload


ProviderRequest = Annotated[GenerateRequest | TypedJudgmentRequest, Field(discriminator="kind")]


class TypedJudgmentResult(WireModel):
    schema_version: Literal[1]
    model_reported: Name
    question_spec_sha256: Digest
    answers: Annotated[dict[Name, AnswerSpec], Field(min_length=1, max_length=256)]

    def validate_for(self, request: TypedJudgmentRequest) -> Self:
        self = self.model_validate(self.model_dump(mode="python", exclude_unset=True))
        request = request.model_validate(
            request.model_dump(mode="python", by_alias=True, exclude_unset=True)
        )
        if self.question_spec_sha256 != request.question_spec_sha256:
            raise ValueError("original question criteria digest mismatch")
        if set(self.answers) != set(request.questions):
            raise ValueError("answer IDs must exactly match submitted question IDs")
        for key, question in request.questions.items():
            answer = self.answers[key]
            if answer.type != question.type:
                raise ValueError("answer primitive does not match question")
            if isinstance(question, ChoiceSpec):
                if set(answer.probabilities) != set(question.criteria):
                    raise ValueError("Choice distribution does not cover requested options")
            elif isinstance(question, ScoreSpec):
                if set(answer.legend) != {str(i) for i in range(len(question.criteria))}:
                    raise ValueError("Score legend length does not match question")
                for index, criterion in enumerate(question.criteria):
                    if isinstance(criterion, str) and answer.legend[str(index)] != criterion:
                        raise ValueError("simple Score legend differs from originating criterion")
        return self


class Capabilities(WireModel):
    schema_version: Literal[1]
    generate: bool
    typed_judgment: bool
    image_input: bool
    streaming: bool
    usage_fields: list[str]
    billing_required_fields: list[str]
    bounds_billed_input: bool
    bounds_billed_output: bool
    input_bound_kind: Literal["count", "documented_bytes", "capacity", "refuse"]


class SafeError(WireModel):
    code: ErrorCode
    variable_name: (
        Literal[
            "OPENAI_API_KEY",
            "OPENAI_API_KEY_FILE",
            "TYPESAFE_API_KEY",
            "TYPESAFE_API_KEY_FILE",
            "ANTHROPIC_API_KEY",
        ]
        | None
    ) = None


class SourceCaptureRef(WireModel):
    capture_id: Identifier
    capture_sha256: Digest
    origin: Literal["synthetic", "live"]
    source_run_id: Identifier
    request_identity_sha256: Digest
    model_requested: Name
    model_reported: Name | None = None
    usage_ref: Digest | None = None
    price_ref: Digest | None = None
    cost_usd: Money | None = None
    latency_ms: NonNegativeFloat | None = None
    first_output_kind: Literal["token", "chunk", "answer", "unavailable"]
    first_output_ms: NonNegativeFloat | None = None


class Result(WireModel):
    schema_version: Literal[1]
    kind: Literal["generated", "typed"]
    status: Status
    text: str | None = None
    parsed: JsonValue = None
    typed: TypedJudgmentResult | None = None
    error: SafeError | None = None
    model_requested: Name
    model_reported: Name | None
    usage_raw: dict[str, JsonValue] | None
    normalized_usage: NormalizedUsage
    accounting_ref: Identifier
    attempt_ids: list[Identifier]
    origin: Literal["live", "replay", "mock"]
    source_capture: SourceCaptureRef | None
    latency_ms: NonNegativeFloat
    first_output_ms: NonNegativeFloat | None
    first_output_kind: Literal["token", "chunk", "answer", "unavailable"]
    current_external_cost_usd: Money | None

    @model_validator(mode="after")
    def channel(self) -> Self:
        if self.first_output_kind == "unavailable" and self.first_output_ms is not None:
            raise ValueError("unavailable first output cannot have a made-up time")
        if self.origin in {"mock", "replay"}:
            if (
                self.source_capture is None
                or self.current_external_cost_usd is None
                or Decimal(self.current_external_cost_usd) != 0
            ):
                raise ValueError(
                    "network-free reuse requires source provenance and zero current cost"
                )
            expected = "synthetic" if self.origin == "mock" else "live"
            if self.source_capture.origin != expected:
                raise ValueError("reuse origin conflicts with capture origin")
        if self.status == "ok":
            if self.error is not None:
                raise ValueError("successful result cannot carry an error")
            if self.kind == "typed":
                if self.typed is None or self.text is not None or self.parsed is not None:
                    raise ValueError("typed success requires only direct typed payload")
                if self.model_reported != self.typed.model_reported:
                    raise ValueError("typed reported model mismatch")
            elif self.typed is not None or (
                self.text is None and "parsed" not in self.model_fields_set
            ):
                raise ValueError("generated success requires generation payload only")
        elif self.typed is not None or self.parsed is not None:
            raise ValueError("failed output must not expose a usable validated payload")
        return self

    def validate_for(self, request: GenerateRequest | TypedJudgmentRequest) -> Self:
        self = self.model_validate(self.model_dump(mode="python", exclude_unset=True))
        request = request.model_validate(
            request.model_dump(mode="python", by_alias=True, exclude_unset=True)
        )
        if self.model_requested != request.model:
            raise ValueError("requested model mismatch")
        if self.status != "ok":
            return self
        if isinstance(request, TypedJudgmentRequest):
            if self.kind != "typed" or self.typed is None:
                raise ValueError("native typed request cannot become generated prose")
            self.typed.validate_for(request)
        else:
            if self.kind != "generated":
                raise ValueError("generation request cannot become native typed payload")
            if request.output_schema is not None:
                if "parsed" not in self.model_fields_set:
                    raise ValueError("structured generation requires validated parsed field")
                if self.text is not None and decode_wire_json(self.text) != self.parsed:
                    raise ValueError("generation text/parsed inconsistency")
        return self


class ExecutionEnvelope(WireModel):
    """Required public accounting binding; does not dispatch or admit an operation."""

    schema_version: Literal[1]
    request: ProviderRequest
    provider_config_sha256: Digest
    purpose: Identifier
    ledger_ref: Identifier
    budget: BudgetAuthority
    context: CallContext
    limits: Limits
    allocation: Allocation
    capture_mode: Literal["disabled", "fixture_replay", "consumer_store"]

    @model_validator(mode="after")
    def binding(self) -> Self:
        if self.purpose != self.context.purpose:
            raise ValueError("explicit purpose differs from trusted context")
        if not (
            self.budget.authority_id == self.context.authority_id == self.allocation.authority_id
        ):
            raise ValueError("accounting authority mismatch")
        if self.context.operation_id != self.allocation.operation_id:
            raise ValueError("allocation operation mismatch")
        if self.limits.max_outbound_attempts > self.budget.max_outbound_attempts:
            raise ValueError("caller cannot enlarge authority attempt quota")
        if datetime.fromisoformat(
            self.limits.run_deadline_utc.replace("Z", "+00:00")
        ) > datetime.fromisoformat(self.budget.run_deadline_utc.replace("Z", "+00:00")):
            raise ValueError("caller cannot extend authority deadline")
        if (
            len(
                json.dumps(
                    self.request.model_dump(mode="json", by_alias=True), ensure_ascii=False
                ).encode("utf-8")
            )
            > self.limits.max_request_bytes
        ):
            raise ValueError("complete serialized request exceeds byte bound")
        if isinstance(self.request, TypedJudgmentRequest):
            if len(self.request.questions) > self.limits.max_questions:
                raise ValueError("question fan-out exceeds caller shape bound")
            if any(
                isinstance(q, ChoiceSpec) and len(q.criteria) > self.limits.max_choice_options
                for q in self.request.questions.values()
            ):
                raise ValueError("Choice options exceed caller shape bound")
        elif (
            self.limits.max_total_output_tokens is not None
            and self.request.max_output_tokens > self.limits.max_total_output_tokens
        ):
            raise ValueError("requested output exceeds caller bound")
        return self

    @property
    def request_identity_sha256(self) -> str:
        return canonical_digest(
            {
                "request": self.request.identity_payload(),
                "context": self.context.semantic_context(),
                "provider_config_sha256": self.provider_config_sha256,
            }
        )

    @property
    def dispatched_envelope_sha256(self) -> str:
        return canonical_digest(
            self.request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        )


def validate_typed_wire(payload: str, request: TypedJudgmentRequest) -> TypedJudgmentResult:
    """Decode closed JSON and bind answers to the exact submitted question specification."""
    return TypedJudgmentResult.model_validate(decode_wire_json(payload)).validate_for(request)


def validate_result_wire(payload: str, request: GenerateRequest | TypedJudgmentRequest) -> Result:
    """Decode the portable Result; output-schema execution remains future driver work."""
    return Result.model_validate(decode_wire_json(payload)).validate_for(request)

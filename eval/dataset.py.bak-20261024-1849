"""Load public synthetic development labels; no heldout or acquisition support."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from gateway.schemas import ErrorCode, GatewayError, RequestFeatures, WireMessage, digest, request_digest
from gateway.schemas.operator import CorpusManifest


@dataclass(frozen=True)
class DevelopmentTask:
    """Scorer-private development input, not a cross-package boundary record."""
    task_id: str
    family: str
    source_id: str
    template_id: str
    input_text: str
    expected_answers: tuple[str, ...]
    route_alias: str
    max_completion_tokens: int

    def source_content(self) -> dict:
        return {"schema_version": 1, "task_id": self.task_id, "family": self.family,
                "source_id": self.source_id, "template_id": self.template_id,
                "input_text": self.input_text, "expected_answers": self.expected_answers,
                "route_alias": self.route_alias, "max_completion_tokens": self.max_completion_tokens}

    def request_sha256(self) -> str:
        return request_digest(route_alias=self.route_alias,
                              messages=(WireMessage(role="user", content=self.input_text),),
                              max_completion_tokens=self.max_completion_tokens)

    def parameters_sha256(self) -> str:
        return digest({"schema_version": 1, "max_completion_tokens": self.max_completion_tokens,
                       "stream": False, "n": 1})

    def features(self) -> RequestFeatures:
        size = len(self.input_text.encode("utf-8"))
        return RequestFeatures(route_alias=self.route_alias, input_utf8_bytes=size, message_count=1,
                               has_system=False, max_completion_tokens=self.max_completion_tokens,
                               length_bucket="small" if size <= 1024 else "medium" if size <= 8192 else "large",
                               input_token_bound=None)

    def success(self, text: str | None) -> bool:
        return text is not None and " ".join(text.split()) in {
            " ".join(answer.split()) for answer in self.expected_answers}


def load_development(directory: Path) -> tuple[CorpusManifest, tuple[DevelopmentTask, ...]]:
    try:
        manifest = CorpusManifest.model_validate_json((directory / "manifest.json").read_bytes())
        rules = json.loads((directory / "matching-rules.json").read_text(encoding="utf-8"))
        raw = json.loads((directory / "tasks.json").read_text(encoding="utf-8"))
        if set(raw) != {"schema_version", "tasks"} or type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValueError("invalid_development_data")
        if rules != {"schema_version": 1, "case_sensitive": True,
                     "whitespace": "strip_outer_and_collapse", "extraction": "exact_value",
                     "evidence_qa": "frozen_evidence_linked_answer_set",
                     "transformation": "exact_reversed_word_sequence", "family_weighting": "equal"}:
            raise ValueError("unsupported_matching_rules")
        if digest(rules) != manifest.matching_rules_sha256:
            raise ValueError("matching_rule_mismatch")
        tasks = []
        metadata = {item.task_id: item for item in manifest.tasks}
        fields = {"schema_version", "task_id", "family", "source_id", "template_id", "input_text",
                  "expected_answers", "route_alias", "max_completion_tokens"}
        for item in raw["tasks"]:
            if set(item) != fields or type(item["schema_version"]) is not int or item["schema_version"] != 1:
                raise ValueError("invalid_development_task")
            if any(type(item[key]) is not str for key in fields - {"schema_version", "expected_answers", "max_completion_tokens"}):
                raise ValueError("invalid_development_task")
            if not isinstance(item["expected_answers"], list) or not item["expected_answers"] or any(type(a) is not str or not a for a in item["expected_answers"]):
                raise ValueError("invalid_development_labels")
            if type(item["max_completion_tokens"]) is not int or not 1 <= item["max_completion_tokens"] <= 1024:
                raise ValueError("invalid_development_cap")
            task = DevelopmentTask(**{k: v for k, v in item.items() if k not in ("schema_version", "expected_answers")},
                                   expected_answers=tuple(item["expected_answers"]))
            entry = metadata[task.task_id]
            if (digest(task.source_content()) != entry.content_sha256 or task.family != entry.family
                    or task.template_id != entry.template_id or task.source_id != entry.source_id):
                raise ValueError("development_manifest_mismatch")
            # Validate input bounds through the canonical body-free feature schema.
            task.features()
            tasks.append(task)
        if len(tasks) != 60 or {task.task_id for task in tasks} != set(metadata):
            raise ValueError("development_manifest_mismatch")
        if digest({"schema_version": 1, "split": "development",
                   "templates": sorted({task.template_id for task in tasks})}) != manifest.template_split_sha256:
            raise ValueError("development_split_mismatch")
        return manifest, tuple(tasks)
    except (OSError, ValueError, TypeError, KeyError):
        raise GatewayError(ErrorCode.INVALID_EVIDENCE) from None

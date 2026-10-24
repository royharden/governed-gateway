"""Closed, payload-free adapter failures; never attach upstream exceptions."""

MESSAGES = {
    "invalid_configuration": "Unsupported adapter configuration.",
    "invalid_profile": "Adapter capability profile is incompatible.",
    "stale_profile": "Adapter capability profile has expired.",
    "unsupported_request": "Request is outside the supported adapter subset.",
    "invalid_envelope": "Provider envelope identity is invalid.",
    "external_disabled": "External generation is disabled in source-only mode.",
    "invalid_deadline": "Attempt deadline must be an aware UTC timestamp.",
}
FIELDS = frozenset({"profile", "mode", "scenario", "messages", "model",
                    "max_completion_tokens", "deadline", "envelope", "request"})


class AdapterError(ValueError):
    def __init__(self, code: str, field: str | None = None) -> None:
        self.code = code if code in MESSAGES else "invalid_configuration"
        self.field = field if field in FIELDS else None
        super().__init__(MESSAGES[self.code])

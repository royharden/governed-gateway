"""Anthropic Messages-shaped serialization; synthetic generation only."""

from gateway.schemas import GatewayRequest, ProviderEnvelope

from .common import BaseAdapter


class AnthropicAdapter(BaseAdapter):
    provider = "anthropic"

    def serialize(self, request: GatewayRequest) -> ProviderEnvelope:
        self._check_request(request)
        messages = list(request.messages)
        payload: dict[str, object] = {
            "model": self._profile.exact_model,
            "max_tokens": request.max_completion_tokens,
            "stream": False,
        }
        if messages[0].role == "system":
            payload["system"] = messages.pop(0).content
        payload["messages"] = [{"role": message.role, "content": message.content}
                               for message in messages]
        return self._envelope(request, payload)

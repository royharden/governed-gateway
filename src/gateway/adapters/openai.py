"""OpenAI Chat Completions-shaped serialization; synthetic generation only."""

from gateway.schemas import GatewayRequest, ProviderEnvelope

from .common import BaseAdapter


class OpenAIAdapter(BaseAdapter):
    provider = "openai"

    def serialize(self, request: GatewayRequest) -> ProviderEnvelope:
        self._check_request(request)
        return self._envelope(request, {
            "model": self._profile.exact_model,
            "messages": [{"role": message.role, "content": message.content}
                         for message in request.messages],
            "max_completion_tokens": request.max_completion_tokens,
            "stream": False, "n": 1,
        })

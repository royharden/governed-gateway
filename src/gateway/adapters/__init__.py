"""Keyless provider-shaped adapters. No external transport is implemented."""

from .anthropic import AnthropicAdapter
from .errors import AdapterError
from .openai import OpenAIAdapter
from .ports import CancellationToken, PendingGeneration, ProviderAdapter

__all__ = ["AdapterError", "AnthropicAdapter", "CancellationToken", "PendingGeneration", "OpenAIAdapter", "ProviderAdapter"]

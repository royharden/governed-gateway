"""Compatibility forwarding exports for the packaged development dataset."""

from gateway.evaluation.dataset import DevelopmentTask, load_development

__all__ = ("DevelopmentTask", "load_development")

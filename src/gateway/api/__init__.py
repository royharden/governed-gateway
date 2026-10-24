"""Narrow authenticated ASGI surface; no import-time serving or configuration."""
from .auth import ClientAuthenticator


def create_app(controller, authenticator):
    from .app import create_app as factory
    return factory(controller, authenticator)

__all__ = ["create_app", "ClientAuthenticator"]

"""Explicit mock-only accounting adapter; importing creates no runtime resources."""
from .adapter import LedgerAdapter
from .configuration import LedgerConfiguration
from .errors import AccountingError
from .ports import AccountingGate, AuthorityGuard

__all__ = ["LedgerAdapter", "LedgerConfiguration", "AccountingError", "AccountingGate", "AuthorityGuard"]
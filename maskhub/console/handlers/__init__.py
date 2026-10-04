"""Request handlers grouped by subject area."""

from maskhub.console.handlers import (
    audit,
    catalog,
    policy,
    rule,
    source,
    system,
    watermark,
)

__all__ = ["audit", "catalog", "policy", "rule", "source", "system", "watermark"]

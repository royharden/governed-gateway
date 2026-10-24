"""Allowlisted numeric usage projection; never preserve provider payload strings."""

from .models import MetadataUsage, NormalizedUsage, canonical_digest


def project_usage(raw: dict) -> tuple[MetadataUsage, bool, str]:
    """Return a safe projection, explicit redaction flag and its content digest."""
    kept = {}
    redacted = False
    for key, value in raw.items():
        if key not in MetadataUsage.model_fields:
            redacted = True
        elif key == "details":
            if isinstance(value, dict):
                details = {}
                for name, count in value.items():
                    if name in NormalizedUsage.model_fields and (
                        count is None or (type(count) is int and count >= 0)
                    ):
                        details[name] = count
                    else:
                        redacted = True
                kept[key] = details
            elif value is None:
                kept[key] = None
            else:
                redacted = True
        elif value is None or (type(value) is int and value >= 0):
            kept[key] = value
        else:
            redacted = True
    projection = MetadataUsage.model_validate(kept)
    return projection, redacted, canonical_digest(projection.model_dump(mode="json"))

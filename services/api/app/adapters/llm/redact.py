"""Bedrock-redaction utilities: strip obvious secret material before any egress."""

from __future__ import annotations

import re

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}")),
    ("aws_secret_access_key", re.compile(r"(?i)(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}")),
    ("pem_body", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)bearer\s+[\"']?[a-z0-9._-]{16,}")),
    ("basic_auth", re.compile(r"(?i)(\w[\w.+-]*):([\w!@#$%^&*_<>?/\\-]{8,})@")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|token)['\"\s:=]+[\w!@#$%^&*.+=-]{12,}")),
)

REDACTED = "[REDACTED]"


def redact(text: str, max_length: int = 4000) -> tuple[str, list[str]]:
    """Redact obvious secret material; return (text, patterns_hit)."""
    hit: list[str] = []
    out = text
    for name, pattern in PATTERNS:
        matches = list(pattern.finditer(out))
        if not matches:
            continue
        hit.append(name)
        out = pattern.sub(REDACTED, out)
    if len(out) > max_length:
        out = out[:max_length] + "…[TRUNCATED]"
    return out, sorted(set(hit))

"""Typed application errors shared across layers."""

from __future__ import annotations


class WardenError(Exception):
    """Base class for all Warden errors."""

    code = "warden_error"

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        if code:
            self.code = code
        self.message = message


class ValidationError(WardenError):
    code = "validation_error"


class ResourceNotFoundError(WardenError):  # noqa: N818
    code = "resource_not_found"


class PipelineFailureError(WardenError):  # noqa: N818
    code = "pipeline_failure"


class ConfigurationError(WardenError):
    code = "configuration_error"

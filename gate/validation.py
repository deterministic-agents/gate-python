"""
gate.validation
===============
JSON Schema validation for all GATE contract types.

Validates Python dicts against the canonical GATE JSON schemas in the
``contracts/`` directory. Use this in your Tool Gateway and tests to
confirm that envelopes, ledger events, and replay traces are conformant
before emitting them to your evidence store.

The validator loads schemas from the filesystem. The default schema
directory is resolved relative to this file (for use within the repo).
You can override it with a custom path.

Schema files
------------
  tool_envelope.schema.json
  policy_decision_record.schema.json
  audit_ledger_event.schema.json
  replay_trace.schema.json
  hitl_decision_record.schema.json
  multi_agent_envelope.schema.json
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import Draft202012Validator, ValidationError


# ---------------------------------------------------------------------------
# Schema discovery
# ---------------------------------------------------------------------------

# Default: look for contracts/ two levels up from this file
# gate-python/gate/validation.py -> gate-python/ -> contracts/
_DEFAULT_SCHEMA_DIR = Path(__file__).parent.parent.parent / "gate-artifacts" / "contracts"

# Fallback: contracts/ in the same repo root
_FALLBACK_SCHEMA_DIR = Path(__file__).parent.parent / "contracts"


def _find_schema_dir() -> Path:
    if _DEFAULT_SCHEMA_DIR.exists():
        return _DEFAULT_SCHEMA_DIR
    if _FALLBACK_SCHEMA_DIR.exists():
        return _FALLBACK_SCHEMA_DIR
    # Last resort: look for schemas bundled alongside this package
    pkg_schemas = Path(__file__).parent / "schemas"
    if pkg_schemas.exists():
        return pkg_schemas
    raise FileNotFoundError(
        "Cannot locate GATE schema directory. "
        "Set schema_dir explicitly when constructing GATEValidator, or "
        "ensure contracts/ is accessible relative to the package root."
    )


# ---------------------------------------------------------------------------
# Schema names
# ---------------------------------------------------------------------------

SCHEMA_TOOL_ENVELOPE = "tool_envelope.schema.json"
SCHEMA_POLICY_DECISION = "policy_decision_record.schema.json"
SCHEMA_LEDGER_EVENT = "audit_ledger_event.schema.json"
SCHEMA_REPLAY_TRACE = "replay_trace.schema.json"
SCHEMA_HITL_DECISION = "hitl_decision_record.schema.json"
SCHEMA_AGENT_MESSAGE = "multi_agent_envelope.schema.json"


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class GATEValidator:
    """
    Validates GATE contract objects against their JSON schemas.

    Loads schemas lazily and caches them. Thread-safe for reads after
    the first load (schemas are immutable).

    Parameters
    ----------
    schema_dir:
        Path to the directory containing the GATE JSON schema files.
        Defaults to auto-discovery (see module docstring).

    Examples
    --------
    >>> validator = GATEValidator()
    >>> envelope = build_request(...)   # from gate.envelopes
    >>> result = validator.validate_tool_envelope(envelope)
    >>> result.valid
    True

    >>> result = validator.validate_tool_envelope({"broken": "envelope"})
    >>> result.valid
    False
    >>> print(result.errors[0].message)
    'schema_version' is a required property
    """

    def __init__(self, schema_dir: str | Path | None = None) -> None:
        if schema_dir is None:
            self._schema_dir = _find_schema_dir()
        else:
            self._schema_dir = Path(schema_dir)
        self._cache: dict[str, dict[str, Any]] = {}

    def _load_schema(self, filename: str) -> dict[str, Any]:
        if filename not in self._cache:
            path = self._schema_dir / filename
            if not path.exists():
                raise FileNotFoundError(
                    f"Schema file not found: {path}\n"
                    f"Schema directory: {self._schema_dir}"
                )
            with open(path, encoding="utf-8") as f:
                self._cache[filename] = json.load(f)
        return self._cache[filename]

    def _validate(
        self,
        instance: dict[str, Any],
        schema_filename: str,
    ) -> "ValidationResult":
        schema = self._load_schema(schema_filename)
        validator = Draft202012Validator(schema)
        errors = list(validator.iter_errors(instance))
        return ValidationResult(
            valid=len(errors) == 0,
            schema=schema_filename,
            errors=errors,
        )

    def validate_tool_envelope(self, envelope: dict[str, Any]) -> "ValidationResult":
        """Validate a ToolRequestEnvelope or ToolResponseEnvelope."""
        return self._validate(envelope, SCHEMA_TOOL_ENVELOPE)

    def validate_policy_decision(self, record: dict[str, Any]) -> "ValidationResult":
        """Validate a PolicyDecisionRecord."""
        return self._validate(record, SCHEMA_POLICY_DECISION)

    def validate_ledger_event(self, event: dict[str, Any]) -> "ValidationResult":
        """Validate a LedgerEvent."""
        return self._validate(event, SCHEMA_LEDGER_EVENT)

    def validate_replay_trace(self, trace: dict[str, Any]) -> "ValidationResult":
        """Validate a ReplayTrace."""
        return self._validate(trace, SCHEMA_REPLAY_TRACE)

    def validate_hitl_decision(self, record: dict[str, Any]) -> "ValidationResult":
        """Validate a HITLDecisionRecord."""
        return self._validate(record, SCHEMA_HITL_DECISION)

    def validate_agent_message(self, envelope: dict[str, Any]) -> "ValidationResult":
        """Validate an AgentMessageEnvelope."""
        return self._validate(envelope, SCHEMA_AGENT_MESSAGE)

    def validate_any(
        self,
        obj: dict[str, Any],
        schema_filename: str,
    ) -> "ValidationResult":
        """Validate *obj* against any schema file in the schema directory."""
        return self._validate(obj, schema_filename)


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

class ValidationResult:
    """
    Result of a GATE schema validation.

    Attributes
    ----------
    valid:
        True if the object is schema-conformant.
    schema:
        The schema filename that was used.
    errors:
        List of jsonschema.ValidationError objects (empty if valid).
    """

    def __init__(
        self,
        valid: bool,
        schema: str,
        errors: list[ValidationError],
    ) -> None:
        self.valid = valid
        self.schema = schema
        self.errors = errors

    def __repr__(self) -> str:
        return (
            f"ValidationResult(valid={self.valid}, "
            f"schema={self.schema!r}, "
            f"errors={len(self.errors)})"
        )

    def raise_on_invalid(self) -> None:
        """
        Raise a ``GATEValidationError`` if validation failed.

        Raises
        ------
        GATEValidationError
            If ``valid`` is False.
        """
        if not self.valid:
            messages = "\n".join(
                f"  - {e.json_path}: {e.message}"
                for e in self.errors[:5]  # cap at 5 for readability
            )
            raise GATEValidationError(
                f"Schema validation failed against {self.schema}:\n{messages}"
            )

    def summary(self) -> str:
        """Return a human-readable summary string."""
        if self.valid:
            return f"PASS — {self.schema}"
        error_strs = [
            f"  [{e.json_path}] {e.message}" for e in self.errors
        ]
        return "FAIL — {}:\n{}".format(self.schema, "\n".join(error_strs))


class GATEValidationError(Exception):
    """Raised by ``ValidationResult.raise_on_invalid()`` on failure."""
    pass


# ---------------------------------------------------------------------------
# Convenience: validate without instantiating a validator
# ---------------------------------------------------------------------------

_default_validator: GATEValidator | None = None


def _get_default_validator() -> GATEValidator:
    global _default_validator
    if _default_validator is None:
        _default_validator = GATEValidator()
    return _default_validator


def validate_tool_envelope(envelope: dict[str, Any]) -> ValidationResult:
    """Validate using the default validator instance."""
    return _get_default_validator().validate_tool_envelope(envelope)


def validate_policy_decision(record: dict[str, Any]) -> ValidationResult:
    return _get_default_validator().validate_policy_decision(record)


def validate_ledger_event(event: dict[str, Any]) -> ValidationResult:
    return _get_default_validator().validate_ledger_event(event)


def validate_replay_trace(trace: dict[str, Any]) -> ValidationResult:
    return _get_default_validator().validate_replay_trace(trace)

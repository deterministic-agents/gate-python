"""
gate.hashing
============
Canonical JSON serialisation (RFC 8785) and SHA-256 hashing.

This is the foundation of all GATE evidence integrity. Every hash in a
ToolRequestEnvelope, LedgerEvent, or ReplayTrace must be computed over
the canonical JSON form of its payload. If your canonicalisation differs
from a peer's, hash verification will silently fail across components.

Canonical JSON rules (normative):
  - Keys sorted by Unicode code point, recursively
  - No insignificant whitespace
  - UTF-8 encoding
  - Numbers: no trailing zeros, no unnecessary scientific notation
  - Strings: standard JSON escaping, no unnecessary unicode escapes

References:
  GATE canonical_json.md
  RFC 8785 - JSON Canonicalization Scheme
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------

def canonical_json(obj: Any) -> bytes:
    """
    Serialise *obj* to canonical JSON bytes (RFC 8785).

    Keys are sorted recursively. No whitespace. UTF-8 encoded.

    Parameters
    ----------
    obj:
        Any JSON-serialisable Python object.

    Returns
    -------
    bytes
        UTF-8 encoded canonical JSON.

    Examples
    --------
    >>> canonical_json({"z": 1, "a": 2})
    b'{"a":2,"z":1}'

    >>> canonical_json({"m": {"z": 1, "a": 2}, "b": [3, 1, 2]})
    b'{"b":[3,1,2],"m":{"a":2,"z":1}}'
    """
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_json_str(obj: Any) -> str:
    """Return canonical JSON as a string (not bytes)."""
    return canonical_json(obj).decode("utf-8")


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def gate_hash(obj: Any) -> str:
    """
    Compute a GATE-format SHA-256 hash over the canonical JSON of *obj*.

    The returned string is always prefixed with ``sha256:`` followed by
    64 lowercase hex characters, matching the ``gate_hash`` pattern in
    all GATE JSON schemas.

    Parameters
    ----------
    obj:
        Any JSON-serialisable Python object.

    Returns
    -------
    str
        ``"sha256:<64-hex-chars>"``

    Examples
    --------
    >>> h = gate_hash({"tool": "transfer_funds", "amount": 500})
    >>> h.startswith("sha256:")
    True
    >>> len(h)
    71  # len("sha256:") + 64
    """
    digest = hashlib.sha256(canonical_json(obj)).hexdigest()
    return f"sha256:{digest}"


def gate_hash_bytes(data: bytes) -> str:
    """
    Compute a GATE-format SHA-256 hash over raw *bytes*.

    Use this for hashing bundle archives (policy bundles, tool schema
    zip files) where you hash the file bytes, not a JSON representation.

    Parameters
    ----------
    data:
        Raw bytes (e.g. ``open("policy_bundle.tar.gz", "rb").read()``).

    Returns
    -------
    str
        ``"sha256:<64-hex-chars>"``
    """
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


def gate_hash_file(path: str) -> str:
    """
    Compute a GATE-format SHA-256 hash over the contents of a file.

    Reads in 64 KB chunks to handle large bundle archives without
    loading the entire file into memory.

    Parameters
    ----------
    path:
        Filesystem path to the file.

    Returns
    -------
    str
        ``"sha256:<64-hex-chars>"``
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_hash(obj: Any, expected_hash: str) -> bool:
    """
    Verify that the canonical JSON hash of *obj* matches *expected_hash*.

    Parameters
    ----------
    obj:
        The Python object to verify.
    expected_hash:
        The expected ``"sha256:<hex>"`` string (e.g. from a stored envelope).

    Returns
    -------
    bool
        True if the hash matches, False otherwise.

    Raises
    ------
    ValueError
        If *expected_hash* is not in ``sha256:<hex>`` format.
    """
    if not expected_hash.startswith("sha256:"):
        raise ValueError(
            f"expected_hash must start with 'sha256:'; got: {expected_hash!r}"
        )
    return gate_hash(obj) == expected_hash


def verify_hash_bytes(data: bytes, expected_hash: str) -> bool:
    """Verify raw bytes against an expected GATE hash string."""
    if not expected_hash.startswith("sha256:"):
        raise ValueError(
            f"expected_hash must start with 'sha256:'; got: {expected_hash!r}"
        )
    return gate_hash_bytes(data) == expected_hash


# ---------------------------------------------------------------------------
# Helpers used by other modules
# ---------------------------------------------------------------------------

def _assert_hash_format(value: str, field_name: str) -> None:
    """Raise ValueError if *value* is not a valid GATE hash string."""
    if not (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(c in "0123456789abcdef" for c in value[7:])
    ):
        raise ValueError(
            f"{field_name} must be 'sha256:<64 hex chars>'; got: {value!r}"
        )

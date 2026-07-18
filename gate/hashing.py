"""
gate.hashing
============
GATE canonical JSON serialisation and SHA-256 hashing.

This is the foundation of all GATE evidence integrity. Every hash in a
ToolRequestEnvelope, LedgerEvent, or ReplayTrace must be computed over
the canonical JSON form of its payload. If your canonicalisation differs
from a peer's, hash verification will silently fail across components.

GATE canonical JSON is a pragmatic subset of RFC 8785 (JSON
Canonicalization Scheme), not full JCS. The differences are documented
in ``canonical_json.md``; the important ones are that string escapes use
lowercase hex (as both this library and gate-rust emit, and as RFC 8785
also requires) and that hashed float surfaces are restricted to values
both serialisers render identically (round to at most four decimal
places at hashing boundaries; see ``gate.rounding``).

Canonical JSON rules (normative, as implemented):
  - Keys sorted by Unicode code point, recursively
  - No insignificant whitespace
  - UTF-8 encoding, non-ASCII emitted raw (``ensure_ascii=False``)
  - Numbers rendered by the platform serialiser on the restricted subset
  - Non-finite floats (NaN, Infinity) and non-string dict keys rejected

References:
  GATE canonical_json.md (the normative spec, with the RFC 8785 subset
  boundaries listed)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------

def _assert_string_keys(obj: Any) -> None:
    """Walk *obj* and raise TypeError if any dict key is not a str.

    Python's default json.dumps silently coerces non-string dict keys
    (`{1: "a", True: "b"}` becomes `{"1": "a", "true": "b"}`). That coercion
    breaks cross-language hash equivalence with gate-rust, which refuses
    non-string keys at serialisation time. GATE canonical JSON requires
    string keys explicitly at both ends of the language boundary.
    """
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise TypeError(
                    f"canonical_json: non-string dict key {k!r} "
                    f"(type {type(k).__name__}) is not permitted; "
                    "GATE canonical JSON requires string keys throughout."
                )
            _assert_string_keys(obj[k])
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _assert_string_keys(item)


def canonical_json(obj: Any) -> bytes:
    """
    Serialise *obj* to canonical JSON bytes.

    Keys are sorted recursively. No whitespace. UTF-8 encoded. Non-finite
    floats (NaN, Infinity, -Infinity) are rejected via ``allow_nan=False``;
    non-string dict keys are rejected up front so the silent-coercion path
    in ``json.dumps`` never runs.

    See ``canonical_json.md`` for the normative rules and documented subset
    boundaries relative to RFC 8785.

    Parameters
    ----------
    obj:
        Any JSON-serialisable Python object whose dict keys are strings and
        whose float values are finite.

    Returns
    -------
    bytes
        UTF-8 encoded canonical JSON.

    Raises
    ------
    TypeError
        If a dict contains a non-string key.
    ValueError
        If a float value is NaN, +Infinity, or -Infinity.

    Examples
    --------
    >>> canonical_json({"z": 1, "a": 2})
    b'{"a":2,"z":1}'

    >>> canonical_json({"m": {"z": 1, "a": 2}, "b": [3, 1, 2]})
    b'{"b":[3,1,2],"m":{"a":2,"z":1}}'
    """
    _assert_string_keys(obj)
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
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
        If *expected_hash* is not a valid GATE hash string
        (``sha256:`` + 64 lowercase hex characters, total length 71).
        This strict validation matches gate-rust's ``verify_hash``,
        which returns ``Err(GateError::InvalidHashFormat)`` for the same
        inputs. A malformed hash is a programming error, not a
        verification failure, so it raises rather than returning False.
    """
    _assert_hash_format(expected_hash, "expected_hash")
    return gate_hash(obj) == expected_hash


def verify_hash_bytes(data: bytes, expected_hash: str) -> bool:
    """Verify raw bytes against an expected GATE hash string.

    Raises ValueError if *expected_hash* is not a valid GATE hash string
    (strict format, matching gate-rust).
    """
    _assert_hash_format(expected_hash, "expected_hash")
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

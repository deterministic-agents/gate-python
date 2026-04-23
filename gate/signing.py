"""
gate.signing
============
ES256 action signing and signature verification for GATE non-repudiation.

Every high-impact action (financial, irreversible_write, infrastructure)
must be digitally signed using the agent's workload identity key. The
signature covers the canonical JSON of the action payload, creating a
mathematically undeniable link between the agent's identity and the
action.

This module uses ECDSA P-256 (ES256), the algorithm specified in the
GATE audit_ledger_event.schema.json. The cryptography library is used
throughout - it is the standard, well-audited choice for Python crypto.

Key management
--------------
In production, agent signing keys are:
  - Derived from or bound to the SPIFFE workload identity
  - Short-lived (rotated with the workload identity TTL)
  - Never stored in the agent runtime (use a secrets manager or TEE)

This module provides the signing and verification primitives. Key
issuance, rotation, and revocation are infrastructure concerns handled
by your identity layer (SPIRE, cloud KMS, etc.).

For long-term non-repudiation of signatures beyond the key TTL, anchor
the event_hash to a trusted timestamping authority (RFC 3161) before
the key expires.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.exceptions import InvalidSignature

from .hashing import canonical_json, gate_hash


# ---------------------------------------------------------------------------
# Key generation (for testing and bootstrap)
# ---------------------------------------------------------------------------

def generate_signing_key() -> EllipticCurvePrivateKey:
    """
    Generate a new P-256 private key for GATE action signing.

    In production, keys are issued by your identity infrastructure
    (SPIRE, cloud KMS, HSM). Use this function for testing and local
    development only.

    Returns
    -------
    EllipticCurvePrivateKey
        A new P-256 private key.
    """
    return ec.generate_private_key(ec.SECP256R1())


def private_key_to_pem(key: EllipticCurvePrivateKey) -> bytes:
    """Serialise a private key to PEM bytes (unencrypted)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(key: EllipticCurvePrivateKey | EllipticCurvePublicKey) -> bytes:
    """Serialise a public key to PEM bytes."""
    if isinstance(key, EllipticCurvePrivateKey):
        key = key.public_key()
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(pem: bytes) -> EllipticCurvePrivateKey:
    """Load a P-256 private key from PEM bytes."""
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key_pem(pem: bytes) -> EllipticCurvePublicKey:
    """Load a P-256 public key from PEM bytes."""
    return serialization.load_pem_public_key(pem)


# ---------------------------------------------------------------------------
# Action signing
# ---------------------------------------------------------------------------

def sign_action(
    *,
    payload: dict[str, Any],
    private_key: EllipticCurvePrivateKey,
    key_id: str,
) -> dict[str, Any]:
    """
    Sign an action payload and return a GATE signature record.

    The signature is computed over the SHA-256 of the canonical JSON
    of *payload*, using ECDSA P-256 with SHA-256 (ES256).

    The returned dict is suitable for inclusion in:
    - ``LedgerEvent.signatures``
    - ``HITLDecisionRecord.evidence``
    - ``AgentMessageEnvelope.signature``

    Parameters
    ----------
    payload:
        The object to sign. For tool actions, this is typically the
        canonical form of ``{action, request_hash, policy_decision_id}``.
        For ledger events, this is the ``event_hash`` string.
        For HITL decisions, this is the ``decision`` sub-object.
    private_key:
        The signing key. Must be a P-256 private key.
    key_id:
        An identifier for this key (e.g. ``"kid-treasury-2026-04"``).
        Stored alongside the signature so verifiers can look up the
        correct public key.

    Returns
    -------
    dict
        ``{"signing_key_id": str, "algorithm": "ES256", "signature": str}``
        where ``signature`` is base64url-encoded (no padding).

    Examples
    --------
    >>> key = generate_signing_key()
    >>> sig = sign_action(
    ...     payload={"tool": "transfer_funds", "amount": 500},
    ...     private_key=key,
    ...     key_id="kid-test-001",
    ... )
    >>> sig["algorithm"]
    'ES256'
    >>> sig["signing_key_id"]
    'kid-test-001'
    """
    canonical = canonical_json(payload)
    raw_sig = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode("ascii")

    return {
        "signing_key_id": key_id,
        "algorithm": "ES256",
        "signature": sig_b64,
    }


def sign_event_hash(
    *,
    event_hash: str,
    private_key: EllipticCurvePrivateKey,
    key_id: str,
) -> dict[str, Any]:
    """
    Sign a GATE event_hash string (for LedgerEvent non-repudiation).

    Convenience wrapper around ``sign_action`` for the common case of
    signing a ledger event hash.

    Parameters
    ----------
    event_hash:
        The ``"sha256:<hex>"`` event hash from the LedgerEvent.
    private_key:
        The signing key.
    key_id:
        Key identifier.

    Returns
    -------
    dict
        Same structure as ``sign_action``.
    """
    return sign_action(
        payload={"event_hash": event_hash},
        private_key=private_key,
        key_id=key_id,
    )


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def verify_signature(
    *,
    payload: dict[str, Any],
    signature_record: dict[str, Any],
    public_key: EllipticCurvePublicKey,
) -> bool:
    """
    Verify a GATE signature record against a payload.

    Parameters
    ----------
    payload:
        The object that was originally signed.
    signature_record:
        The dict returned by ``sign_action``, containing
        ``"signature"`` (base64url), ``"algorithm"``, and
        ``"signing_key_id"``.
    public_key:
        The P-256 public key corresponding to the signing key.

    Returns
    -------
    bool
        True if the signature is valid, False otherwise.

    Notes
    -----
    This function never raises on an invalid signature — it returns
    False. It only raises on programming errors (wrong key type, etc.).

    Examples
    --------
    >>> key = generate_signing_key()
    >>> payload = {"tool": "transfer_funds", "amount": 500}
    >>> sig = sign_action(payload=payload, private_key=key, key_id="k1")
    >>> verify_signature(
    ...     payload=payload,
    ...     signature_record=sig,
    ...     public_key=key.public_key(),
    ... )
    True
    >>> verify_signature(
    ...     payload={"tool": "transfer_funds", "amount": 999},  # tampered
    ...     signature_record=sig,
    ...     public_key=key.public_key(),
    ... )
    False
    """
    algorithm = signature_record.get("algorithm", "ES256")
    if algorithm != "ES256":
        raise ValueError(f"Unsupported signature algorithm: {algorithm!r}")

    sig_b64 = signature_record.get("signature", "")
    # Add padding if needed for standard base64 decoding
    padding = 4 - len(sig_b64) % 4
    if padding != 4:
        sig_b64 += "=" * padding
    try:
        raw_sig = base64.urlsafe_b64decode(sig_b64)
    except Exception:
        return False

    canonical = canonical_json(payload)
    try:
        public_key.verify(raw_sig, canonical, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def verify_event_hash_signature(
    *,
    event_hash: str,
    signature_record: dict[str, Any],
    public_key: EllipticCurvePublicKey,
) -> bool:
    """
    Verify the signature over a ledger event_hash.

    Convenience wrapper matching ``sign_event_hash``.
    """
    return verify_signature(
        payload={"event_hash": event_hash},
        signature_record=signature_record,
        public_key=public_key,
    )


# ---------------------------------------------------------------------------
# Key registry (lightweight, for testing and demos)
# ---------------------------------------------------------------------------

class KeyRegistry:
    """
    In-memory mapping of key_id → public key for signature verification.

    In production, use your cloud KMS or SPIRE's key distribution.
    This class is for testing and local development.

    Examples
    --------
    >>> registry = KeyRegistry()
    >>> key = generate_signing_key()
    >>> registry.register("kid-001", key.public_key())
    >>> pub = registry.get("kid-001")
    """

    def __init__(self) -> None:
        self._keys: dict[str, EllipticCurvePublicKey] = {}

    def register(self, key_id: str, public_key: EllipticCurvePublicKey) -> None:
        """Register a public key under *key_id*."""
        self._keys[key_id] = public_key

    def register_private(self, key_id: str, private_key: EllipticCurvePrivateKey) -> None:
        """Extract and register the public key from a private key."""
        self._keys[key_id] = private_key.public_key()

    def get(self, key_id: str) -> EllipticCurvePublicKey:
        """
        Look up a public key by key_id.

        Raises
        ------
        KeyError
            If *key_id* is not registered.
        """
        if key_id not in self._keys:
            raise KeyError(f"No public key registered for key_id={key_id!r}")
        return self._keys[key_id]

    def verify(
        self,
        *,
        payload: dict[str, Any],
        signature_record: dict[str, Any],
    ) -> bool:
        """
        Verify a signature, looking up the public key from this registry.

        Returns False (not KeyError) if the key_id is not found, to
        treat missing keys as verification failures.
        """
        key_id = signature_record.get("signing_key_id", "")
        try:
            pub = self.get(key_id)
        except KeyError:
            return False
        return verify_signature(
            payload=payload,
            signature_record=signature_record,
            public_key=pub,
        )

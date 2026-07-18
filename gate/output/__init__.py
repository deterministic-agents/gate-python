"""
gate.output
===========
Construction of GATE C20 output classification events and evaluation
functions.

The evaluation function (evaluate_output_sensitivity) is a pure function
with no I/O. It can be called independently to test a single response
against an output classification bundle before calling
apply_output_action_matrix to compose the obligation list.

Per the v1.3 framework constraint, this module is independent of
gate.envelopes and gate.validation. It produces dicts conformant to
output_classification_event.schema.json from gate-contracts v1.2.0.

Retention class selection follows Erratum 2 / Erratum 3 in
v1.4/paper-updates/01-C20-errata.md. Each action-matrix entry MAY carry
an optional retention_class field drawn from the
audit_ledger_event.immutability.retention_class enum
(sandbox_hot_30d | prod_hot_365d | prod_cold_6y_worm |
regulated_cold_7y_plus). When a matched entry omits retention_class,
the per-tier default applies: sandbox_hot_30d at sandbox tier,
prod_cold_6y_worm at bounded and high-privilege tiers.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..hashing import gate_hash
from ..rounding import round4


_VALID_OBLIGATIONS: frozenset[str] = frozenset(
    {"redact_fields", "hitl_review", "hold_for_review"}
)
_VALID_TIERS: frozenset[str] = frozenset(
    {"sandbox", "bounded", "high_privilege"}
)
_VALID_RETENTION_CLASSES: frozenset[str] = frozenset(
    {
        "sandbox_hot_30d",
        "prod_hot_365d",
        "prod_cold_6y_worm",
        "regulated_cold_7y_plus",
    }
)
_RETENTION_DEFAULT_BY_TIER: dict[str, str] = {
    "sandbox": "sandbox_hot_30d",
    "bounded": "prod_cold_6y_worm",
    "high_privilege": "prod_cold_6y_worm",
}


def build_output_classification_event(
    *,
    run_id: str,
    trace_id: str,
    output: Any,
    classification: dict[str, Any],
    obligations: list[str],
    ledger_event_id: str,
    tenant_id: str,
    environment: str,
    bundle_hash: str,
) -> dict[str, Any]:
    """
    Build a conformant gate.output.classification event.

    Called by the C20 classification engine on every final agent response
    immediately before delivery. The output_hash is computed via gate_hash
    over the canonical-JSON serialisation of output, matching the existing
    hash function used elsewhere in the library.

    classification is the dict returned by evaluate_output_sensitivity
    (sensitivity_tier, regulated_categories, confidence_score,
    requires_human_review). obligations is the list returned by
    apply_output_action_matrix.

    bundle_hash is the hash of the signed output classification bundle in
    force at emission time. Recorded so the auditor verifies by hash, not
    by bundle version label.
    """
    if environment not in {"dev", "test", "prod"}:
        raise ValueError(
            f"environment must be one of dev/test/prod; got {environment!r}"
        )
    for obligation in obligations:
        if obligation not in _VALID_OBLIGATIONS:
            raise ValueError(
                f"obligation must be one of {set(_VALID_OBLIGATIONS)}; "
                f"got {obligation!r}"
            )

    output_hash = gate_hash(output)
    # Round the confidence_score at the hashing boundary. Envelopes round
    # to four places (gate.rounding.round4); the C20 event's classification
    # is a hashed surface too, so it must obey the same float restriction
    # (canonical_json.md) or a divergent-serialising float would break
    # cross-language hash equivalence with gate-rust.
    classification = dict(classification)
    if "confidence_score" in classification:
        classification["confidence_score"] = round4(
            float(classification["confidence_score"])
        )
    return {
        "schema_version": "v1",
        "event_type": "gate.output.classification",
        "time": _now_iso(),
        "run_id": run_id,
        "trace_id": trace_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "output_hash": output_hash,
        "classification": classification,
        "obligations": obligations,
        "bundle_hash": bundle_hash,
        "ledger_event_id": ledger_event_id,
    }


def evaluate_output_sensitivity(
    output_text: str,
    classification_bundle: dict[str, Any],
    autonomy_tier: str,
) -> dict[str, Any]:
    """
    Evaluate an output response against the classification bundle.

    Pure function. Returns a classification dict with sensitivity_tier,
    regulated_categories, confidence_score, and requires_human_review.

    Resolution rules (mirroring the rego in
    policies/output/c20_output_classification.rego):

    - sensitivity_tier resolves from the bundle's classifier output for
      output_text. The bundle provides a classifier_fn entry (callable in
      the in-memory bundle, opaque elsewhere) plus the enumerated
      sensitivity_tiers list. When the bundle carries a callable
      classifier, it is invoked here; otherwise the bundle's
      default_sensitivity_tier is returned (fail-closed at the bundle
      layer, not at the runtime).
    - regulated_categories returns the matched subset of the bundle's
      regulated_categories enumeration.
    - confidence_score is provided by the bundle's confidence_fn callable
      or defaults to the bundle's default_confidence (0.5 if absent so
      the matrix's confidence_band logic has a stable input).
    - requires_human_review is derived from the action matrix by calling
      apply_output_action_matrix and checking whether hitl_review is in
      the obligation list.

    This evaluation surface is intentionally minimal in the reference
    library. Operators wire their own classifier_fn and confidence_fn
    into the bundle at load time; the library does not ship a content
    classifier.
    """
    if autonomy_tier not in _VALID_TIERS:
        raise ValueError(
            f"autonomy_tier must be one of {set(_VALID_TIERS)}; "
            f"got {autonomy_tier!r}"
        )

    bundle = classification_bundle
    classifier_fn = bundle.get("classifier_fn")
    confidence_fn = bundle.get("confidence_fn")

    if callable(classifier_fn):
        classifier_result = classifier_fn(output_text)
        sensitivity_tier = classifier_result.get(
            "sensitivity_tier", bundle.get("default_sensitivity_tier", "low")
        )
        regulated_categories = list(
            classifier_result.get("regulated_categories", [])
        )
    else:
        sensitivity_tier = bundle.get("default_sensitivity_tier", "low")
        regulated_categories = []

    if callable(confidence_fn):
        confidence_score = float(confidence_fn(output_text))
    else:
        confidence_score = float(bundle.get("default_confidence", 0.5))

    # Bound confidence to the schema-allowed [0, 1] range.
    if confidence_score < 0.0:
        confidence_score = 0.0
    elif confidence_score > 1.0:
        confidence_score = 1.0
    # Restrict to the hashable float subspace (four decimal places, ties
    # away from zero) so the classification hashes identically in Rust.
    confidence_score = round4(confidence_score)

    classification = {
        "sensitivity_tier": sensitivity_tier,
        "regulated_categories": regulated_categories,
        "confidence_score": confidence_score,
        "requires_human_review": False,
    }

    obligations = apply_output_action_matrix(
        classification=classification,
        autonomy_tier=autonomy_tier,
        action_matrix=bundle.get("action_matrix", []),
    )
    classification["requires_human_review"] = "hitl_review" in obligations
    return classification


def apply_output_action_matrix(
    *,
    classification: dict[str, Any],
    autonomy_tier: str,
    action_matrix: list[dict[str, Any]],
) -> list[str]:
    """
    Apply the action matrix to a classification and return the sorted
    obligation list.

    Each entry in action_matrix is a dict with optional keys:

      - sensitivity_tier: string. Required for the entry to match a
        classification; no wildcard support. Operators enumerate
        tier values explicitly. Matches the W3 rego at
        policies/output/c20_output_classification.rego lines 46-51
        (Steer 1 Q3).
      - regulated_categories: list of strings. Set-inclusion semantic:
        every category in the entry list must be present in the
        classification's regulated_categories. An empty entry list
        matches any classification (vacuously true), mirroring the
        rego's `every cat in entry.regulated_categories` clause.
      - autonomy_tier: string. Required for the entry to match;
        no wildcard support.
      - confidence_band: {"min": float, "max": float} closed interval
      - obligations: list of strings from
        {redact_fields, hitl_review, hold_for_review}
      - is_pass_through: bool (default false). Marks an entry whose
        empty obligation list is the operator's deliberate
        pass-through, suppressing the high-privilege fail-closed
        guardrail.
      - retention_class: optional string drawn from
        {sandbox_hot_30d, prod_hot_365d, prod_cold_6y_worm,
        regulated_cold_7y_plus}. See select_retention_class below.

    Multiple matching entries compose: the obligation lists are unioned
    and returned sorted for stable consumer ordering.

    Fail-closed guardrail (mirrors enforce_default_high_privilege_hold
    in the rego): at high_privilege tier, when the matched entries
    contribute no obligations and no matched entry is marked
    is_pass_through, the obligation list is forced to
    ["hold_for_review"].

    Pure function. autonomy_tier is validated; an unknown tier raises.
    """
    if autonomy_tier not in _VALID_TIERS:
        raise ValueError(
            f"autonomy_tier must be one of {set(_VALID_TIERS)}; "
            f"got {autonomy_tier!r}"
        )

    matched_entries = [
        entry
        for entry in action_matrix
        if _entry_matches(entry, classification, autonomy_tier)
    ]

    obligations: set[str] = set()
    for entry in matched_entries:
        for obligation in entry.get("obligations", []):
            if obligation not in _VALID_OBLIGATIONS:
                raise ValueError(
                    f"obligation must be one of {set(_VALID_OBLIGATIONS)}; "
                    f"got {obligation!r}"
                )
            obligations.add(obligation)

    if (
        autonomy_tier == "high_privilege"
        and not obligations
        and not any(entry.get("is_pass_through") for entry in matched_entries)
    ):
        obligations.add("hold_for_review")

    return sorted(obligations)


def select_retention_class(
    *,
    classification: dict[str, Any],
    autonomy_tier: str,
    action_matrix: list[dict[str, Any]],
) -> str:
    """
    Select the retention_class for the C20 event's wrapping audit ledger
    event from the matched action-matrix entries.

    Per Erratum 2 / Erratum 3 in v1.4/paper-updates/01-C20-errata.md:

    - When a matched entry carries retention_class, that value wins.
      When multiple matched entries carry retention_class, the strongest
      retention wins (longest duration / WORM tier). Order:
      regulated_cold_7y_plus > prod_cold_6y_worm > prod_hot_365d >
      sandbox_hot_30d.
    - When no matched entry carries retention_class, fall back to the
      per-tier default: sandbox_hot_30d at sandbox tier,
      prod_cold_6y_worm at bounded and high_privilege tiers.

    Returns one of the four values in the existing
    audit_ledger_event.immutability.retention_class enum. Pure function.
    """
    if autonomy_tier not in _VALID_TIERS:
        raise ValueError(
            f"autonomy_tier must be one of {set(_VALID_TIERS)}; "
            f"got {autonomy_tier!r}"
        )

    strength = {
        "sandbox_hot_30d": 0,
        "prod_hot_365d": 1,
        "prod_cold_6y_worm": 2,
        "regulated_cold_7y_plus": 3,
    }

    selected: str | None = None
    for entry in action_matrix:
        if not _entry_matches(entry, classification, autonomy_tier):
            continue
        candidate = entry.get("retention_class")
        if candidate is None:
            continue
        if candidate not in _VALID_RETENTION_CLASSES:
            raise ValueError(
                f"retention_class must be one of "
                f"{set(_VALID_RETENTION_CLASSES)}; got {candidate!r}"
            )
        if selected is None or strength[candidate] > strength[selected]:
            selected = candidate

    if selected is not None:
        return selected
    return _RETENTION_DEFAULT_BY_TIER[autonomy_tier]


class OutputClassificationBundle:
    """
    In-memory representation of a signed output classification bundle.

    Holds the action matrix in structured form usable by
    apply_output_action_matrix. Provides load / verify / sign helpers
    against the bundle's payload.

    The bundle structure (operator-defined, narrated in the C20 spec):

      {
        "bundle_id": "<uuid>",
        "bundle_version": "<semver>",
        "sensitivity_tiers": ["low", "medium", "high"],
        "regulated_categories": ["medical", "legal", ...],
        "default_sensitivity_tier": "low",
        "default_confidence": 0.5,
        "action_matrix": [ {entry}, ... ],
        "signature": "<base64 signature over canonical body>",
        "signing_key_id": "kid-<id>"
      }

    The library does not promote this to a first-class JSON Schema in
    v1.4 (per Erratum 4); promotion is a v1.5 candidate. A minimal
    structural check runs at load time so an obviously-broken bundle
    raises before the engine starts emitting events.
    """

    REQUIRED_KEYS: frozenset[str] = frozenset(
        {"bundle_id", "bundle_version", "action_matrix"}
    )

    def __init__(self, payload: dict[str, Any]) -> None:
        missing = self.REQUIRED_KEYS - set(payload)
        if missing:
            raise ValueError(
                f"output classification bundle missing required keys: "
                f"{sorted(missing)}"
            )
        if not isinstance(payload["action_matrix"], list):
            raise ValueError("action_matrix must be a list of entries")
        self._payload = payload
        self._bundle_hash: str | None = None

    @classmethod
    def load(cls, payload: dict[str, Any]) -> "OutputClassificationBundle":
        """Build a bundle from an in-memory dict payload."""
        return cls(payload)

    @property
    def bundle_id(self) -> str:
        return self._payload["bundle_id"]

    @property
    def bundle_version(self) -> str:
        return self._payload["bundle_version"]

    @property
    def action_matrix(self) -> list[dict[str, Any]]:
        return self._payload["action_matrix"]

    @property
    def payload(self) -> dict[str, Any]:
        return self._payload

    def bundle_hash(self) -> str:
        """
        Hash over the canonical body excluding the signature field.

        Cached after first computation.
        """
        if self._bundle_hash is None:
            body = {k: v for k, v in self._payload.items() if k != "signature"}
            self._bundle_hash = gate_hash(body)
        return self._bundle_hash

    def verify_signature(self, public_key: Any) -> bool:
        """
        Verify the bundle's detached signature against public_key.

        Delegates to gate.signing.verify_signature against the canonical
        body (signature field excluded). Returns False if no signature is
        attached.
        """
        signature_field = self._payload.get("signature")
        signing_key_id = self._payload.get("signing_key_id")
        if not signature_field or not signing_key_id:
            return False
        # Local import so gate.output stays importable without
        # cryptography being installed (the dependency is required for
        # the v1.1.0 library overall but isolating the import here
        # keeps the module test-runnable in stripped environments).
        from ..signing import verify_signature
        body = {k: v for k, v in self._payload.items() if k != "signature"}
        record = {
            "signing_key_id": signing_key_id,
            "algorithm": self._payload.get("algorithm", "ES256"),
            "signature": signature_field,
        }
        return verify_signature(
            payload=body,
            signature_record=record,
            public_key=public_key,
        )

    def apply(
        self,
        classification: dict[str, Any],
        autonomy_tier: str,
    ) -> list[str]:
        """Apply the bundle's action matrix and return obligations."""
        return apply_output_action_matrix(
            classification=classification,
            autonomy_tier=autonomy_tier,
            action_matrix=self.action_matrix,
        )

    def select_retention_class(
        self,
        classification: dict[str, Any],
        autonomy_tier: str,
    ) -> str:
        """Select retention_class via the module-level helper."""
        return select_retention_class(
            classification=classification,
            autonomy_tier=autonomy_tier,
            action_matrix=self.action_matrix,
        )


# ---------------------------------------------------------------------------
# Internal matching helpers
# ---------------------------------------------------------------------------

def _entry_matches(
    entry: dict[str, Any],
    classification: dict[str, Any],
    autonomy_tier: str,
) -> bool:
    """Return True when an action-matrix entry matches the classification."""
    if not _sensitivity_tier_matches(entry, classification):
        return False
    if not _regulated_categories_match(entry, classification):
        return False
    if not _autonomy_tier_matches(entry, autonomy_tier):
        return False
    if not _confidence_band_matches(entry, classification):
        return False
    return True


def _sensitivity_tier_matches(
    entry: dict[str, Any],
    classification: dict[str, Any],
) -> bool:
    # No wildcard support per W3 Steer 1 Q3. An entry without a
    # sensitivity_tier key cannot match (the rego's `entry.sensitivity_tier
    # == input.classification.sensitivity_tier` returns undefined when the
    # key is absent, which fails the match).
    if "sensitivity_tier" not in entry:
        return False
    return classification.get("sensitivity_tier") == entry["sensitivity_tier"]


def _regulated_categories_match(
    entry: dict[str, Any],
    classification: dict[str, Any],
) -> bool:
    # Set-inclusion semantic mirroring rego lines 103-109:
    #   every cat in entry.regulated_categories {
    #       cat in input.classification.regulated_categories
    #   }
    # An empty entry list is vacuously true and matches any classification.
    # A non-list value (including "*") cannot match; no wildcard support.
    expected = entry.get("regulated_categories")
    if not isinstance(expected, list):
        return False
    classified = set(classification.get("regulated_categories", []))
    return all(cat in classified for cat in expected)


def _autonomy_tier_matches(
    entry: dict[str, Any],
    autonomy_tier: str,
) -> bool:
    # No wildcard support per W3 Steer 1 Q3.
    if "autonomy_tier" not in entry:
        return False
    return autonomy_tier == entry["autonomy_tier"]


def _confidence_band_matches(
    entry: dict[str, Any],
    classification: dict[str, Any],
) -> bool:
    band = entry.get("confidence_band")
    if band is None:
        return True
    score = float(classification.get("confidence_score", 0.0))
    return float(band["min"]) <= score <= float(band["max"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "build_output_classification_event",
    "evaluate_output_sensitivity",
    "apply_output_action_matrix",
    "select_retention_class",
    "OutputClassificationBundle",
]

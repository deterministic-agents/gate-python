"""
gate.rounding
=============
Deterministic float rounding at hashing boundaries.

GATE restricts hashed float surfaces to values that both the Python and
the Rust serialiser render identically (see ``canonical_json.md``). The
enforcement rule is: round every float to at most four decimal places at
the hashing boundary, using half-away-from-zero rounding.

Half-away-from-zero is chosen because it is what gate-rust's ``round4``
already does (``(v * 10000.0).round() / 10000.0``; Rust ``f64::round``
rounds ties away from zero). Python's built-in ``round`` uses banker's
rounding (ties to even), which diverges from Rust on tie values such as
``2.5`` scaled or the float representation of ``0.00005``. ``round4``
below reproduces the Rust result bit-for-bit: it performs the identical
``v * 10000.0`` product (bit-identical across IEEE-754 f64 platforms)
and then rounds the resulting float to the nearest integer with ties
away from zero, avoiding the ``floor(x + 0.5)`` overflow pitfall by
comparing the fractional part directly.
"""

from __future__ import annotations

import math

__all__ = ["round4"]


def round4(value: float) -> float:
    """Round *value* to four decimal places, ties away from zero.

    Bit-for-bit equivalent to gate-rust's ``round4``:
    ``(value * 10000.0).round() / 10000.0`` where ``round`` rounds ties
    away from zero. Use this at every boundary where a float enters a
    hashed surface so the Python and Rust serialisations agree.
    """
    scaled = value * 10000.0
    floor = math.floor(scaled)
    frac = scaled - floor
    if frac < 0.5:
        nearest = floor
    elif frac > 0.5:
        nearest = floor + 1
    else:
        # Exact half: round away from zero.
        nearest = floor + 1 if scaled > 0 else floor
    return nearest / 10000.0

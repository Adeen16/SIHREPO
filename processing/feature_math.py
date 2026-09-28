"""
processing/feature_math.py
--------------------------
Shared mathematical helpers for feature computation.
All conventions are documented here; adapters and ML preprocessing
must import from this module — never re-implement locally.

BYTE_RATIO_CAP:
    Maximum value for the byte_ratio feature.
    Convention (per §C.1 of the order):
        rev > 0          → fwd / rev
        rev == 0 & fwd > 0 → BYTE_RATIO_CAP
        rev == 0 & fwd == 0 → 0.0
    Always clipped to [0, BYTE_RATIO_CAP].
    ML preprocessing applies log1p on top of this.
    is_unidirectional disambiguates the cap case.
"""

BYTE_RATIO_CAP: float = 10_000.0


def compute_byte_ratio(fwd_bytes: int, rev_bytes: int) -> float:
    """
    Compute the forward-to-reverse byte ratio with a documented cap.

    Args:
        fwd_bytes: total bytes in the forward (initiator) direction.
        rev_bytes: total bytes in the reverse (responder) direction.

    Returns:
        float in [0.0, BYTE_RATIO_CAP].
    """
    if fwd_bytes == 0 and rev_bytes == 0:
        return 0.0
    if rev_bytes == 0:
        return BYTE_RATIO_CAP
    ratio = fwd_bytes / rev_bytes
    return min(ratio, BYTE_RATIO_CAP)

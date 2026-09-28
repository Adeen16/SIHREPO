"""
dataset/validation.py
----------------------
Validates a UnifiedFeatureRecord for schema correctness.
Returns (is_valid, reason_or_None).

Also computes ValidationReport statistics across a batch.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Tuple, Optional
from dataset.schema import UnifiedFeatureRecord, CanonicalLabel


def validate_record(rec: UnifiedFeatureRecord) -> Tuple[bool, Optional[str]]:
    """
    Returns (True, None) if valid, or (False, rejection_reason).
    rejection_reason is one of AdapterStats.REJECTION_REASONS.
    """
    # Timestamp must be positive and non-zero (zero indicates a parse failure default)
    if rec.timestamp <= 0.0:
        return False, "bad_timestamp"
    # flow_end must be >= flow_start
    if rec.flow_end < rec.flow_start:
        return False, "negative_value"
    # flow_duration must be non-negative
    if rec.flow_duration < 0.0:
        return False, "negative_value"
    # byte counts must be non-negative
    if rec.fwd_byte_count < 0 or rec.rev_byte_count < 0:
        return False, "negative_value"
    # packet counts must be non-negative
    if rec.fwd_packet_count < 0 or rec.rev_packet_count < 0:
        return False, "negative_value"
    return True, None


@dataclass
class ValidationReport:
    total: int = 0
    valid: int = 0
    rejected: int = 0
    label_counts: dict = field(default_factory=dict)
    rejected_fraction: float = 0.0

    def finish(self) -> None:
        if self.total > 0:
            self.rejected_fraction = self.rejected / self.total

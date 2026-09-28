"""
dataset/stats.py
----------------
AdapterStats dataclass: tracks rejection and label distribution
across an adapter iteration. Updated in-place by adapters; exposed
as adapter.stats after iteration.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict


REJECTION_REASONS = (
    "bad_timestamp",
    "bad_numeric",
    "negative_value",
    "duplicate_header_row",
    "nan_or_inf",
    "missing_required_field",
    "duplicate_row",
)


@dataclass
class AdapterStats:
    rows_read: int = 0
    rows_yielded: int = 0
    rows_rejected: Dict[str, int] = field(
        default_factory=lambda: {r: 0 for r in REJECTION_REASONS}
    )
    distinct_labels: Counter = field(default_factory=Counter)

    def reject(self, reason: str) -> None:
        """Record a rejected row. reason must be one of REJECTION_REASONS."""
        if reason not in self.rows_rejected:
            self.rows_rejected[reason] = 0
        self.rows_rejected[reason] += 1

    @property
    def total_rejected(self) -> int:
        return sum(self.rows_rejected.values())

    @property
    def rejected_fraction(self) -> float:
        if self.rows_read == 0:
            return 0.0
        return self.total_rejected / self.rows_read

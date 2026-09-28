"""
dataset/record_aggregator.py
-----------------------------
RecordWindowAggregator: computes src_ip_* context features from
IP-bearing records (e.g., CTU-13) using the same sliding-window
definitions as Phase 6.

DESIGN:
- Keyed by src_ip.
- For each src_ip, tracks flows starting in (t-W, t] where t = current
  record's flow_start.
- Features: src_ip_flow_count, src_ip_unique_dst_ips, src_ip_unique_dst_ports
  — identical definitions to processing/features.py (snapshot-window context).
- Requires records in non-decreasing flow_start order; raises if violated.
- Bounded memory: per-source deques evict flows outside the window horizon.
- feature_source is set to 'record_aggregated' on updated records.

NOTE: This is a record-level approximation of the packet-window definition.
      When both paths are available on the same synthetic flows (Stage 4),
      a consistency test quantifies the difference.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple

from dataset.schema import UnifiedFeatureRecord


@dataclass
class _FlowEntry:
    flow_start: float
    dst_ip: Optional[str]
    dst_port: Optional[int]


class RecordWindowAggregator:
    """
    Streaming aggregator that computes src-IP context features over
    a sliding window of records.

    Usage:
        agg = RecordWindowAggregator(window=10.0)
        for rec in adapter:
            rec_with_ctx = agg.update(rec)
            ...
    """

    def __init__(self, window: float = 10.0) -> None:
        if window <= 0:
            raise ValueError("window must be positive")
        self.window = window
        # Maps src_ip -> deque of _FlowEntry within the window
        self._buckets: Dict[str, Deque[_FlowEntry]] = {}
        self._last_ts: Optional[float] = None

    def update(self, rec: UnifiedFeatureRecord) -> UnifiedFeatureRecord:
        """
        Update aggregator state with this record, then set src_ip_*
        features on the record in-place (mutating).

        Raises ValueError if rec.flow_start < previous flow_start
        (non-decreasing requirement).

        Returns the (mutated) record.
        """
        ts = rec.flow_start

        if self._last_ts is not None and ts < self._last_ts:
            raise ValueError(
                f"RecordWindowAggregator requires non-decreasing flow_start; "
                f"got {ts} < {self._last_ts}"
            )
        self._last_ts = ts

        src = rec.src_ip
        if not src:
            # No src_ip → cannot compute context; leave as None
            return rec

        if src not in self._buckets:
            self._buckets[src] = deque()

        bucket = self._buckets[src]

        # Add this flow to the bucket
        bucket.append(_FlowEntry(
            flow_start=ts,
            dst_ip=rec.dst_ip,
            dst_port=rec.dst_port,
        ))

        # Evict flows outside window (flow_start <= ts - window)
        cutoff = ts - self.window
        while bucket and bucket[0].flow_start <= cutoff:
            bucket.popleft()

        # Compute features from current window
        unique_dsts: set = set()
        unique_ports: set = set()
        for entry in bucket:
            if entry.dst_ip:
                unique_dsts.add(entry.dst_ip)
            if entry.dst_port is not None:
                unique_ports.add(entry.dst_port)

        rec.src_ip_flow_count = float(len(bucket))
        rec.src_ip_unique_dst_ips = float(len(unique_dsts))
        rec.src_ip_unique_dst_ports = float(len(unique_ports))
        rec.feature_source = "record_aggregated"
        return rec

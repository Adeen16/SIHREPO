"""
detection/candidates.py
-----------------------
Shared data structures produced by the detection pipeline.

Detection → raw candidate from a single window
Incident  → merged consecutive-window detections (hysteresis)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class Detection:
    """
    Raw detection candidate from one window.
    All times are capture-time floats (seconds since epoch or trace start).
    """
    entity: str                  # e.g. src_ip or flow_id
    threat_class: str            # canonical CanonicalLabel name
    confidence: float            # calibrated probability [0, 1]
    is_unknown: bool = False     # True for UNKNOWN_SUSPICIOUS
    window_start: float = 0.0
    window_end: float = 0.0
    flow_id: str = ""
    flow_ids: List[str] = field(default_factory=list)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    top_features: Dict[str, float] = field(default_factory=dict)
    raw_features: Dict[str, float] = field(default_factory=dict)
    # Timing hook (wall-clock ns; 0 if not measured)
    inference_ns: int = 0


@dataclass
class Incident:
    """
    Merged incident from consecutive Detection windows for the same (entity, threat).
    """
    incident_id: str
    entity: str
    threat_class: str
    is_unknown: bool = False
    src_ip: Optional[str] = None

    first_seen: float = 0.0
    last_seen: float = 0.0
    window_count: int = 0
    max_confidence: float = 0.0
    mean_confidence: float = 0.0
    _conf_sum: float = field(default=0.0, init=False, repr=False)

    # Cumulative evidence counters (updated per window)
    unique_dst_ips: set = field(default_factory=set)
    unique_dst_ports: set = field(default_factory=set)
    total_bytes: int = 0
    flow_ids: List[str] = field(default_factory=list)

    # Last window's top features (for evidence rendering)
    top_features: Dict[str, float] = field(default_factory=dict)
    raw_features: Dict[str, float] = field(default_factory=dict)

    is_open: bool = True
    quiet_window_count: int = 0  # consecutive windows without detection

    def update(self, det: Detection) -> None:
        """Ingest a new detection window into this incident."""
        self.last_seen = det.window_end
        self.window_count += 1
        self._conf_sum += det.confidence
        self.mean_confidence = self._conf_sum / self.window_count
        self.max_confidence = max(self.max_confidence, det.confidence)
        self.quiet_window_count = 0
        if det.src_ip:
            self.src_ip = self.src_ip or det.src_ip
        if det.dst_ip:
            self.unique_dst_ips.add(det.dst_ip)
        for fid in det.flow_ids:
            if fid not in self.flow_ids:
                self.flow_ids.append(fid)
        self.top_features = det.top_features
        self.raw_features = det.raw_features

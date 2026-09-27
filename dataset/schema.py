from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

class CanonicalLabel(Enum):
    BENIGN = 0
    DDOS = 1
    C2_BEACONING = 2
    DGA_DNS_TUNNEL = 3
    ENCRYPTED_MALWARE = 4
    RECON = 5
    EXFILTRATION = 6
    UNKNOWN = -1  # For unmapped or unclassifiable dataset labels

@dataclass
class Phase6FeatureVector:
    """
    STRICT COMPLETE Phase 6 Feature Vector.
    This represents the exact 16 behavioural features produced by the Phase 3-6
    streaming pipeline. No fields are optional.
    """
    flow_duration: float
    fwd_packet_count: float
    rev_packet_count: float
    fwd_byte_count: float
    rev_byte_count: float
    fwd_bytes_per_sec: float
    rev_bytes_per_sec: float
    fwd_pkts_per_sec: float
    rev_pkts_per_sec: float
    byte_ratio: float
    is_unidirectional: float
    src_ip_flow_count: float
    src_ip_unique_dst_ips: float
    src_ip_unique_dst_ports: float
    is_tcp: float
    is_udp: float

@dataclass
class ExternalDatasetRecord:
    """
    Schema for auxiliary external datasets (CIC-IDS2018, CTU-13).
    These datasets DO NOT inherently match Phase 5 window snapshots or complete
    Phase 6 feature vectors.
    Missing/Unsupported Phase 6 mapped fields must explicitly be None.
    Dataset-specific raw features are preserved in dataset_specific_features.
    """

    # Metadata & Temporal
    timestamp: float  # Flow event time (NOT a Phase 5 window end time)
    flow_id: str
    dataset_name: str
    scenario_id: Optional[str] = None

    # Temporal extent of the source flow record
    # This is NOT a Phase 5 sliding window
    flow_duration: Optional[float] = None

    # Graph-ready fields (May be missing in some datasets like anonymized CIC)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    # Label
    label: CanonicalLabel = CanonicalLabel.UNKNOWN
    mitre_stage: Optional[str] = None
    original_label: Optional[str] = None

    # Core Phase 6 Features (Mapped ONLY when semantically equivalent)
    fwd_packet_count: Optional[float] = None
    rev_packet_count: Optional[float] = None
    fwd_byte_count: Optional[float] = None
    rev_byte_count: Optional[float] = None
    fwd_bytes_per_sec: Optional[float] = None
    rev_bytes_per_sec: Optional[float] = None
    fwd_pkts_per_sec: Optional[float] = None
    rev_pkts_per_sec: Optional[float] = None
    byte_ratio: Optional[float] = None
    is_unidirectional: Optional[float] = None
    src_ip_flow_count: Optional[float] = None
    src_ip_unique_dst_ips: Optional[float] = None
    src_ip_unique_dst_ports: Optional[float] = None
    is_tcp: Optional[float] = None
    is_udp: Optional[float] = None

    # Native dataset features preserved without forcing them into Phase 6 definitions
    dataset_specific_features: Dict[str, Any] = field(default_factory=dict)

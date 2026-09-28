"""
dataset/schema.py
-----------------
Canonical data schema for unified feature records ingested from
any data source (PCAP pipeline, CTU-13, CIC-IDS2018).

CanonicalLabel encodes the threat taxonomy for SIH 26145.
UnifiedFeatureRecord is the single row type passed between adapters,
preprocessors, and ML training code.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Dict, Any


class CanonicalLabel(IntEnum):
    BENIGN = 0
    DDOS = 1
    C2_BEACONING = 2
    DNS_DGA_TUNNEL = 3
    ENCRYPTED_MALWARE = 4
    RECON_PORT_SCAN = 5
    DATA_EXFILTRATION = 6
    UNKNOWN = -1   # out-of-scope attack (held-out for open-set evaluation)
    UNLABELED = -2  # background / truly unlabelled traffic


@dataclass
class UnifiedFeatureRecord:
    """
    One labelled row representing a flow (or entity-window aggregate)
    in a form usable by both adapters and the ML pipeline.

    Fields marked Optional are None when the source does not supply them;
    missing-because-unavailable is represented as None/NaN, never as 0.0.

    Backward-compatibility note: new optional fields with defaults may be
    added; existing fields must not be removed or renamed.
    """
    # --- Temporal ----------------------------------------------------------
    timestamp: float          # flow_start epoch seconds UTC
    flow_start: float         # alias of timestamp; always set
    flow_end: float           # flow_start + duration
    window_start: float       # = flow_start  (populated for compat)
    window_end: float         # = flow_end    (populated for compat)

    # --- Identity ----------------------------------------------------------
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  # 'tcp'|'udp'|'icmp'|'other'
    is_tcp: float = 0.0
    is_udp: float = 0.0

    # --- Phase-6 core features (16) ----------------------------------------
    flow_duration: float = 0.0
    fwd_packet_count: float = 0.0
    rev_packet_count: float = 0.0
    fwd_byte_count: float = 0.0
    rev_byte_count: float = 0.0
    fwd_bytes_per_sec: float = 0.0
    rev_bytes_per_sec: float = 0.0
    fwd_pkts_per_sec: float = 0.0
    rev_pkts_per_sec: float = 0.0
    byte_ratio: float = 0.0           # via compute_byte_ratio
    src_ip_flow_count: Optional[float] = None
    src_ip_unique_dst_ips: Optional[float] = None
    src_ip_unique_dst_ports: Optional[float] = None

    # --- Provenance / meta -------------------------------------------------
    # feature_source: how features were derived
    #   'pcap_pipeline'       — from PCAP via StreamingFeaturePipeline
    #   'record_aggregated'   — from CSV record + RecordWindowAggregator
    #   'dataset_native'      — from dataset-native columns directly
    feature_source: str = "dataset_native"

    # label_source: confidence level of the label
    #   'ground_truth'  — manually verified
    #   'weak'          — labelled by tool/heuristic; may mislabel
    #   'unlabeled'     — not labelled (background traffic)
    label_source: str = "ground_truth"

    # label_group: free-form, e.g. 'botnet_spam', 'dos_loic'
    label_group: str = ""

    # canonical label
    label: CanonicalLabel = CanonicalLabel.UNKNOWN

    # Optional extras from specific sources
    optional_features: Dict[str, Any] = field(default_factory=dict)

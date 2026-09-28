"""
ml/feature_contract.py
-----------------------
Single source of truth for the feature column ordering and preprocessing
applied to ALL data paths (PCAP pipeline + CSV adapters).

This module is intentionally free of model code — it only defines:
  FEATURE_COLUMNS   : ordered list of feature column names
  LABEL_COLUMN      : name of the target column
  LABEL_MAP         : str → int mapping (must match CanonicalLabel values)
  build_preprocessor() : returns a fitted-or-fittable sklearn Pipeline
  apply_log1p_cols  : columns where log1p is applied before scaling

ML code must always import FEATURE_COLUMNS from here.
Adapter code must always produce records whose numeric fields match these names.
"""
from __future__ import annotations
from typing import List

import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

# ---------------------------------------------------------------------------
# Feature column ordering (must match processing/features.py FEATURE_NAMES
# plus any extra columns from dataset adapters)
# ---------------------------------------------------------------------------
FEATURE_COLUMNS: List[str] = [
    # core_flow
    "flow_duration",
    "fwd_packet_count",
    "rev_packet_count",
    "total_packet_count",
    "fwd_byte_count",
    "rev_byte_count",
    "total_byte_count",
    "byte_ratio",
    # rates
    "fwd_bytes_per_sec",
    "rev_bytes_per_sec",
    "fwd_pkts_per_sec",
    "rev_pkts_per_sec",
    # tcp_flags
    "syn_count",
    "fin_count",
    "rst_count",
    "ack_count",
    "psh_count",
    # iat
    "fwd_iat_mean",
    "fwd_iat_std",
    "rev_iat_mean",
    "rev_iat_std",
    # pkt_size
    "pkt_size_mean",
    # src_context
    "src_ip_flow_count",
    "src_ip_unique_dst_ips",
    "src_ip_unique_dst_ports",
    # protocol encoding
    "is_tcp",
    "is_udp",
    # window global
    "window_total_packets",
    "window_total_bytes",
    "window_flow_count",
    "window_packets_per_sec",
]

LABEL_COLUMN = "label"

# Columns where log1p is applied before scaling (large-range, right-skewed)
LOG1P_COLS: List[str] = [
    "fwd_byte_count",
    "rev_byte_count",
    "total_byte_count",
    "fwd_bytes_per_sec",
    "rev_bytes_per_sec",
    "window_total_bytes",
    "byte_ratio",
    "fwd_pkts_per_sec",
    "rev_pkts_per_sec",
    "window_total_packets",
    "window_packets_per_sec",
    "src_ip_flow_count",
    "src_ip_unique_dst_ips",
    "src_ip_unique_dst_ports",
]

# Columns where log1p is NOT applied (already bounded or binary)
PASSTHROUGH_COLS: List[str] = [
    col for col in FEATURE_COLUMNS if col not in LOG1P_COLS
]

# ---------------------------------------------------------------------------
# Label map
# ---------------------------------------------------------------------------
from dataset.schema import CanonicalLabel

LABEL_MAP: dict = {lbl.name: lbl.value for lbl in CanonicalLabel if lbl.value >= 0}
# Produces: {'BENIGN': 0, 'DDOS': 1, 'C2_BEACONING': 2, ...}

INT_TO_LABEL: dict = {v: k for k, v in LABEL_MAP.items()}


# ---------------------------------------------------------------------------
# Log1p transformer (sklearn compatible)
# ---------------------------------------------------------------------------
from sklearn.base import BaseEstimator, TransformerMixin


class Log1pTransformer(BaseEstimator, TransformerMixin):
    """Apply log1p to specified column indices."""

    def __init__(self, col_indices: List[int]):
        self.col_indices = col_indices

    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        X = X.copy()
        if len(X.shape) == 2:
            X[:, self.col_indices] = np.log1p(X[:, self.col_indices])
        return X


def build_preprocessor() -> Pipeline:
    """
    Returns a sklearn Pipeline:
      1. SimpleImputer (median)  — fills NaN from missing src_ip_* etc.
      2. Log1pTransformer        — applies log1p to right-skewed columns
      3. StandardScaler          — zero-mean unit-variance

    Must be fitted on training data ONLY (no data leakage).
    """
    log1p_indices = [FEATURE_COLUMNS.index(c) for c in LOG1P_COLS]
    return Pipeline([
        ("impute",    SimpleImputer(strategy="median")),
        ("log1p",     Log1pTransformer(col_indices=log1p_indices)),
        ("scale",     StandardScaler()),
    ])

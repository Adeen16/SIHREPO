"""
ml/dataset_builder.py
----------------------
Builds a consolidated Parquet dataset from synthetic PCAP files.

TWO DATA PATHS:
  A) PCAP pipeline path:
     PCAP → PCAPIngestor → SlidingWindowManager → FeatureExtractor → rows
     Labels come from the scenario's .labels.json sidecar.
     Labelling by time interval: flow_start in [label.start_ts, label.end_ts].
     Flows not matching any label interval → BENIGN.

  B) Record-based path (CSV adapters):
     CSV → CICAdapter/CTUAdapter → RecordWindowAggregator → rows
     Labels already in records.

NO MIXING of feature_sources without explicit flag (--allow-mixed).

Output: datasets/processed/<split>.parquet (train / val / test)
        reports/dataset_build_report.json

Usage:
    python -m scripts.build_dataset --out datasets/processed/ [--synth datasets/synthetic/]
"""
from __future__ import annotations
import dataclasses
import json
import math
import pathlib
from typing import List, Optional, Tuple, Iterator

import numpy as np
import pandas as pd

from dataset.schema import CanonicalLabel, UnifiedFeatureRecord
from dataset.record_aggregator import RecordWindowAggregator
from ml.feature_contract import FEATURE_COLUMNS, LABEL_COLUMN


# ---------------------------------------------------------------------------
# Path A: PCAP scenario pipeline
# ---------------------------------------------------------------------------

def _label_from_intervals(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    flow_start: float,
    label_intervals: list,
) -> CanonicalLabel:
    """
    Assign label to a flow based on its src/dst IP and start time.
    Logic:
      - If ANY interval matches (time overlap + ip match) → use its threat label
      - Otherwise → BENIGN
    IP matching: if interval has src_ip set, src_ip must match.
                 if interval has dst_ip set, dst_ip must match.
                 None means "any".
    """
    for interval in label_intervals:
        start_ts = interval["start_ts"]
        end_ts   = interval["end_ts"]
        if not (start_ts <= flow_start <= end_ts):
            continue
        i_src = interval.get("src_ip")
        i_dst = interval.get("dst_ip")
        if i_src is not None and src_ip != i_src:
            continue
        if i_dst is not None and dst_ip != i_dst:
            continue
        threat_name = interval["threat"]
        try:
            return CanonicalLabel[threat_name]
        except KeyError:
            return CanonicalLabel.UNKNOWN
    return CanonicalLabel.BENIGN


def pcap_scenario_to_rows(
    pcap_path: pathlib.Path,
    window_seconds: float = 10.0,
    slide_seconds: float = 1.0,
) -> List[dict]:
    """
    Run the PCAP through the streaming pipeline.
    Returns a list of row dicts (one per flow-window pair) with features + label.
    """
    from ingestion.pcap_reader import PCAPIngestor
    from processing.window import SlidingWindowManager
    from processing.features import FeatureExtractor

    # Load label sidecar
    labels_path = pcap_path.with_suffix(".labels.json")
    label_intervals = []
    if labels_path.exists():
        sidecar = json.loads(labels_path.read_text(encoding="utf-8"))
        label_intervals = sidecar.get("label_intervals", [])

    ingestor = PCAPIngestor(str(pcap_path))
    window_mgr = SlidingWindowManager(window_seconds=window_seconds,
                                       slide_seconds=slide_seconds)
    extractor = FeatureExtractor()
    rows: List[dict] = []

    for pkt in ingestor:
        snapshots = window_mgr.add_packet(pkt)
        for snap in snapshots:
            feature_map = extractor.extract_features(snap)
            for flow_id, vec in feature_map.items():
                flow = snap.flows.get(flow_id)
                src_ip = flow.src_ip if flow else None
                dst_ip = flow.dst_ip if flow else None
                flow_start = flow.first_seen if flow else snap.window_start

                label = _label_from_intervals(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    flow_start=flow_start,
                    label_intervals=label_intervals,
                )
                row = {k: vec.get(k, 0.0) for k in FEATURE_COLUMNS}
                row[LABEL_COLUMN] = label.value
                row["label_name"] = label.name
                row["feature_source"] = "pcap_pipeline"
                row["flow_id"] = flow_id
                rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# Path B: record-based (CSV adapters)
# ---------------------------------------------------------------------------

def record_to_row(rec: UnifiedFeatureRecord) -> Optional[dict]:
    """Convert a UnifiedFeatureRecord to a feature row dict for ML."""
    if rec.label in (CanonicalLabel.UNKNOWN, CanonicalLabel.UNLABELED):
        return None  # Exclude unknown/unlabeled from supervised training
    row: dict = {}
    for col in FEATURE_COLUMNS:
        val = getattr(rec, col, None)
        row[col] = float(val) if val is not None else float("nan")
    row[LABEL_COLUMN] = rec.label.value
    row["label_name"] = rec.label.name
    row["feature_source"] = rec.feature_source
    row["flow_id"] = ""  # no flow_id in record path
    return row


# ---------------------------------------------------------------------------
# Dataset builder: loads synthetic PCAPs + optional CSV datasets
# ---------------------------------------------------------------------------

def build_from_synthetic(
    synth_dir: pathlib.Path,
    window_seconds: float = 10.0,
    slide_seconds: float = 1.0,
    verbose: bool = True,
) -> pd.DataFrame:
    """
    Process all *.pcap files in synth_dir through the PCAP pipeline.
    Returns a DataFrame with features + label.
    """
    all_rows: List[dict] = []
    pcaps = sorted(synth_dir.glob("*.pcap"))
    if not pcaps:
        raise FileNotFoundError(f"No PCAP files in {synth_dir}")

    for pcap in pcaps:
        if verbose:
            print(f"  Processing {pcap.name}...", end="", flush=True)
        rows = pcap_scenario_to_rows(pcap, window_seconds, slide_seconds)
        all_rows.extend(rows)
        if verbose:
            print(f" {len(rows)} rows")

    df = pd.DataFrame(all_rows)
    return df


# ---------------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------------

def temporal_split(
    df: pd.DataFrame,
    val_frac: float = 0.10,
    test_frac: float = 0.15,
    seed: int = 1337,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Stratified random split.
    Note: for PCAP data a temporal split would require timestamp sorting;
    since synthetic data timestamps start at 0 per scenario, we use stratified
    random split instead. This is documented.
    """
    from sklearn.model_selection import train_test_split
    test_frac_of_all = test_frac
    val_frac_of_trainval = val_frac / (1 - test_frac_of_all)

    y = df[LABEL_COLUMN]
    df_trainval, df_test = train_test_split(
        df, test_size=test_frac_of_all, stratify=y, random_state=seed
    )
    y_tv = df_trainval[LABEL_COLUMN]
    df_train, df_val = train_test_split(
        df_trainval, test_size=val_frac_of_trainval, stratify=y_tv, random_state=seed
    )
    return df_train, df_val, df_test


# ---------------------------------------------------------------------------
# Baseline stats report
# ---------------------------------------------------------------------------

def label_distribution(df: pd.DataFrame) -> dict:
    """Return {label_name: count} dict."""
    return df.groupby("label_name").size().to_dict()


def baseline_report(df_train: pd.DataFrame, df_val: pd.DataFrame,
                    df_test: pd.DataFrame) -> dict:
    """Compute baseline metrics for the majority-class classifier."""
    from collections import Counter

    def majority_acc(df: pd.DataFrame) -> float:
        counts = Counter(df[LABEL_COLUMN])
        majority_n = max(counts.values())
        return majority_n / len(df)

    return {
        "train_rows": len(df_train),
        "val_rows": len(df_val),
        "test_rows": len(df_test),
        "train_label_dist": label_distribution(df_train),
        "val_label_dist": label_distribution(df_val),
        "test_label_dist": label_distribution(df_test),
        "baseline_accuracy_train": majority_acc(df_train),
        "baseline_accuracy_val": majority_acc(df_val),
        "baseline_accuracy_test": majority_acc(df_test),
        "note": (
            "Baseline = majority-class classifier. "
            "Any trained model must beat this on all splits."
        ),
    }

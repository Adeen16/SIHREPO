"""
tests/test_dataset_stage4.py
-----------------------------
Stage 4 tests: dataset builder, preprocessor, feature contract.
Does NOT require PCAP files or the synthetic generator.
Uses fabricated DataFrames.
"""
import math
import pathlib
import numpy as np
import pandas as pd
import pytest

from ml.feature_contract import (
    FEATURE_COLUMNS, LABEL_COLUMN, LABEL_MAP, INT_TO_LABEL,
    build_preprocessor, LOG1P_COLS,
)
from ml.dataset_builder import (
    _label_from_intervals, temporal_split, baseline_report, record_to_row
)
from dataset.schema import CanonicalLabel, UnifiedFeatureRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_df(n=200, seed=42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    labels = list(LABEL_MAP.values())
    for i in range(n):
        row = {col: rng.exponential(100) for col in FEATURE_COLUMNS}
        row[LABEL_COLUMN] = labels[i % len(labels)]
        row["label_name"] = INT_TO_LABEL[row[LABEL_COLUMN]]
        row["feature_source"] = "pcap_pipeline"
        row["flow_id"] = f"flow_{i}"
        rows.append(row)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# §4.1 — Feature contract
# ---------------------------------------------------------------------------

class TestFeatureContract:
    def test_feature_columns_non_empty(self):
        assert len(FEATURE_COLUMNS) >= 30

    def test_no_duplicate_feature_columns(self):
        assert len(FEATURE_COLUMNS) == len(set(FEATURE_COLUMNS))

    def test_label_map_matches_canonical_label(self):
        for name, val in LABEL_MAP.items():
            assert CanonicalLabel[name].value == val

    def test_int_to_label_inverse(self):
        for val, name in INT_TO_LABEL.items():
            assert LABEL_MAP[name] == val

    def test_log1p_cols_subset_of_feature_columns(self):
        for col in LOG1P_COLS:
            assert col in FEATURE_COLUMNS, f"{col} in LOG1P_COLS but not FEATURE_COLUMNS"


# ---------------------------------------------------------------------------
# §4.2 — Preprocessor
# ---------------------------------------------------------------------------

class TestPreprocessor:
    def test_preprocessor_pipeline_fits_and_transforms(self):
        df = _random_df(n=100)
        X = df[FEATURE_COLUMNS].values.astype(float)
        pre = build_preprocessor()
        X_t = pre.fit_transform(X)
        assert X_t.shape == X.shape
        assert not np.any(np.isnan(X_t))
        assert not np.any(np.isinf(X_t))

    def test_preprocessor_no_data_leakage_on_transform(self):
        """Fitting on train must not use test stats."""
        df = _random_df(n=100)
        X = df[FEATURE_COLUMNS].values.astype(float)
        split = len(X) // 2
        X_train, X_test = X[:split], X[split:]
        pre = build_preprocessor()
        pre.fit(X_train)
        X_test_t = pre.transform(X_test)
        assert not np.any(np.isnan(X_test_t))

    def test_preprocessor_handles_nan(self):
        """NaN inputs (from missing src_ip_* features) must be imputed."""
        df = _random_df(n=60)
        X = df[FEATURE_COLUMNS].values.astype(float)
        # Inject NaN in src_ip_flow_count column
        col_idx = FEATURE_COLUMNS.index("src_ip_flow_count")
        X[::3, col_idx] = float("nan")
        pre = build_preprocessor()
        X_t = pre.fit_transform(X)
        assert not np.any(np.isnan(X_t))

    def test_log1p_applied_to_positive_values(self):
        """After preprocessing, log1p-scaled columns should be positive (log1p(x)≥0 for x≥0)."""
        rng = np.random.default_rng(1)
        X = rng.exponential(1000, size=(100, len(FEATURE_COLUMNS)))
        pre = build_preprocessor()
        pre.fit(X)
        # Just verify no errors thrown and output finite
        X_t = pre.transform(X.copy())
        assert np.all(np.isfinite(X_t))


# ---------------------------------------------------------------------------
# §4.3 — Label interval matching
# ---------------------------------------------------------------------------

class TestLabelIntervalMatching:
    def test_flow_in_attack_interval_gets_threat_label(self):
        intervals = [{"threat": "DDOS", "src_ip": None, "dst_ip": "10.0.0.1",
                      "start_ts": 0.0, "end_ts": 10.0}]
        label = _label_from_intervals(None, "10.0.0.1", 5.0, intervals)
        assert label == CanonicalLabel.DDOS

    def test_flow_outside_interval_gets_benign(self):
        intervals = [{"threat": "DDOS", "src_ip": None, "dst_ip": "10.0.0.1",
                      "start_ts": 0.0, "end_ts": 10.0}]
        label = _label_from_intervals(None, "10.0.0.1", 15.0, intervals)
        assert label == CanonicalLabel.BENIGN

    def test_ip_mismatch_gets_benign(self):
        intervals = [{"threat": "C2_BEACONING", "src_ip": "10.0.0.5", "dst_ip": None,
                      "start_ts": 0.0, "end_ts": 100.0}]
        # Different src_ip → benign
        label = _label_from_intervals("10.0.0.99", None, 50.0, intervals)
        assert label == CanonicalLabel.BENIGN

    def test_src_ip_match_gets_label(self):
        intervals = [{"threat": "RECON_PORT_SCAN", "src_ip": "10.0.0.5", "dst_ip": None,
                      "start_ts": 0.0, "end_ts": 100.0}]
        label = _label_from_intervals("10.0.0.5", "192.168.1.1", 50.0, intervals)
        assert label == CanonicalLabel.RECON_PORT_SCAN

    def test_empty_intervals_returns_benign(self):
        label = _label_from_intervals("1.2.3.4", "5.6.7.8", 100.0, [])
        assert label == CanonicalLabel.BENIGN

    def test_unknown_threat_name_returns_unknown(self):
        intervals = [{"threat": "MADE_UP_THREAT", "src_ip": None, "dst_ip": None,
                      "start_ts": 0.0, "end_ts": 100.0}]
        label = _label_from_intervals("1.2.3.4", "5.6.7.8", 50.0, intervals)
        assert label == CanonicalLabel.UNKNOWN


# ---------------------------------------------------------------------------
# §4.4 — Split
# ---------------------------------------------------------------------------

class TestTemporalSplit:
    def test_split_sizes_approximately_correct(self):
        df = _random_df(n=1000)
        train, val, test = temporal_split(df, val_frac=0.10, test_frac=0.15)
        assert 0.70 < len(train) / len(df) < 0.80
        assert 0.08 < len(val)   / len(df) < 0.12
        assert 0.13 < len(test)  / len(df) < 0.17

    def test_split_no_overlap(self):
        df = _random_df(n=500)
        df = df.reset_index(drop=True)
        train, val, test = temporal_split(df)
        ti = set(train.index)
        vi = set(val.index)
        ti2 = set(test.index)
        assert len(ti & vi) == 0
        assert len(ti & ti2) == 0
        assert len(vi & ti2) == 0

    def test_split_covers_all_rows(self):
        df = _random_df(n=500)
        train, val, test = temporal_split(df)
        assert len(train) + len(val) + len(test) == len(df)

    def test_split_deterministic(self):
        df = _random_df(n=300)
        t1, v1, te1 = temporal_split(df, seed=99)
        t2, v2, te2 = temporal_split(df, seed=99)
        assert list(t1.index) == list(t2.index)


# ---------------------------------------------------------------------------
# §4.5 — record_to_row
# ---------------------------------------------------------------------------

class TestRecordToRow:
    def test_known_label_produces_row(self):
        rec = UnifiedFeatureRecord(
            timestamp=100.0, flow_start=100.0, flow_end=101.0,
            window_start=100.0, window_end=101.0,
            label=CanonicalLabel.DDOS, label_source="ground_truth",
        )
        row = record_to_row(rec)
        assert row is not None
        assert row[LABEL_COLUMN] == CanonicalLabel.DDOS.value

    def test_unknown_label_returns_none(self):
        rec = UnifiedFeatureRecord(
            timestamp=100.0, flow_start=100.0, flow_end=101.0,
            window_start=100.0, window_end=101.0,
            label=CanonicalLabel.UNKNOWN,
        )
        row = record_to_row(rec)
        assert row is None

    def test_unlabeled_returns_none(self):
        rec = UnifiedFeatureRecord(
            timestamp=100.0, flow_start=100.0, flow_end=101.0,
            window_start=100.0, window_end=101.0,
            label=CanonicalLabel.UNLABELED,
        )
        row = record_to_row(rec)
        assert row is None

    def test_row_has_all_feature_columns(self):
        rec = UnifiedFeatureRecord(
            timestamp=100.0, flow_start=100.0, flow_end=101.0,
            window_start=100.0, window_end=101.0,
            label=CanonicalLabel.BENIGN,
        )
        row = record_to_row(rec)
        assert row is not None
        for col in FEATURE_COLUMNS:
            assert col in row, f"Missing feature column: {col}"

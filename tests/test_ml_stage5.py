"""
tests/test_ml_stage5.py
------------------------
Stage 5 tests for the ML training pipeline.
Uses tiny in-memory DataFrames to avoid needing PCAP or dataset files.
"""
import json
import math
import pathlib
import tempfile

import numpy as np
import pandas as pd
import pytest

from ml.feature_contract import (
    FEATURE_COLUMNS, LABEL_COLUMN, INT_TO_LABEL, LABEL_MAP, build_preprocessor
)
from ml.train import (
    to_arrays, evaluate, get_feature_importance, compute_threshold_map,
    _rf_model, _hgb_model,
)
from dataset.schema import CanonicalLabel


# ---------------------------------------------------------------------------
# Shared fixture: tiny training DataFrame
# ---------------------------------------------------------------------------

N_CLASSES = 4
_CLASSES_USED = [
    CanonicalLabel.BENIGN.value,
    CanonicalLabel.DDOS.value,
    CanonicalLabel.C2_BEACONING.value,
    CanonicalLabel.RECON_PORT_SCAN.value,
]


def _make_df(n=300, seed=42) -> pd.DataFrame:
    """Create a tiny labelled DataFrame with 4 classes."""
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        cls = _CLASSES_USED[i % N_CLASSES]
        row = {col: rng.exponential(1.0) for col in FEATURE_COLUMNS}
        # Make DDoS stand out on packet rate (class-conditional signal)
        if cls == CanonicalLabel.DDOS.value:
            row["window_packets_per_sec"] = rng.exponential(500)
            row["syn_count"] = rng.exponential(100)
        elif cls == CanonicalLabel.RECON_PORT_SCAN.value:
            row["src_ip_unique_dst_ports"] = rng.exponential(50)
        row[LABEL_COLUMN] = cls
        row["label_name"] = INT_TO_LABEL[cls]
        row["feature_source"] = "pcap_pipeline"
        row["flow_id"] = f"f{i}"
        rows.append(row)
    return pd.DataFrame(rows)


@pytest.fixture(scope="module")
def tiny_dataset():
    """Returns train, val, test DataFrames."""
    from ml.dataset_builder import temporal_split
    df = _make_df(n=400)
    return temporal_split(df, val_frac=0.10, test_frac=0.15, seed=1)


@pytest.fixture(scope="module")
def fitted_rf(tiny_dataset):
    """Return a fitted Random Forest."""
    df_train, df_val, df_test = tiny_dataset
    X_train, y_train = to_arrays(df_train)
    pre = build_preprocessor()
    X_pp = pre.fit_transform(X_train)
    model = _rf_model(seed=1)
    model.fit(X_pp, y_train)
    return model, pre, df_train, df_val, df_test


# ---------------------------------------------------------------------------
# §5.1 — to_arrays
# ---------------------------------------------------------------------------

class TestToArrays:
    def test_output_shapes(self):
        df = _make_df(n=50)
        X, y = to_arrays(df)
        assert X.shape == (50, len(FEATURE_COLUMNS))
        assert y.shape == (50,)

    def test_no_nan_in_X(self):
        df = _make_df(n=50)
        X, _ = to_arrays(df)
        assert not np.any(np.isnan(X))

    def test_y_values_are_label_ints(self):
        df = _make_df(n=50)
        _, y = to_arrays(df)
        valid = set(LABEL_MAP.values())
        for v in y:
            assert int(v) in valid


# ---------------------------------------------------------------------------
# §5.2 — Evaluate
# ---------------------------------------------------------------------------

class TestEvaluate:
    def test_evaluate_returns_required_keys(self, fitted_rf):
        model, pre, _, df_val, _ = fitted_rf
        X_val, y_val = to_arrays(df_val)
        X_pp = pre.transform(X_val)
        result = evaluate(model, X_pp, y_val, "val")
        required = {"split", "n_samples", "accuracy", "macro_f1",
                    "macro_precision", "macro_recall", "per_class",
                    "confusion_matrix", "confusion_labels"}
        assert required <= set(result.keys())

    def test_evaluate_accuracy_in_range(self, fitted_rf):
        model, pre, _, df_val, _ = fitted_rf
        X_val, y_val = to_arrays(df_val)
        X_pp = pre.transform(X_val)
        result = evaluate(model, X_pp, y_val, "val")
        assert 0.0 <= result["accuracy"] <= 1.0

    def test_evaluate_f1_is_float(self, fitted_rf):
        model, pre, _, df_val, _ = fitted_rf
        X_val, y_val = to_arrays(df_val)
        X_pp = pre.transform(X_val)
        result = evaluate(model, X_pp, y_val, "val")
        assert isinstance(result["macro_f1"], float)
        assert math.isfinite(result["macro_f1"])

    def test_evaluate_n_samples_matches(self, fitted_rf):
        model, pre, _, df_val, _ = fitted_rf
        X_val, y_val = to_arrays(df_val)
        X_pp = pre.transform(X_val)
        result = evaluate(model, X_pp, y_val, "val")
        assert result["n_samples"] == len(y_val)


# ---------------------------------------------------------------------------
# §5.3 — Feature importance
# ---------------------------------------------------------------------------

class TestFeatureImportance:
    def test_feature_importance_returns_list(self, fitted_rf):
        model, _, _, _, _ = fitted_rf
        fi = get_feature_importance(model, top_n=10)
        assert isinstance(fi, list)
        assert len(fi) <= 10

    def test_feature_importance_sorted_descending(self, fitted_rf):
        model, _, _, _, _ = fitted_rf
        fi = get_feature_importance(model, top_n=20)
        values = [entry["importance"] for entry in fi]
        assert values == sorted(values, reverse=True)

    def test_feature_names_in_contract(self, fitted_rf):
        model, _, _, _, _ = fitted_rf
        fi = get_feature_importance(model, top_n=20)
        for entry in fi:
            assert entry["feature"] in FEATURE_COLUMNS


# ---------------------------------------------------------------------------
# §5.4 — Threshold map
# ---------------------------------------------------------------------------

class TestThresholdMap:
    def test_all_classes_have_threshold(self, fitted_rf):
        model, pre, _, df_val, _ = fitted_rf
        X_val, y_val = to_arrays(df_val)
        X_pp = pre.transform(X_val)
        tm = compute_threshold_map(model, X_pp, y_val)
        assert isinstance(tm, dict)
        for cls_name, threshold in tm.items():
            assert 0.0 <= threshold <= 1.0, f"{cls_name}: {threshold} out of range"

    def test_thresholds_are_floats(self, fitted_rf):
        model, pre, _, df_val, _ = fitted_rf
        X_val, y_val = to_arrays(df_val)
        X_pp = pre.transform(X_val)
        tm = compute_threshold_map(model, X_pp, y_val)
        for val in tm.values():
            assert isinstance(val, float)


# ---------------------------------------------------------------------------
# §5.5 — End-to-end training run (tiny, fast)
# ---------------------------------------------------------------------------

class TestEndToEndTraining:
    def test_train_produces_artefacts(self, tmp_path):
        """Full training run on tiny DataFrame must produce all artefact files."""
        from ml.dataset_builder import temporal_split

        # Write tiny parquet splits
        df = _make_df(n=300)
        train, val, test = temporal_split(df, seed=2)
        for name, split in [("train", train), ("val", val), ("test", test)]:
            split.to_parquet(str(tmp_path / f"{name}.parquet"), index=False)

        from ml.train import train_and_evaluate
        models_dir = tmp_path / "models"
        report = train_and_evaluate(
            processed_dir=tmp_path,
            models_dir=models_dir,
            seed=1,
        )

        # Artefacts exist
        assert (models_dir / "best_classifier.joblib").exists()
        assert (models_dir / "training_report.json").exists()
        assert (models_dir / "threshold_map.json").exists()
        assert (models_dir / "feature_importance.json").exists()

    def test_training_report_keys(self, tmp_path):
        from ml.dataset_builder import temporal_split
        from ml.train import train_and_evaluate

        df = _make_df(n=300)
        train, val, test = temporal_split(df, seed=3)
        for name, split in [("train", train), ("val", val), ("test", test)]:
            split.to_parquet(str(tmp_path / f"{name}.parquet"), index=False)

        report = train_and_evaluate(tmp_path, tmp_path / "models", seed=2)

        required = {"best_model", "val_macro_f1", "test_metrics", "all_candidates"}
        assert required <= set(report.keys())
        assert "macro_f1" in report["test_metrics"]
        assert "accuracy" in report["test_metrics"]

    def test_saved_model_loads_and_predicts(self, tmp_path):
        """Model loaded from disk must produce predictions without errors."""
        import joblib
        from ml.dataset_builder import temporal_split
        from ml.train import train_and_evaluate

        df = _make_df(n=300)
        train, val, test = temporal_split(df, seed=4)
        for name, split in [("train", train), ("val", val), ("test", test)]:
            split.to_parquet(str(tmp_path / f"{name}.parquet"), index=False)

        train_and_evaluate(tmp_path, tmp_path / "models", seed=3)
        bundle = joblib.load(str(tmp_path / "models" / "best_classifier.joblib"))

        X_test, y_test = to_arrays(test)
        X_pp = bundle["preprocessor"].transform(X_test)
        preds = bundle["classifier"].predict(X_pp)
        assert len(preds) == len(y_test)
        # All predictions must be valid label integers
        valid = set(LABEL_MAP.values())
        for p in preds:
            assert int(p) in valid

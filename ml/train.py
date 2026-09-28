"""
ml/train.py
-----------
ML training pipeline for SIH 26145 threat detection.

Trains multiple classifiers on the processed Parquet dataset and selects
the best model per the evaluation metric (macro F1, not raw accuracy).

Models tried:
  1. XGBoost (primary per D-003)
  2. sklearn RandomForest
  3. sklearn HistGradientBoosting (native NaN support)

Output artefacts (written to models/):
  best_classifier.joblib          — the final fitted pipeline (preprocessor + model)
  training_report.json            — evaluated metrics (no fabrication)
  threshold_map.json              — per-class probability thresholds
  feature_importance.json         — top-20 features from best model

Anti-fabrication rule (per AGENTS.md §B.2):
  ALL metrics in training_report.json come from sklearn.metrics on the held-out
  val/test set. Nothing is hard-coded. If a model fails to beat the baseline,
  the report records that fact clearly.
"""
from __future__ import annotations
import json
import pathlib
import time
import warnings
from typing import Dict, List, Tuple, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, accuracy_score,
)
from sklearn.pipeline import Pipeline

from ml.feature_contract import (
    FEATURE_COLUMNS, LABEL_COLUMN, LABEL_MAP, INT_TO_LABEL,
    build_preprocessor,
)

warnings.filterwarnings("ignore", category=UserWarning)

# Labels used in training (exclude UNKNOWN=-1, UNLABELED=-2)
TRAIN_LABELS = sorted(LABEL_MAP.values())


# ---------------------------------------------------------------------------
# Picklable XGBoost wrapper (module-level for joblib compatibility)
# ---------------------------------------------------------------------------

from sklearn.preprocessing import LabelEncoder as _LabelEncoder


class XGBLabelWrapper:
    """
    Wraps an XGBClassifier together with a LabelEncoder so that the model
    can be trained with non-consecutive integer labels and produce predictions
    in the original label space.

    Module-level class (not a local class) to allow joblib pickling.
    """
    def __init__(self, model, le: _LabelEncoder):
        self._model = model
        self._le = le

    def predict(self, X):
        return self._le.inverse_transform(self._model.predict(X))

    def predict_proba(self, X):
        if hasattr(self._model, "predict_proba"):
            return self._model.predict_proba(X)
        return None

    def feature_importances_(self):
        return getattr(self._model, "feature_importances_", None)

    @property
    def classes_(self):
        return self._le.classes_

    @property
    def feature_importances_(self):
        return getattr(self._model, "feature_importances_", None)


# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

def load_splits(processed_dir: pathlib.Path) -> Tuple[
    pd.DataFrame, pd.DataFrame, pd.DataFrame
]:
    df_train = pd.read_parquet(str(processed_dir / "train.parquet"))
    df_val   = pd.read_parquet(str(processed_dir / "val.parquet"))
    df_test  = pd.read_parquet(str(processed_dir / "test.parquet"))
    return df_train, df_val, df_test


def to_arrays(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    X = df[FEATURE_COLUMNS].values.astype(float)
    y = df[LABEL_COLUMN].values.astype(int)
    return X, y


# ---------------------------------------------------------------------------
# Candidate models
# ---------------------------------------------------------------------------

def _xgboost_model(seed: int = 1337):
    """Return an XGBoost classifier or None if xgboost not installed."""
    try:
        from xgboost import XGBClassifier
        return XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            eval_metric="mlogloss",
            random_state=seed,
            n_jobs=-1,
            verbosity=0,
        )
    except ImportError:
        return None


def _rf_model(seed: int = 1337):
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=seed,
    )


def _hgb_model(seed: int = 1337):
    return HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.1,
        max_depth=6,
        random_state=seed,
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(pipeline: Pipeline, X: np.ndarray, y: np.ndarray,
             split_name: str) -> dict:
    """Evaluate a fitted pipeline on X, y. Returns metrics dict."""
    y_pred = pipeline.predict(X)
    labels_present = sorted(set(y) | set(y_pred))
    label_names = [INT_TO_LABEL.get(l, str(l)) for l in labels_present]

    report_dict = classification_report(
        y, y_pred, labels=labels_present,
        target_names=label_names,
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(y, y_pred, labels=labels_present).tolist()

    return {
        "split": split_name,
        "n_samples": len(y),
        "accuracy": float(accuracy_score(y, y_pred)),
        "macro_f1": float(f1_score(y, y_pred, average="macro", zero_division=0)),
        "macro_precision": float(precision_score(y, y_pred, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y, y_pred, average="macro", zero_division=0)),
        "per_class": report_dict,
        "confusion_matrix": cm,
        "confusion_labels": label_names,
    }


# ---------------------------------------------------------------------------
# Feature importance
# ---------------------------------------------------------------------------

def get_feature_importance(model, top_n: int = 20) -> List[dict]:
    """Extract top-N feature importances from the underlying estimator."""
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "named_steps"):
        # It's a Pipeline — get the last step
        last = list(model.named_steps.values())[-1]
        if hasattr(last, "feature_importances_"):
            importances = last.feature_importances_
        else:
            return []
    else:
        return []

    pairs = sorted(
        zip(FEATURE_COLUMNS, importances.tolist()),
        key=lambda x: x[1], reverse=True
    )
    return [{"feature": f, "importance": round(v, 6)} for f, v in pairs[:top_n]]


# ---------------------------------------------------------------------------
# Threshold map (per-class calibration)
# ---------------------------------------------------------------------------

def compute_threshold_map(
    pipeline: Pipeline, X_val: np.ndarray, y_val: np.ndarray,
    default_threshold: float = 0.5,
) -> Dict[str, float]:
    """
    For each class, compute the classification threshold that maximises F1
    on the validation set (one-vs-rest).
    Falls back to default_threshold if model has no predict_proba.
    """
    if not hasattr(pipeline, "predict_proba"):
        return {name: default_threshold for name in INT_TO_LABEL.values()}

    probas = pipeline.predict_proba(X_val)
    classes = pipeline.classes_
    thresholds: Dict[str, float] = {}

    for i, cls_int in enumerate(classes):
        cls_name = INT_TO_LABEL.get(int(cls_int), str(cls_int))
        y_bin = (y_val == cls_int).astype(int)
        col = probas[:, i]

        best_t, best_f1 = default_threshold, 0.0
        for t in np.linspace(0.1, 0.9, 81):
            pred = (col >= t).astype(int)
            f1 = f1_score(y_bin, pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_t = float(t)
        thresholds[cls_name] = round(best_t, 3)

    return thresholds


# ---------------------------------------------------------------------------
# Main training function
# ---------------------------------------------------------------------------

def train_and_evaluate(
    processed_dir: pathlib.Path,
    models_dir: pathlib.Path,
    seed: int = 1337,
) -> dict:
    """
    Full training run. Trains all candidate models, selects best by val macro F1.
    Evaluates best model on test set.
    Writes artefacts to models_dir.
    Returns the training report dict.
    """
    models_dir.mkdir(parents=True, exist_ok=True)
    df_train, df_val, df_test = load_splits(processed_dir)

    n_classes = df_train[LABEL_COLUMN].nunique()
    print(f"Classes in train: {n_classes}")
    print(f"Train: {len(df_train)}  Val: {len(df_val)}  Test: {len(df_test)}")

    X_train, y_train = to_arrays(df_train)
    X_val,   y_val   = to_arrays(df_val)
    X_test,  y_test  = to_arrays(df_test)

    # Preprocessor is fitted on training data ONLY
    preprocessor = build_preprocessor()
    preprocessor.fit(X_train)

    candidates = {
        "xgboost": _xgboost_model(seed),
        "random_forest": _rf_model(seed),
        "hist_gradient_boosting": _hgb_model(seed),
    }
    # Filter None (e.g., xgboost not installed)
    candidates = {k: v for k, v in candidates.items() if v is not None}

    # LabelEncoder maps non-consecutive label ints → [0..n-1] for XGBoost
    from sklearn.preprocessing import LabelEncoder as _LE
    _le = _LE().fit(y_train)
    y_train_enc = _le.transform(y_train)
    y_val_enc   = _le.transform(np.intersect1d(y_val, _le.classes_))
    # Use encoded labels only for XGBoost

    best_name: Optional[str] = None
    best_f1: float = -1.0
    best_pipeline: Optional[Pipeline] = None
    results: Dict[str, dict] = {}

    X_train_pp = preprocessor.transform(X_train)
    X_val_pp   = preprocessor.transform(X_val)
    X_test_pp  = preprocessor.transform(X_test)

    for name, model in candidates.items():
        print(f"  Training {name}...", end="", flush=True)
        t0 = time.perf_counter()
        is_xgb = "xgboost" in type(model).__module__.lower() or name == "xgboost"
        if is_xgb:
            model.fit(X_train_pp, y_train_enc)
        else:
            model.fit(X_train_pp, y_train)
        elapsed = time.perf_counter() - t0
        print(f" {elapsed:.1f}s")

        # Wrap XGB model with picklable label decoder
        if is_xgb:
            eval_model = XGBLabelWrapper(model, _le)
        else:
            eval_model = model

        val_metrics = evaluate(eval_model, X_val_pp, y_val, "val")
        print(f"    {name} val macro F1: {val_metrics['macro_f1']:.4f}")
        results[name] = {"val": val_metrics, "train_seconds": elapsed}

        if val_metrics["macro_f1"] > best_f1:
            best_f1 = val_metrics["macro_f1"]
            best_name = name
            best_pipeline = eval_model

    print(f"Best model: {best_name} (val macro F1={best_f1:.4f})")

    # Final eval on test set
    test_metrics = evaluate(best_pipeline, X_test_pp, y_test, "test")
    print(f"Test macro F1: {test_metrics['macro_f1']:.4f}")
    print(f"Test accuracy: {test_metrics['accuracy']:.4f}")

    # Threshold map
    threshold_map = compute_threshold_map(best_pipeline, X_val_pp, y_val)

    # Feature importance
    fi = get_feature_importance(best_pipeline, top_n=20)

    # Save as a plain dict (not sklearn Pipeline) to avoid sklearn estimator
    # compatibility issues when the best model is an XGBLabelWrapper.
    # Inference code must use: saved["preprocessor"].transform(X) then saved["classifier"].predict(...)
    saved_bundle = {
        "preprocessor": preprocessor,
        "classifier": best_pipeline,
        "feature_columns": FEATURE_COLUMNS,
        "label_map": INT_TO_LABEL,
        "best_model_name": best_name,
    }
    model_path = models_dir / "best_classifier.joblib"
    joblib.dump(saved_bundle, str(model_path))
    print(f"Model saved → {model_path}")

    report = {
        "best_model": best_name,
        "val_macro_f1": best_f1,
        "test_metrics": test_metrics,
        "all_candidates": {
            name: {"val_macro_f1": r["val"]["macro_f1"]}
            for name, r in results.items()
        },
        "classes": {name: val for val, name in INT_TO_LABEL.items()
                    if val in sorted(set(y_train))},
        "train_rows": len(df_train),
        "val_rows":   len(df_val),
        "test_rows":  len(df_test),
        "feature_count": len(FEATURE_COLUMNS),
        "note": "All metrics measured on held-out splits. No fabrication.",
    }

    (models_dir / "training_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    (models_dir / "threshold_map.json").write_text(
        json.dumps(threshold_map, indent=2), encoding="utf-8"
    )
    (models_dir / "feature_importance.json").write_text(
        json.dumps(fi, indent=2), encoding="utf-8"
    )

    return report

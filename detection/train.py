import os
import json
import logging
from typing import List, Tuple, Dict
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
SKLEARN_AVAILABLE = True
import joblib

from dataset.cic_adapter import CICIDS2018Adapter
from dataset.schema import ExternalDatasetRecord
from detection.baseline_config import Phase8FeatureConfig
from detection.preprocessing import FeaturePreprocessor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def split_random_stratified(records: List[ExternalDatasetRecord]) -> Tuple[List[ExternalDatasetRecord], List[ExternalDatasetRecord], List[ExternalDatasetRecord]]:
    """Standard Baseline: Deterministic Random Stratified Split."""
    labels = [r.label.value for r in records]

    train_val, test, y_train_val, y_test = train_test_split(
        records, labels, test_size=0.15, random_state=42, stratify=labels
    )
    train, val, y_train, y_val = train_test_split(
        train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val # 0.1765 of 0.85 approx 0.15 of total
    )
    return train, val, test

def split_chronological(records: List[ExternalDatasetRecord]) -> Tuple[List[ExternalDatasetRecord], List[ExternalDatasetRecord], List[ExternalDatasetRecord]]:
    """Chronological Temporal Generalization Split."""
    records_sorted = sorted(records, key=lambda x: x.timestamp)
    n = len(records_sorted)
    train_end = int(n * 0.70)
    val_end = train_end + int(n * 0.15)
    return records_sorted[:train_end], records_sorted[train_end:val_end], records_sorted[val_end:]

def split_scenario_holdout(records: List[ExternalDatasetRecord], holdout_scenario="DoS attacks-SlowHTTPTest") -> Tuple[List[ExternalDatasetRecord], List[ExternalDatasetRecord], List[ExternalDatasetRecord]]:
    """
    Scenario Holdout: Hold out SlowHTTPTest (and proportional benign) for test set.
    """
    train_val_recs = []
    test_recs = []

    for r in records:
        if holdout_scenario.lower() in r.original_label.lower():
            test_recs.append(r)
        else:
            train_val_recs.append(r)

    # Add some Benign to the test set for realism (20% of benign goes to test)
    benign_recs = [r for r in train_val_recs if r.label.value == 0]
    attack_recs = [r for r in train_val_recs if r.label.value != 0]

    benign_train_val, benign_test = train_test_split(benign_recs, test_size=0.20, random_state=42)
    test_recs.extend(benign_test)
    train_val_recs = attack_recs + benign_train_val

    # Split remaining into train/val
    train_recs, val_recs = train_test_split(train_val_recs, test_size=0.15, random_state=42)

    return train_recs, val_recs, test_recs

def evaluate_split(split_name: str, train_recs: List[ExternalDatasetRecord], val_recs: List[ExternalDatasetRecord], test_recs: List[ExternalDatasetRecord], output_dir: str):
    logger.info(f"--- Running Evaluation: {split_name} ---")
    logger.info(f"Split sizes - Train: {len(train_recs)}, Val: {len(val_recs)}, Test: {len(test_recs)}")

    preprocessor = FeaturePreprocessor()
    X_train, y_train, _ = preprocessor.extract_dataset(train_recs)
    X_test, y_test, _ = preprocessor.extract_dataset(test_recs)

    preprocessor.fit(X_train)
    X_train_scaled = preprocessor.transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)

    split_dir = os.path.join(output_dir, split_name)
    os.makedirs(split_dir, exist_ok=True)

    models = {
        "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'),
        "RandomForest": RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1, class_weight='balanced')
    }

    results = {}
    for model_name, model in models.items():
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)

        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()

        results[model_name] = {
            "accuracy": acc,
            "classification_report": report,
            "confusion_matrix": cm
        }
        joblib.dump(model, os.path.join(split_dir, f"{model_name}.joblib"))

    with open(os.path.join(split_dir, "metrics.json"), "w") as f:
        json.dump(results, f, indent=4)

    logger.info(f"Completed {split_name}")
    return results

def run_all_evaluations(dataset_path: str, output_dir: str):
    adapter = CICIDS2018Adapter("CIC-IDS2018", dataset_path)

    all_records = []
    for rec in adapter.get_records():
        if rec.label.value >= 0:
            preprocessor = FeaturePreprocessor()
            if preprocessor.extract_features(rec) is not None:
                all_records.append(rec)

    logger.info(f"Loaded {len(all_records)} valid records.")

    # 1. Random/Stratified (Standard Baseline)
    tr, va, te = split_random_stratified(all_records.copy())
    evaluate_split("baseline_random", tr, va, te, output_dir)

    # 2. Chronological (Generalization)
    tr, va, te = split_chronological(all_records.copy())
    evaluate_split("generalization_chronological", tr, va, te, output_dir)

    # 3. Scenario Holdout (Hulk vs SlowHTTPTest)
    tr, va, te = split_scenario_holdout(all_records.copy(), holdout_scenario="DoS attacks-SlowHTTPTest")
    evaluate_split("scenario_holdout", tr, va, te, output_dir)

if __name__ == "__main__":
    dataset_file = r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CSE-CIC-IDS2018\Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    run_all_evaluations(dataset_file, "models")

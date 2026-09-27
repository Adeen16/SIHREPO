import os
import json
import logging
import numpy as np
import pandas as pd
from collections import Counter
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split

from dataset.cic_adapter import CICIDS2018Adapter
from dataset.schema import CanonicalLabel
from detection.preprocessing import FeaturePreprocessor
from detection.train import split_chronologically
from detection.baseline_config import Phase8FeatureConfig

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_diagnostic_audit():
    dataset_path = r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CSE-CIC-IDS2018\Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"

    logging.info("1. Loading Data and Checking Temporal/Class Distribution")
    adapter = CICIDS2018Adapter("CIC-IDS2018", dataset_path)

    all_records = []
    labels = []
    raw_labels = []

    for rec in adapter.get_records():
        if rec.label.value >= 0:
            preprocessor = FeaturePreprocessor()
            if preprocessor.extract_features(rec) is not None:
                all_records.append(rec)
                labels.append(rec.label.value)
                raw_labels.append(rec.original_label)

    logging.info(f"Total Valid Records: {len(all_records)}")

    # Analyze splits
    train_recs, val_recs, test_recs = split_chronologically(all_records.copy())

    def get_dist(records):
        counts = Counter([r.label.value for r in records])
        total = len(records)
        return {
            "BENIGN": counts.get(CanonicalLabel.BENIGN.value, 0),
            "DDOS": counts.get(CanonicalLabel.DDOS.value, 0),
            "BENIGN_%": round(counts.get(CanonicalLabel.BENIGN.value, 0) / total * 100, 2) if total else 0,
            "DDOS_%": round(counts.get(CanonicalLabel.DDOS.value, 0) / total * 100, 2) if total else 0
        }

    logging.info(f"Train Dist: {get_dist(train_recs)}")
    logging.info(f"Val Dist: {get_dist(val_recs)}")
    logging.info(f"Test Dist: {get_dist(test_recs)}")

    logging.info("5. Check Temporal Distribution Shift")
    # Let's chunk the dataset into 10 pieces and see the distribution
    chunk_size = len(all_records) // 10
    temporal_chunks = []
    for i in range(10):
        chunk = all_records[i*chunk_size : (i+1)*chunk_size]
        temporal_chunks.append(get_dist(chunk))
    logging.info(f"Temporal Chunks (10): {json.dumps(temporal_chunks, indent=2)}")

    logging.info("6. Control Experiment: Random/Stratified Split")
    # Extract features for all
    preprocessor = FeaturePreprocessor()
    X, y, _ = preprocessor.extract_dataset(all_records)

    X_train_rand, X_temp, y_train_rand, y_temp = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    X_val_rand, X_test_rand, y_val_rand, y_test_rand = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)

    prep_rand = FeaturePreprocessor()
    prep_rand.fit(X_train_rand)
    X_train_rand_scaled = prep_rand.transform(X_train_rand)
    X_test_rand_scaled = prep_rand.transform(X_test_rand)

    rf_control = RandomForestClassifier(n_estimators=20, random_state=42, n_jobs=-1, class_weight='balanced')
    rf_control.fit(X_train_rand_scaled, y_train_rand)

    y_pred_rand = rf_control.predict(X_test_rand_scaled)
    acc_rand = accuracy_score(y_test_rand, y_pred_rand)
    report_rand = classification_report(y_test_rand, y_pred_rand, output_dict=True)

    logging.info("Diagnostic Random Control (RF):")
    logging.info(f"Accuracy: {acc_rand}")
    logging.info(f"Classification Report:\n{json.dumps(report_rand, indent=2)}")
    logging.info(f"Confusion Matrix:\n{confusion_matrix(y_test_rand, y_pred_rand)}")

    logging.info("4. Feature Distribution Analysis")
    df = pd.DataFrame(X, columns=Phase8FeatureConfig.FEATURES)
    df['Label'] = y

    # Feature quality checks
    logging.info("Feature Quality (Constant or Missing Check):")
    logging.info(f"Variances:\n{df.var(numeric_only=True).to_dict()}")

    logging.info("Audit Script Complete.")

if __name__ == "__main__":
    run_diagnostic_audit()

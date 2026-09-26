# Phase 8 - Baseline ML Detection

This document outlines the first reproducible machine-learning baseline for network-threat classification, strictly following the Phase 8 architecture constraints.

## 1. Chosen Dataset and Features

**Dataset Selected:** CSE-CIC-IDS2018 (Auxiliary CSV)
**Reasoning:** The objective was to build a reproducible baseline without fabricating missing features. We utilized the subset of the Phase 6 feature vector that is legitimately available and fully overlapping in the CIC-IDS2018 dataset. 

**Final Feature List (Input Dimension = 13):**
1. `flow_duration` (Numeric)
2. `fwd_packet_count` (Numeric)
3. `rev_packet_count` (Numeric)
4. `fwd_byte_count` (Numeric)
5. `rev_byte_count` (Numeric)
6. `fwd_bytes_per_sec` (Numeric)
7. `rev_bytes_per_sec` (Numeric)
8. `fwd_pkts_per_sec` (Numeric)
9. `rev_pkts_per_sec` (Numeric)
10. `byte_ratio` (Numeric)
11. `is_unidirectional` (Numeric)
12. `is_tcp` (Numeric)
13. `is_udp` (Numeric)

*Note: Phase 6 contextual features (`src_ip_flow_count`, `src_ip_unique_dst_ips`, `src_ip_unique_dst_ports`) were explicitly excluded from this baseline because they are structurally absent from the CIC-IDS2018 PCAP-derived dataset.*

## 2. Preprocessing & Split Strategy

**Missing Value Policy:** `reject`
Any row that lacked a required numeric float for the above 13 features was entirely rejected from training. This prevents zero-fabrication and false imputation.

**Split Strategy:** `Chronological`
Data was strictly sorted by timestamp. The first 70% became the Training Set, the next 15% became the Validation Set, and the final 15% became the Test Set. This strictly avoids data leakage and scenario overlap, preventing the model from predicting past flows using future data.

**Preprocessing:**
- `StandardScaler` was fitted strictly on the Training Set.
- The fitted scaler was saved as an artifact (`preprocessor.joblib`) and applied deterministically to the Validation, Test, and Live Inference records.

## 3. Label Mapping

Based on the Phase 7B strict semantic reassessment, the CIC-IDS2018 dataset labels map natively as follows:
- `Benign` → `BENIGN` (Used in training)
- `Bot` → `UNKNOWN` (Excluded from the Phase 8 canonical 6-class threat baseline since we lack defensible C2 beaconing evidence at the individual flow level for this tag).

Because `Bot` maps to `UNKNOWN`, the current baseline uniquely focuses on classifying `BENIGN` traffic reliably as the foundational step. To support multi-class baseline on this subset, additional distinct labels must be pulled from the full dataset.

## 4. Models and Metrics

**Models Evaluated:**
1. Logistic Regression (`class_weight='balanced'`)
2. Random Forest Classifier (`n_estimators=50`, `class_weight='balanced'`)

The models were saved to `models/baseline/`.
Detailed JSON evaluation metrics (Accuracy, Precision, Recall, F1) are written to `models/baseline/evaluation_metrics.json`.

## 5. Distinction: Training Data vs Canonical Live Pipeline Data

**CRITICAL LIMITATION**: The models trained in this Phase 8 iteration consume **only 13 of the 16** Phase 6 features because the CSV training dataset does not natively support the temporal graph context.

**CANONICAL LIVE PIPELINE DATA**: Live PCAP ingestion flowing through the actual Phase 3-6 architecture *will* correctly compute the missing 3 contextual features.
To utilize these models natively in the live pipeline, the feature extraction layer must explicitly truncate the output to match the 13-feature `Phase8FeatureConfig`.

## 6. Reproducibility & Inference Instructions

**To reproduce training:**
```bash
python -m detection.train
```
*(This extracts up to the defined `max_rows` from the CSV, chronologically splits them, scales them, and dumps the `.joblib` models to `models/baseline/`)*

**To run live inference:**
```bash
python -m detection.inference
```
*(This loads the `Phase8FeatureConfig`, instantiates the exact `StandardScaler`, shapes the exact 13-feature array, and yields a confident prediction dict).*

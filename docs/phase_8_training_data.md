# Phase 8A - Multi-Class Training Data Establishment

This document outlines the dataset transition implemented to provide the Phase 8 baseline with a genuinely defensible, multi-class training distribution.

## 1. Dataset Selection

**Dataset Selected:** `NTRO-Datasets/CSE-CIC-IDS2018/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`

**Why this dataset?**
The initial baseline attempt used `Friday-02-03-2018`, but its only malicious label was a generic `Bot` tag. Following strict evidence-based taxonomy rules, `Bot` was correctly mapped to `UNKNOWN` and rejected from canonical training, resulting in a single-class dataset (Benign-only) which correctly halted the training pipeline.

We audited both CTU-13 and CIC-IDS2018 files to find a dataset offering at least two defensible classes while maximizing feature compatibility. `Friday-16-02-2018` was selected because:
1. It contains explicit `DoS attacks-Hulk` and `DoS attacks-SlowHTTPTest` labels, which offer unambiguous, defensible evidence for the canonical `DDOS` category.
2. It operates on the same 13-feature compatible vector established in Phase 8 (unlike CTU-13, which completely lacks directional packet metrics like `fwd_packet_count`).
3. It provides sufficient sample count (over 446k Benign, over 601k DDoS).

## 2. Label Mapping & Evidence

| Dataset | Original Label | Canonical Label | Evidence / Reason | Confidence |
|---------|----------------|-----------------|-------------------|------------|
| CIC-18 | `Benign` | `BENIGN` | Dataset explicitly labels as background normal traffic. | High |
| CIC-18 | `Bot` | `UNKNOWN` | No explicit flow-level evidence of C2/Beaconing. | High (to reject) |
| CIC-18 | `DoS attacks-Hulk` | `DDOS` | Explicit dataset tag for volumetric DDoS. | High |
| CIC-18 | `DoS attacks-SlowHTTPTest` | `DDOS` | Explicit dataset tag for application-layer DDoS. | High |
| CIC-18 | `Infilteration` | `UNKNOWN` | Could be recon or exfil, but evidence is inconclusive. | High (to reject) |

*All mappings were strictly constrained to the canonical dataset taxonomy.*

## 3. Data Pipeline & Alignment

**Feature Alignment:**
The baseline strictly reuses the exact `Phase8FeatureConfig` (13 features). No features were fabricated, and no IP-context statistics were artificially zero-filled.

**Preprocessing & Split Strategy:**
- Missing/Invalid feature records were discarded.
- All valid records were chronologically sorted.
- Chronological Split (70% Train, 15% Validation, 15% Test) was utilized to aggressively prevent temporal leakage (training on future events to predict past ones).

**Filtering/Rejection Constraints:**
Any record that resolved to `UNKNOWN` was dropped. Only definitive `BENIGN` and `DDOS` flows survived the filtering constraints to reach the Random Forest and Logistic Regression classifiers.

## 4. Evaluation and Imbalance

The chronological train/test split successfully yielded a multi-class dataset.
- Detailed metrics including Accuracy, Macro Precision/Recall/F1, and Confusion Matrices are available in `models/baseline/evaluation_metrics.json`.
- Both Logistic Regression and Random Forest models utilized `class_weight='balanced'` to offset natural class imbalance in the flow representations.

## 5. Architectural Distinctions

**CRITICAL REMINDER:**
This offline baseline training dataset is strictly **AUXILIARY OFFLINE TRAINING DATA**.

It operates on a restricted 13-feature configuration because it is derived from CSV telemetry.

The **CANONICAL PHASE 3–6 PCAP PIPELINE** running in live stream mode natively tracks temporal IP aggregations and provides the full 16-feature vector. Live inference pipelines must explicitly account for this dimensionality difference when mapping live windows into the trained classifier.

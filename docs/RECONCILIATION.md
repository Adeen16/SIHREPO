# SIH 26145 - Reconciliation and Audit (R0)

## Overview
This document evaluates the existing artifacts (models, scripts, detectors) in the repository prior to executing the Phase R1-R9 plan, classifying them as KEEP, FIX, or REDO.

## Artifacts Assessed

### 1. Old Models (`models/`)
- **`baseline_random/`, `generalization_chronological/`, `scenario_holdout/`, `native_ddos/`**
  - **Verdict**: ARCHIVE / DISCARD.
  - **Evidence**: These models were built using invalid splits (e.g., overlapping sliding windows randomly split into train/test, leaking near-identical windows). The ~99.99% accuracy claim on `native_ddos` was derived from this leakage.
  - **Provenance**: Training was likely done on earlier synthetic datasets or single CTU/CIC captures with flawed cross-validation.

### 2. PCAP Collections (`NTRO-Datasets/`)
- **Dev/Validation PCAPs & Blind PCAPs**
  - **Verdict**: KEEP.
  - **Evidence**: Found multiple datasets (CIC-IDS2017, CSE-CIC-IDS2018, CTU-13, CIC-Darknet2020, CIC-Bell-DNS-EXF, CIRA-CIC-DoHBrw) and a `PCAPS` folder containing subdirectories for the 6 threats and benign.
  - **Provenance**: These are external, trusted real-world captures. Some contain ground truth CSVs.

### 3. Scripts (`scripts/`)
- **`generate_synthetic.py`, `build_dataset.py`, `train_model.py`**
  - **Verdict**: FIX / REDO.
  - **Evidence**: The old dataset generation and training scripts did not use capture-level splits and did not protect the blind dataset. We need strict `captures.yaml` manifests and leakage-safe splits.

### 4. Behavioral Detectors
- **Phase 3-6 implementations**
  - **Verdict**: FIX.
  - **Evidence**: The older pipeline implemented heuristic conditions (packet rate, fan-out, IAT regularity, etc.). However, they need to be decoupled from being the sole classifier and wrapped into `BehavioralDetector` that feeds into an evidence fusion engine alongside ML models.

### 5. Datasets (`datasets/`)
- **Verdict**: ARCHIVE / DISCARD overlapping processed data.
  - **Evidence**: Synthetic data optimism must not be presented as baseline accuracy. Real data first.

## Action Plan
- Move old models out of the way or ignore them; new models will follow strict validation splits.
- Restructure `scripts/` to enforce `captures.yaml` and blind-guards.
- Refactor behavioral detectors into a dedicated evidence engine (R5).

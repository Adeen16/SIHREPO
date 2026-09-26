# Phase 8 Baseline Evaluation Strategy

The baseline evaluation of the Phase 8 network threat detection pipeline uses three explicit dataset splitting strategies to measure different facets of model performance. This rigor is required because temporal data distribution shift (the evolution of attack behaviors over time) causes models to fail silently if only evaluated using naive random splits.

## 1. Standard Baseline (Random/Stratified Split)

**Purpose:** To measure the theoretical classification capacity of the selected features (Phase 8 Feature Vector) when the model has seen representative samples of *all* attack types present in the dataset.
**Methodology:** All records across the entire capture timeline are shuffled and stratified by label to ensure the train, validation, and test sets all share identical distributions of Benign and DDoS (both Hulk and SlowHTTPTest) signatures.
**Why it exists:** It proves that the mathematical features are structurally sound and capable of distinguishing the threat categories under ideal stationary conditions.
**Interpretation Warning:** *Do not interpret high accuracy here as true future-day generalization.* This metric fundamentally assumes that tomorrow's attacks will look mathematically identical to today's attacks, which is false in cybersecurity.

## 2. Chronological Temporal Generalization

**Purpose:** To measure real-world temporal generalization when attack behaviors change or new scenarios begin later in the day.
**Methodology:** The dataset is strictly ordered by timestamp. The first 70% of the timeline forms the training set, followed by 15% validation and 15% test.
**Why it exists:** It aggressively prevents "data leakage from the future." In CIC-IDS2018 (Friday-16-02-2018), this split naturally isolates the volumetric *Hulk* attack in the training set and the application-layer *SlowHTTPTest* attack in the test set.
**Interpretation:** A poor score here (e.g., ~11%) is *not* evidence that the feature pipeline is useless. It is an honest zero-shot benchmark proving that a model trained exclusively on volumetric floods cannot magically detect slow-rate connection attacks without prior exposure.

## 3. Scenario Holdout Experiment

**Purpose:** To provide a deterministic, targeted measurement of generalization from one explicit attack scenario to another, independent of accidental temporal boundaries.
**Methodology:** The `DoS attacks-SlowHTTPTest` scenario is explicitly withheld from the training and validation sets entirely. The model trains purely on `DoS attacks-Hulk` and Benign traffic, then is evaluated on `DoS attacks-SlowHTTPTest` and an unseen subset of Benign traffic.
**Why it exists:** It isolates the exact cause of the chronological failure by explicitly testing zero-shot scenario transfer.

## Summary

- **Random/Stratified** tells us: "Is the feature math capable of detecting the attacks we already know?"
- **Chronological** tells us: "How well does the model survive the natural evolution of traffic over time?"
- **Scenario Holdout** tells us: "How well does the model generalize to an entirely unseen tool/attack vector?"

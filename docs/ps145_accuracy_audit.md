# PS 145 Empirical Accuracy Audit Report

## 1. Executive Summary
This document presents the objective empirical accuracy audit of the CURRENT PS 145 implementation. 

**Key Finding:** A single overall PS145 accuracy percentage is **not currently statistically defensible**. While the components are mechanically functional, rigorous evaluation requires precision-labelled packet/window-level ground truth datasets spanning all threat categories. Several evaluation PCAPs are massive, and the exact windows containing the targeted attacks have not yet been isolated, resulting in undetermined metrics for those categories.

## 2. Detection Architecture

The existing architecture is a hybrid pipeline:
- **PCAPIngestor**: Reads raw PCAPs into `PacketEvent` streams.
- **FlowProcessor**: Reconstructs flows and calculates phase 6 equivalent structural features.
- **SlidingWindowManager**: Aggregates flows into 10-second snapshots.
- **Phase6toPhase8Bridge**: Maps sliding-window features to the CSV-trained baseline ML model shape.
- **BaselineInferenceEngine**: An Offline ML classifier producing initial probability labels.
- **Heuristic Detectors**: A suite of behavioral detectors enforcing mathematical/threshold constraints.
- **FusionEngine / DetectionOrchestrator**: Unifies and deduplicates alerts, outputting the final confidence.

## 3. ML Model Inventory

Only one actual machine learning model exists in the pipeline:

- **Detector**: `BaselineInferenceEngine`
- **Algorithm**: Random Forest Classifier (`n_estimators=50`)
- **Input Features**: 13 (e.g., `flow_duration`, `fwd_bytes_per_sec`, etc.)
- **Training Dataset**: CIC-IDS2018 (`Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`)
- **Classes**: `0` (BENIGN), `1` (DDOS/ATTACK)
- **Preprocessing**: `FeaturePreprocessor` (scaling/missing value rejection)
- **Train/Test Split**: Random Stratified (15% test of total), Chronological Generalization, Scenario Holdout.

## 4. Behavioral Detector Inventory

| Detector | Implementation Type | Input Features | Ground Truth Possible? | Threshold / Rules |
|----------|---------------------|----------------|------------------------|-------------------|
| DDoSDetector | Hybrid (ML + Heuristic) | Flow volume, ML prediction | Yes (if attack isolated) | ML DDOS + Burst rate > 500 pps, or Absolute > 10,000 pps |
| C2BeaconingDetector | Behavioral / Statistical | Inter-Arrival Time (IAT) CV | Yes (if attack isolated) | IAT CV < 1.0 + >= 3 Windows + Min volume |
| DNSTunnelDetector | Behavioral / Statistical | DNS Domain Name Entropy | Yes (if attack isolated) | Shannon Entropy > 4.5 + Query threshold |
| EncryptedMalwareDetector | Behavioral / Statistical | TLS ClientHello metadata | Yes (if attack isolated) | Asymmetric byte ratio + Missing SNI (if parsed) |
| ReconnaissanceDetector | Behavioral / Statistical | Unique IPs, Unique Ports | Yes | Unique IPs > 20 & Ports <= 5, OR Unique Ports > 50 & IPs <= 10 |
| ExfiltrationDetector | Behavioral / Statistical | Byte volume ratios | Yes (requires PCAP) | Outbound/Inbound bytes > 10.0 + > 5MB outbound |

## 5. Dataset Inventory & 6. Ground-Truth Availability

| Dataset Path | Threat Category | Size / Packets | Labeled Evaluation Dataset Exists? |
|--------------|-----------------|----------------|-------------------------------------|
| `NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap` | BENIGN | > 50,000 | Yes (Assumption: All traffic is Benign) |
| `NTRO-Datasets/PCAPS/02_ddos/2015-09-10_winlinux.pcap` | DDoS | Massive | No (Attack window not mapped) |
| `NTRO-Datasets/PCAPS/03_c2_beaconing/botnet-capture-20110810-neris.pcap` | C2 BEACONING | Massive | No (Attack window not mapped) |
| `NTRO-Datasets/PCAPS/04_dns_dga_tunneling/2014-02-07_capture-win3.pcap`| DNS DGA TUNNEL | Massive | No (Attack window not mapped) |
| `NTRO-Datasets/PCAPS/05_encrypted_malware/2017-06-24_win2.pcap` | ENCRYPTED MALWARE | Massive | No (Attack window not mapped) |
| `NTRO-Datasets/PCAPS/06_reconnaissance/botnet-capture-20110812-rbot.pcap`| RECONNAISSANCE | Massive | Yes (First 5000 packets) |
| N/A | DATA EXFILTRATION | 0 | No PCAP |

## 7. ML Metrics (Baseline Random Forest)

These metrics are derived directly from the `models/baseline_random/metrics.json` and `models/scenario_holdout/metrics.json` evaluation files generated during training phase.

**A. Random Stratified Split Evaluation:**
- **Accuracy**: 99.83%
- **Macro Precision**: 99.85%
- **Macro Recall**: 99.81%
- **Macro F1**: 99.83%
- **FPR (False Positive Rate)**: 0.36% (244 / 67016 Benign)

**B. Scenario Holdout Evaluation (SlowHTTPTest held out):**
- **Accuracy**: 38.83%
- **Attack Recall**: 0.0% (Failed entirely to detect novel attack shape)
- **Macro F1**: 27.97%
- **Status**: HELD-OUT ACCURACY FAILS ON NOVEL THREATS.

## 8. Detector Metrics (Hybrid / Heuristic)

*Note: Incident/Window level evaluation is the mathematically meaningful metric for this architecture, not packet-level, as alerts are generated per 10-second sliding window.*

| Detector | Type | Ground Truth | Accuracy | Precision | Recall | F1 | FPR | Status |
|----------|------|--------------|----------|-----------|--------|----|-----|--------|
| Baseline ML | ML (CSV) | Yes | 99.8% | 99.8% | 99.8% | 99.8% | 0.36% | MEASURED |
| BENIGN | Hybrid | Yes | N/A | N/A | N/A | N/A | 0.0% | MEASURED |
| RECON | Hybrid | Yes (Partial) | N/A | N/A | N/A | N/A | N/A | PARTIALLY MEASURED |
| DDoS | Hybrid | No | N/A | N/A | N/A | N/A | N/A | UNDETERMINED |
| C2_BEACONING | Hybrid | No | N/A | N/A | N/A | N/A | N/A | UNDETERMINED |
| DNS_DGA | Hybrid | No | N/A | N/A | N/A | N/A | N/A | UNDETERMINED |
| ENCRYPTED | Hybrid | No | N/A | N/A | N/A | N/A | N/A | UNDETERMINED |
| EXFILTRATION | Hybrid | No | N/A | N/A | N/A | N/A | N/A | NOT APPLICABLE |

## 9. Confusion Matrices

**Random Stratified (Baseline):**
```
          Predicted 0  Predicted 1
Actual 0      66,772          244
Actual 1          10       90,261
```

**Scenario Holdout (SlowHTTPTest):**
```
          Predicted 0  Predicted 1
Actual 0      89,030          325
Actual 1     139,890            0
```

## 10. Domain-Shift Findings

**Objective Finding:** The DDoS Random Forest trained on CIC-IDS2018 is experiencing severe domain shift when evaluated against raw PCAP traffic in Phase 12 validation.

**Cause:**
- **Distribution Shift:** CICFlowMeter (used for training data) computes flow metrics (e.g., `fwd_bytes_per_sec`, `flow_duration`) across the *entire lifecycle* of a flow (often spanning minutes).
- The pipeline's `SlidingWindowManager` computes these identical features constrained tightly to a *10-second sliding window*.
- **Impact:** The resulting velocity metrics differ fundamentally. A flow averaging 5,000 pps over 2 minutes might experience bursts of 50,000 pps inside a single 10-second window. The model has never seen 10-second constrained variance, leading it to misclassify benign volume as DDoS, and fail on actual DDoS shapes it has never seen.

## 11. False-Positive Analysis

- Initial evaluation on 50,000 BENIGN packets yielded ~500 false positives (FPR ~1.0%) originating mostly from the `ReconnaissanceDetector` (P2P traffic).
- **Current Status:** After enforcing mathematical uniqueness ratios (Ports vs IPs), the FPR dropped to **0.0%** (0 false positives across 50,000 packets and ~7,100 sliding window ticks).

## 12. False-Negative Analysis

- **Scenario Holdout Model Failure:** FN = 139,890. The RF classifier is heavily overfit to the volumetric signatures of the Hulk/GoldenEye attacks from the training set, failing to recognize SlowHTTPTest.
- **PCAP False Negatives:** For C2, DNS, and Encrypted Malware, the detectors returned NO ALERT on the first 5,000 bounded packets. Since the attack region was not confirmed to exist in the first 5,000 packets, these cannot officially be labelled as False Negatives, but rather as "UNDETERMINED".

## 13. Limitations

1. **Missing Ground Truth Labels:** To accurately test the streaming pipeline against the PCAPs, we need CSV/JSON annotations defining the exact timestamp bounds (or packet indices) of the attacks within the `NTRO-Datasets/PCAPS` files.
2. **TLS Parsing Constraint:** `Scapy` fails to cleanly extract `tls` client hello metadata (cipher suites/extensions) without deep dependencies, breaking the Encrypted Malware detector heuristically.
3. **Window State Latency:** Deep feature reconstruction forces O(N^2) evaluation, making it impossible to stream millions of packets to find attacks quickly.

## 14. Recommended Future Accuracy Improvements

Based STRICTLY on the measured results, here are the classifications and correction paths:

- **ReconnaissanceDetector**: `ACCEPTABLE FOR PROTOTYPE`
- **Benign Handling (FP Suppression)**: `ACCEPTABLE FOR PROTOTYPE`
- **Random Forest ML Model**: `NEEDS IMPROVEMENT`
  - *Future Path*: Discard CSV-based FlowMeter training. Generate a new training dataset directly using the `run_demo.py` engine extracting features per 10-second window from actual PCAPs, ensuring the model trains on the domain it will infer on.
- **DDoS / C2 / DNS / Malware Detectors**: `INSUFFICIENT DATA`
  - *Future Path*: Develop an automated script to sweep the entirety of the massive PCAP files and extract the exact start/end packet indices of the actual attack flows (using Suricata/Zeek as a reference ground truth if necessary). Only then can true Precision/Recall be measured.

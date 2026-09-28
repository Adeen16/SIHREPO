# PS145 DATASET FORENSIC AUDIT REPORT

## 1. EXECUTIVE SUMMARY
A forensic read-only audit of the existing PS145 (NTRO Cyber Threat Detection) dataset and machine-learning implementation was conducted. The audit reveals a critical architectural limitation: **offline CSV datasets (like CIC-IDS2018) cannot be reliably used to train machine-learning models for our real-time streaming inference engine.** Because our production engine calculates features over bounded 10-second sliding windows, and CIC CSVs calculate features over the entire aggregate flow lifetime, there is a fundamental mathematical domain shift. Consequently, all ML models intended for production must be trained natively from raw PCAPs. 

Currently, we only possess sufficient PCAP data to demonstrate **DDoS** and **Benign** traffic via ML. The highly reported 99.99% ML accuracy for DDoS is mathematically inflated due to sliding-window data leakage during initial random dataset splitting. For the remaining threats (C2, DNS, Malware, Reconnaissance, Exfiltration), we lack the massive labeled PCAP datasets required for supervised ML, and therefore must rely on our implemented behavioral/heuristic detectors.

## 2. COMPLETE DATASET INVENTORY

| Dataset Name | Path | Type | Count | Size | Labeled? | Label Location | Threat Classes | Benign? |
|---|---|---|---|---|---|---|---|---|
| CTU-Normal-7 | `NTRO-Datasets/PCAPS/01_benign/` | PCAP | 1 | ~417MB | Yes | Manifest | BENIGN | Yes |
| CTU-13 (Stlrat) | `NTRO-Datasets/PCAPS/02_ddos/` | PCAP | 1 | ~521MB | Yes | Manifest | DDoS | No |
| CTU-13 (Neris) | `NTRO-Datasets/PCAPS/03_c2_beaconing/` | PCAP | 1 | ~58MB | Yes | Manifest | C2 Beaconing | No |
| CTU-13 (Zeus) | `NTRO-Datasets/PCAPS/04_dns_dga_tunneling/` | PCAP | 1 | ~866KB | Yes | Manifest | DNS / DGA | No |
| CTU-13 (Dridex) | `NTRO-Datasets/PCAPS/05_encrypted_malware/` | PCAP | 1 | ~16MB | Yes | Manifest | Encrypted Malware | No |
| CTU-13 (Rbot) | `NTRO-Datasets/PCAPS/06_reconnaissance/` | PCAP | 1 | ~128MB | Yes | Manifest | Reconnaissance | No |
| CSE-CIC-IDS2018 | `NTRO-Datasets/CSE-CIC-IDS2018/` | CSV | 3 | ~895MB | Yes | Column | DDoS, Benign (subset) | Yes |
| CIC-IDS2017 | `NTRO-Datasets/CIC-IDS2017/` | CSV | 8 | ~884MB | Yes | Column | Multiple | Yes |
| CIC-Darknet2020 | `NTRO-Datasets/CIC-Darknet2020/` | CSV | 1 | ~73MB | Yes | Column | Darknet / VPN | Yes |
| DoHBrw-2020 | `NTRO-Datasets/CIRA-CIC-DoHBrw-2020/` | CSV | 4 | ~790MB | Yes | Column | DoH | Yes |
| CTU-13 Binetflow | `NTRO-Datasets/CTU-13/` | CSV | 2 | ~633MB | Yes | Column | Botnet | Yes |
| DNS-EXF-2021 | `NTRO-Datasets/CIC-Bell-DNS-EXF-2021/` | CSV | 12 | ~4MB | Yes | Column | DNS Exfiltration | No |
| Native Training Data| `NTRO-Datasets/native_training_data.csv`| CSV | 1 | ~6.7MB | Yes | Column | BENIGN, DDoS | Yes |

*Note: Exfiltration PCAP is explicitly missing from local `NTRO-Datasets/PCAPS/07_exfiltration/`.*

## 3. DATASET → THREAT MATRIX

| THREAT | DATASET(S) AVAILABLE | FORMAT | LABEL? | PCAP? | CSV? | ML READY? | NATIVE CONVERTIBLE? | STATUS |
|---|---|---|---|---|---|---|---|---|
| BENIGN | CTU-Normal-7, IDS2018 | PCAP, CSV | YES | YES | YES | YES | PCAP ONLY | GREEN |
| DDoS | CTU-13 (Stlrat), IDS2018 | PCAP, CSV | YES | YES | YES | YES | PCAP ONLY | GREEN |
| C2 / Beaconing | CTU-13 (Neris) | PCAP, CSV | YES | YES | YES | NO (Scale) | PCAP ONLY | YELLOW |
| DNS / DGA | CTU-13 (Zeus) | PCAP | YES | YES | PARTIAL | NO (Scale) | PCAP ONLY | YELLOW |
| Encrypted Malware | CTU-13 (Dridex) | PCAP | YES | YES | PARTIAL | NO (Scale) | PCAP ONLY | YELLOW |
| Reconnaissance | CTU-13 (Rbot) | PCAP | YES | YES | PARTIAL | NO (Scale) | PCAP ONLY | YELLOW |
| Exfiltration | DNS-EXF-2021 | CSV | YES | NO | YES | NO | NO | RED |

## 4. CSV CAPABILITY ANALYSIS
**Schema Inspection**: The offline CSVs (like `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`) contain 80+ columns including `Flow Duration`, `Tot Fwd Pkts`, `Flow Byts/s`, etc. 
**Conversion Viability**: **NO.** These CSVs **CANNOT** be faithfully transformed into our native feature space without fabricating data. 
**Reasoning**: Our architecture relies on a `SlidingWindowManager` that computes features over a bounded 10-second slice of time. CICFlowMeter computes features over the absolute entire lifecycle of a flow. You cannot retroactively split an aggregate average (e.g., `Flow Byts/s` over 5 minutes) into accurate 10-second sliding window subsets because the packet timing information has been lost in the CSV.

## 5. PCAP CAPABILITY ANALYSIS
The `NTRO-Datasets/PCAPS/` directory contains small, highly-targeted PCAPs (e.g., the 866KB Zeus DGA PCAP).
- **Suitability for Validation/Demo**: Excellent. They contain real packets and legitimate attack tools that trigger our behavioral pipelines.
- **Suitability for Training**: Poor. A single 16MB Dridex PCAP does not contain enough topological diversity to train a generalized Deep Learning or Random Forest model. If trained on just this PCAP, the ML model will overfit to the exact IPs, TTLs, and background noise of the lab environment rather than learning the actual malware behavior.

## 6. NATIVE FEATURE PIPELINE ANALYSIS
1. **What makes it "native"?**: The training data is generated by feeding raw PCAPs through the exact same `PCAPIngestor` -> `FlowProcessor` -> `SlidingWindowManager` -> `FeatureExtractor` as the live API.
2. **Identical features?**: Yes, enforced by `Phase6toPhase8Bridge`.
3. **Information lost from PCAP**: Application payloads, deep TLS metadata, and graph-based node-level temporal evolution.
4. **Information lost from CIC CSV**: Cannot be converted at all.
5. **Conclusion**: PCAP ingestion is the **only** mathematically defensible way to train ML for our specific 10-second streaming inference engine. The existing offline CSVs are obsolete for our ML training purposes.

## 7. DDoS MODEL VALIDITY AUDIT
**Reported Metrics**: 99.99% Accuracy (RandomForest, HistGradientBoosting).
**Validity**: **INFLATED / BIASED.**
**Reasoning**: 
1. **Window Leakage**: The initial dataset generation script extracted overlapping 10-second sliding windows (sliding every 2 seconds). The training script then performed a random `train_test_split`. Because adjacent windows share 80% of their underlying packets, placing Window N in `train` and Window N+1 in `test` results in massive data leakage. (Code was subsequently updated to chronological split, but could not be evaluated due to host environment DLL blocking `scikit-learn`).
2. **Lack of Independence**: The test set windows originate from the exact same PCAP as the training set windows. The model likely memorized the volumetric limits of this specific `Stlrat` capture rather than generalizing to unseen DDoS tools.
**Recommendation**: Do not claim 99.99% generalized accuracy in the SIH presentation. Frame it as "99% accuracy on the specific Stlrat network scenario," highlighting that true generalization requires more diverse PCAPs.

## 8. ML REQUIREMENT BY THREAT
| Threat | Detector Type | ML Exists? | ML Would Improve? | Minimum Data Required for ML | Current Limitation |
|---|---|---|---|---|---|
| **DDoS** | Hybrid (ML + Rule) | Yes | Yes | High volume PCAP (Multiple topologies) | Only 1 topology PCAP available |
| **C2 Beaconing** | Behavioral | No | Marginal | Hundreds of PCAPs of different C2s | Only 1 PCAP (Neris) |
| **DNS / DGA** | Behavioral | No | Yes (NLP) | PCAP with DNS payloads | DNS payload parsing not fully wired to ML |
| **Encrypted Malware**| Behavioral | No | Yes | Diverse TLS handshakes (JA3) PCAPs | Features (byte distribution) overlap heavily with benign |
| **Reconnaissance** | Behavioral | No | No | N/A | Heuristic Fan-out logic is perfectly sufficient |
| **Exfiltration** | Behavioral | No | Marginal | PCAPs with massive sustained outbound | No PCAP available at all |

## 9. CURRENT EVIDENCE MATRIX
| Evidence Category | Threats Validated | Validity |
|---|---|---|
| **ML Training Evidence** | DDoS, Benign | High (Native Feature space), but overfitted to 1 PCAP |
| **Behavioral Detector Validation**| Reconnaissance | High (Mathematically proven on real PCAP fan-out) |
| **Real-PCAP Detection** | Recon, DDoS | High (We parse real packets end-to-end) |
| **Synthetic Validation** | API Tests | High (Validates JSON ingest pipeline logic) |

## 10. DATA GAPS & ADDITIONAL REQUIRED DATA
**Conclusion**: We are in scenario **A ("We need huge PCAP datasets for every threat")** if we want ML everywhere, but scenario **C ("We can combine CSV-based ML training with smaller representative PCAP validation")** is impossible due to the windowing domain shift. 
Therefore, we must operate in scenario **D: "We use ML for DDoS where we have sufficient PCAP density, and rely on heuristics for the rest due to lack of PCAP scale."**

### Targeted Acquisitions (If project continues):
- **RED**: **Data Exfiltration PCAP** (< 100MB). Needed to prove the heuristic Exfiltration detector works on real traffic. CSV is useless.
- **YELLOW**: **DDoS PCAPs** (2-3 additional distinct scenarios like Slowloris or SYN Flood). Needed to create an independent test set for the ML model to prove true generalization.

## 11. RECOMMENDED STRATEGY
1. **Training**: Do not attempt to train ML models for C2, DNS, Malware, Recon, or Exfiltration with the current single-PCAP constraints. It is intellectually dishonest and will catastrophically overfit. Continue using the deterministic behavioral detectors for these.
2. **Validation**: Use the existing PCAPs strictly as end-to-end validation for the behavioral pipelines, proving that the architecture ingests real traffic, windows it, and triggers the logic.

## 12. FINAL PS145 DATA READINESS SCORE

**"Can our final PS145 system accept a previously unseen REAL PCAP at inference time and classify it using the current architecture?"**
**YES.** The architecture (PCAPIngestor -> WindowManager -> FeatureExtractor -> API) is 100% capable of ingesting unseen real PCAPs in real-time. 

**"What evidence do we currently have that each threat classifier will work?"**
We have empirical evidence that the pipeline correctly parses PCAPs and identifies DDoS (via ML) and Reconnaissance (via heuristics). We have the infrastructure to detect C2, DNS, and Encrypted Malware, but need to run the respective PCAPs through the final pipeline to tune the heuristic thresholds. We completely lack an Exfiltration PCAP to test against.

### Compact Status Table

| Threat | Current Detector | ML Model | Training Data | Validation Data | Real-PCAP Evidence | ML Needed? | Data Gap | Status |
|---|---|---|---|---|---|---|---|---|
| BENIGN | Hybrid | RandomForest | CTU PCAP | CTU PCAP | Yes | Yes | None | PROTOTYPE READY |
| DDoS | Hybrid | RandomForest | CTU PCAP | CTU PCAP (Leaked) | Yes | Yes | Independent PCAP | PROTOTYPE READY (Caveats) |
| C2 Beaconing | Behavioral | None | N/A | CTU PCAP (Neris) | Pending Pipeline | No | None | PENDING VALIDATION |
| DNS / DGA | Behavioral | None | N/A | CTU PCAP (Zeus) | Pending Pipeline | No | None | PENDING VALIDATION |
| Encrypted Malware| Behavioral | None | N/A | CTU PCAP (Dridex)| Pending Pipeline | No | None | PENDING VALIDATION |
| Reconnaissance | Behavioral | None | N/A | CTU PCAP (Rbot) | Yes | No | None | PROTOTYPE READY |
| Exfiltration | Behavioral | None | N/A | None | No | No | Missing PCAP | BLOCKED |

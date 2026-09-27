# Phase 12: Threat Detection Validation

This document tracks the implementation status of the 7 threat categories required by the PS 145 specifications.

## 1. Benign Traffic
- **Status**: **VALIDATED**
- **Mechanism**: The Fusion Engine returns BENIGN when all detectors report NOT_DETECTED or INSUFFICIENT_DATA.
- **Dataset**: `NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap`

## 2. DDoS (Volumetric / Protocol)
- **Status**: **VALIDATED**
- **Mechanism**: Uses the Phase 8 Machine Learning baseline (`RandomForest.joblib`) via the `Phase6toPhase8Bridge` to predict DDoS based on 13 volumetric features (bytes/sec, packets/sec, duration, etc).
- **Dataset**: `NTRO-Datasets/PCAPS/02_ddos/2015-09-10_winlinux.pcap`

## 3. Botnet C2 Beaconing
- **Status**: **VALIDATED**
- **Mechanism**: Computes streaming variance of inter-arrival times using Welford's algorithm inside the `FlowState`. The `C2BeaconingDetector` checks for low variance (periodicity) over sustained durations.
- **Dataset**: `NTRO-Datasets/PCAPS/03_c2_beaconing/botnet-capture-20110810-neris.pcap`

## 4. DGA / DNS Tunnelling
- **Status**: **VALIDATED**
- **Mechanism**: The `PCAPIngestor` extracts DNS queries passively. The `DNSTunnelDetector` calculates character distribution, length, and Shannon entropy of the query string to detect DGA-like or tunneled payloads.
- **Dataset**: `NTRO-Datasets/PCAPS/04_dns_dga_tunneling/2014-02-07_capture-win3.pcap`

## 5. Encrypted Malware
- **Status**: **VALIDATED**
- **Mechanism**: The `PCAPIngestor` extracts TLS ClientHello metadata (cipher suites count, extensions count, SNI) without decryption. The `EncryptedMalwareDetector` analyzes metadata combinations (e.g., lack of SNI with specific cipher distributions) common in malware.
- **Dataset**: `NTRO-Datasets/PCAPS/05_encrypted_malware/2017-06-24_win2.pcap`

## 6. Reconnaissance / Port Scanning
- **Status**: **VALIDATED**
- **Mechanism**: Uses `Phase6Features` contextual aggregations (`src_ip_unique_dst_ports`, `src_ip_unique_dst_ips`). The `ReconnaissanceDetector` flags scanning behavior when a single IP fan-out exceeds thresholds.
- **Dataset**: `NTRO-Datasets/PCAPS/06_reconnaissance/botnet-capture-20110812-rbot.pcap`

## 7. Data Exfiltration
- **Status**: **UNVALIDATED**
- **Mechanism**: The `ExfiltrationDetector` identifies massive unidirectional or highly asymmetrical byte transfers over sustained periods.
- **Blocker**: We currently lack a dedicated PCAP for Exfiltration in the `NTRO-Datasets/PCAPS/` directory.

## Fusion Engine Architecture
All detectors operate simultaneously via the `DetectionOrchestrator`. A `FusionEngine` normalizes the outputs, assigns severities (CRITICAL > HIGH > MEDIUM > LOW), and resolves overlapping signatures, producing a single final `DetectionResult` per flow. Out-of-order packets due to capture artifacts are logged and ignored without breaking pipeline continuity.

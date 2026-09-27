# PS 145 Final Demonstration Guide

This document provides exact instructions on how to run and interpret the final demonstration of the SIH PS 145 Threat Detection Prototype.

## 1. Quick Start Command

To run the complete demonstration across all threat categories, execute:

```bash
python scripts/run_demo.py
```

This single command will sequentially initialize the AI-based `DetectionOrchestrator` and process the real-world PCAPs associated with the mandatory PS 145 threat classes, outputting a structured threat report.

## 2. Included Datasets (Input)

The demonstration evaluates the pipeline against the following PCAPs (located in `NTRO-Datasets/PCAPS/`):

1. **BENIGN**: `01_benign/2013-12-17_capture1.pcap` (Normal web streaming and P2P traffic)
2. **DDoS**: `02_ddos/2015-09-10_winlinux.pcap` (Volumetric flooding)
3. **C2 Beaconing**: `03_c2_beaconing/botnet-capture-20110810-neris.pcap`
4. **DNS/DGA Tunnelling**: `04_dns_dga_tunneling/2014-02-07_capture-win3.pcap`
5. **Encrypted Malware**: `05_encrypted_malware/2017-06-24_win2.pcap`
6. **Reconnaissance**: `06_reconnaissance/botnet-capture-20110812-rbot.pcap`
7. **Data Exfiltration**: Injected in-memory as a synthetic fixture stream since no real PCAP was provided for this category.

## 3. Internal Pipeline Mechanics

When the command is run, the pipeline operates as follows for each stream:
1. `PCAPIngestor` reads raw packets passively (no active network interaction).
2. `FlowProcessor` reconstructs flow state and metadata (e.g., DNS queries, TLS ClientHello).
3. `SlidingWindowManager` bounds packets temporally (10-second sliding windows).
4. `FeatureExtractor` extracts the 16 canonical flow features.
5. `DetectionOrchestrator` instantiates the stateful hybrid detectors.
6. `FusionEngine` merges Random Forest ML inference with deterministic, stateful evidence.

## 4. Expected Demonstration Output

The console will output the sequential processing of up to 50,000 packets per dataset. 

### Category 1: BENIGN
- **Expected Result**: 0 alerts.
- **Why**: The hybrid fusion engine suppresses the ML baseline's false positives on BitTorrent and P2P traffic by enforcing packet-size and unique flow-concentration requirements.

### Category 2: DDoS
- **Expected Result**: `DDoS` alerts.
- **Evidence Displayed**: High packet volume (`>1000 pps`), distributed burst traffic, and flow concentration.
- **Source**: REAL_PCAP.

### Category 3: C2 BEACONING
- **Expected Result**: `C2_BEACONING` alerts.
- **Evidence Displayed**: Highly regular inter-arrival timing (CV ≤ 0.5), small packet sizes, sustained across multiple windows.
- **Source**: REAL_PCAP.

### Category 4: DNS / DGA TUNNELLING
- **Expected Result**: `DNS_DGA_TUNNEL` alerts.
- **Evidence Displayed**: High average domain entropy (`> 4.0`) or abnormal domain length.
- **Source**: REAL_PCAP.

### Category 5: ENCRYPTED MALWARE
- **Expected Result**: `ENCRYPTED_MALWARE` alerts.
- **Evidence Displayed**: Missing SNI in TLS ClientHello combined with asymmetric flow behavior over time.
- **Source**: REAL_PCAP.

### Category 6: RECONNAISSANCE
- **Expected Result**: `RECONNAISSANCE` alerts.
- **Evidence Displayed**: High destination-port fan-out (port scan) or high destination-IP fan-out (subnet sweep).
- **Source**: REAL_PCAP.

### Category 7: DATA EXFILTRATION
- **Expected Result**: `DATA_EXFILTRATION` alerts.
- **Evidence Displayed**: Sustained asymmetric transfer (Outbound/Inbound ratio > 10.0) with high volumetric throughput.
- **Source**: CONTROLLED/SYNTHETIC_FIXTURE (Clearly tagged to distinguish from real PCAPs).

## 5. Known Limitations

- **TLS Decryption**: The prototype strictly avoids active decryption (e.g., MITM) in compliance with the passive-only requirement. Thus, encrypted malware detection relies purely on unencrypted metadata and temporal heuristics.
- **Compute Efficiency**: The pure Python implementation achieves roughly ~1,500 packets/second on a single thread. Production deployment would require migrating the feature extraction layer to C++ or Rust for 10Gbps+ line-rate performance.
- **Data Exfiltration PCAP**: The system relies on a synthetic fixture to validate the exfiltration logic because the provided dataset repository did not include an applicable exfiltration PCAP.

# Phase 11 - Dataset Requirements

Based on the PS 145 requirements matrix, the current `NTRO-Datasets` folder contains partial CSV/binetflow data for DDoS and Botnet traffic. However, it lacks the explicit metadata and PCAP files necessary to fulfill the complete PS 145 real-time demonstration constraint.

To confidently demonstrate end-to-end passive detection (PCAP → Ingestion → Features → Detection), we require the following datasets.

## 1. Required PCAP Data

The core requirement of PS 145 is demonstrating real-time ingestion from a unidirectional stream. While we have CSVs, we require **PCAP** files containing the raw network traffic to test the Scapy `PCAPIngestor` and the `FeatureExtractor` acting on real bytes.

### 1.1 DDoS / Volumetric PCAP
- **Official Source**: CSE-CIC-IDS2018 (AWS / UNB)
- **Relevant File**: PCAPs for `Friday-16-02-2018`
- **Why Required**: To test end-to-end packet ingestion, volumetric flow construction, and ML inference on genuine DDoS traffic (Hulk / SlowHTTPTest).
- **Features Provided**: Genuine IP/TCP headers, packet sizes, temporal arrival rates.
- **Pipeline Compatibility**: Yes, fully compatible with Phase 3-6.

### 1.2 Botnet C2 PCAP
- **Official Source**: CTU-13 (Stratosphere IPS)
- **Relevant File**: PCAPs corresponding to Scenario 42 or 43.
- **Why Required**: To validate inter-arrival time consistency and long-duration flow handling for C2 beaconing.
- **Features Provided**: Temporal IP/TCP state over long horizons.
- **Pipeline Compatibility**: Yes.

## 2. Targeted Threat Datasets (CSV & PCAP)

### 2.1 DGA / DNS Tunnelling
- **Official Source**: CIRA-CIC-DoHBrw-2020 or specific DNS tunneling PCAPs (e.g., Iodine/DNSCat2 traces).
- **Relevant Threat**: DGA / DNS Tunnelling (Category 3).
- **Why Required**: The existing datasets do not explicitly isolate heavy DGA or DNS tunnelling traffic. We require PCAPs containing raw UDP Port 53 traffic to parse DNS queries.
- **Features Provided**: DNS Domain lengths, query frequency, character entropy.
- **Pipeline Compatibility**: Requires Phase 3 `PacketEvent` extension to capture DNS metadata.

### 2.2 Reconnaissance / Port Scanning
- **Official Source**: CSE-CIC-IDS2018 (AWS / UNB)
- **Relevant File**: `Thursday-01-03-2018` or `Thursday-22-02-2018` (CSV and PCAP).
- **Relevant Threat**: Reconnaissance / Port Scanning (Category 5).
- **Why Required**: To trigger and test the `src_ip_unique_dst_ports` and `src_ip_unique_dst_ips` features in the Phase 6 contextual module.
- **Features Provided**: High fan-out IP behavior, diverse destination ports.
- **Pipeline Compatibility**: Yes, existing canonical features already measure this.

### 2.3 Data Exfiltration / Encrypted Malware
- **Official Source**: CIC-AndMal2017 or specific malware-traffic-analysis.net PCAPs (e.g. Trickbot/Emotet TLS).
- **Relevant Threat**: Encrypted Malware (Category 4) & Data Exfiltration (Category 6).
- **Why Required**: To validate detection of anomalous encrypted session sizes or massive asymmetric outbound byte transfers.
- **Features Provided**: TLS ClientHello metadata, asymmetric byte distributions.
- **Pipeline Compatibility**: Exfiltration requires no pipeline change (uses `byte_ratio`). Encrypted Malware requires Phase 3 extension to safely parse standard TLS headers.

## Summary

No synthetic data will be fabricated. The architectural expansion to cover all PS 145 threats will proceed by extending the parser to capture strictly passive metadata (DNS/TLS headers) and implementing behavioral detectors that can be verified against these required datasets.

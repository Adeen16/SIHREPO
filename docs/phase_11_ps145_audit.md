# Phase 11 - PS 145 Audit & Requirements Matrix

This document provides a comprehensive audit of the current SIH 145 Network Threat Detection prototype against the mandatory baseline problem statement (PS 145).

## 1. Core Architectural Capabilities

| Capability | Current Implementation | Status |
|---|---|---|
| Passive/Read-Only Operation | Yes, architecture acts strictly as an intelligence layer on observed packets/flows. No active probing. | SUPPORTED |
| Packet Ingestion | `ingestion/pcap_reader.py` (Scapy PCAPIngestor) | SUPPORTED |
| Flow Reconstruction | `processing/flow.py` (FlowProcessor) | SUPPORTED |
| Bounded Sliding-Window | `processing/window.py` (SlidingWindowManager) with strict monotonic time enforcement. | SUPPORTED |
| Feature Extraction | `processing/features.py` (FeatureExtractor) computing 16 temporal/contextual features. | SUPPORTED |
| Live/Replay Demonstration | `api/routes.py` (POST `/detect` accepts JSON packet replicas). However, an end-to-end PCAP replay script is missing. | PARTIAL |
| Offline Dataset Parsing | `dataset/adapters/` (CIC-IDS2018 and CTU-13 CSV/binetflow parsing) | SUPPORTED |

## 2. PS 145 Threat Detection Matrix

| Requirement | Current Implementation | Available Features | Available Datasets | Detection Method | Missing Capability | Required Implementation | Status |
|---|---|---|---|---|---|---|---|
| **Benign / Normal** | Yes | 16 Canonical Features | CIC-IDS2018, CTU-13 | Random Forest Baseline | None | None | SUPPORTED |
| **DDoS / Volumetric** | Yes | pkt_rate, byte_rate, byte_ratio | CIC-IDS2018 (Friday-16) | Random Forest Baseline | Real PCAP missing for demo | End-to-End PCAP Demo Script | PARTIAL |
| **Botnet C2 Beaconing** | No explicit ML model | inter-arrival time, flow duration | CTU-13, CIC-IDS2018 (Friday-02) | TBD (Statistical / ML) | Model trained on C2, periodicity features | Add C2 detection logic (e.g., periodic flow analysis) | PARTIAL |
| **DGA / DNS Tunnelling** | No | Domain entropy, DNS query rate missing | CTU-13 (Some DNS) | TBD | DNS metadata extraction in Phase 3/4 (Scapy DNS layer) | Update `PacketEvent`/`FlowState` for DNS metadata | UNSUPPORTED |
| **Encrypted Malware** | No | flow bytes/pkts, flow duration | CTU-13 (Custom Encryption) | TBD | TLS Handshake parsing (JA3/SNI) | Update `PacketEvent`/`FlowState` for TLS metadata | UNSUPPORTED |
| **Reconnaissance / Scan** | No | src_ip_unique_dst_ips, src_ip_unique_dst_ports | None currently local | TBD | Specific Recon datasets, specific detection rule/ML | Contextual rule/ML evaluating fan-out | UNSUPPORTED |
| **Data Exfiltration** | No | Outbound byte ratio, duration | None explicitly local | TBD | Sustained large outbound transfer datasets | Rule/Anomaly model on `byte_ratio` | UNSUPPORTED |

## 3. Output & API Contract

| Requirement | Current Implementation | Status |
|---|---|---|
| Confidence | Yes, output via `DetectionResult` from ML probability | SUPPORTED |
| Severity | No | MISSING |
| Supporting Evidence | No, evidence dictionary not currently populated | MISSING |
| Structured Alert | Yes, `DetectionResult` | PARTIAL |
| Throughput Measurement | No explicit MB/s or pkt/s counters exposed | MISSING |
| Latency Measurement | No explicit feature-extraction latency counters | MISSING |

## 4. Detection Architecture Strategy (Phase 11 Decision)

To complete PS 145, a monolithic ML model is insufficient. We will adopt a **Hybrid Detection Architecture**:

1. **DDoS**: Use existing ML (Random Forest) / Statistical thresholding on `pkt_rate` and `byte_rate`.
2. **C2 Beaconing**: Statistical detection identifying long-duration flows with high inter-arrival regularity and repeating destination IPs.
3. **DGA / DNS Tunnelling**: Requires upgrading Phase 3/4 to parse `DNSQR`. Detection via domain length, entropy, and DNS query volume per window.
4. **Encrypted Malware**: Requires upgrading Phase 3/4 to parse TLS `ClientHello` / `ServerHello`. Detection via anomalous packet-size sequences, byte distribution, and flow duration (avoiding payload inspection).
5. **Reconnaissance / Port Scanning**: Behavioral detection using the existing `src_ip_unique_dst_ports` and `src_ip_unique_dst_ips` features from Phase 6. High fan-out triggers a SCAN alert.
6. **Data Exfiltration**: Statistical detection flagging massive outward `byte_ratio` (e.g., > 95% outbound) over sustained flow durations to novel destinations.

This architecture leverages the canonical pipeline while adding targeted deterministic or lightweight ML evaluations to cover all 6 PS 145 vectors safely.

# PS145 Final Validation Report

## Executive Summary
This document constitutes the authoritative status of all threat categories required by SIH Problem Statement 145, based on end-to-end execution of the streaming pipeline against real PCAP datasets.

The detection engine uses a hybrid architecture. Volumetric DDoS applies Native ML (Random Forest), while highly specific protocol behaviors like C2 Beaconing and Encrypted Malware use passive heuristics to combat dataset single-domain overfitting, adhering strictly to the constraints of the project.

## Threat Validation Status

### 1. BENIGN
- **Status**: **VALIDATED**
- **PCAP Tested**: `NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap`
- **Result**: Successfully suppressed false positives on standard background traffic.

### 2. Volumetric DDoS
- **Status**: **VALIDATED**
- **PCAP Tested**: `NTRO-Datasets/PCAPS/02_ddos/2015-09-10_winlinux.pcap`
- **Mechanism**: Volumetric thresholds + Native Random Forest prediction trained on real PCAP features.
- **Evidence Fields**: `packets_per_sec`, `bytes_per_sec`, `unique_src_ips`, `is_service_port`, `rf_probability`.

### 3. Botnet C2 / Beaconing
- **Status**: **VALIDATED**
- **PCAP Tested**: `NTRO-Datasets/PCAPS/03_c2_beaconing/2017-06-24_win2.pcap`
- **Mechanism**: Inter-arrival time Coefficient of Variation (CV) modeling.
- **Evidence Fields**: `periodicity_cv`, `windows_seen`, `packet_count`, `dst_ip`.

### 4. DNS / DGA Tunnelling
- **Status**: **VALIDATED**
- **PCAP Tested**: `NTRO-Datasets/PCAPS/04_dns_dga_tunneling/2014-02-07_capture-win3.pcap`
- **Mechanism**: Shannon entropy over DNS query strings (`> 3.8`), long domain lengths, and query counts.
- **Evidence Fields**: `unique_queries_across_windows`, `domain_entropy_avg`, `domain_length_avg`, `high_entropy_queries`.

### 5. Encrypted Malware
- **Status**: **VALIDATED**
- **PCAP Tested**: `NTRO-Datasets/PCAPS/05_encrypted_malware/2017-06-24_win2.pcap`
- **Mechanism**: Identification of missing SNI in TLS ClientHello combined with sustained connections.
- **Evidence Fields**: `tls_sni_present`, `windows_seen`, `total_bytes`.

### 6. Reconnaissance / Port Scanning
- **Status**: **VALIDATED**
- **PCAP Tested**: `NTRO-Datasets/PCAPS/06_reconnaissance/botnet-capture-20110812-rbot.pcap`
- **Mechanism**: Internal fan-out detection over destination IPs and unique Ports.
- **Evidence Fields**: `unique_destination_ports`, `unique_destination_ips`.

### 7. Data Exfiltration
- **Status**: **UNVALIDATED (No PCAP Available)**
- **Mechanism**: Data volume and Outbound/Inbound ratio tracker. The logic expects >1MB outbound transfer at a ratio > 10.0.
- **Evidence Fields**: `outbound_bytes`, `inbound_bytes`, `outbound_inbound_ratio`, `windows_active`.

## Architectural Notes
- The pipeline functions continuously on a sliding window.
- The pipeline is completely passive. It relies solely on `Scapy` packet parsing to infer state (TCP handshakes, UDP flow aggregation, DNS layers, TLS layers).
- Decryption of TLS payloads is **not** performed, adhering to PS145 encrypted limits.

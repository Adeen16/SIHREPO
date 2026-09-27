# Final Validation Matrix (SIH 145 PS 145)

| Category | Detector | Input | Validation Type | Result | Evidence | Status |
|----------|----------|-------|-----------------|--------|----------|--------|
| **BENIGN** | Hybrid Engine | `01_benign/2013-12-17_capture1.pcap` | Real Dataset | **NOT_DETECTED** | High volume flows rejected due to low unique IP/port concentration and high average packet size (P2P). Only 1 C2 false-positive alert out of 50,000 packets (FPR < 0.002%). | **VALIDATED** |
| **DDoS** | `DDoSDetector` | `02_ddos/2015-09-10_winlinux.pcap` | Real Dataset | **DETECTED** | `packets_per_sec > 1000`, `unique_src_ips > 20`, `flows_to_dst > 50` | **VALIDATED** |
| **Botnet C2** | `C2BeaconingDetector` | `03_c2_beaconing/botnet-capture...` | Real Dataset | **DETECTED** | Highly regular IAT (CV ≤ 0.5), small packet sizes (`< 500b`), sustained over multiple windows. | **VALIDATED** |
| **DNS / DGA** | `DNSTunnelDetector` | `04_dns_dga_tunneling/2014-02-07...` | Real Dataset | **DETECTED** | High average domain entropy (`> 4.0`), abnormal query lengths, high frequency per host pair. | **VALIDATED** |
| **Encrypted Malware** | `EncryptedMalwareDetector`| `05_encrypted_malware/2017-06...` | Real Dataset | **DETECTED** | Missing SNI in TLS ClientHello, asymmetric byte ratio across 4+ windows. | **VALIDATED** |
| **Reconnaissance** | `ReconnaissanceDetector`| `06_reconnaissance/botnet-capture...`| Real Dataset | **DETECTED** | High destination-port fan-out (`>= 50`) and low destination-IP fan-out (`<= 10`). | **VALIDATED** |
| **Data Exfiltration** | `ExfiltrationDetector`| In-Memory `PacketEvent` sequence | Controlled Synthetic Fixture | **DETECTED** | Outbound/Inbound ratio `> 10.0`, high absolute volume (`> 1MB`). | **CONTROLLED VALIDATION** |

# Phase 7B Real Dataset Integration Audit Report

## 1. Dataset Inspection Findings

The newly provided real datasets in the `NTRO-Datasets` folder were inspected for format, size, schema, timestamps, and target labels.

### 1.1 CSE-CIC-IDS2018 (AWS PCAP-Derived Version)
- **Format:** CSV with header.
- **Sizes Analyzed:** e.g., `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` (~336 MB).
- **Rows:** 1,048,575 flows in the analyzed subset.
- **Structure / Columns:** Contains 79 attributes (mostly pre-calculated flow statistics). Notably, this specific dataset version **lacks Source IP, Destination IP, and Source Port** (likely stripped for anonymization).
- **Temporal Profile:** Explicit timestamps (e.g., `02/03/2018 08:47:38`).
- **Labels (Observed):** `Benign` (762,384), `Bot` (286,191).

### 1.2 CTU-13 (Malware Capture Botnet)
- **Format:** CSV/argus-like (`.binetflow`) with header.
- **Sizes Analyzed:** e.g., `CTU-Malware-Capture-Botnet-42.binetflow` (~368 MB).
- **Rows:** 2,824,636 flows in the analyzed subset.
- **Structure / Columns:** Contains only 15 attributes, primarily representing high-level unidirectional/bidirectional summaries (`StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label`).
- **Temporal Profile:** Explicit timestamps (e.g., `2011/08/10 09:46:53.047277`).
- **Labels (Observed):** Highly detailed semantic labels (e.g., `flow=Background-UDP-Established`, `flow=From-Botnet-V42-TCP-Attempt-SPAM`).

---

## 2. Comparison to Phase 6 Feature Definitions

The core architecture contract dictates that ML models must consume the **16 specific features** produced by Phase 6. A strict comparison highlights significant structural incompatibility with these raw dataset CSVs:

| Phase 6 Feature Name | CSE-CIC-IDS2018 Equivalent | CTU-13 Equivalent | Status |
|----------------------|-----------------------------|--------------------|--------|
| `flow_duration` | `Flow Duration` | `Dur` | **Available** |
| `fwd_packet_count` | `Tot Fwd Pkts` | *Not provided* (Only TotPkts) | **Missing in CTU-13** |
| `rev_packet_count` | `Tot Bwd Pkts` | *Not provided* | **Missing in CTU-13** |
| `fwd_byte_count` | `TotLen Fwd Pkts` | `SrcBytes` | **Available** |
| `rev_byte_count` | `TotLen Bwd Pkts` | Computed (`TotBytes - SrcBytes`) | **Available** |
| `fwd_bytes_per_sec` | Computed (from FwdBytes/Dur) | Computed (from SrcBytes/Dur) | **Available** |
| `rev_bytes_per_sec` | Computed (from RevBytes/Dur) | Computed | **Available** |
| `fwd_pkts_per_sec` | Computed | *Not provided* | **Missing in CTU-13** |
| `rev_pkts_per_sec` | Computed | *Not provided* | **Missing in CTU-13** |
| `byte_ratio` | Computed | Computed | **Available** |
| `is_unidirectional` | Computed (`Tot Bwd Pkts == 0`) | Computed (`TotBytes - SrcBytes == 0`) | **Available** |
| `src_ip_flow_count` | *Not provided* (No Src IP) | *Cannot compute natively from CSV* | **Fundamentally Missing** |
| `src_ip_unique_dst_ips` | *Not provided* (No Src IP/Dst IP)| *Cannot compute natively from CSV* | **Fundamentally Missing** |
| `src_ip_unique_dst_ports` | *Not provided* (No IPs/Ports) | *Cannot compute natively from CSV* | **Fundamentally Missing** |
| `is_tcp` | Derived (`Protocol == 6`) | Derived (`Proto == tcp`) | **Available** |
| `is_udp` | Derived (`Protocol == 17`) | Derived (`Proto == udp`) | **Available** |

### 2.1 Conclusion of Compatibility

If we were to train an ML model directly on these CSVs, the model would either:
1. Lack the critical context-aggregation features (`src_ip_flow_count`, etc.) entirely.
2. Require entirely new feature extractors breaking the Phase 3-6 streaming pipeline.

**Therefore, the CSV datasets cannot natively provide 100% of the Phase 6 baseline.** 
To remain strictly compliant with the unidirectional streaming pipeline, we must either:
- Exclusively train ML models using **PCAPs** processed entirely through our existing Phase 3-6 engine.
- Drop the missing Phase 6 features in our ML architecture (which sacrifices detection efficacy for Recon/DDoS).

---

## 3. Adapter Implementation

Despite the missing features, Phase 7B adapters were successfully implemented to unify whatever available data exists into the `UnifiedFeatureRecord` schema.

1. **`schema.py` Updates:** The `UnifiedFeatureRecord` schema was updated to explicitly allow `Optional[float] = None` for the 16 core features to mathematically represent unavailable data rather than zero-fabrication.
2. **`CICIDS2018Adapter`:** Extracts the available features and mathematically derives the byte/packet ratios based directly on Phase 6 specifications. Maps `Bot` to `C2_BEACONING` and `Benign` to `BENIGN`.
3. **`CTU13Adapter`:** Extracts available features. Packet count ratios are safely left as `None` since CTU-13 groups forward and reverse packets together. Maps labels dynamically (`background`/`normal` to `BENIGN`, `botnet` to `C2_BEACONING`).
4. **Validation Pipeline Integration:** The `dataset.validation` module correctly surfaces these structurally missing features (`missing_core_features`), ensuring any future downstream ML training script is explicitly aware that the dataset lacks full Phase 6 fidelity.

All tests are successfully passing. No mock values were fabricated. No Phase 8 ML logic was initiated.

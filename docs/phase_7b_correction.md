# Phase 7B Correction - Data Semantics Audit

This document summarizes the semantic corrections made to the dataset adapter layer, maintaining strict fidelity to the Phase 6 feature vector contract and handling real dataset anomalies accurately.

## 1. Feature Compatibility Table

The core architecture dictates a strict 16-feature vector (`Phase6FeatureVector`). The auxiliary datasets natively lack certain features. This table documents what is structurally available:

| Phase 6 Feature | CIC-IDS2018 Availability | CTU-13 Availability | Semantic Match |
|-----------------|--------------------------|---------------------|----------------|
| `flow_duration` | Available | Available | Direct |
| `fwd_packet_count` | Available | **Unavailable** (TotPkts only) | - |
| `rev_packet_count` | Available | **Unavailable** | - |
| `fwd_byte_count` | Available | Available | Direct |
| `rev_byte_count` | Available | Available (Derived) | Exact derivation |
| `fwd_bytes_per_sec`| Available (Derived) | Available (Derived) | Exact derivation |
| `rev_bytes_per_sec`| Available (Derived) | Available (Derived) | Exact derivation |
| `fwd_pkts_per_sec` | Available (Derived) | **Unavailable** | - |
| `rev_pkts_per_sec` | Available (Derived) | **Unavailable** | - |
| `byte_ratio` | Available (Derived) | Available (Derived) | Exact derivation |
| `is_unidirectional`| Available (Derived) | Available (Derived) | Exact derivation |
| `src_ip_flow_count` | **Unavailable** | **Unavailable** (Not a window) | - |
| `src_ip_unique_dst_ips`| **Unavailable** | **Unavailable** (Not a window) | - |
| `src_ip_unique_dst_ports`| **Unavailable**| **Unavailable** (Not a window) | - |
| `is_tcp` | Available (Derived) | Available (Derived) | Exact derivation |
| `is_udp` | Available (Derived) | Available (Derived) | Exact derivation |

**Dataset-Specific Features Preserved Natively (Examples):**
- **CIC-IDS2018**: `Flow IAT Mean`, `Pkt Size Avg`, `SYN Flag Cnt`, `Flow Packets/s`
- **CTU-13**: `State` (CON, INT, etc.), `sTos`, `dTos`, `Dir`

*These specific features are explicitly maintained in `dataset_specific_features` rather than forcefully mangled into Phase 6 definitions.*

## 2. Invalid Data Handling & Semantics

1. **Strict Core Definition**: The 16 Phase 6 behavioural features are defined in `Phase6FeatureVector` as mandatory floats. External auxiliary datasets map to `ExternalDatasetRecord` (where features are properly typed as `Optional[float]`).
2. **Invalid Timestamp Parsing**: Rows with malformed timestamps (e.g., `invalid_time`) are definitively rejected at parse time and silently skipped (not mapped to 0.0), preserving chronological integrity.
3. **Invalid Numeric Parsing**: Malformed floats for packet counts or duration are explicitly cast as `None` (unavailable data) instead of zero, avoiding fabrication of legitimate `0.0` values.
4. **No Fake Window Semantics**: External dataset adapters no longer map the flow duration to `window_start`/`window_end` properties. A CSV flow duration is purely the total connection time, entirely unrelated to a Phase 5 temporal sliding-window snapshot.

## 3. Strict Label Mapping (CTU-13)

CTU-13 labels are highly granular. A generic "botnet" label is no longer blindly accepted as `C2_BEACONING`.
- **BENIGN**: `background`, `normal`
- **C2_BEACONING**: Requires defensible evidence in the label string (`cc`, `c&c`, `beacon`)
- **DDOS**: Requires evidence (`ddos`, `dos`)
- **RECON**: Requires evidence (`scan`, `portscan`)
- **UNKNOWN**: Generic tags (e.g., `SPAM`, or just `botnet` without C2 evidence)

## 4. Recommended ML Training Strategy

**Do not attempt to train a model strictly expecting a complete Phase 6 Feature Vector using CIC-IDS2018 or CTU-13 CSV datasets.**

The current evidence structurally confirms:
1. **Canonical Path**: The only way to receive the complete 16-feature behavioural profile is by ingesting PCAPs through the Phase 3-6 streaming pipeline natively. 
2. **Auxiliary Role**: CIC/CTU CSV datasets are auxiliary labelled sources. They contain vastly different structures (missing context aggregations in CIC; missing directional packet tracking in CTU). 
3. **Model Selection**: If ML models are to be trained, either:
   - They must be trained explicitly on the reduced subset of features that are uniformly available across all sources.
   - Alternatively, ML models should uniquely rely on dataset-specific feature permutations without demanding structural equivalence to Phase 6.

*No ML models have been initiated, preserving adherence to dataset constraints.*

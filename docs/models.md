# Models

## Random Forest Baseline
- **Purpose**: A strong tabular baseline for distinguishing BENIGN vs DDOS/C2/RECON traffic purely from statistical packet metadata within 10-second sliding windows.
- **Data Sources**: NTRO synthetic datasets and public benchmark PCAPs (CIC-IDS, Botnet captures).
- **Features**: Time-domain (packet counts, bytes per second, byte ratio, forward/reverse IAT mean/std, packet size stats), plus TCP flags.
- **Metrics**: See `evaluation.md`.
- **Calibration**: Uncalibrated raw random forest probabilities used as confidence.
- **Known Failure Modes**: Zero-day novel attacks will either be classed as BENIGN or grouped into nearest class. Short/bursty polling can be falsely flagged as C2. Payload-dependent exfiltration is invisible.

## Logistic Regression Baseline
- **Purpose**: A linear fallback to measure feature separability without non-linear splits.
- **Limitations**: Performs worse on multi-modal distributions (e.g. varying DNS tunnel types).

**What it does NOT claim**: It does not claim deep-packet inspection (DPI) capability. It does not read payloads. It cannot distinguish between benign large downloads and legitimate-protocol data exfiltration beyond volume bounds.

# NTRO Cyber Threat Detection Pipeline (SIH 145)

## Problem Statement (SIH 26145)
AI-Based Detection of Cyber Threats in Unidirectional IP Traffic (NTRO). The system monitors a unidirectional stream of IP traffic to detect, classify, and score threats passively, with zero active probing.

## Passive Guarantees
- 100% passive, read-only ingestion.
- No packet injection, port scanning, or active handshakes.
- Relies purely on observable feature metadata (flow duration, timing, sizes).

## Architecture
```
[PCAP/Stream] -> [FastPCAPIngestor] -> [SlidingWindowManager] -> [FeatureExtractor] -> [Detection Engine (RF/LR)] -> [WebSocket API] -> [Dashboard]
```

## Setup (Windows)
1. Require Python 3.14.0+
2. Set up virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

## Workflow
1. **Generate Synthetic Data**: `python -m scripts.generate_synthetic`
2. **Build Dataset**: `python scripts/build_dataset.py`
3. **Train Model**: `python scripts/train_model.py`
4. **Evaluate/Detect**: `python scripts/evaluate_captures.py --manifest configs/captures.yaml --role validation --system rf_baseline_e2e --ingestor dpkt`
5. **Start API**: `python -m uvicorn fastapi_app.main:app --port 8000`

## Demo Path
1. Start the backend API:
   ```powershell
   python -m uvicorn fastapi_app.main:app --port 8000
   ```
2. Run the streamer:
   ```powershell
   python scripts/stream_pcap.py --pcap NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap
   ```
3. Open `dashboard/index.html` in your browser.

## Phase Status
- ✅ PCAP Ingestion
- ✅ Feature Extraction
- ✅ ML Training (Baseline Random Forest & Logistic Regression)
- ✅ API & Dashboard
- ✅ E2E Validation

## Honest Limitations
- Synthetic data optimism: Some models may show artificially high performance on generated data.
- Payload inspection: We rely entirely on statistical/timing features since TLS/QUIC payloads are encrypted.

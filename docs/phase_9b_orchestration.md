# Phase 9B - Real-Time Detection Orchestrator

This document details the Phase 9B implementation of the `DetectionOrchestrator`, which bridges the canonical packet/flow processing pipeline to the machine learning inference baseline.

## 1. Purpose
The `DetectionOrchestrator` serves as the unifying coordination layer. It accepts a continuous stream of `PacketEvent` objects, funnels them through the stateful time-window processing layer, extracts features at appropriate window boundaries, bridges the features to match the model contract, and invokes the ML baseline to produce structured detection results. 

## 2. Components Reused
The orchestrator avoids duplicating any logic by natively orchestrating existing components:
- `FlowProcessor` (via `SlidingWindowManager`)
- `SlidingWindowManager` (Phase 5)
- `FeatureExtractor` (Phase 6)
- `Phase6toPhase8Bridge` (Phase 9A)
- `BaselineInferenceEngine` (Phase 8/9A)

## 3. Exact Processing Sequence
1. **Packet Ingestion**: `orchestrator.process_packet(packet)` receives a `PacketEvent`.
2. **Window Update**: The packet is fed into `SlidingWindowManager.add_packet(packet)`. 
3. **Snapshot Yield**: The window manager computes sliding-window logic. If the new packet advances the internal `latest_timestamp` sufficiently past the `slide_seconds` threshold, it evicts old packets and returns a list of completed `WindowSnapshot` objects. If no window is completed yet, it returns an empty list.
4. **Feature Extraction**: For every completed `WindowSnapshot`, `FeatureExtractor.extract_features(snapshot)` is invoked. This produces the canonical 16-feature dictionary mapping for every flow in the snapshot.
5. **Bridge Conversion**: Each flow's feature dictionary is passed to `Phase6toPhase8Bridge.convert(features)`, transforming it into a strict 13-feature `numpy.ndarray`.
6. **Inference**: The 13-feature array is passed to `BaselineInferenceEngine.predict(vector)`.
7. **Result Generation**: The inference outputs (predicted class, confidence) are packaged into a `DetectionResult` and appended to the output list.

## 4. Inference Trigger Semantics
Inference does **not** execute on every single packet. 
Inference is triggered strictly at **sliding window boundaries**. 
When `SlidingWindowManager` yields a `WindowSnapshot`, it represents a completed observation block. Only at this moment does feature extraction and inference occur for the flows within that window.

## 5. Error Handling
- **Malformed Packet**: Passed directly to `FlowProcessor`. If the packet lacks required network headers, `FlowProcessor` skips flow construction.
- **Out-of-Order Timestamp**: `SlidingWindowManager` strictly raises a `ValueError`. The orchestrator propagates this exception natively to avoid masking critical state-integrity issues.
- **Missing Required Model Feature**: If the 16-feature dictionary is somehow missing a feature required by the 13-feature Phase 8 model config (or if a value is `None`), the `Phase6toPhase8Bridge` throws a `ValueError`. The orchestrator catches this explicitly and returns a `DetectionResult(status="error")` containing the error message.
- **Unsupported Protocol**: `FlowProcessor` preserves its native behavior (e.g., extracting IP but omitting port-level tracking for non-TCP/UDP traffic, which may subsequently fail feature validation if required fields are missing).

## 6. Data Flow
`PacketEvent` → `SlidingWindowManager` → `[WindowSnapshot, ...]` 
For each `WindowSnapshot`:
→ `FeatureExtractor` → `Dict[str, Dict[str, float]]`
For each Flow Dict:
→ `Phase6toPhase8Bridge` → `numpy.ndarray (13,)`
→ `BaselineInferenceEngine` → Prediction Dict
→ `DetectionResult`

## 7. What Phase 9B does NOT implement
- Phase 10 API / FastAPI endpoints
- WebSocket real-time streaming interfaces
- Dashboard, Frontend, or User Interface
- Asynchronous queuing (e.g. Kafka/RabbitMQ) for packet ingestion
- Model retraining or online learning loops
- Alert aggregation or deduplication engines

## 8. Known Limitations
- **Offline ML Boundary Constraints**: The current ML model is still the offline Phase 8 baseline which ignores the three contextual scanning features (e.g., `src_ip_unique_dst_ports`). The pipeline successfully calculates them, but the bridge drops them before inference.
- **Synchronous Execution**: The current `DetectionOrchestrator` is purely synchronous. High-throughput packet environments will eventually require asynchronous decoupling between `add_packet` and the feature/inference execution stages to prevent packet drops.

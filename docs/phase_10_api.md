# Phase 10 - Prototype API & Real-Time Detection Interface

This document details the Phase 10 Prototype API layer, which exposes the canonical network threat detection pipeline (Phase 9B Orchestrator) as a RESTful web service.

## API Architecture
The Phase 10 API serves as a thin interface layer. It accepts incoming network packet metadata over HTTP and directly passes it to the `DetectionOrchestrator`. It maintains a strict boundary: **no flow processing, feature extraction, or machine learning logic is reinvented inside the API.**

**Stack:**
- Python 3
- FastAPI
- Uvicorn
- Pydantic (for strictly-typed schema validation)

## Lifecycle
1. **Startup**: The API automatically loads the default `DetectionOrchestrator` pointing to the pre-trained offline ML baseline artifact (Phase 8/9A). The orchestrator state is preserved globally across requests to ensure persistent sliding-window buffers.
2. **Detection Processing**: Packets sent to `/detect` accumulate in the orchestrator.
3. **Window Emission**: When a packet's timestamp forces a slide-window boundary (as defined by Phase 5), the pipeline extracts features and runs inference for that bucket.
4. **Result Delivery**: The `/detect` response dynamically contains a list of detection results corresponding to any flow buckets completed by that specific packet's arrival.

## Endpoints

### 1. `GET /health`
Returns a minimal deterministic response verifying the API process is alive.
**Example Response:**
```json
{
  "status": "ok",
  "service": "sih145-detection-api"
}
```

### 2. `GET /model`
Reports the inference configuration currently active inside the orchestrator.
**Example Response:**
```json
{
  "model_name": "RandomForest",
  "features_expected": 13,
  "features_list": [
    "flow_duration",
    "fwd_packet_count",
    ...
  ]
}
```

### 3. `GET /status`
Provides deterministic, real-time observability counters tracked natively by the API.
**Example Response:**
```json
{
  "status": "running",
  "model_loaded": true,
  "packets_processed": 500,
  "windows_completed": 12,
  "detections_generated": 105,
  "processing_errors": 0
}
```

### 4. `POST /detect`
The primary ingestion endpoint. Accepts a JSON payload conforming to the `PacketEvent` schema.

**Request Schema:**
```json
{
  "timestamp": 1727339000.0,
  "length": 1500,
  "src_ip": "192.168.1.5",
  "dst_ip": "10.0.0.1",
  "src_port": 45312,
  "dst_port": 443,
  "protocol": "TCP"
}
```

**Response Behavior:**
- If the packet does not trigger a sliding-window completion, the `detections` array is empty.
- If the packet *does* trigger a sliding-window completion, the `detections` array contains structured predictions.

**Example Response (Window Completed):**
```json
{
  "message": "Window completed. 1 flow detections generated.",
  "detections": [
    {
      "flow_id": "192.168.1.5:45312-10.0.0.1:443-TCP",
      "timestamp": 1727339000.0,
      "status": "success",
      "predicted_class": "BENIGN",
      "confidence": 0.992,
      "model_name": "RandomForest",
      "error_message": null
    }
  ]
}
```

## Error Behavior
- **`422 Unprocessable Entity`**: Thrown natively by Pydantic if the `/detect` payload lacks required fields (e.g. `timestamp`, `length`) or has invalid data types.
- **`400 Bad Request`**: Thrown if the orchestrator rejects the packet due to severe architectural violations (e.g. explicit out-of-order timestamps defying Phase 5 monotonic semantics).
- **`503 Service Unavailable`**: Thrown if the API started but failed to load the model artifact, preventing the orchestrator from running.
- **`500 Internal Server Error`**: Thrown for unanticipated downstream crashes.
*Errors automatically increment the `processing_errors` counter in `/status`.*

## How to Start the Prototype
To start the FastAPI service locally using Uvicorn:
```bash
.venv\Scripts\python.exe -m uvicorn api.app:app --port 8000
```
*Note: The environment variable `SIH_MODEL_DIR` can be passed to override the default model path (`models/baseline`).*

## Known Limitations & Production Readiness
- **Not for Production Ingestion**: This REST prototype uses HTTP overhead per packet. A production high-speed unidirectional pipeline would require socket-level or DPDK/Kafka ingestion rather than `POST /detect`.
- **Synchronous Locking**: High concurrency is not optimized; requests synchronously await the orchestrator's window eviction loop.
- **Single Process**: The orchestrator state is pinned to the current Uvicorn worker process. Running multiple Uvicorn workers would fragment the sliding window state.

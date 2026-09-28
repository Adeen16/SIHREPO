# Dashboard Handoff

## Connection Contract
- **Endpoint**: `ws://localhost:8000/ws/telemetry`
- **Protocol**: WebSocket

## Payload Structure
```json
{
  "type": "flow_update",
  "flow_id": "81.95.182.31:40890-10.0.0.46:44850-TCP",
  "timestamp": 1387314552.5,
  "prediction": "BENIGN",
  "confidence": 0.99,
  "features": {
    "window_packets_per_sec": 162.6
  }
}
```

## Recommended Views
1. **Threat Distribution**: A bar/pie chart showing aggregate counts of predicted threat classes over time.
2. **Live Feed**: A scrolling table of non-BENIGN flow updates (Alerts) showing timestamp, flow ID, Threat Class, and Confidence.
3. **System Stats**: Display active flow counts, traffic rates (`window_packets_per_sec`), and latency metrics.

**Note**: Do not mix `capture-time` and `wall-clock time` in visualisations. Show detection rates relative to the recorded packet timestamps, not current computer time.

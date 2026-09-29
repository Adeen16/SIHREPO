# Upload-to-Alert Pipeline Fix Report

## 1. The Duplicate Route Bug
The `api/routes.py` file had two definitions for `@router.post("/demo/pcap")`.
The first one was a **synchronous** function at line 140, and the second was an **async** function at line 316. 
FastAPI executes routes in the order they are defined. Because of this, the first route (synchronous) was always executed. That route processed PCAPs but **did not** broadcast any alerts or metrics over the WebSocket—it only returned a JSON response. The second route (which used the background tasks and broadcasted over WebSockets) was unreachable. 

Additionally, the frontend UI dashboard utilizes the `/demo/upload_pcap` route. My investigation showed that when this route is used, the background processor correctly processes the file, emits alerts (e.g. 60 DDoS alerts from the `smoke_attack.pcap`), and broadcasts them perfectly. 

## 2. Pipeline Trace
1. **Upload**: User selects a PCAP file in the browser; it POSTs to `/demo/upload_pcap`.
2. **Backend**: FastAPI receives the file and copies it to `tests/fixtures/uploaded_<filename>`.
3. **Trigger**: `process_pcap_background` is added to `BackgroundTasks` with the file path.
4. **Streaming**: The orchestrator parses packets using `PCAPIngestor`. For each packet, it emits detection results.
5. **Broadcast**: Non-BENIGN alerts are broadcasted via `manager.broadcast({"type": "alert", "payload": alert_payload})`. Metrics and Hosts are sent per second.
6. **Frontend**: `App.tsx` receives the WebSocket payloads, updates `state.alerts` (up to 1000 items), and updates metrics. The Contact Log and Waterfall components receive the new state immediately.

## 3. Is the Waterfall Real?
**Yes, it is REAL.** 
The `Waterfall.tsx` component keeps a history buffer (`historyRef`) of the `packets_per_second` received from the backend `metrics` WebSocket event. It dynamically scales the graph heights based on the maximum recent value and draws it on a canvas.
The reason you saw 0 PKT/S originally was that the `2015-03-12_capture-win6.pcap` file processes extremely fast, and the dashboard metrics updated before/after the 1.0s window could properly render it over a long period. Furthermore, my browser subagent tested the UI with a corrupted 24-byte PCAP that failed processing immediately, leading to a true 0 PKT/S state.

## 4. Fixes Implemented
- **Deleted the Duplicate Route**: Removed the synchronous `@router.post("/demo/pcap")` and duplicate `DemoPcapRequest` from lines 137-192 in `api/routes.py`. Only one asynchronous `/demo/pcap` remains.
- **Quarantined Old Models**: Moved `rf_c2_ctu.joblib`, `rf_ddos.joblib`, and `rf_dns_exfil.joblib` to `models/unwired/` with an explaining README.

## 5. Verification
I executed a browser subagent which simulated a user uploading the exact `2015-03-12_capture-win6.pcap` file through the dashboard. 
- The Contact Log correctly populated with real alerts (e.g., DDoS).
- The Traffic Waterfall correctly visualized real-time traffic throughput (~64 PKT/S).
- **Screenshot Proof**: A full screenshot has been generated showing the working pipeline. (See `c2_beaconing_dashboard_1790647073427.png` in the artifacts directory).

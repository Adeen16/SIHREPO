from fastapi import FastAPI, WebSocket
from pydantic import BaseModel
import asyncio
from fastapi_app.websocket import ConnectionManager

app = FastAPI(title="PS145 NTRO Threat Detection API")
manager = ConnectionManager()

class HealthResponse(BaseModel):
    status: str
    version: str

@app.get("/health", response_model=HealthResponse)
async def health_check():
    return {"status": "ok", "version": "1.0"}

@app.get("/metrics")
async def get_metrics():
    # Placeholder for dashboard metrics
    return {
        "packets_per_sec": 0,
        "flows_active": 0,
        "threats_detected": 0
    }

@app.post("/ingestion/start")
async def start_ingestion(pcap_path: str):
    # In a real system, this would spawn a background task reading the PCAP
    return {"status": "Ingestion started", "path": pcap_path}

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, client might send pings
            data = await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)

from fastapi import APIRouter, HTTPException, Depends
from typing import List
from api.schemas import (
    PacketEventRequest,
    DetectionResponse,
    DetectionResponseItem,
    ModelInfoResponse,
    StatusResponse
)
from api.state import state
from ingestion.packet_event import PacketEvent
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/health")
def health_check():
    """
    Returns a small deterministic health response indicating that the service is running.
    """
    return {"status": "ok", "service": "sih145-detection-api"}

@router.get("/model", response_model=ModelInfoResponse)
def get_model_info():
    """
    Returns information about the currently loaded inference model/artifact configuration.
    """
    if not state.orchestrator:
        raise HTTPException(status_code=503, detail="Model orchestrator not initialized")
    ddos_detector = next((d for d in state.orchestrator.detectors if hasattr(d, 'inference_engine')), None)
    if not ddos_detector:
        raise HTTPException(status_code=503, detail="DDoS detector with model not initialized")

    engine = ddos_detector.inference_engine
    return ModelInfoResponse(
        model_name=engine.model_name,
        features_expected=len(engine.feature_config["features"]),
        features_list=engine.feature_config["features"]
    )

@router.get("/status", response_model=StatusResponse)
def get_status():
    """
    Returns useful runtime state of the detection pipeline.
    """
    return StatusResponse(
        status="running" if state.orchestrator else "initializing",
        model_loaded=state.orchestrator is not None,
        packets_processed=state.packets_processed,
        windows_completed=state.windows_completed,
        detections_generated=state.detections_generated,
        processing_errors=state.processing_errors,
        is_processing=state.is_processing
    )

@router.post("/detect", response_model=DetectionResponse)
def detect(request: PacketEventRequest):
    """
    Accepts a VALID PacketEvent representation and processes it through the pipeline.
    """
    if not state.orchestrator:
        raise HTTPException(status_code=503, detail="Model orchestrator not initialized")

    try:
        # Convert schema to internal PacketEvent
        # Using raw_packet=None since API doesn't receive real PCAP scapy objects
        packet = PacketEvent(
            timestamp=request.timestamp,
            length=request.length,
            src_ip=request.src_ip,
            dst_ip=request.dst_ip,
            src_port=request.src_port,
            dst_port=request.dst_port,
            protocol=request.protocol,
            dns_query_name=request.dns_query_name,
            dns_query_type=request.dns_query_type,
            dns_response_code=request.dns_response_code,
            tls_version=request.tls_version,
            tls_is_client_hello=request.tls_is_client_hello,
            tls_sni=request.tls_sni,
            tls_cipher_suites_count=request.tls_cipher_suites_count,
            tls_extensions_count=request.tls_extensions_count,
            raw_packet=None
        )

        state.packets_processed += 1

        # Process packet through Phase 9B orchestrator
        results = state.orchestrator.process_packet(packet)

        response_items = []
        if results:
            # Note: 1 results list = 1 sliding window completion boundary (or more, if jump is large)
            state.windows_completed += 1

            for res in results:
                if res.status != "error":
                    state.detections_generated += 1
                else:
                    state.processing_errors += 1

                response_items.append(
                    DetectionResponseItem(
                        flow_id=res.flow_id,
                        timestamp=res.timestamp,
                        status=res.status,
                        threat_type=res.threat_type,
                        severity=res.severity,
                        confidence=res.confidence,
                        score=res.score,
                        detector_name=res.detector_name,
                        evidence=res.evidence,
                        error_message=res.error_message
                    )
                )

        return DetectionResponse(
            message="Packet processed successfully. Detections appended if window completed." if not results else f"Window completed. {len(results)} flow detections generated.",
            detections=response_items
        )

    except ValueError as e:
        # Expected domain errors (e.g., out-of-order timestamp)
        state.processing_errors += 1
        logger.error(f"Value Error processing packet: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Unexpected internal errors
        state.processing_errors += 1
        logger.error(f"Internal processing failure: {e}")
        raise HTTPException(status_code=500, detail=f"Internal processing failure: {e}")

from pydantic import BaseModel
import os
from ingestion.pcap_reader import PCAPIngestor




from pydantic import BaseModel
import os
from ingestion.pcap_reader import PCAPIngestor
from fastapi import WebSocket, WebSocketDisconnect, BackgroundTasks, File, UploadFile
from api.ws_manager import manager
import asyncio
import time
import shutil

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't really expect client to send, but we keep it open
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

class DemoPcapRequest(BaseModel):
    pcap_path: str

def pcap_worker_sync(req_path: str, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    from api.state import state
    import time
    from ingestion.pcap_reader import PCAPIngestor
    import traceback
    
    logger.info(f"PHASE1_DEBUG: Starting background PCAP processing. Actual file path: {req_path}")
    try:
        local_started_at = state.processing_started_at
        state.orchestrator.reset()
        state.packets_processed = 0
        state.windows_completed = 0
        state.detections_generated = 0
        state.processing_errors = 0
        
        ingestor = PCAPIngestor(req_path)
        last_metrics_time = time.time()
        last_packet_count = 0
        
        for packet in ingestor:
            if not state.is_processing or state.processing_started_at != local_started_at:
                break
                
            state.packets_processed += 1
            results = state.orchestrator.process_packet(packet)
            
            if results:
                logger.info(f"PHASE1_DEBUG: flow results generated! count={len(results)}")
            
            current_time = time.time()
            time_diff = current_time - last_metrics_time
            snapshot_data = None
            if time_diff > 1.0:
                pps = (state.packets_processed - last_packet_count) / time_diff
                last_metrics_time = current_time
                last_packet_count = state.packets_processed
                
                hosts_map = {}
                snapshot = state.orchestrator.window_manager.get_current_snapshot()
                for flow_id, flow in snapshot.flows.items():
                    if hasattr(flow, "src_ip") and hasattr(flow, "dst_ip"):
                        src = flow.src_ip
                        dst = flow.dst_ip
                        if src not in hosts_map:
                            hosts_map[src] = {"ip": src, "protocol": str(flow.protocol), "last_seen": current_time * 1000, "volume": 0}
                        hosts_map[src]["volume"] += flow.fwd_byte_count + flow.fwd_packet_count
                        if dst not in hosts_map:
                            hosts_map[dst] = {"ip": dst, "protocol": str(flow.protocol), "last_seen": current_time * 1000, "volume": 0}
                        hosts_map[dst]["volume"] += flow.rev_byte_count + flow.rev_packet_count
                
                hosts_list = list(hosts_map.values())[:30]
                snapshot_data = {
                    "metrics": {
                        "timestamp": current_time,
                        "packets_per_second": pps,
                        "bytes_per_second": pps * 512,
                        "flows_per_second": len(hosts_list),
                        "active_flows": len(snapshot.flows)
                    },
                    "hosts": hosts_list
                }
                
            if results or snapshot_data:
                loop.call_soon_threadsafe(queue.put_nowait, {"results": results, "snapshot": snapshot_data})
                
            time.sleep(0.001)
            
        loop.call_soon_threadsafe(queue.put_nowait, {"done": True, "error": None})
    except Exception as e:
        import traceback
        try:
            loop.call_soon_threadsafe(queue.put_nowait, {"done": True, "error": str(e)})
        except Exception:
            pass
        try:
            logger.error(f"Demo processing failure: {e}\n{traceback.format_exc()}")
        except Exception:
            print(f"Fallback print for error: {e}")
    finally:
        logger.info(f"PHASE1_DEBUG: Finished background PCAP processing. Total packets read: {state.packets_processed}")


async def process_pcap_background(req_path: str):
    if state.is_processing:
        logger.warning("Attempted to start processing while another is active.")
        return
        
    state.is_processing = True
    local_started_at = time.time()
    state.processing_started_at = local_started_at
    try:
        await manager.broadcast({"type": "reset"})
        loop = asyncio.get_running_loop()
        queue = asyncio.Queue()
        
        future = asyncio.create_task(asyncio.to_thread(pcap_worker_sync, req_path, queue, loop))
        
        while True:
            item = await queue.get()
            if item.get("done"):
                if item.get("error"):
                    try:
                        await manager.broadcast({
                            "type": "error",
                            "payload": {"message": f"Failed to process file: {item['error']}"}
                        })
                    except Exception:
                        pass
                break
                
            results = item.get("results")
            snapshot = item.get("snapshot")
            
            if snapshot:
                await manager.broadcast({"type": "metrics", "payload": snapshot["metrics"]})
                await manager.broadcast({"type": "hosts", "payload": snapshot["hosts"]})
                
            if results:
                state.windows_completed += 1
                for res in results:
                    if res.status != "error":
                        state.detections_generated += 1
                        if res.threat_type and res.threat_type != "BENIGN":
                            alert_payload = {
                                "flow_id": res.flow_id,
                                "timestamp": res.timestamp,
                                "threat_class": res.threat_type,
                                "confidence": res.confidence,
                                "evidence": res.evidence,
                                "severity": res.severity,
                                "fusion_reason": res.fusion_reason,
                                "all_detector_results": res.all_detector_results,
                            }
                            logger.info(f"PHASE1_DEBUG: Broadcasting alert: {alert_payload}")
                            await manager.broadcast({"type": "alert", "payload": alert_payload})
                    else:
                        state.processing_errors += 1
                        
        await future
    finally:
        if state.processing_started_at == local_started_at:
            state.is_processing = False


@router.post("/demo/pcap", response_model=DetectionResponse)
async def demo_pcap(request: DemoPcapRequest, background_tasks: BackgroundTasks):
    if not state.orchestrator:
        raise HTTPException(status_code=503, detail="Model orchestrator not initialized")

    if state.is_processing:
        if time.time() - state.processing_started_at > 300:
            logger.warning("Lock was stuck for > 5 minutes. Clearing stuck lock.")
            state.is_processing = False
        else:
            raise HTTPException(status_code=409, detail="Another file is currently being processed. Please wait.")

    safe_dir = os.path.abspath(os.path.join(os.getcwd(), "NTRO-Datasets", "PCAPS"))
    safe_dir2 = os.path.abspath(os.path.join(os.getcwd(), "PS145-Test-PCAPs"))
    safe_dir3 = os.path.abspath(os.path.join(os.getcwd(), "tests", "fixtures"))

    req_path = os.path.abspath(request.pcap_path)

    if not (req_path.lower().startswith(safe_dir.lower()) or req_path.lower().startswith(safe_dir2.lower()) or req_path.lower().startswith(safe_dir3.lower())) or not os.path.exists(req_path):
        raise HTTPException(status_code=400, detail="Invalid or unsafe PCAP path.")

    background_tasks.add_task(process_pcap_background, req_path)

    return DetectionResponse(
        message=f"Started streaming processing for {req_path}",
        detections=[]
    )


@router.post("/demo/upload_pcap", response_model=DetectionResponse)
async def upload_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not state.orchestrator:
        raise HTTPException(status_code=503, detail="Model orchestrator not initialized")
    
    if state.is_processing:
        if time.time() - state.processing_started_at > 300:
            logger.warning("Lock was stuck for > 5 minutes. Clearing stuck lock.")
            state.is_processing = False
        else:
            raise HTTPException(status_code=409, detail="Another file is currently being processed. Please wait.")
    
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are allowed.")
    
    temp_dir = os.path.abspath(os.path.join(os.getcwd(), "tests", "fixtures"))
    os.makedirs(temp_dir, exist_ok=True)
    file_path = os.path.join(temp_dir, f"uploaded_{file.filename}")
    
    try:
        with open(file_path, "wb") as buffer:
            import shutil
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(status_code=500, detail="Failed to save uploaded file.")
    finally:
        file.file.close()

    background_tasks.add_task(process_pcap_background, file_path)

    return DetectionResponse(
        message=f"Started streaming processing for uploaded file {file.filename}",
        detections=[]
    )

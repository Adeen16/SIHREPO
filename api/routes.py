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
        
    engine = state.orchestrator.inference_engine
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
        processing_errors=state.processing_errors
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
                if res.status == "success":
                    state.detections_generated += 1
                else:
                    state.processing_errors += 1
                    
                response_items.append(
                    DetectionResponseItem(
                        flow_id=res.flow_id,
                        timestamp=res.timestamp,
                        status=res.status,
                        predicted_class=res.predicted_class,
                        confidence=res.confidence,
                        model_name=res.model_name,
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

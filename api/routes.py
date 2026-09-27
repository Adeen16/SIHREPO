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

class DemoPcapRequest(BaseModel):
    pcap_path: str

@router.post("/demo/pcap", response_model=DetectionResponse)
def demo_pcap(request: DemoPcapRequest):
    """
    Safely runs a local PCAP file through the pipeline for demonstration.
    """
    if not state.orchestrator:
        raise HTTPException(status_code=503, detail="Model orchestrator not initialized")
        
    safe_dir = os.path.abspath(os.path.join(os.getcwd(), "NTRO-Datasets", "PCAPS"))
    safe_dir2 = os.path.abspath(os.path.join(os.getcwd(), "PS145-Test-PCAPs"))
    
    req_path = os.path.abspath(request.pcap_path)
    
    if not (req_path.startswith(safe_dir) or req_path.startswith(safe_dir2)) or not os.path.exists(req_path):
        raise HTTPException(status_code=400, detail="Invalid or unsafe PCAP path. Must be within NTRO-Datasets/PCAPS or PS145-Test-PCAPs.")
        
    try:
        ingestor = PCAPIngestor(req_path)
        all_results = []
        for packet in ingestor:
            state.packets_processed += 1
            results = state.orchestrator.process_packet(packet)
            if results:
                state.windows_completed += 1
                for res in results:
                    if res.status != "error":
                        state.detections_generated += 1
                    else:
                        state.processing_errors += 1
                    
                    all_results.append(
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
            message=f"Demo PCAP processed. {len(all_results)} detections generated.",
            detections=all_results
        )
    except Exception as e:
        logger.error(f"Demo processing failure: {e}")
        raise HTTPException(status_code=500, detail=f"Demo processing failure: {e}")


from pydantic import BaseModel, Field
from typing import Optional, List

class PacketEventRequest(BaseModel):
    """
    Pydantic schema matching the ingestion.packet_event.PacketEvent structure.
    Used for HTTP API request validation.
    """
    timestamp: float = Field(..., description="The time the packet was observed")
    length: int = Field(..., ge=0, description="The size of the packet in bytes")
    
    src_ip: Optional[str] = Field(None, description="Source IP Address")
    dst_ip: Optional[str] = Field(None, description="Destination IP Address")
    
    src_port: Optional[int] = Field(None, ge=0, le=65535, description="Source Port")
    dst_port: Optional[int] = Field(None, ge=0, le=65535, description="Destination Port")
    
    protocol: Optional[str] = Field(None, description="Transport Protocol (e.g., TCP, UDP)")

class DetectionResponseItem(BaseModel):
    """
    Represents a single detection result for a flow.
    """
    flow_id: str
    timestamp: float
    status: str
    predicted_class: Optional[str] = None
    confidence: Optional[float] = None
    model_name: Optional[str] = None
    error_message: Optional[str] = None

class DetectionResponse(BaseModel):
    """
    The response structure for a detect request.
    It returns a list of results (if any windows were completed).
    """
    message: str
    detections: List[DetectionResponseItem]

class ModelInfoResponse(BaseModel):
    """
    Configuration information for the current ML model.
    """
    model_name: str
    features_expected: int
    features_list: List[str]

class StatusResponse(BaseModel):
    """
    Real-time status counters of the API and orchestrator.
    """
    status: str
    model_loaded: bool
    packets_processed: int
    windows_completed: int
    detections_generated: int
    processing_errors: int

from typing import Optional
from dataclasses import dataclass
from detection.orchestrator import DetectionOrchestrator

@dataclass
class APIState:
    orchestrator: Optional[DetectionOrchestrator] = None
    packets_processed: int = 0
    windows_completed: int = 0
    detections_generated: int = 0
    processing_errors: int = 0

state = APIState()

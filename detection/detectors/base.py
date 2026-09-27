from dataclasses import dataclass
from typing import Optional, Dict, Any
from api.schemas import DetectionResponseItem

@dataclass
class DetectionResult:
    """Internal model for detection result before API translation."""
    flow_id: str
    timestamp: float
    status: str  # DETECTED, NOT_DETECTED, INSUFFICIENT_DATA, UNVALIDATED
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    score: Optional[float] = None
    detector_name: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class BaseDetector:
    """Base class for all threat detectors."""
    
    @property
    def name(self) -> str:
        return self.__class__.__name__

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        """
        Evaluate a single flow's snapshot within a window.
        Returns a DetectionResult.
        """
        raise NotImplementedError("Detectors must implement evaluate()")

import logging
from dataclasses import dataclass
from typing import List, Optional, Dict

from ingestion.packet_event import PacketEvent
from processing.window import SlidingWindowManager
from processing.features import FeatureExtractor
from detection.bridge import Phase6toPhase8Bridge
from detection.inference import BaselineInferenceEngine

logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    flow_id: str
    timestamp: float  # The end time of the window snapshot
    status: str       # "success" or "error"
    predicted_class: Optional[str] = None
    confidence: Optional[float] = None
    model_name: Optional[str] = None
    error_message: Optional[str] = None

class DetectionOrchestrator:
    """
    Coordinates the real-time detection pipeline from raw packets to ML inference.
    
    Pipeline:
    PacketEvent -> SlidingWindowManager -> FeatureExtractor -> Phase6toPhase8Bridge -> BaselineInferenceEngine
    """
    def __init__(self, model_dir: str, model_name: str = "RandomForest", window_seconds: float = 10.0, slide_seconds: float = 1.0):
        self.window_manager = SlidingWindowManager(window_seconds=window_seconds, slide_seconds=slide_seconds)
        self.feature_extractor = FeatureExtractor()
        self.bridge = Phase6toPhase8Bridge()
        self.inference_engine = BaselineInferenceEngine(model_dir=model_dir, model_name=model_name)

    def process_packet(self, packet: PacketEvent) -> List[DetectionResult]:
        """
        Processes a single PacketEvent through the pipeline.
        Returns a list of DetectionResults for any flows whose sliding window has completed.
        """
        results: List[DetectionResult] = []
        
        # 1. Update sliding window and get completed snapshots
        try:
            snapshots = self.window_manager.add_packet(packet)
        except ValueError as e:
            # e.g., Out-of-order timestamp. Preserve Phase 5 behavior by letting the caller handle or log it.
            raise e

        # 2. For each completed snapshot, extract features and run inference
        for snapshot in snapshots:
            # Phase 6: Extract canonical 16-feature representation for all flows in the window
            features_by_flow = self.feature_extractor.extract_features(snapshot)
            
            for flow_id, phase6_features in features_by_flow.items():
                result = self._run_inference_for_flow(flow_id, snapshot.window_end, phase6_features)
                results.append(result)
                
        return results

    def _run_inference_for_flow(self, flow_id: str, timestamp: float, phase6_features: Dict[str, float]) -> DetectionResult:
        """
        Converts features through the bridge and executes the baseline model.
        """
        try:
            # Phase 6 -> Phase 8 Bridge (validates and converts to 13-feature array)
            vector = self.bridge.convert(phase6_features)
            
            # Phase 8 Baseline Inference
            inference_output = self.inference_engine.predict(vector)
            
            return DetectionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                status="success",
                predicted_class=inference_output.get("predicted_class"),
                confidence=inference_output.get("confidence"),
                model_name=inference_output.get("model_name")
            )
            
        except Exception as e:
            # Missing feature, None value, or other failure
            return DetectionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                status="error",
                error_message=str(e)
            )

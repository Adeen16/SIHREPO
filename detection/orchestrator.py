import logging
from dataclasses import dataclass
from typing import List, Optional, Dict

from ingestion.packet_event import PacketEvent
from processing.window import SlidingWindowManager
from processing.features import FeatureExtractor
from detection.detectors.base import DetectionResult
from detection.detectors.fusion import FusionEngine
from detection.detectors.ddos import DDoSDetector
from detection.detectors.c2_beacon import C2BeaconingDetector
from detection.detectors.dns_tunnel import DNSTunnelDetector
from detection.detectors.encrypted_malware import EncryptedMalwareDetector
from detection.detectors.reconnaissance import ReconnaissanceDetector
from detection.detectors.exfiltration import ExfiltrationDetector

logger = logging.getLogger(__name__)



class DetectionOrchestrator:
    """
    Coordinates the real-time detection pipeline from raw packets to ML inference.
    
    Pipeline:
    PacketEvent -> SlidingWindowManager -> FeatureExtractor -> Phase6toPhase8Bridge -> BaselineInferenceEngine
    """
    def __init__(self, model_dir: str, model_name: str = "RandomForest", window_seconds: float = 10.0, slide_seconds: float = 1.0):
        self.window_manager = SlidingWindowManager(window_seconds=window_seconds, slide_seconds=slide_seconds)
        self.feature_extractor = FeatureExtractor()
        
        self.detectors = [
            DDoSDetector(model_dir=model_dir, model_name=model_name),
            C2BeaconingDetector(),
            DNSTunnelDetector(),
            EncryptedMalwareDetector(),
            ReconnaissanceDetector(),
            ExfiltrationDetector()
        ]
        self.fusion = FusionEngine()

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
                result = self._run_inference_for_flow(snapshot, flow_id, phase6_features)
                results.append(result)
                
        return results

    def _run_inference_for_flow(self, snapshot, flow_id: str, phase6_features: Dict[str, float]) -> DetectionResult:
        """
        Executes all PS 145 detectors and fuses the result.
        """
        flow_state = snapshot.flows.get(flow_id)
        if not flow_state:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=snapshot.window_end,
                status="error",
                error_message="Flow state missing from snapshot"
            )
            
        raw_results = []
        for detector in self.detectors:
            try:
                res = detector.evaluate(snapshot, flow_state, phase6_features)
                raw_results.append(res)
            except Exception as e:
                logger.error(f"Detector {detector.name} failed: {e}")
                raw_results.append(DetectionResult(
                    flow_id=flow_id,
                    timestamp=snapshot.window_end,
                    status="error",
                    detector_name=detector.name,
                    evidence={"error": str(e)}
                ))
                
        return self.fusion.fuse(flow_id, snapshot.window_end, raw_results)

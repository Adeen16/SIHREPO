from typing import Dict, Any
from detection.detectors.base import BaseDetector, DetectionResult
from detection.bridge import Phase6toPhase8Bridge
from detection.inference import BaselineInferenceEngine

class DDoSDetector(BaseDetector):
    """
    Detects Volumetric DDoS using the Phase 8 Random Forest baseline.
    """
    def __init__(self, model_dir: str, model_name: str = "RandomForest"):
        self.bridge = Phase6toPhase8Bridge()
        self.inference_engine = BaselineInferenceEngine(model_dir=model_dir, model_name=model_name)

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        flow_id = flow_state.flow_id
        
        try:
            vector = self.bridge.convert(phase6_features)
            inference_output = self.inference_engine.predict(vector)
            
            predicted_class = inference_output.get("predicted_class")
            confidence = inference_output.get("confidence")
            
            if predicted_class and "DoS" in predicted_class:
                return DetectionResult(
                    flow_id=flow_id,
                    timestamp=window_snapshot.window_end,
                    status="DETECTED",
                    threat_type="DDoS",
                    severity="HIGH",
                    confidence=confidence,
                    detector_name=self.name,
                    evidence={
                        "packets_per_sec": phase6_features.get("fwd_pkts_per_sec", 0) + phase6_features.get("rev_pkts_per_sec", 0),
                        "bytes_per_sec": phase6_features.get("fwd_bytes_per_sec", 0) + phase6_features.get("rev_bytes_per_sec", 0),
                        "model": inference_output.get("model_name"),
                        "predicted_class": predicted_class
                    }
                )
            else:
                return DetectionResult(
                    flow_id=flow_id,
                    timestamp=window_snapshot.window_end,
                    status="NOT_DETECTED",
                    detector_name=self.name
                )
        except Exception as e:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="error",
                detector_name=self.name,
                error_message=str(e),
                evidence={"error": str(e)}
            )

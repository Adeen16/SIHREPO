import math
from detection.detectors.base import BaseDetector, DetectionResult

class C2BeaconingDetector(BaseDetector):
    """
    Detects Botnet C2 Beaconing using inter-arrival time (IAT) regularity.
    Relies on Welford's streaming variance implemented in FlowState.
    """
    def __init__(self, min_packets: int = 10, max_cv: float = 0.1, min_duration: float = 10.0):
        self.min_packets = min_packets
        # Coefficient of Variation (stddev / mean). A low CV means highly regular timing.
        self.max_cv = max_cv 
        self.min_duration = min_duration

    def evaluate(self, window_snapshot, flow_state, phase6_features) -> DetectionResult:
        flow_id = flow_state.flow_id
        
        if flow_state.packet_count < self.min_packets or flow_state.duration < self.min_duration:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="INSUFFICIENT_DATA",
                detector_name=self.name
            )
            
        if flow_state._iat_count < 2 or flow_state._iat_mean == 0.0:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="NOT_DETECTED",
                detector_name=self.name
            )
            
        variance = flow_state._iat_m2 / (flow_state._iat_count - 1)
        stddev = math.sqrt(variance)
        cv = stddev / flow_state._iat_mean
        
        if cv <= self.max_cv:
            return DetectionResult(
                flow_id=flow_id,
                timestamp=window_snapshot.window_end,
                status="DETECTED",
                threat_type="C2_BEACONING",
                severity="HIGH",
                score=1.0 - cv,  # higher score for more regularity
                detector_name=self.name,
                evidence={
                    "periodicity_cv": cv,
                    "iat_mean": flow_state._iat_mean,
                    "packet_count": flow_state.packet_count,
                    "duration": flow_state.duration,
                    "reason": "highly regular inter-arrival timing (beaconing)"
                }
            )
            
        return DetectionResult(
            flow_id=flow_id,
            timestamp=window_snapshot.window_end,
            status="NOT_DETECTED",
            detector_name=self.name
        )
